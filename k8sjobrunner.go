package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	k8swatch "k8s.io/client-go/tools/watch"
	"k8s.io/utils/ptr"
)

// K8sJob encapsulates the configuration and state needed to manage a Kubernetes
// Job for running fuzzing tasks, including context, logger, Kubernetes client,
// configuration, working directories, and command.
type K8sJob struct {
	ctx       context.Context
	logger    *slog.Logger
	jobName   string
	clientset *kubernetes.Clientset
	cfg       *Config
	workDir   string
	cmd       []string
}

// Start creates a Kubernetes Job with the specified configuration.
// It returns the job name if successful, or an error if job creation fails.
//
//nolint:lll
func (k *K8sJob) Start() (string, error) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: k.jobName,
		},
		Spec: batchv1.JobSpec{
			// No retries so that we do not restart if there is a fuzz crash.
			BackoffLimit: ptr.To(int32(0)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "go-continuous-fuzz-sa",
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:  ptr.To(int64(os.Getuid())),
						RunAsGroup: ptr.To(int64(os.Getgid())),
					},
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:       "fuzz-container",
							Image:      ContainerImage,
							Command:    k.cmd,
							WorkingDir: k.workDir,
							Env: []corev1.EnvVar{
								{
									Name:  "GOCACHE",
									Value: "/tmp",
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "go-continuous-fuzz-src",
									MountPath: InClusterWorkspacePath,
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("2Gi"),
									corev1.ResourceCPU:    resource.MustParse("1"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("2Gi"),
									corev1.ResourceCPU:    resource.MustParse("1"),
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "go-continuous-fuzz-src",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: "go-continuous-fuzz-pvc",
								},
							},
						},
					},
				},
			},
		},
	}

	// Create job in Kubernetes
	_, err := k.clientset.BatchV1().Jobs(k.cfg.Fuzz.NameSpace).Create(k.ctx, job, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create job: %w", err)
	}

	// Returning the job name to maintain consistency with the Container
	// implementation for abstraction.
	return k.jobName, nil
}

// WaitAndGetLogs watches the job's pod and listens to the pod's log stream,
// processes fuzz output, and reports either a fuzz crash or the job's status.
//
// It reads logs until EOF or context cancellation, then:
// 1. If a fuzz failure is detected, crash data is sent on fuzzCrashChan.
// 2. Otherwise, retrieves the job's exit error and sends it on errChan.
//
// No values are sent if the context is canceled or times out.
//
//	This MUST be run as a goroutine.
func (k *K8sJob) WaitAndGetLogs(jobName, pkg, target string,
	fuzzCrashChan chan fuzzCrash, errChan chan error) {
	// Wait until a pod associated with the job is created and is either
	// Running, Succeeded, or Failed.
	pod, err := k.waitForPod()
	if err != nil {
		if k.ctx.Err() == nil {
			errChan <- fmt.Errorf("error waiting for pod: %w", err)
		}
		return
	}

	// Acquire the log stream for the running pod.
	logsReq := k.clientset.CoreV1().Pods(k.cfg.Fuzz.NameSpace).GetLogs(
		pod.Name, &corev1.PodLogOptions{
			Follow: true,
		})
	logsStream, err := logsReq.Stream(k.ctx)
	if err != nil {
		if k.ctx.Err() == nil {
			errChan <- fmt.Errorf("failed to get logs stream: %w",
				err)
		}
		return
	}
	defer func() {
		if err := logsStream.Close(); err != nil {
			k.logger.Error("error closing logs stream", "jobName",
				jobName, "error", err)
		}
	}()

	// Define the path where failing corpus inputs might be saved by the
	// fuzzing process.
	maybeFailingCorpusPath := filepath.Join(k.cfg.Project.SrcDir, pkg,
		"testdata", "fuzz")

	// Process the standard output, which may include both stdout and stderr
	// content.
	processor := NewFuzzOutputProcessor(k.logger.With("target", target).
		With("package", pkg), maybeFailingCorpusPath)
	crashData, err := processor.processFuzzStream(logsStream)
	if err != nil {
		errChan <- fmt.Errorf("failed to process fuzz stream for "+
			"job %s: %w", jobName, err)
		return
	}

	// Fuzz target crashed, so report and exit this goroutine.
	if crashData != nil {
		fuzzCrashChan <- *crashData
		return
	}

	// Retrieve the job status and send error (if any) on errChan.
	errChan <- k.waitForJobCompletion()
}

// waitForPod waits for a pod associated with the job to be created and reach a
// terminal or running state. It first lists existing pods and then watches for
// any changes. The function returns when a pod transitions to one of the
// following phases: Running, Succeeded, or Failed.
func (k *K8sJob) waitForPod() (*corev1.Pod, error) {
	labelSel := fmt.Sprintf("job-name=%s", k.jobName)

	lw := &cache.ListWatch{
		ListFunc: func(opts metav1.ListOptions) (runtime.Object,
			error) {

			opts.LabelSelector = labelSel
			return k.clientset.CoreV1().
				Pods(k.cfg.Fuzz.NameSpace).
				List(k.ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface,
			error) {

			opts.LabelSelector = labelSel
			return k.clientset.CoreV1().
				Pods(k.cfg.Fuzz.NameSpace).
				Watch(k.ctx, opts)
		},
	}

	// Wait for Pod to reach a terminal or running state.
	evt, err := k8swatch.UntilWithSync(k.ctx, lw, &corev1.Pod{}, nil,
		func(event watch.Event) (bool, error) {
			if event.Type == watch.Error {
				return false, fmt.Errorf("watch error: %v",
					event.Object)
			}
			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				return false, nil
			}

			phase := pod.Status.Phase
			if phase == corev1.PodRunning ||
				phase == corev1.PodSucceeded ||
				phase == corev1.PodFailed {

				return true, nil
			}
			return false, nil
		})
	if err != nil {
		return nil, fmt.Errorf("timed out or failed waiting for "+
			"pod: %w", err)
	}

	pod, ok := evt.Object.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("unexpected object type %T", evt.Object)
	}
	return pod, nil
}

// waitForJobCompletion waits for the Kubernetes Job to complete by either
// succeeding or failing. It returns nil if the job succeeds, or an error if the
// job fails or a watch error occurs. If the context is cancelled or times out,
// it returns nil
func (k *K8sJob) waitForJobCompletion() error {
	fieldSel := fmt.Sprintf("metadata.name=%s", k.jobName)
	lw := &cache.ListWatch{
		ListFunc: func(opts metav1.ListOptions) (runtime.Object,
			error) {

			opts.FieldSelector = fieldSel
			return k.clientset.BatchV1().Jobs(k.cfg.Fuzz.NameSpace).
				List(k.ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface,
			error) {

			opts.FieldSelector = fieldSel
			return k.clientset.BatchV1().Jobs(k.cfg.Fuzz.NameSpace).
				Watch(k.ctx, opts)
		},
	}

	// Wait for Job to succeed or fail.
	_, err := k8swatch.UntilWithSync(k.ctx, lw, &batchv1.Job{}, nil,
		func(event watch.Event) (bool, error) {
			if event.Type == watch.Error {
				return false, fmt.Errorf("watch error: %v",
					event.Object)
			}

			job, ok := event.Object.(*batchv1.Job)
			if !ok {
				return false, nil
			}

			switch {
			case job.Status.Succeeded > 0:
				return true, nil
			case job.Status.Failed > 0:
				return false, fmt.Errorf("fuzz job %q failed",
					k.jobName)
			default:
				return false, nil
			}
		})

	if err != nil && k.ctx.Err() == nil {
		return fmt.Errorf("job %q watch failed: %w", k.jobName, err)
	}
	return nil
}

// Stop deletes a specified Kubernetes job and its associated pods.
func (k *K8sJob) Stop(jobName string) {
	propagationPolicy := metav1.DeletePropagationBackground
	err := k.clientset.BatchV1().Jobs(k.cfg.Fuzz.NameSpace).Delete(
		context.Background(), jobName, metav1.DeleteOptions{
			PropagationPolicy: &propagationPolicy,
		})
	if err != nil {
		k.logger.Error("Failed to delete job", "error", err, "jobName",
			jobName)
	}
}
