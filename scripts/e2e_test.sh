#!/bin/bash

set -eux

# ====== CONFIGURATION ======

readonly MODE="${1:-docker}" # default to 'docker' if not specified
# Validate MODE
if [[ "$MODE" != "docker" && "$MODE" != "k8s" ]]; then
  echo "❌ Invalid mode: '$MODE'. Allowed values are 'docker' or 'k8s'."
  exit 1
fi

# Temporary Variables
readonly PROJECT_SRC_PATH="https://oauth2:${GO_FUZZING_EXAMPLE_AUTH_TOKEN}@github.com/go-continuous-fuzz/go-fuzzing-example.git"
readonly SYNC_FREQUENCY="3m"
readonly MAKE_TIMEOUT="330s"

# Use test workspace directory
readonly TEST_WORKDIR=$(mktemp -dt "test-go-continuous-fuzz-XXXXXX")
readonly PROJECT_DIR="${TEST_WORKDIR}/project"
readonly REPORT_DIR="${TEST_WORKDIR}/reports"
readonly CORPUS_DIR_NAME="go-fuzzing-example_corpus"
readonly CORPUS_ZIP_NAME="${CORPUS_DIR_NAME}.zip"
readonly CORPUS_DIR_PATH="${TEST_WORKDIR}/${CORPUS_DIR_NAME}"
readonly FUZZ_RESULTS_PATH="${TEST_WORKDIR}/fuzz_results"
readonly BUCKET_NAME="test-go-continuous-fuzz-bucket"

# Non-crashing fuzz target definitions (package:function)
readonly NON_CRASHING_FUZZ_TARGETS=(
  "parser:FuzzEvalExpr"
  "stringutils:FuzzReverseString"
)

# All fuzz target definitions (package:function)
readonly ALL_FUZZ_TARGETS=(
  "parser:FuzzEvalExpr"
  "parser:FuzzParseComplex"
  "stringutils:FuzzReverseString"
  "stringutils:FuzzUnSafeReverseString"
  "tree:FuzzBuildTree"
)

# ====== FUNCTION DEFINITIONS ======

# Counts the number of test inputs in a corpus directory
# Arguments:
#   $1 - Package name
#   $2 - Function name
# Returns: Number of input files
count_corpus_inputs() {
  local pkg="$1"
  local func="$2"

  local dir="${CORPUS_DIR_PATH}/${pkg}/testdata/fuzz/${func}"

  if [[ -d "${dir}" ]]; then
    local num_inputs=$(ls "${dir}" | wc -l)
    echo ${num_inputs}
  else
    echo 0
  fi
}

# Measures the code coverage for a fuzz target
# Arguments:
#   $1 - Package name
#   $2 - Function name
# Returns: Coverage percentage value
measure_fuzz_coverage() {
  local pkg="$1"
  local func="$2"
  local coverage_result

  cd "${PROJECT_DIR}/${pkg}"

  # Enable Go fuzzing debug output
  export GODEBUG="fuzzdebug=1"

  # Count existing corpus inputs
  local num_inputs=$(count_corpus_inputs "${pkg}" "${func}")

  # Run coverage measurement
  coverage_result=$(go test -run="^${func}$" -fuzz="^${func}$" \
    -fuzztime="${num_inputs}x" \
    -test.fuzzcachedir="${CORPUS_DIR_PATH}/${pkg}/testdata/fuzz" |
    grep "initial coverage bits:" | grep -oE "[0-9]+$")

  echo "${coverage_result}"
}

# Checks if any GitHub issue in a repository contains a given string.
# Arguments:
#   $1 - String to search for in issue bodies
# Returns:
#   Exits with 0 if a matching issue is found; otherwise exits with 1
check_issue_contains_string() {
  local search_string="$1"

  # Extract owner, and repo from URL
  local owner_repo owner repo
  owner_repo=$(echo "${PROJECT_SRC_PATH}" | sed -n 's|.*github.com/\(.*\)\.git|\1|p')
  owner=$(echo "${owner_repo}" | cut -d'/' -f1)
  repo=$(echo "${owner_repo}" | cut -d'/' -f2)

  if [[ -z "${owner}" || -z "${repo}" ]]; then
    echo "❌ ERROR: Failed to parse owner/repo from URL."
    return 1
  fi

  echo "Checking issues in ${owner}/${repo} for '${search_string}'..."

  # Fetch issues from GitHub API
  local issues
  issues=$(curl -s -H "Authorization: token ${GO_FUZZING_EXAMPLE_AUTH_TOKEN}" \
    "https://api.github.com/repos/${owner}/${repo}/issues")

  # Check if any issue body contains the target string
  if ! echo "${issues}" | grep -qF "${search_string}"; then
    echo "❌ ERROR: No issue contains '${search_string}'"
    return 1
  fi

  return 0
}

# Cleans up temporary workspace
cleanup() {
  echo "Cleaning up resources..."
  rm -rf "${TEST_WORKDIR}"
}

# ====== MAIN EXECUTION ======

# Ensure that resources are cleaned up when the script exits
trap cleanup EXIT

# Clone the target repository
echo "Cloning project repository..."
git clone "${PROJECT_SRC_PATH}" "${PROJECT_DIR}"

# Download and extract only the seed_corpus directory from the project tarball
echo "Downloading seed corpus..."
mkdir -p ${CORPUS_DIR_PATH}
curl -L https://codeload.github.com/go-continuous-fuzz/go-fuzzing-example/tar.gz/main |
  tar -xz --strip-components=2 -C ${CORPUS_DIR_PATH} go-fuzzing-example-main/seed_corpus

# Create the S3 bucket (if not already) and upload the zipped corpus
echo "Creating S3 bucket and uploading corpus..."
if ! aws s3api head-bucket --bucket "${BUCKET_NAME}"; then
  echo "Bucket ${BUCKET_NAME} not found—creating it now."
  aws s3 mb "s3://${BUCKET_NAME}"
else
  echo "Bucket ${BUCKET_NAME} already exists, skipping creation."
  # Remove all the bucket contents
  aws s3 rm "s3://${BUCKET_NAME}" --recursive
fi
(
  cd "${TEST_WORKDIR}"
  zip -r ${CORPUS_ZIP_NAME} ${CORPUS_DIR_NAME}
  aws s3 cp ${CORPUS_ZIP_NAME} s3://${BUCKET_NAME}/${CORPUS_ZIP_NAME}
)

# Initialize data stores
declare -A initial_input_counts
declare -A initial_coverage_metrics
declare -A final_input_counts
declare -A final_coverage_metrics

# Capture initial corpus state
echo "Recording initial corpus state..."
for target in "${NON_CRASHING_FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg func <<<"${target}"
  echo "  - ${pkg}/${func}"
  initial_input_counts["${target}"]=$(count_corpus_inputs "${pkg}" "${func}")
  initial_coverage_metrics["${target}"]=$(measure_fuzz_coverage "${pkg}" "${func}")
done

# Execute fuzzing process
echo "Starting fuzzing process (timeout: ${MAKE_TIMEOUT})..."
mkdir -p "${FUZZ_RESULTS_PATH}"
MAKE_LOG="${FUZZ_RESULTS_PATH}/make_run.log"

if [[ ${MODE} == "k8s" ]]; then
  echo "Running in Kubernetes mode..."

  # Configuration variables
  readonly AWS_SECRET_NAME="aws-creds"
  readonly HELM_RELEASE_NAME="go-continuous-fuzz"
  readonly K8S_NAMESPACE="go-continuous-fuzz-ns"
  readonly POD_NAME="go-continuous-fuzz-pod"

  # Enable Docker environment inside Minikube
  eval $(minikube docker-env)

  # Build Docker image
  echo "Building Docker image..."
  if ! make docker; then
    echo "❌ Failed to build Docker image"
    exit 1
  fi

  # Deploy Helm chart
  echo "Installing/Upgrading Helm release..."
  if ! helm upgrade --install "${HELM_RELEASE_NAME}" "./go-continuous-fuzz-chart" --namespace "${K8S_NAMESPACE}" --create-namespace; then
    echo "❌ Failed to deploy Helm chart"
    exit 1
  fi

  # Set the default namespace for kubectl commands
  kubectl config set-context --current --namespace="${K8S_NAMESPACE}"

  # Recreate AWS credentials secret
  kubectl delete secret ${AWS_SECRET_NAME} --ignore-not-found

  secret_args=(
    --from-literal=AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}"
    --from-literal=AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}"
    --from-literal=AWS_REGION="${AWS_REGION}"
  )
  if [[ -n "${AWS_SESSION_TOKEN:-}" ]]; then
    secret_args+=(--from-literal=AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN}")
  fi

  if ! kubectl create secret generic "${AWS_SECRET_NAME}" "${secret_args[@]}"; then
    echo "❌ Failed to create AWS credentials secret"
    exit 1
  fi

  # Apply additional K8s resources
  echo "Applying manifests..."
  # Substitute the GitHub token into the ConfigMap manifest and apply it to the cluster
  if ! sed "s|\${GO_FUZZING_EXAMPLE_AUTH_TOKEN}|${GO_FUZZING_EXAMPLE_AUTH_TOKEN}|g" ./manifests/configmap.yaml | kubectl apply -f -; then
    echo "❌ Failed to apply configmap.yaml"
    exit 1
  fi

  for manifest in pvc.yaml pod.yaml; do
    if ! kubectl apply -f "./manifests/${manifest}"; then
      echo "❌ Failed to apply ${manifest}"
      exit 1
    fi
  done

  # Wait for the pod to be ready
  echo "Waiting for pod '${POD_NAME}' to be ready..."
  if ! kubectl wait --for=condition=Ready pod/"${POD_NAME}" --timeout=60s; then
    echo "❌ Pod '${POD_NAME}' did not become ready in time"
    kubectl describe pod "${POD_NAME}"
    exit 1
  fi

  # Stream logs with timeout
  echo "Streaming logs from pod for ${MAKE_TIMEOUT} seconds..."
  kubectl logs -f "${POD_NAME}" &
  sleep "${MAKE_TIMEOUT}"

  # Gracefully stop the fuzzing process
  echo "Stopping fuzzing process in pod..."
  if ! kubectl exec "${POD_NAME}" -- pkill -SIGINT -f go-continuous-fuzz; then
    echo "❌ Failed to send SIGINT to go-continuous-fuzz. Process may have exited early."
    exit 1
  fi
  sleep 20s

  # Collect final logs
  kubectl logs "${POD_NAME}" >>"${MAKE_LOG}"

  # Clean up pod
  kubectl delete pod "${POD_NAME}" --ignore-not-found

else
  echo "Running in Docker mode..."

  # Command-line flags for fuzzing process configuration
  ARGS="\
--project.src-repo=${PROJECT_SRC_PATH} \
--project.s3-bucket-name=${BUCKET_NAME} \
--fuzz.sync-frequency=${SYNC_FREQUENCY} \
--fuzz.crash-repo=${PROJECT_SRC_PATH} \
--fuzz.num-workers=3 \
--fuzz.pkgs-path=parser \
--fuzz.pkgs-path=stringutils \
--fuzz.pkgs-path=tree"

  # Run make run under timeout, capturing stdout+stderr into MAKE_LOG.
  timeout -s INT --preserve-status "${MAKE_TIMEOUT}" make run ARGS="${ARGS}" 2>&1 | tee "${MAKE_LOG}"
  status=${PIPESTATUS[0]}

  # Handle exit codes:
  #   130 → timeout sent SIGINT; treat as expected termination
  #   any other non-zero → unexpected error
  if [[ ${status} -ne 130 ]]; then
    echo "❌ Fuzzing exited with unexpected error (status: ${status})."
    exit "${status}"
  fi
fi

# List of required patterns to check in the log
REQUIRED_PATTERNS=(
  'All workers completed early; cleaning up cycle' # due to grace period
  'Successfully downloaded and unzipped corpus'
  'Successfully zipped and uploaded corpus'
  'msg="Successfully added/updated coverage report" package=stringutils target=FuzzUnSafeReverseString'
  'msg="Successfully added/updated coverage report" package=stringutils target=FuzzReverseString'
  'msg="Successfully added/updated coverage report" package=parser target=FuzzParseComplex'
  'msg="Successfully added/updated coverage report" package=parser target=FuzzEvalExpr'
  'msg="Successfully added/updated coverage report" package=tree target=FuzzBuildTree'
  'Shutdown initiated during fuzzing cycle; performing final cleanup.'
  'msg="Worker starting fuzz target" workerID=1'
  'msg="Worker starting fuzz target" workerID=2'
  'msg="Worker starting fuzz target" workerID=3'
  'msg="Per-target fuzz timeout calculated" duration=1m30s'
)

if [[ ${MODE} == "k8s" ]]; then
  REQUIRED_PATTERNS+=(
    'Running fuzzing jobs inside Kubernetes'
    'msg="Fuzzing completed successfully" mode=Kubernetes package=stringutils target=FuzzUnSafeReverseString'
    'msg="Fuzzing completed successfully" mode=Kubernetes package=stringutils target=FuzzReverseString'
    'msg="Fuzzing completed successfully" mode=Kubernetes package=parser target=FuzzParseComplex'
    'msg="Fuzzing completed successfully" mode=Kubernetes package=parser target=FuzzEvalExpr'
    'msg="Fuzzing completed successfully" mode=Kubernetes package=tree target=FuzzBuildTree'
  )
else
  REQUIRED_PATTERNS+=(
    'Running fuzzing jobs in Docker container'
    'msg="Fuzzing completed successfully" mode=Docker package=stringutils target=FuzzUnSafeReverseString'
    'msg="Fuzzing completed successfully" mode=Docker package=stringutils target=FuzzReverseString'
    'msg="Fuzzing completed successfully" mode=Docker package=parser target=FuzzParseComplex'
    'msg="Fuzzing completed successfully" mode=Docker package=parser target=FuzzEvalExpr'
    'msg="Fuzzing completed successfully" mode=Docker package=tree target=FuzzBuildTree'
  )
fi

# Verify that worker logs contain expected entries
echo "Verifying worker log entries in ${MAKE_LOG}..."
for pattern in "${REQUIRED_PATTERNS[@]}"; do
  if ! grep -q -- "${pattern}" "${MAKE_LOG}"; then
    echo "❌ ERROR: Missing expected log entry: ${pattern}"
    exit 1
  fi
done

# List of required log patterns where at least one in each group must be present
# Format: pattern1 || pattern2
readonly REQUIRED_PATTERN_GROUPS=(
  'msg="Issue already exists" target=FuzzParseComplex package=parser||msg="Issue created successfully" target=FuzzParseComplex package=parser'
  'msg="Issue already exists" target=FuzzUnSafeReverseString package=stringutils||msg="Issue created successfully" target=FuzzUnSafeReverseString package=stringutils'
  'msg="Issue already exists" target=FuzzBuildTree package=tree||msg="Issue created successfully" target=FuzzBuildTree package=tree'
)

echo "Verifying required issue-related log entries in ${MAKE_LOG}..."
for group in "${REQUIRED_PATTERN_GROUPS[@]}"; do
  IFS='||' read -r pattern1 pattern2 <<<"$group"
  if ! grep -q -- "${pattern1}" "${MAKE_LOG}" && ! grep -q -- "${pattern2}" "${MAKE_LOG}"; then
    echo "❌ ERROR: Neither of the expected log entries found:"
    echo "  -> ${pattern1}"
    echo "  -> ${pattern2}"
    exit 1
  fi
done

# List of patterns that should NOT be present in the log
FORBIDDEN_PATTERNS=(
  'level=ERROR'
  'msg="Worker starting fuzz target" workerID=4'
  'Cycle duration complete; initiating cleanup.'
  'Corpus object not found. Starting with empty corpus.'
  'warning: starting with empty corpus'
)

if [[ ${MODE} == "k8s" ]]; then
  FORBIDDEN_PATTERNS+=(
    'Running fuzzing jobs in Docker container'
  )
else
  FORBIDDEN_PATTERNS+=(
    'Running fuzzing jobs inside Kubernetes'
  )
fi

# Verify that worker logs do not contain forbidden entries
echo "Verifying absence of forbidden log entries in ${MAKE_LOG}..."
for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
  if grep -q -- "${pattern}" "${MAKE_LOG}"; then
    echo "❌ ERROR: Unexpected log entry found: ${pattern}"
    exit 1
  fi
done

# Download updated ZIP from S3 and extract into corpus directory
echo "Downloading updated corpus from S3..."
(
  cd "${TEST_WORKDIR}"
  aws s3 cp s3://${BUCKET_NAME}/${CORPUS_ZIP_NAME} "${CORPUS_ZIP_NAME}"
  unzip -o "${CORPUS_ZIP_NAME}"
)

# Download master state report from S3
echo "Downloading master state report from S3..."
mkdir -p "${REPORT_DIR}"
aws s3 cp s3://${BUCKET_NAME}/state.json "${REPORT_DIR}"

# Capture final corpus state
echo "Recording final corpus state..."
for target in "${NON_CRASHING_FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg func <<<"${target}"
  echo "  - ${pkg}/${func}"
  final_input_counts["${target}"]=$(count_corpus_inputs "${pkg}" "${func}")
  final_coverage_metrics["${target}"]=$(measure_fuzz_coverage "${pkg}" "${func}")
done

# Validate corpus growth
echo "Validating corpus growth..."
for target in "${NON_CRASHING_FUZZ_TARGETS[@]}"; do
  initial_count=${initial_input_counts["${target}"]}
  final_count=${final_input_counts["${target}"]}

  if [[ ${final_count} -le ${initial_count} ]]; then
    echo "❌ ERROR: ${target} regressed - inputs decreased from ${initial_count} to ${final_count}"
    exit 1
  fi
done

# Validate coverage metrics
echo "Validating coverage metrics..."
for target in "${NON_CRASHING_FUZZ_TARGETS[@]}"; do
  initial_cov=${initial_coverage_metrics["${target}"]}
  final_cov=${final_coverage_metrics["${target}"]}

  if [[ ${final_cov} -le ${initial_cov} ]]; then
    echo "❌ ERROR: ${target} coverage decreased from ${initial_cov} to ${final_cov}"
    exit 1
  fi
done

# Verify crash reports
echo "Checking crash reports..."
# Ensure only the expected number of files exist in FUZZ_RESULTS_PATH (1 make_run.log)
num_crash_files=$(ls "${FUZZ_RESULTS_PATH}" | wc -l)
if [[ "${num_crash_files}" -ne 1 ]]; then
  echo "❌ ERROR: Unexpected number of files in ${FUZZ_RESULTS_PATH} (found: ${num_crash_files}, expected: 1)"
  exit 1
fi

required_crashes=(
  "testing.go:1591: panic: runtime error: index out of range [6] with length 6"
  "stringutils_test.go:17: Reverse produced invalid UTF-8 string"
  "fuzzing process hung or terminated unexpectedly: exit status 2"
)

for crash in "${required_crashes[@]}"; do
  if ! check_issue_contains_string "${crash}"; then
    echo "❌ Fuzzing exited with unexpected error (crash: ${crash})."
    exit 1
  fi
done

# Verify the expected number of open issues in the crash repo
issue_count=$(curl -s -H "Authorization: token ${GO_FUZZING_EXAMPLE_AUTH_TOKEN}" \
  "https://api.github.com/repos/go-continuous-fuzz/go-fuzzing-example/issues" | jq length)
if [[ "${issue_count}" -ne 3 ]]; then
  echo "❌ ERROR: Expected 3 open issues, but found ${issue_count}"
  exit 1
fi

# Verify coverage reports
echo "Checking coverage reports..."

# Check index.html file in BUCKET_NAME
if ! aws s3api head-object --bucket "${BUCKET_NAME}" --key "index.html"; then
  echo "❌ ERROR: Missing daily coverage report: index.html"
  exit 1
fi

# Ensure only the expected number of top-level files exist in S3
num_s3_files=$(aws s3 ls "s3://${BUCKET_NAME}" | wc -l)
if [[ "${num_s3_files}" -ne 4 ]]; then
  echo "❌ ERROR: Unexpected number of files in ${BUCKET_NAME} (found: ${num_s3_files}, expected: 4)"
  exit 1
fi

# Compare state.json content
if ! diff "${REPORT_DIR}/state.json" "./testdata/state.json"; then
  echo "❌ ERROR: state.json does not match expected content"
  exit 1
fi

# Ensure expected number of target files in BUCKET_NAME/targets/
num_target_files=$(aws s3 ls "s3://${BUCKET_NAME}/targets/" --recursive | wc -l)
if [[ "${num_target_files}" -ne 15 ]]; then
  echo "❌ ERROR: Unexpected number of files in ${BUCKET_NAME}/targets (found: ${num_target_files}, expected: 15)"
  exit 1
fi

# Check that each target has the expected .html, .json, and daily coverage HTML file
for entry in "${ALL_FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg target <<<"${entry}"
  base="${pkg}/${target}"

  # Check summary .json and .html
  if ! aws s3api head-object --bucket "${BUCKET_NAME}" --key "targets/${base}.json"; then
    echo "❌ ERROR: Missing ${base}.json in targets/"
    exit 1
  fi
  if ! aws s3api head-object --bucket "${BUCKET_NAME}" --key "targets/${base}.html"; then
    echo "❌ ERROR: Missing ${base}.html in targets/"
    exit 1
  fi

  files=$(aws s3api list-objects-v2 \
    --bucket "${BUCKET_NAME}" \
    --prefix "targets/${base}/" \
    --query 'Contents[].Key' \
    --output text)

  # Count how many files are found
  file_count=$(echo "${files}" | wc -w)

  if [[ "${file_count}" -ne 1 ]]; then
    echo "❌ ERROR: Expected exactly one file under targets/${base}/, found ${file_count}"
    exit 1
  fi

  # Get the last modified time of the only file
  last_modified=$(aws s3api head-object \
    --bucket "${BUCKET_NAME}" \
    --key "${files}" \
    --query "LastModified" \
    --output text)

  if [[ -z "${last_modified}" ]]; then
    echo "❌ ERROR: Failed to retrieve metadata for '${files}'"
    exit 1
  fi

  # Compare last modified time to now
  DATE_BIN=$(command -v gdate || command -v date) # Use GNU date if available, fallback to standard date for broader compatibility
  last_epoch=$("${DATE_BIN}" -d "${last_modified}" +%s)
  now_epoch=$("${DATE_BIN}" +%s)
  diff_seconds=$(( now_epoch - last_epoch ))

  if (( diff_seconds > 180 )); then
    echo "❌ ERROR: File '${files}' is older than 180 seconds (${diff_seconds} seconds ago)"
    exit 1
  fi
done

echo "✅ Fuzzing process completed successfully."
exit 0
