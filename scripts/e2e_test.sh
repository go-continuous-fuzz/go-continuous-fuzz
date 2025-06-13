#!/bin/bash

set -eux

# ====== CONFIGURATION ======

# Temporary Variables
readonly PROJECT_SRC_PATH="https://github.com/go-continuous-fuzz/go-fuzzing-example.git"
readonly FUZZ_TIME="3m"
readonly MAKE_TIMEOUT="5m"

# Use test workspace directory
readonly TEST_WORKDIR=$(mktemp -dt "test-go-continuous-fuzz-XXXXXX")
readonly PROJECT_DIR="${TEST_WORKDIR}/project"
readonly CORPUS_DIR_PATH="${TEST_WORKDIR}/corpus"
readonly FUZZ_RESULTS_PATH="${TEST_WORKDIR}/fuzz_results"

# Command-line flags for fuzzing process configuration
ARGS="\
--project.src-repo=${PROJECT_SRC_PATH} \
--project.corpus-path=${CORPUS_DIR_PATH} \
--fuzz.sync-frequency=${FUZZ_TIME} \
--fuzz.results-path=${FUZZ_RESULTS_PATH} \
--fuzz.num-workers=3 \
--fuzz.pkgs-path=parser \
--fuzz.pkgs-path=stringutils"

# Fuzz target definitions (package:function)
readonly FUZZ_TARGETS=(
  "parser:FuzzParseComplex"
  "parser:FuzzEvalExpr"
  "stringutils:FuzzUnSafeReverseString"
  "stringutils:FuzzReverseString"
)

# Ensure that resources are cleaned up when the script exits
trap 'echo "Cleaning up resources..."; rm -rf "${TEST_WORKDIR}"' EXIT

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

# ====== MAIN EXECUTION ======

# Clone the target repository
echo "Cloning project repository..."
git clone "${PROJECT_SRC_PATH}" "${PROJECT_DIR}"

# Download and extract only the seed_corpus directory from the project tarball
echo "Downloading seed corpus..."
mkdir -p ${CORPUS_DIR_PATH}
curl -L https://codeload.github.com/go-continuous-fuzz/go-fuzzing-example/tar.gz/main |
  tar -xz --strip-components=2 -C ${CORPUS_DIR_PATH} go-fuzzing-example-main/seed_corpus

# Initialize data stores
declare -A initial_input_counts
declare -A initial_coverage_metrics
declare -A final_input_counts
declare -A final_coverage_metrics

# Capture initial corpus state
echo "Recording initial corpus state..."
for target in "${FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg func <<<"${target}"
  echo "  - ${pkg}/${func}"
  initial_input_counts["${target}"]=$(count_corpus_inputs "${pkg}" "${func}")
  initial_coverage_metrics["${target}"]=$(measure_fuzz_coverage "${pkg}" "${func}")
done

# Execute fuzzing process
echo "Starting fuzzing process (timeout: ${MAKE_TIMEOUT})..."
mkdir -p "${FUZZ_RESULTS_PATH}"
MAKE_LOG="${FUZZ_RESULTS_PATH}/make_run.log"

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

# List of required patterns to check in the log
readonly REQUIRED_PATTERNS=(
  'Cycle duration complete; initiating cleanup.'
  'msg="Re-enqueuing task" package=stringutils target=FuzzReverseString'
  'msg="Re-enqueuing task" package=parser target=FuzzEvalExpr'
  'Fuzzing completed successfully'
  'gathering baseline coverage'
  'Shutdown initiated during fuzzing cycle; performing final cleanup.'
  'msg="Worker starting fuzz target" workerID=1'
  'msg="Worker starting fuzz target" workerID=2'
  'msg="Worker starting fuzz target" workerID=3'
  'msg="Per-target fuzz timeout calculated" duration=2m15s'
)

# Verify that worker logs contain expected entries
echo "Verifying worker log entries in ${MAKE_LOG}..."
for pattern in "${REQUIRED_PATTERNS[@]}"; do
  if ! grep -q -- "${pattern}" "${MAKE_LOG}"; then
    echo "❌ ERROR: Missing expected log entry: ${pattern}"
    exit 1
  fi
done

# List of patterns that should NOT be present in the log
readonly FORBIDDEN_PATTERNS=(
  'msg="Worker starting fuzz target" workerID=4'
  'msg="Re-enqueuing task" package=stringutils target=FuzzUnSafeReverseString'
  'msg="Re-enqueuing task" package=parser target=FuzzParseComplex'
  'All workers completed early; cleaning up cycle'
)

# Verify that worker logs do not contain forbidden entries
echo "Verifying absence of forbidden log entries in ${MAKE_LOG}..."
for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
  if grep -q -- "${pattern}" "${MAKE_LOG}"; then
    echo "❌ ERROR: Unexpected log entry found: ${pattern}"
    exit 1
  fi
done

# Capture final corpus state
echo "Recording final corpus state..."
for target in "${FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg func <<<"${target}"
  echo "  - ${pkg}/${func}"
  final_input_counts["${target}"]=$(count_corpus_inputs "${pkg}" "${func}")
  final_coverage_metrics["${target}"]=$(measure_fuzz_coverage "${pkg}" "${func}")
done

# Validate corpus growth
echo "Validating corpus growth..."
for target in "${FUZZ_TARGETS[@]}"; do
  initial_count=${initial_input_counts["${target}"]}
  final_count=${final_input_counts["${target}"]}

  if [[ ${final_count} -le ${initial_count} ]]; then
    echo "❌ ERROR: ${target} regressed - inputs decreased from ${initial_count} to ${final_count}"
    exit 1
  fi
done

# Validate coverage metrics
echo "Validating coverage metrics..."
for target in "${FUZZ_TARGETS[@]}"; do
  initial_cov=${initial_coverage_metrics["${target}"]}
  final_cov=${final_coverage_metrics["${target}"]}

  if [[ ${final_cov} -le ${initial_cov} ]]; then
    echo "❌ ERROR: ${target} coverage decreased from ${initial_cov} to ${final_cov}"
    exit 1
  fi
done

# Verify crash reports
echo "Checking crash reports..."
required_crashes=(
  "${FUZZ_RESULTS_PATH}/FuzzParseComplex_failure.log"
  "${FUZZ_RESULTS_PATH}/FuzzUnSafeReverseString_failure.log"
)

for crash_file in "${required_crashes[@]}"; do
  if [[ ! -f "${crash_file}" ]]; then
    echo "❌ ERROR: Missing crash report: ${crash_file}"
    exit 1
  fi

  if ! grep -q "go test fuzz v1" "${crash_file}"; then
    echo "❌ ERROR: Invalid crash report format in ${crash_file}"
    exit 1
  fi
done

echo "✅ Fuzzing process completed successfully."
exit 0
