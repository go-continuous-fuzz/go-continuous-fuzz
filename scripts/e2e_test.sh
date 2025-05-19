#!/bin/bash

set -x

# Specify the environment variables for the fuzzing process
export PROJECT_SRC_PATH="https://github.com/lightningnetwork/lnd.git"
export GIT_STORAGE_REPO="https://github.com/lightninglabs/lnd-fuzz.git"
export FUZZ_TIME="1700"
export FUZZ_PKG="macaroons routing watchtower/wtclient watchtower/wtwire zpay32"

# Run the make command with a 30-minute timeout
timeout -s INT --preserve-status 30m make run
EXIT_STATUS=$?

# If make run failed (not timeout and SIGINT), exit with error
if [ $EXIT_STATUS -ne 0 ] && [ $EXIT_STATUS -ne 130 ]; then
  echo "❌ The operation exited with status $EXIT_STATUS."
  exit $EXIT_STATUS
fi

# Check if the ./fuzz_results directory exists
if [ -d "./fuzz_results" ]; then
  echo "✅ Fuzzing process completed successfully."
else
  echo "❌ Fuzzing process failed."
  exit 1
fi

# Cleanup: Delete the ./fuzz_results directory
rm -rf ./fuzz_results