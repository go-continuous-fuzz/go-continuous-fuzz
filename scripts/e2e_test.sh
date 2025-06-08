#!/bin/bash

set -x

# Specify the command-line flags for the fuzzing process
ARGS="\
--project.src-repo=https://github.com/lightningnetwork/lnd.git \
--project.storage-repo=https://github.com/lightninglabs/lnd-fuzz.git \
--fuzz.time=1700s \
--fuzz.results-path=~/fuzz_results \
--fuzz.pkgs-path=macaroons \
--fuzz.pkgs-path=routing \
--fuzz.pkgs-path=watchtower/wtclient \
--fuzz.pkgs-path=watchtower/wtwire \
--fuzz.pkgs-path=zpay32"

# Run the make command with a 30-minute timeout
timeout -s INT --preserve-status 30m make run ARGS="$ARGS"
EXIT_STATUS=$?

# If make run failed (not timeout and SIGINT), exit with error
if [ $EXIT_STATUS -ne 0 ] && [ $EXIT_STATUS -ne 130 ]; then
  echo "❌ The operation exited with status $EXIT_STATUS."
  exit $EXIT_STATUS
fi

# Check if the $HOME/fuzz_results directory exists
if [ -d "$HOME/fuzz_results" ]; then
  echo "✅ Fuzzing process completed successfully."
else
  echo "❌ Fuzzing process failed."
  exit 1
fi

# Cleanup: Delete the $HOME/fuzz_results directory
rm -rf "$HOME/fuzz_results"