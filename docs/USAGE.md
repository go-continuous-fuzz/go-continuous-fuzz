# Usage: go-continuous-fuzz

## Environment Variables

Configure **go-continuous-fuzz** by creating a `.env` file in the project root and setting the following variables, Alternatively, these variables can be set directly in the process environment:

- **FUZZ_NUM_PROCESSES**  
  Specifies the number of fuzzing processes to run concurrently.  
  _Default_: Maximum number of CPU cores available on the machine.

- **PROJECT_SRC_PATH** (_Required_)  
  The Git repository URL of the project to be fuzzed. Use one of the following formats:

  - For private repositories:  
    `https://oauth2:PAT@github.com/OWNER/REPO.git`
  - For public repositories:  
    `https://github.com/OWNER/REPO.git`

- **GIT_STORAGE_REPO** (_Required_)  
  The Git repository where the input corpus is stored. Use one of the following formats:

  - For private repositories:  
    `https://oauth2:PAT@github.com/OWNER/REPO.git`
  - For public repositories:  
    `https://github.com/OWNER/REPO.git`

- **FUZZ_TIME**  
  The duration (in seconds) for which the fuzzing engine should run.  
  _Default_: 120 Seconds.

- **FUZZ_PKG** (_Required_)
  The specific Go package within the repository that will be fuzzed.

- **FUZZ_RESULTS_PATH**
  Path to store fuzzing results, relative to the current working directory
  _Default_: Current working directory

## How It Works

1. **Configuration:**  
   Set the required environment variables in `.env` file or directly in the process environment to configure the fuzzing process.

2. **Fuzz Target Detection:**  
   The tool automatically detects all available fuzz targets in the provided project repository.

3. **Fuzzing Execution:**  
   Go's native fuzzing is executed on each detected fuzz target. The number of concurrent fuzzing processes is controlled by the `FUZZ_NUM_PROCESSES` variable.

4. **Corpus Persistence:**  
   For each fuzz target, the fuzzing engine generates an input corpus. Depending on the `FUZZ_RESULTS_PATH` setting, this corpus is saved to the specified directory, ensuring that the test inputs are preserved and can be reused in future runs.

## Running go-continuous-fuzz

1. **Clone or Download repo:**

   ```bash
   git clone github.com/go-continuous-fuzz/go-continuous-fuzz.git
   cd go-continuous-fuzz
   ```

2. **Set Environment Variables:**  
   You can export the necessary environment variables in `.env` file:

   ```bash
   export FUZZ_NUM_PROCESSES=<number_of_processes>
   export PROJECT_SRC_PATH=<project_repo_url>
   export GIT_STORAGE_REPO=<storage_repo_url>
   export FUZZ_TIME=<time_in_seconds>
   export FUZZ_PKG=<target_package>
   export FUZZ_RESULTS_PATH=<path/to/file>
   ```

3. **Run the Fuzzing Engine:**  
   With your environment configured, start the fuzzing process. Run:
   ```bash
   make run
   ```

See [INSTALL.md](./INSTALL.md) for other ways to run the go-continuous-fuzz project.
