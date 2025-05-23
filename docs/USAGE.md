# Usage: go-continuous-fuzz

## Configuration Options

You can configure **go-continuous-fuzz** using either environment variables or command-line flags. All options are listed below:

| Environment Variable | Command-line Flag     | Description                                 | Required | Default |
| -------------------- | --------------------- | ------------------------------------------- | -------- | ------- |
| `FUZZ_NUM_PROCESSES` | `--num_processes`     | Number of concurrent fuzzing processes      | No       | 1       |
| `PROJECT_SRC_PATH`   | `--project_src_path`  | Git repo URL of the project to fuzz         | Yes      | —       |
| `GIT_STORAGE_REPO`   | `--git_storage_repo`  | Git repo where the input corpus is stored   | Yes      | —       |
| `FUZZ_TIME`          | `--fuzz_time`         | Duration for fuzzing run                    | No       | 120s    |
| `FUZZ_PKG`           | `--fuzz_pkg`          | Comma-separated list of Go packages to fuzz | Yes      | —       |
| `FUZZ_RESULTS_PATH`  | `--fuzz_results_path` | Path to store fuzzing results               | Yes      | —       |

**Repository URL formats:**

- Private: `https://oauth2:PAT@github.com/OWNER/REPO.git`
- Public: `https://github.com/OWNER/REPO.git`

## How It Works

1. **Configuration:**  
   Set the required environment variables or pass the corresponding flags to configure the fuzzing process.

2. **Fuzz Target Detection:**  
   The tool automatically detects all available fuzz targets in the provided project repository.

3. **Fuzzing Execution:**  
   Go's native fuzzing is executed on each detected fuzz target. The number of concurrent fuzzing processes is controlled by the `FUZZ_NUM_PROCESSES` variable.

4. **Corpus Persistence:**  
   For each fuzz target, the fuzzing engine generates an input corpus. Depending on the `FUZZ_RESULTS_PATH` setting, this corpus is saved to the specified directory, ensuring that the test inputs are preserved and can be reused in future runs.

## Running go-continuous-fuzz

1. **Clone the Repository**

   ```bash
   git clone github.com/go-continuous-fuzz/go-continuous-fuzz.git
   cd go-continuous-fuzz
   ```

2. **Set Configuration paramaters**  
   You can use environment variables:

   ```bash
   export FUZZ_NUM_PROCESSES=<number_of_processes>
   export PROJECT_SRC_PATH=<project_repo_url>
   export GIT_STORAGE_REPO=<storage_repo_url>
   export FUZZ_TIME=<time>
   export FUZZ_PKG=<target_package>
   export FUZZ_RESULTS_PATH=<path/to/file>
   ```

   Or pass flags directly:

   ```bash
     --project_src_path=<project_repo_url>
     --git_storage_repo=<storage_repo_url>
     --fuzz_results_path=<path/to/file>
     --fuzz_pkg=<target_package>
     --fuzz_time=<time>
     --num_processes=<number_of_processes>
   ```

3. **Run the Fuzzing Engine:**  
   With your environment configured, start the fuzzing process. Run:

   ```bash
   make run
   ```

   Or pass flags directly:

   ```bash
   make run ARGS=<flags>
   ```

## Additional Information

- You can mix environment variables and command-line flags; flags take precedence.
- For more advanced usage, including Docker integration and running tests, see [INSTALL.md](./INSTALL.md).
