# Usage: go-continuous-fuzz

## Configuration Options

You can configure **go-continuous-fuzz** using either conifg file or command-line flags. All options are listed below:

| Configuration Variable | Description                                            | Required | Default |
| ---------------------- | -------------------------------------------------------| -------- | ------- |
| `project.src-repo`     | Git repo URL of the project to fuzz                    | Yes      | —       |
| `project.corpus-path`  | Absolute path to directory where seed corpus is stored | Yes      | —       |
| `fuzz.results-path`    | Path to store fuzzing results                          | Yes      | —       |
| `fuzz.pkgs-path`       | List of package paths to fuzz                          | Yes      | —       |
| `fuzz.time`            | Duration between consecutive fuzzing cycles            | No       | 120s    |
| `fuzz.num-processes`   | Number of concurrent fuzzing processes                 | No       | 1       |

**Repository URL formats:**

- Private: `https://oauth2:PAT@github.com/OWNER/REPO.git`
- Public: `https://github.com/OWNER/REPO.git`

## How It Works

1. **Configuration:**  
   Set the required configuration variables in the config file or pass the corresponding flags to configure the fuzzing process.

2. **Fuzz Target Detection:**  
   The tool automatically detects all available fuzz targets in the provided project repository.

3. **Fuzzing Execution:**  
   Go's native fuzzing is executed on each detected fuzz target. The number of concurrent fuzzing processes is controlled by the `fuzz.num-processes` variable.

4. **Corpus Persistence:**  
   For each fuzz target, the fuzzing engine generates an input corpus. Depending on the `fuzz.results-path` setting, this corpus is saved to the specified directory, ensuring that the test inputs are preserved and can be reused in future runs.

## Running go-continuous-fuzz

1. **Clone the Repository**

   ```bash
   git clone github.com/go-continuous-fuzz/go-continuous-fuzz.git
   cd go-continuous-fuzz
   ```

2. **Set Configuration paramaters**  
   You can set the configuration variables in the config file:
   See: [sample-go-continuous-fuzz.conf](../sample-go-continuous-fuzz.conf)

   Or pass flags directly:

   ```bash
     --project.src-repo=<project_repo_url>
     --project.corpus-path=<path/to/file>
     --fuzz.results-path=<path/to/file>
     --fuzz.pkgs-path=<path/to/pkg>
     --fuzz.time=<time>
     --fuzz.num-processes=<number_of_processes>
   ```

3. **Run the Fuzzing Engine:**  
   With your config file configured, start the fuzzing process. Run:

   ```bash
   make run
   ```

   Or pass flags directly:

   ```bash
   make run ARGS=<flags>
   ```

## Additional Information

- You can mix config file and command-line flags; flags take precedence.
- The default location for config file is in:
  - `~/.go-continuous-fuzz/go-continuous-fuzz.conf` on POSIX OSes,
  - `$LOCALAPPDATA/Go-continuous-fuzz/go-continuous-fuzz.conf` on Windows,
  - `~/Library/Application Support/Go-continuous-fuzz/go-continuous-fuzz.conf` on Mac OS
  - `$home/go-continuous-fuzz/go-continuous-fuzz.conf` on Plan9.
- For more advanced usage, including Docker integration and running tests, see [INSTALL.md](./INSTALL.md).
