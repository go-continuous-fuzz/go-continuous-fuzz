# Usage: go-continuous-fuzz

## Configuration Options

You can configure **go-continuous-fuzz** using either conifg file or command-line flags. All options are listed below:

| Configuration Variable          | Description                                                  | Required | Default |
| ------------------------------- | ------------------------------------------------------------ | -------- | ------- |
| `project.workspace-path`        | Absolute path to the directory for storing generated files   | No       | —       |
| `project.src-repo`              | Git repo URL of the project to fuzz                          | Yes      | —       |
| `project.s3-bucket-name`        | Name of the S3 bucket where the seed corpus will be stored   | Yes      | —       |
| `fuzz.crash-repo`               | Git repository URL where issues are created for fuzz crashes | Yes      | —       |
| `fuzz.pkgs-path`                | List of package paths to fuzz                                | Yes      | —       |
| `fuzz.sync-frequency`           | Duration between consecutive fuzzing cycles                  | No       | 24h     |
| `fuzz.num-workers`              | Number of concurrent fuzzing workers                         | No       | 1       |
| `fuzz.corpus-minimize-interval` | Interval between consecutive corpus minimizations            | No       | 7d      |

**Repository URL formats:**
For `project.src-repo`:

- Private: `https://oauth2:PAT@github.com/OWNER/REPO.git`
- Public: `https://github.com/OWNER/REPO.git`

For `fuzz.crash-repo`:

- (Requires authentication): `https://oauth2:PAT@github.com/OWNER/REPO.git`

Note: The authentication token is used to open issues on GitHub whenever a crash is detected.
In short, issues will be created from the GitHub account associated with the provided authentication token.

**AWS S3 Storage Guidelines**

1. **Credentials**

   - The application reads AWS credentials from the default AWS config and credentials files.
   - It uses only the S3 `GetObject`, `PutObject` and `ListBucket` permissions, so you can scope the IAM policy to those actions.

2. **Bucket Requirements**

   - The S3 bucket named in `project.s3-bucket-name` **must already exist**.
   - If you're starting with an empty corpus, the bucket may be empty; otherwise, it should contain a ZIP file named according to the repository‑key rules below.

3. **Corpus Key Naming**

   - The object key is derived from your repository URL.

     - For `https://github.com/OWNER/REPO.git`, the key will be:

       ```
       REPO_corpus.zip
       ```

   - When unzipped, the archive **must** expand into a root folder named:

     ```
     REPO_corpus/
     ```

     which then contains your corpus subdirectories, for example:

     ```
     REPO_corpus/
     ├─ pkg1/testdata/...
     └─ pkg2/testdata/...
     ```

Note: The updated corpus will be uploaded to the S3 bucket only if the fuzzing cycle completes successfully without any errors or user interruptions.

**Coverage Reports**

Coverage reports are stored in the specified AWS S3 bucket. This bucket can be configured to serve as a static website for viewing the reports. The entry point for the reports is the `index.html` file. Users should ensure that the appropriate settings are enabled in the S3 bucket to allow static website hosting.

The file structure of the coverage reports is as follows:

- `index.html`: The master report page containing links to individual package/target reports.
- `state.json`: A JSON file containing all previously registered package/target pairs.
- `targets/`: A directory containing:

  - A separate `.html` file for each package/target coverage report.
  - A `.json` history file tracking daily coverage changes for each package/target.
  - Subdirectories structured as `pkg/fuzzTarget/` containing daily HTML coverage reports (e.g., `2025-07-12.html`) generated via `go tool cover`.

## How It Works

1. **Configuration:**  
   Set the required configuration variables in the config file or pass the corresponding flags to configure the fuzzing process.

2. **Fuzz Target Detection:**  
   The tool automatically detects all available fuzz targets in the provided project repository.

3. **Fuzzing Execution:**  
   Go's native fuzzing is executed on each detected fuzz target. The number of concurrent fuzzing workers is controlled by the `fuzz.num-workers` variable.

4. **Corpus Persistence:**  
   For each fuzz target, the fuzzing engine generates an input corpus. Depending on the `project.s3-bucket-name` setting, this corpus is saved to the specified AWS S3 bucket, ensuring that the test inputs are preserved and can be reused in future runs.

5. **Crash Reporting:**
   Whenever a crash is detected, an issue will be opened in `fuzz.crash-repo` containing the error logs and the failing input data. This feature includes crash deduplication to avoid creating duplicate issues.

6. **Coverage Reports:**
   For each fuzz target, coverage reports are generated and uploaded to the configured AWS S3 bucket (`project.s3-bucket-name`). The bucket can be optionally configured for static website hosting to view reports via a browser.

7. **Coprus Minimization:**
   To prevent the corpus from becoming bloated over time, it is periodically minimized after every `fuzz.corpus-minimize-interval` where each input is evaluated and those that do not improve or reduce overall coverage are removed.

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
     --project.workspace-path=</path/to/file>
     --project.src-repo=<project_repo_url>
     --project.s3-bucket-name=<bucket_name>
     --fuzz.crash-repo=<repo_url>
     --fuzz.pkgs-path=<path/to/pkg>
     --fuzz.sync-frequency=<time>
     --fuzz.num-workers=<number_of_workers>
     --fuzz.corpus-minimize-interval=<time>
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
- `project.workspace-path` is completely optional and is mainly used for debugging in case a crash occurs during the last run. If this option is not set, a temporary directory will be used, which will be deleted even if errors occur.
- For more advanced usage, including Docker integration and running tests, see [INSTALL.md](./INSTALL.md).
