# Usage: go-continuous-fuzz

## Configuration Options

You can configure **go-continuous-fuzz** using either conifg file or command-line flags. All options are listed below:

| Configuration Variable   | Description                                                | Required | Default |
| ------------------------ | ---------------------------------------------------------- | -------- | ------- |
| `project.src-repo`       | Git repo URL of the project to fuzz                        | Yes      | —       |
| `project.s3-bucket-name` | Name of the S3 bucket where the seed corpus will be stored | Yes      | —       |
| `fuzz.results-path`      | Path to store fuzzing results                              | Yes      | —       |
| `fuzz.pkgs-path`         | List of package paths to fuzz                              | Yes      | —       |
| `fuzz.sync-frequency`    | Duration between consecutive fuzzing cycles                | No       | 24h     |
| `fuzz.num-workers`       | Number of concurrent fuzzing workers                       | No       | 1       |

**Repository URL formats:**

- Private: `https://oauth2:PAT@github.com/OWNER/REPO.git`
- Public: `https://github.com/OWNER/REPO.git`

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

## How It Works

1. **Configuration:**  
   Set the required configuration variables in the config file or pass the corresponding flags to configure the fuzzing process.

2. **Fuzz Target Detection:**  
   The tool automatically detects all available fuzz targets in the provided project repository.

3. **Fuzzing Execution:**  
   Go's native fuzzing is executed on each detected fuzz target. The number of concurrent fuzzing workers is controlled by the `fuzz.num-workers` variable.

4. **Corpus Persistence:**  
   For each fuzz target, the fuzzing engine generates an input corpus. Depending on the `project.s3-bucket-name` setting, this corpus is saved to the specified AWS S3 bucket, ensuring that the test inputs are preserved and can be reused in future runs.

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
     --project.s3-bucket-name=<bucket_name>
     --fuzz.results-path=<path/to/file>
     --fuzz.pkgs-path=<path/to/pkg>
     --fuzz.sync-frequency=<time>
     --fuzz.num-workers=<number_of_workers>
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
