# go-continuous-fuzz

Continuous fuzzing of Go projects.

go-continuous-fuzz is a Go native fuzzing tool that automatically detects and runs fuzz targets in the repository. It is designed to run multiple fuzzing workers concurrently and persist the generated input corpus in AWS S3, helping continuously test and improve the codebase's resilience.

## Features

- **Automatic Fuzz Target Detection:** Scans the repository and identifies all available fuzz targets.
- **Concurrent Fuzzing:** Runs multiple fuzzing workers concurrently, with the default set to one CPU core.
- **Customizable Execution:** Configure the duration and target package for fuzzing with config variables.
- **Corpus Persistence:** Saves the input corpus for each fuzz target to a specified AWS S3 bucket, ensuring that test cases are preserved for future runs.

## Deployment & Execution

go-continuous-fuzz can be deployed as a long-running service on any cloud instance (e.g., AWS EC2, GCP Compute Engine, or DigitalOcean Droplet). Once initiated, the application autonomously manages its execution cycles, running continuously and restarting the fuzzing process at intervals defined in the configuration file or via command-line flags.

## For more information, see:

1. [INSTALL.md](docs/INSTALL.md)
2. [USAGE.md](docs/USAGE.md)
