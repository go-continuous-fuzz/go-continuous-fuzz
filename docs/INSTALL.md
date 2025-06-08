# go-continuous-fuzz

## Installation Instructions

### Step 1: Install Go 1.23.9

1. Visit the official Go download page: [Go Downloads](https://go.dev/dl).
2. Download and install the appropriate version for your OS and hardware architecture.

### Step 2: Add GOBIN Path to Your $PATH

1. Open your terminal.
2. Add the following lines to your shell profile file (e.g., `~/.bashrc`, `~/.zshrc`, `~/.profile`):

```sh
export GOROOT="/usr/local/go" # your go installation path.
export GOPATH="$HOME/go"
export GOBIN="$GOPATH/bin"
export PATH="$PATH:$GOBIN:$GOROOT/bin"
```

3. Reload your shell profile:

```sh
source ~/.bashrc
```

### Step 3: Install Make Command

1. Ensure `make` is installed on your system. On most Unix-based systems, `make` is pre-installed. If not, install it using your package manager.
   - **Ubuntu/Debian**: `sudo apt-get install build-essential`
   - **MacOS**: `xcode-select --install`

### Step 4: Build the go-continuous-fuzz project

1. Run the following command to build the go-continuous-fuzz project:

```sh
make build
```

### Step 5: Run the go-continuous-fuzz project

1. Make sure the required configuration variables are set in the config file.
   Run the following command to run the go-continuous-fuzz project:

```sh
make run
```

OR

2. You can pass the configurations as command-line flags instead of specifying them in the config file.
   Run the following command to run the go-continuous-fuzz project:

```sh
make run ARGS=<flags>
```

For more details, see: [docs/USAGE.md](USAGE.md)

### Step 6: Run the go-continuous-fuzz project in docker

1. Run the following command to run the go-continuous-fuzz project in docker container, loading config file through $(VOLUME_MOUNTS):

```sh
make docker-run VOLUME_MOUNTS=<required>
```

### Step 7: Run the Test Cases

1. Run the following command to execute the test cases (both unit and integration tests):

```sh
make test
```
