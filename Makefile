# Variables
APP_NAME := go-continuous-fuzz
SRC := main.go
DOCKER_APP_NAME := go-continuous-fuzz

#? build: Build the project and create go-continuous-fuzz binary
build:
	@go build -o $(APP_NAME) $(SRC)

#? run: Run the application with command-line flags set in $(ARGS) or config variables specified in configuration file.
run: build
	@./$(APP_NAME) $(ARGS)

#? run-help: Show the help message
run-help: build
	@./$(APP_NAME) --help

#? docker: Build the docker image of go-continuous-fuzz project
docker:
	@docker build -t $(DOCKER_APP_NAME) .

#? docker-run: Run the go-continuous-fuzz container, loading config file through $(VOLUME_MOUNTS)
docker-run: docker
	@echo "Running $(DOCKER_APP_NAME) with volume mount '$(VOLUME_MOUNTS)'"
	docker run -v $(VOLUME_MOUNTS) "$(DOCKER_APP_NAME)"

#? test: Run unit and integration tests
test: unit-test e2e-test

#? unit-test: Run unit tests with verbose output
unit-test:
	go test ./... -v

#? e2e-test: Run e2e(integration) tests
e2e-test:
	./scripts/e2e_test.sh

#? cover: Generate the test coverage
cover:
	go test -cover ./...

#? lint: Run golangci-lint
lint:
	golangci-lint run -v

#? fmt: Format the code
fmt:
	go fmt ./...

#? clean: Clean binaries
clean:
	@rm -f $(APP_NAME)

#? all: Run all targets
all: fmt lint test run

#? help: List all available make targets with their descriptions
help: Makefile
	@$(call print, "Listing commands:")
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'