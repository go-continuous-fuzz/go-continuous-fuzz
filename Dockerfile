# Use an official Go runtime as a parent image.
FROM golang:1.23.9 AS build

# Install necessary tools and dependencies.
RUN apt-get update && \
    apt-get install -y \
        build-essential \
        make

# Create a directory for cloning the repository.
RUN mkdir /go-continuous-fuzz

# Change current working directory.
WORKDIR /go-continuous-fuzz

# Copy the go-continuous-fuzz repo into the /go-continuous-fuzz directory.
COPY . .

# Install Go modules.
RUN go mod download

# Build the go-continuous-fuzz project.
RUN make build

# By default, run the fuzzing target with `make run`
ENTRYPOINT ["make", "run"]