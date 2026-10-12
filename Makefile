# proxyd — build, test and deployment helpers.

GO           ?= go
BINARY       ?= proxyd
PKG          ?= ./...
IMAGE        ?= proxyd:latest
VERSION      ?=
LDFLAGS      := $(if $(VERSION),-X main.Version=$(VERSION),)

.PHONY: all build test vet fmt fmt-check e2e race clean run \
        docker-build docker-up docker-down

all: build

## build: compile the proxyd binary (override VERSION=x.y.z for a stamped build)
build:
	$(GO) build $(LDFLAGS) -o $(BINARY) ./cmd/proxyd

## test: run unit and package integration tests
test:
	$(GO) test $(PKG)

## vet: run go vet
vet:
	$(GO) vet $(PKG)

## fmt: format all Go sources
fmt:
	gofmt -w .

## fmt-check: fail if any Go source is not gofmt-clean
fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

## race: run tests with the race detector
race:
	$(GO) test -race $(PKG)

## e2e: run the root-gated network-namespace end-to-end test
e2e:
	$(GO) test -tags integration -run TestNetworkNamespace -v -timeout 180s ./tests/

## run: build and run with the example-local config
run: build
	./$(BINARY) -config config.yaml

## clean: remove build artifacts
clean:
	rm -f $(BINARY)

## docker-build: build the container image (override VERSION and IMAGE)
docker-build:
	docker build $(if $(VERSION),--build-arg VERSION=$(VERSION),) -t $(IMAGE) .

## docker-up: start proxyd with docker compose (builds if needed)
docker-up:
	docker compose up -d --build

## docker-down: stop the docker compose deployment
docker-down:
	docker compose down
