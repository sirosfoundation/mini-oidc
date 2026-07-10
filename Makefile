.PHONY: build test lint vet fmt docker-build docker-run clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	@CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/op ./cmd/op
	@CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/rp ./cmd/rp

test:
	@go test -v -race -cover ./...

test-coverage:
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

lint:
	@golangci-lint run --timeout=5m

vet:
	@go vet ./...

fmt:
	@gofmt -w .
	@goimports -w -local github.com/sirosfoundation/mini-oidc .

docker-build:
	@docker build --build-arg VERSION=$(VERSION) -t ghcr.io/sirosfoundation/mini-oidc:latest .

docker-run: docker-build
	@docker compose up

clean:
	@rm -rf bin/

run-op:
	@go run ./cmd/op

run-rp:
	@go run ./cmd/rp
