.PHONY: build build-arm64 build-min build-min-arm64 build-all clean fmt vet tidy

BIN := warp-relay-agent
BIN_MIN := warp-relay-agent-min
VERSION ?= 2.2.0
LDFLAGS := -s -w -X main.Version=$(VERSION)
LDFLAGS_MIN := -s -w -X main.Version=$(VERSION)-min

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	  go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BIN) ./cmd/agent

build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	  go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BIN)-arm64 ./cmd/agent

build-min:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	  go build -trimpath -ldflags '$(LDFLAGS_MIN)' -o bin/$(BIN_MIN) ./cmd/agent-min

build-min-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	  go build -trimpath -ldflags '$(LDFLAGS_MIN)' -o bin/$(BIN_MIN)-arm64 ./cmd/agent-min

build-all: build build-min

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/

run:
	go run ./cmd/agent

run-min:
	go run ./cmd/agent-min
