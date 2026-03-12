VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN := postern
DIST := dist

.PHONY: build clean test fmt dist

build:
	go build -ldflags '$(LDFLAGS)' -o $(BIN) .

test:
	go test ./...

fmt:
	gofmt -w .

clean:
	rm -rf $(BIN) $(DIST)

dist: clean
	@mkdir -p $(DIST)
	GOOS=linux   GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN)-linux-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN)-darwin-arm64 .
	@echo "Built $(VERSION):" && ls -lh $(DIST)/
