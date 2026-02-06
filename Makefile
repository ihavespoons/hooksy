.PHONY: build install test clean lint

BINARY_NAME=hooksy
BUILD_DIR=./build

build:
	go build -o $(BINARY_NAME) ./cmd/hooksy

install:
	go install ./cmd/hooksy

test:
	go test -v ./...

test-integration:
	go test -v ./test/integration/... -count=1

clean:
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)

lint:
	go vet ./...
	@which golint > /dev/null || go install golang.org/x/lint/golint@latest
	golint ./...

release:
	mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/hooksy
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/hooksy
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/hooksy
	GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/hooksy
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/hooksy

validate:
	./$(BINARY_NAME) validate --config configs/default.yaml
	./$(BINARY_NAME) validate --config configs/strict.yaml
	./$(BINARY_NAME) validate --config configs/permissive.yaml
