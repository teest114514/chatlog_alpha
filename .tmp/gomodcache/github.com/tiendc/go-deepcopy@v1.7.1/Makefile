all: lint test

prepare:
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.4.0

build:
	@go build -v ./...

test:
	@go test -cover  -v ./...

cover:
	@go test -race -coverprofile=coverage.txt -coverpkg=./... ./...
	@go tool cover -html=coverage.txt -o coverage.html

lint:
	golangci-lint --timeout=5m0s run -v ./...

bench:
	go test -benchmem -count 100 -bench .

mod:
	go mod tidy && go mod vendor
