# List available recipes
default:
    @just --list

# Build CLI binary
build:
    GOOS=linux go build -o swdfw ./cmd/swdfw/

# Run unit tests
test *FLAGS:
    go test ./rule/... ./chain/... {{FLAGS}}

# Run Docker integration tests (requires Docker)
test-docker *FLAGS:
    go test ./chain/ -v -run Docker -timeout 300s -count=1 {{FLAGS}}

# Run all tests (unit + integration)
test-all *FLAGS:
    go test ./rule/... ./chain/... -v -timeout 300s -count=1 {{FLAGS}}

# Vet and lint
check:
    go vet ./...
    GOOS=linux go vet ./...

# Run golangci-lint
lint:
    golangci-lint run

# Tidy go modules
tidy:
    go mod tidy

# Generate TCP option flags from RFC CSV
generate:
    go run ./hack/parse_tcp_params.go < ./hack/tcp-parameters-1.csv
