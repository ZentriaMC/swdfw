# List available recipes
default:
    @just --list

# Run unit tests
test *FLAGS:
    go test ./internal/... {{FLAGS}}

# Run Docker integration tests (requires Docker)
test-docker *FLAGS:
    go test ./internal/chain/ -v -run Docker -timeout 300s -count=1 {{FLAGS}}

# Run all tests (unit + integration)
test-all *FLAGS:
    go test ./internal/... -v -timeout 300s -count=1 {{FLAGS}}

# Vet and lint
check:
    go vet ./internal/...
    GOOS=linux go vet ./internal/...

# Run golangci-lint
lint:
    golangci-lint run ./internal/...

# Tidy go modules
tidy:
    go mod tidy

# Generate TCP option flags from RFC CSV
generate:
    go run ./hack/parse_tcp_params.go < ./hack/tcp-parameters-1.csv
