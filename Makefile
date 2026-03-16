##@ Help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\033[1mUsage\033[0m\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build
build: clean ## Build the plugin binary
	@mkdir -p dist/
	@go build -o dist/plugin .

clean: ## Remove build artifacts
	@rm -rf dist/

##@ Test
test: ## Run tests with race detection
	@go test -v -race ./...

##@ Lint
lint: ## Run golangci-lint
	@golangci-lint run ./...
