# 项目信息
BINARY_NAME=uscf
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go 构建参数
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.Commit=$(COMMIT)"

# 交叉编译目标平台
PLATFORMS=\
	darwin/amd64 \
	darwin/arm64 \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	windows/amd64 \
	windows/arm64

.PHONY: all build clean test linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 help

# 默认目标
all: clean build

# 构建当前平台
build:
	@echo "Building for current platform..."
	@mkdir -p $(GOBIN)
	go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME) .
	@echo "Build complete: $(GOBIN)/$(BINARY_NAME)"

# 交叉编译所有平台
build-all: clean
	@echo "Building for all platforms..."
	@mkdir -p $(GOBIN)
	@$(foreach platform,$(PLATFORMS),\
		$(call build_platform,$(platform)))
	@echo "All builds complete!"

# 定义构建函数
define build_platform
	$(eval OS=$(word 1,$(subst /, ,$(1))))
	$(eval ARCH=$(word 2,$(subst /, ,$(1))))
	$(eval OUTPUT=$(GOBIN)/$(BINARY_NAME)-$(OS)-$(ARCH)$(if $(filter windows,$(OS)),.exe,))
	@echo "Building $(OS)/$(ARCH)..."
	@GOOS=$(OS) GOARCH=$(ARCH) go build -trimpath $(LDFLAGS) -o $(OUTPUT) . || echo "Failed to build $(OS)/$(ARCH)"
endef

# Linux AMD64
linux-amd64:
	@echo "Building for Linux AMD64..."
	@mkdir -p $(GOBIN)
	GOOS=linux GOARCH=amd64 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-linux-amd64 .
	@echo "Build complete: $(GOBIN)/$(BINARY_NAME)-linux-amd64"

# Linux ARM64
linux-arm64:
	@echo "Building for Linux ARM64..."
	@mkdir -p $(GOBIN)
	GOOS=linux GOARCH=arm64 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-linux-arm64 .
	@echo "Build complete: $(GOBIN)/$(BINARY_NAME)-linux-arm64"

# Linux ARM
linux-arm:
	@echo "Building for Linux ARM..."
	@mkdir -p $(GOBIN)
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-linux-arm .
	@echo "Build complete: $(GOBIN)/$(BINARY_NAME)-linux-arm"

# macOS AMD64
darwin-amd64:
	@echo "Building for macOS AMD64..."
	@mkdir -p $(GOBIN)
	GOOS=darwin GOARCH=amd64 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-darwin-amd64 .
	@echo "Build complete: $(GOBIN)/$(BINARY_NAME)-darwin-amd64"

# macOS ARM64 (Apple Silicon)
darwin-arm64:
	@echo "Building for macOS ARM64..."
	@mkdir -p $(GOBIN)
	GOOS=darwin GOARCH=arm64 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-darwin-arm64 .
	@echo "Build complete: $(GOBIN)/$(BINARY_NAME)-darwin-arm64"

# Windows AMD64
windows-amd64:
	@echo "Building for Windows AMD64..."
	@mkdir -p $(GOBIN)
	GOOS=windows GOARCH=amd64 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Build complete: $(GOBIN)/$(BINARY_NAME)-windows-amd64.exe"

# Windows ARM64
windows-arm64:
	@echo "Building for Windows ARM64..."
	@mkdir -p $(GOBIN)
	GOOS=windows GOARCH=arm64 go build -trimpath $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME)-windows-arm64.exe .
	@echo "Build complete: $(GOBIN)/$(BINARY_NAME)-windows-arm64.exe"

# 运行测试
test:
	@echo "Running tests..."
	go test -v ./...

# 清理构建产物
clean:
	@echo "Cleaning..."
	@rm -rf $(GOBIN)
	@go clean
	@echo "Clean complete!"

# 安装到 $GOPATH/bin
install:
	@echo "Installing..."
	go install $(LDFLAGS) .
	@echo "Install complete!"

# 检查依赖
deps:
	@echo "Checking dependencies..."
	go mod download
	go mod verify
	@echo "Dependencies OK!"

# 整理依赖
tidy:
	@echo "Tidying dependencies..."
	go mod tidy
	@echo "Tidy complete!"

# 显示帮助信息
help:
	@echo "Available targets:"
	@echo "  make build          - Build for current platform"
	@echo "  make build-all      - Build for all platforms"
	@echo "  make linux-amd64    - Build for Linux AMD64"
	@echo "  make linux-arm64    - Build for Linux ARM64"
	@echo "  make linux-arm      - Build for Linux ARM"
	@echo "  make darwin-amd64   - Build for macOS AMD64"
	@echo "  make darwin-arm64   - Build for macOS ARM64 (Apple Silicon)"
	@echo "  make windows-amd64  - Build for Windows AMD64"
	@echo "  make windows-arm64  - Build for Windows ARM64"
	@echo "  make test           - Run tests"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make install        - Install to GOPATH/bin"
	@echo "  make deps           - Download and verify dependencies"
	@echo "  make tidy           - Tidy up go.mod and go.sum"
	@echo ""
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
