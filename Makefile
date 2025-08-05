# FluxSwap Makefile
# Comprehensive build, test, and deployment automation

.PHONY: help build test coverage deploy clean lint format docs anvil

# Default target
help:
	@echo "🚀 FluxSwap - Cross-Chain FX Swaps with CCTP v2"
	@echo "================================================"
	@echo ""
	@echo "Available commands:"
	@echo "  build         - Build all contracts"
	@echo "  test          - Run all tests (300 tests)"
	@echo "  test-quick    - Run quick test subset"
	@echo "  coverage      - Generate test coverage report"
	@echo "  gas-report    - Generate gas usage report"
	@echo "  deploy-anvil  - Deploy to local Anvil"
	@echo "  deploy-sepolia- Deploy to Sepolia testnet"
	@echo "  deploy-mainnet- Deploy to mainnet"
	@echo "  lint          - Run code linting"
	@echo "  format        - Format code"
	@echo "  clean         - Clean build artifacts"
	@echo "  docs          - Generate documentation"
	@echo "  anvil         - Start local Anvil node"
	@echo ""

# Build all contracts
build:
	@echo "🔨 Building FluxSwap contracts..."
	forge build
	@echo "✅ Build complete!"

# Run all 300 tests
test:
	@echo "🧪 Running FluxSwap comprehensive test suite (300 tests)..."
	@echo "This may take a few minutes..."
	forge test -vvv --gas-report
	@echo "✅ All tests complete!"

# Run quick test subset
test-quick:
	@echo "⚡ Running quick test subset..."
	forge test --match-test "test_0[0-2][0-9]" -vv
	@echo "✅ Quick tests complete!"

# Run specific test files
test-foundation:
	@echo "🏗️  Running Foundation Tests..."
	forge test --match-path test/FoundationTest.t.sol -vvv

test-hook:
	@echo "🎣 Running Hook Tests..."
	forge test --match-path test/ComprehensiveHookTest.t.sol -vvv

test-security:
	@echo "🛡️  Running Security Tests..."
	forge test --match-path test/SecurityModuleTest.t.sol -vvv

test-oracle:
	@echo "📊 Running Oracle Tests..."
	forge test --match-path test/OracleTest.t.sol -vvv

test-liquidity:
	@echo "💧 Running Liquidity Tests..."
	forge test --match-path test/LiquidityManagerTest.t.sol -vvv

test-settlement:
	@echo "🎯 Running Settlement Tests..."
	forge test --match-path test/SettlementEngineTest.t.sol -vvv

test-cctp:
	@echo "🌐 Running CCTP Tests..."
	forge test --match-path test/CCTPIntegrationTest.t.sol -vvv

test-crosschain:
	@echo "🔍 Running Cross-Chain Tests..."
	forge test --match-path test/CrossChainDetectionTest.t.sol -vvv

test-integration:
	@echo "🔗 Running Integration Tests..."
	forge test --match-path test/IntegrationTest.t.sol -vvv

test-performance:
	@echo "⚡ Running Performance Tests..."
	forge test --match-path test/PerformanceTest.t.sol -vvv

# Generate coverage report
coverage:
	@echo "📊 Generating test coverage report..."
	forge coverage --report lcov
	@if command -v genhtml >/dev/null 2>&1; then \
		genhtml lcov.info -o coverage/ --branch-coverage --function-coverage; \
		echo "📈 Coverage report generated in coverage/index.html"; \
	else \
		echo "📋 Coverage data generated in lcov.info"; \
		echo "💡 Install lcov to generate HTML report: apt-get install lcov"; \
	fi
	@echo "✅ Coverage analysis complete!"

# Generate gas usage report
gas-report:
	@echo "⛽ Generating gas usage report..."
	forge test --gas-report | tee gas-report.txt
	@echo "📋 Gas report saved to gas-report.txt"
	@echo "✅ Gas analysis complete!"

# Deploy to local Anvil
deploy-anvil:
	@echo "🔧 Deploying FluxSwap to local Anvil..."
	@echo "Make sure Anvil is running (make anvil)"
	forge script script/Deploy.s.sol:Deploy --rpc-url http://localhost:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --broadcast
	@echo "✅ Deployment to Anvil complete!"

# Deploy to Sepolia testnet
deploy-sepolia:
	@echo "🌐 Deploying FluxSwap to Sepolia testnet..."
	@if [ -z "$$SEPOLIA_RPC_URL" ]; then echo "❌ Please set SEPOLIA_RPC_URL"; exit 1; fi
	@if [ -z "$$PRIVATE_KEY" ]; then echo "❌ Please set PRIVATE_KEY"; exit 1; fi
	forge script script/Deploy.s.sol:Deploy --rpc-url $$SEPOLIA_RPC_URL --private-key $$PRIVATE_KEY --broadcast --verify
	@echo "✅ Deployment to Sepolia complete!"

# Deploy to mainnet (with extra confirmation)
deploy-mainnet:
	@echo "🚨 MAINNET DEPLOYMENT - This will use real funds!"
	@echo "Are you sure you want to deploy to mainnet? [y/N]"
	@read -r REPLY; \
	if [ "$$REPLY" = "y" ] || [ "$$REPLY" = "Y" ]; then \
		echo "🌐 Deploying FluxSwap to Ethereum mainnet..."; \
		if [ -z "$$MAINNET_RPC_URL" ]; then echo "❌ Please set MAINNET_RPC_URL"; exit 1; fi; \
		if [ -z "$$PRIVATE_KEY" ]; then echo "❌ Please set PRIVATE_KEY"; exit 1; fi; \
		forge script script/Deploy.s.sol:Deploy --rpc-url $$MAINNET_RPC_URL --private-key $$PRIVATE_KEY --broadcast --verify; \
		echo "✅ Deployment to mainnet complete!"; \
	else \
		echo "❌ Mainnet deployment cancelled"; \
	fi

# Code linting
lint:
	@echo "🔍 Running code linting..."
	@if command -v solhint >/dev/null 2>&1; then \
		solhint 'src/**/*.sol' 'test/**/*.sol'; \
	else \
		echo "💡 Install solhint for linting: npm install -g solhint"; \
	fi
	@echo "✅ Linting complete!"

# Code formatting
format:
	@echo "✨ Formatting code..."
	forge fmt
	@echo "✅ Code formatting complete!"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	forge clean
	rm -rf coverage/
	rm -f lcov.info
	rm -f gas-report.txt
	@echo "✅ Clean complete!"

# Generate documentation
docs:
	@echo "📚 Generating documentation..."
	forge doc
	@echo "📖 Documentation generated in docs/"
	@echo "✅ Documentation complete!"

# Start local Anvil node
anvil:
	@echo "🔧 Starting local Anvil node..."
	@echo "This will run indefinitely. Press Ctrl+C to stop."
	anvil --host 0.0.0.0 --port 8545 --chain-id 1

# Advanced test commands
test-with-coverage:
	@echo "🧪 Running tests with coverage..."
	forge test -vvv --coverage
	forge coverage --report lcov
	@if command -v genhtml >/dev/null 2>&1; then \
		genhtml lcov.info -o coverage/ --branch-coverage --function-coverage; \
	fi
	@echo "✅ Tests with coverage complete!"

test-gas-optimization:
	@echo "⛽ Running gas optimization tests..."
	forge test --match-test "test_2[7-9][0-9]" -vvv --gas-report
	@echo "✅ Gas optimization tests complete!"

# Continuous Integration
ci: build test coverage gas-report
	@echo "🎯 CI pipeline complete!"
	@echo "Build: ✅"
	@echo "Tests: ✅"
	@echo "Coverage: ✅"
	@echo "Gas Report: ✅"

# Development setup
setup:
	@echo "🛠️  Setting up FluxSwap development environment..."
	@if ! command -v forge >/dev/null 2>&1; then \
		echo "Installing Foundry..."; \
		curl -L https://foundry.paradigm.xyz | bash; \
		export PATH="$$PATH:$$HOME/.foundry/bin"; \
		foundryup; \
	fi
	forge install
	@echo "✅ Development setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Run 'make build' to build contracts"
	@echo "2. Run 'make test' to run all 300 tests"
	@echo "3. Run 'make anvil' to start local node"
	@echo "4. Run 'make deploy-anvil' to deploy locally"

# Performance benchmarking
benchmark:
	@echo "⚡ Running performance benchmarks..."
	@echo "This will run performance-specific tests multiple times..."
	forge test --match-test "test_2[7-9][0-9]" -vvv --gas-report | tee benchmark-results.txt
	@echo "📊 Benchmark results saved to benchmark-results.txt"
	@echo "✅ Performance benchmarking complete!"

# Security audit preparation
audit-prep: build test coverage lint
	@echo "🔒 Preparing for security audit..."
	@echo "✅ Build complete"
	@echo "✅ All tests passing"
	@echo "✅ Coverage report generated"
	@echo "✅ Code linting complete"
	@echo ""
	@echo "📋 Audit package ready!"
	@echo "Include the following in audit package:"
	@echo "• src/ directory (source code)"
	@echo "• test/ directory (test files)"
	@echo "• coverage/ directory (coverage report)"
	@echo "• gas-report.txt (gas analysis)"
	@echo "• README.md (project documentation)"

# Help for specific commands
help-test:
	@echo "🧪 FluxSwap Test Suite Help"
	@echo "==========================="
	@echo ""
	@echo "Test Structure (300 total tests):"
	@echo "• Foundation (001-025): Basic setup and deployment"
	@echo "• Hook Functionality (026-075): Core hook operations"
	@echo "• Access Control (076-100): Permission management"
	@echo "• Oracle (101-125): Price feed management"
	@echo "• Security (126-150): Risk and safety features"
	@echo "• Liquidity (151-175): LP token management"
	@echo "• Settlement (176-200): Route optimization"
	@echo "• CCTP (201-225): Cross-chain messaging"
	@echo "• Cross-Chain (226-250): Intent detection"
	@echo "• Integration (251-275): System-wide testing"
	@echo "• Performance (276-300): Gas and edge cases"
	@echo ""
	@echo "Individual test commands:"
	@echo "• make test-foundation"
	@echo "• make test-hook"
	@echo "• make test-security"
	@echo "• make test-oracle"
	@echo "• make test-liquidity"
	@echo "• make test-settlement"
	@echo "• make test-cctp"
	@echo "• make test-crosschain"
	@echo "• make test-integration"
	@echo "• make test-performance"

help-deploy:
	@echo "🚀 FluxSwap Deployment Help"
	@echo "============================"
	@echo ""
	@echo "Environment Variables Required:"
	@echo "• PRIVATE_KEY: Your private key"
	@echo "• SEPOLIA_RPC_URL: Sepolia RPC endpoint"
	@echo "• MAINNET_RPC_URL: Mainnet RPC endpoint"
	@echo "• ADMIN_ADDRESS: Admin wallet address"
	@echo "• FEE_COLLECTOR: Fee collection address"
	@echo "• HOOK_FEE_COLLECTOR: Hook fee collection address"
	@echo ""
	@echo "Deployment Commands:"
	@echo "• make deploy-anvil: Local deployment"
	@echo "• make deploy-sepolia: Testnet deployment"
	@echo "• make deploy-mainnet: Mainnet deployment (CAREFUL!)"
	@echo ""
	@echo "Post-Deployment:"
	@echo "• Verify all contracts on Etherscan"
	@echo "• Test basic functionality"
	@echo "• Set up monitoring and alerts"