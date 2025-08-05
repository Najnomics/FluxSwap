# FluxSwap Dependencies

This document lists all the dependencies installed for the FluxSwap project.

## Foundry Framework
- **forge**: Ethereum testing framework
- **cast**: Swiss army knife for interacting with EVM smart contracts  
- **anvil**: Local Ethereum node for development

## Smart Contract Dependencies

### 1. OpenZeppelin Contracts (v5.0.2)
- **Path**: `lib/openzeppelin-contracts/`
- **Remapping**: `@openzeppelin/=lib/openzeppelin-contracts/`
- **Usage**: Core security contracts, access control, reentrancy guards, pausable contracts
- **Key Contracts Used**:
  - `AccessControl.sol` - Role-based access control
  - `Pausable.sol` - Emergency pause functionality
  - `ReentrancyGuard.sol` - Reentrancy protection
  - `ERC20.sol` - Standard ERC20 token implementation

### 2. Uniswap v4 Periphery (latest)
- **Path**: `lib/v4-periphery/`
- **Remapping**: `@uniswap/v4-periphery/=lib/v4-periphery/`
- **Usage**: Uniswap v4 hook implementations and utilities
- **Key Components**:
  - `BaseHook.sol` - Base contract for hook implementations
  - `ImmutableState.sol` - Immutable state management
  - Hook utilities and interfaces

### 3. Uniswap v4 Core (via periphery)
- **Path**: `lib/v4-periphery/lib/v4-core/`
- **Remapping**: `@uniswap/v4-core/=lib/v4-periphery/lib/v4-core/`
- **Usage**: Core Uniswap v4 types and interfaces
- **Key Components**:
  - `IPoolManager.sol` - Pool manager interface
  - `IHooks.sol` - Hook interface definitions
  - `PoolKey.sol`, `BeforeSwapDelta.sol` - Core types
  - `PoolOperation.sol` - Operation parameter types

### 4. Circle CCTP Contracts (latest)
- **Path**: `lib/evm-cctp-contracts/`
- **Remapping**: `@circle-fin/=lib/evm-cctp-contracts/`
- **Usage**: Circle Cross-Chain Transfer Protocol integration
- **Key Components**:
  - `ITokenMessenger.sol` - Token messenger interface
  - `IMessageTransmitter.sol` - Message transmitter interface
  - CCTP v2 interfaces in `src/interfaces/v2/`
  - `ITokenMinterV2.sol`, `IMessageTransmitterV2.sol` - v2 interfaces

### 5. Chainlink Contracts (v1.3.0)
- **Path**: `lib/chainlink-brownie-contracts/`
- **Remapping**: `@chainlink/=lib/chainlink-brownie-contracts/`
- **Usage**: Price feed interfaces for FX rate oracles
- **Key Components**:
  - `AggregatorV3Interface.sol` - Price feed interface
  - Located at: `contracts/src/v0.8/shared/interfaces/`

### 6. Forge Standard Library (v1.10.0)
- **Path**: `lib/forge-std/`
- **Remapping**: `forge-std/=lib/forge-std/src/`
- **Usage**: Testing utilities and console logging
- **Key Components**:
  - `Test.sol` - Base test contract
  - `console.sol` - Console logging for tests

## Remappings Configuration

The following remappings are configured in `foundry.toml`:

```toml
remappings = [
    "@openzeppelin/=lib/openzeppelin-contracts/",
    "@uniswap/v4-periphery/=lib/v4-periphery/",
    "@uniswap/v4-core/=lib/v4-periphery/lib/v4-core/",
    "@chainlink/=lib/chainlink-brownie-contracts/",
    "@circle-fin/=lib/evm-cctp-contracts/",
    "forge-std/=lib/forge-std/src/"
]
```

## Installation Commands Used

```bash
# Install OpenZeppelin contracts
forge install openzeppelin/openzeppelin-contracts@v5.0.2

# Install Uniswap v4 periphery
forge install Uniswap/v4-periphery

# Install Circle CCTP contracts
forge install circlefin/evm-cctp-contracts

# Install Chainlink contracts
forge install smartcontractkit/chainlink-brownie-contracts
```

## Verification

All dependencies have been successfully installed and the project compiles without errors:

```bash
forge build
# ✓ Compiling 9 files with Solc 0.8.26
# ✓ Solc 0.8.26 finished in 1.10s
# ✓ Compiler run successful with warnings
```

## Next Steps

With all dependencies installed, the project is ready for:
1. Implementation of core FluxSwap contracts
2. CCTP v2 integration development
3. Uniswap v4 hook implementation
4. Comprehensive testing suite
5. Deployment scripts

All required smart contract dependencies are now available and properly configured for production-ready FluxSwap development.