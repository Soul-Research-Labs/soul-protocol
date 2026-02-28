# ZK-Bound State Locks Demo

A minimal frontend demo for ZASEON's ZK-Bound State Locks.

## Features

- 🔐 Connect MetaMask wallet
- 🔒 Create ZK-bound state locks
- 🔓 Unlock states with ZK proofs
- 📊 View protocol statistics
- 📋 Track your locks

## Quick Start

```bash
# Option 1: Using npx serve
npx serve . -p 3000

# Option 2: Using Python
python3 -m http.server 3000

# Option 3: Using VS Code Live Server extension
# Right-click index.html → Open with Live Server
```

Open http://localhost:3000 in your browser.

## Requirements

- MetaMask or compatible Web3 wallet
- Sepolia testnet ETH for gas
- Browser with ES modules support

## Network

This demo connects to **Sepolia Testnet** (Chain ID: 11155111).

Get testnet ETH from:
- https://sepoliafaucet.com
- https://faucet.sepolia.dev

## Contract Addresses (Sepolia)

| Contract | Address |
|----------|---------|
| ZKBoundStateLocks | `0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78` |
| NullifierRegistry | `0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191` |
| CrossChainProofHub | `0x40eaa5de0c6497c8943c967b42799cb092c26adc` |
| ZaseonAtomicSwapV2 | `0xdefb9a66dc14a6d247b282555b69da7745b0ab57` |

## How It Works

### Creating a Lock

1. Connect your wallet
2. Enter a **State Hash** (32-byte hex) - represents the encrypted state
3. Enter **ZK Requirements** (32-byte hex) - the proof requirements
4. Select **Destination Chain** - where the state will be unlocked
5. Click **Create Lock**

### Unlocking a State

1. Get the **Lock ID** from a created lock
2. Generate a valid **ZK Proof** that satisfies the requirements
3. Click **Unlock with Proof**

## Architecture

```
┌─────────────────┐     ┌──────────────────┐
│   Browser UI    │────▶│   MetaMask       │
└────────┬────────┘     └────────┬─────────┘
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────┐
│           Sepolia Testnet               │
│  ┌────────────────────────────────┐     │
│  │     ZKBoundStateLocks          │     │
│  │  - createStateLock()           │     │
│  │  - unlockState()               │     │
│  │  - getLock()                   │     │
│  └────────────────────────────────┘     │
└─────────────────────────────────────────┘
```

## Tech Stack

- Vanilla HTML/CSS/JavaScript (no build step)
- [ethers.js v6](https://docs.ethers.org/v6/) via CDN
- MetaMask wallet integration

## License

MIT
