# BitVM Bridge Integration

## Overview

The `BitVMBridge` implements a trust-minimized Bitcoin bridge using BitVM's challenge-response protocol. It enables verification of Bitcoin computations on Ethereum through an optimistic fraud proof mechanism with gate-level circuit verification.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    BitVM Bridge Architecture                      │
│                                                                   │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────┐   │
│  │ Deposit     │───▶│ Circuit      │───▶│ Challenge-        │   │
│  │ Initiation  │    │ Registration │    │ Response Protocol │   │
│  └─────────────┘    └──────────────┘    └─────────┬─────────┘   │
│                                                    │             │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────▼─────────┐   │
│  │ Gate        │◄──▶│ Commitment/  │    │ Fraud Proof       │   │
│  │ Verification│    │ Reveal       │    │ Submission        │   │
│  └─────────────┘    └──────────────┘    └───────────────────┘   │
│                                                                   │
│  States: Initiated → Committed → Challenged → Settled/Fraud     │
└──────────────────────────────────────────────────────────────────┘
```

## Contract

- **Path**: `contracts/crosschain/BitVMBridge.sol`
- **Solidity**: `^0.8.20`
- **Lines**: ~771

## Key Features

- BitVM challenge-response protocol for trustless bridge verification
- Gate-level computation verification (NAND gates, Boolean circuits)
- Optimistic deposit processing with fraud proof window
- Circuit registration and management
- Prover stake and challenger stake requirements
- 7-day challenge window for dispute resolution
- Configurable gate commitment and reveal protocol

## Protocol Flow

```
1. initiateDeposit → Prover stakes, circuit is committed
2. commitDeposit → Prover commits taproot pubkey & output
3. Challenge Window (7 days) → Anyone can challenge
4. openChallenge → Challenger stakes, selects gate to verify
5. commitGate → Prover commits gate inputs/output
6. revealGate → Prover reveals actual values
7. proveFraud → If values mismatch, slash prover
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MIN_PROVER_STAKE` | 1 ether | Minimum prover collateral |
| `MIN_CHALLENGER_STAKE` | 0.1 ether | Minimum challenger collateral |
| `CHALLENGE_WINDOW` | 7 days | Time for dispute resolution |

## Roles

| Role | Purpose |
|------|---------|
| `DEFAULT_ADMIN_ROLE` | Core configuration |
| `OPERATOR_ROLE` | Register circuits, configure verifier |
| `PROVER_ROLE` | Commit deposits, reveal gates |
| `GUARDIAN_ROLE` | Pause/unpause, emergency operations |

## Configuration

```solidity
BitVMBridge bridge = new BitVMBridge(admin);

// Configure verifier and Bitcoin bridge
bridge.configure(bitvmVerifier, btcBridge);

// Register a circuit
bridge.registerCircuit(circuitId, numGates, numInputs, numOutputs, commitment);
```

## Testing

```bash
# Run fuzz tests
forge test --match-contract BitVMBridgeFuzz -vvv
```

## Deployment

```bash
npx hardhat run scripts/deploy/deploy-bitvm-bridge.ts --network mainnet
```

## Security Considerations

- Prover must stake minimum 1 ETH per deposit
- Challengers risk their stake if fraud proof fails
- 7-day challenge window allows sufficient time for verification
- Gate-by-gate verification prevents selective proof attacks
- All stake slashing is irreversible
