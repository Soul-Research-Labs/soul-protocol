# Taiko Integration

## Overview

ZASEON integrates with **Taiko**, a "based rollup" where sequencing is performed by Ethereum L1 validators. Taiko uses a multi-tier contestable proof system (optimistic → SGX → ZK) for finality.

| Property       | Value                                |
| -------------- | ------------------------------------ |
| Chain ID       | `167000` (mainnet), `167009` (Hekla) |
| Bridge Type    | Signal Service / Based Rollup        |
| Contract       | `TaikoBridgeAdapter.sol`             |
| VM             | EVM (Type 1 zkEVM)                   |
| Finality       | SGX ~15 min, ZK ~24 hours            |
| Security Model | Based sequencing + multi-tier proofs |

## Key Features

- Based sequencing (no centralized sequencer)
- Multi-tier proof system: optimistic → SGX → ZK
- Signal Service for canonical L1↔L2 messaging
- Merkle proofs against synced state roots
- `FINALITY_BLOCKS = 1` (proof-based finality)
- `MAX_PROOF_SIZE = 32768`

## Contract

```solidity
constructor(
    address _signalService,
    address _taikoBridge,
    address _taikoL1,
    address _admin
)
```

## Deployment

```bash
DEPLOY_TARGET=taiko forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $TAIKO_RPC --broadcast --verify -vvv
```

## References

- [Taiko Documentation](https://docs.taiko.xyz/)
- [Based Rollup Design](https://ethresear.ch/t/based-rollups-superpowers-from-l1-sequencing/15016)
- [Taiko Multi-Tier Proofs](https://docs.taiko.xyz/core-concepts/multi-proofs/)
