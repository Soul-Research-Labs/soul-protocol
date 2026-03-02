# zkSync Era Integration

## Overview

ZASEON integrates with **zkSync Era**, a Type 4 zkEVM rollup using its own LLVM-based compiler. zkSync Era provides native account abstraction and ZK proof-based finality.

| Property       | Value                              |
| -------------- | ---------------------------------- |
| Chain ID       | `324` (mainnet), `300` (Sepolia)   |
| Bridge Type    | Diamond Proxy / IMailbox           |
| Contract       | `zkSyncBridgeAdapter.sol`          |
| VM             | zkEVM (LLVM-based, Type 4)         |
| Finality       | ~1 hour (batch commitment + proof) |
| Security Model | zkSNARK validity proofs            |
| Status         | Graduated, Certora verified        |

## Key Features

- LLVM-based zkEVM with native account abstraction
- Diamond Proxy / IMailbox interface for messaging
- L2Log proofs via `verifyL2Log` for withdrawal verification
- `FINALITY_BLOCKS = 1`
- `DEFAULT_L2_GAS_LIMIT = 800000`
- `DEFAULT_GAS_PER_PUBDATA = 800`
- `MAX_PROOF_SIZE = 32768`

## Contract

```solidity
constructor(address _admin, address _zkSyncDiamond)
```

## Deployment

```bash
DEPLOY_TARGET=zksync forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ZKSYNC_RPC --broadcast --verify -vvv
```

## References

- [zkSync Era Documentation](https://docs.zksync.io/)
- [zkSync Era Architecture](https://docs.zksync.io/zk-stack)
