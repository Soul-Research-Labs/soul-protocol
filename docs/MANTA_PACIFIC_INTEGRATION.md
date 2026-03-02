# Manta Pacific Integration

## Overview

ZASEON integrates with **Manta Pacific**, a modular L2 focused on ZK applications. Manta Pacific uses Celestia for data availability and Polygon CDK-based ZK proving (migrated from OP Stack).

| Property       | Value                                 |
| -------------- | ------------------------------------- |
| Chain ID       | `169` (mainnet), `3441006` (Sepolia)  |
| Bridge Type    | Polygon CDK Bridge / GlobalExitRoot   |
| Contract       | `MantaPacificBridgeAdapter.sol`       |
| VM             | EVM (Polygon CDK zkEVM)               |
| Finality       | Instant (ZK proof finality)           |
| Security Model | zkSNARK validity proofs + Celestia DA |

## Key Features

- Migrated from OP Stack to Polygon CDK/zkEVM
- PolygonZkEVMBridge for L1↔L2 messaging
- Celestia DA for cheap data posting
- Universal Circuits for native ZK operations
- GlobalExitRoot Merkle proof verification
- Network IDs: `NETWORK_ID_MAINNET = 0`, `NETWORK_ID_MANTA = 1`
- `FINALITY_BLOCKS = 1`
- `MAX_PROOF_SIZE = 32768`

## Contract

```solidity
constructor(
    address _cdkBridge,
    address _globalExitRootManager,
    address _mantaRollup,
    uint32 _networkId,
    address _admin
)
```

## Deployment

```bash
DEPLOY_TARGET=manta forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $MANTA_RPC --broadcast --verify -vvv
```

## References

- [Manta Pacific Documentation](https://docs.manta.network/)
- [Manta Universal Circuits](https://docs.manta.network/docs/concepts/Universal-Circuits)
- [Celestia DA](https://celestia.org/)
