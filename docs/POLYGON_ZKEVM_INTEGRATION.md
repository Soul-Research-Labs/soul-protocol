# Polygon zkEVM Integration

## Overview

ZASEON integrates with **Polygon zkEVM**, a Type 2 zkEVM rollup providing full EVM equivalence with ZK validity proofs and the Polygon CDK bridge infrastructure.

| Property       | Value                               |
| -------------- | ----------------------------------- |
| Chain ID       | `1101` (mainnet), `1442` (Cardona)  |
| Bridge Type    | PolygonZkEVMBridge / GlobalExitRoot |
| Contract       | `PolygonZkEVMBridgeAdapter.sol`     |
| VM             | EVM (Type 2 zkEVM)                  |
| Finality       | Instant (ZK proof finality on L1)   |
| Security Model | zkSNARK validity proofs             |
| Status         | Graduated, Certora verified         |

## Key Features

- Full EVM equivalence (Type 2)
- GlobalExitRootManager tracks L2 exit roots on L1
- `bridgeMessage()` for L1→L2, `claimMessage()` for L2→L1
- GlobalExitRoot Merkle proof verification
- Network ID separation: L1 (0) vs zkEVM (1)
- `FINALITY_BLOCKS = 1`
- `MAX_PROOF_SIZE = 32768`

## Contract

```solidity
constructor(
    address _bridge,
    address _globalExitRootManager,
    address _polygonZkEVM,
    uint32 _networkId,
    address _admin
)
```

## Deployment

```bash
DEPLOY_TARGET=polygon-zkevm forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $POLYGON_ZKEVM_RPC --broadcast --verify -vvv
```

## References

- [Polygon zkEVM Documentation](https://docs.polygon.technology/zkEVM/)
- [Polygon CDK](https://docs.polygon.technology/cdk/)
