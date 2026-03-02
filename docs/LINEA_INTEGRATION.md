# Linea Integration

## Overview

ZASEON integrates with **Linea**, a Type 2 zkEVM rollup developed by Consensys, providing EVM equivalence with zero-knowledge proof finality.

| Property       | Value                                  |
| -------------- | -------------------------------------- |
| Chain ID       | `59144` (mainnet), `59141` (Sepolia)   |
| Bridge Type    | IMessageService / ZK Proof             |
| Contract       | `LineaBridgeAdapter.sol`               |
| VM             | EVM (Type 2 zkEVM)                     |
| Finality       | ~8–32 hours (data submission + proofs) |
| Security Model | zkSNARK validity proofs                |
| Status         | Graduated, Certora verified            |

## Key Features

- Type 2 zkEVM by Consensys
- IMessageService for L1↔L2 messaging
- Merkle proof for L2→L1 `claimMessage`
- Token bridge with native ETH support
- `FINALITY_BLOCKS = 1`
- `DEFAULT_MESSAGE_FEE = 0.001 ether`
- `MAX_PROOF_SIZE = 32768`

## Contract

```solidity
constructor(
    address _messageService,
    address _tokenBridge,
    address _rollup,
    address _admin
)
```

## Deployment

```bash
DEPLOY_TARGET=linea forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $LINEA_RPC --broadcast --verify -vvv
```

## References

- [Linea Documentation](https://docs.linea.build/)
- [Linea Architecture](https://docs.linea.build/developers/linea-version)
