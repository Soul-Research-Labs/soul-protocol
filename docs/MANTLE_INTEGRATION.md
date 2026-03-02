# Mantle Integration

## Overview

ZASEON integrates with **Mantle Network**, a modified OP Stack L2 with modular data availability via EigenDA. Mantle uses MNT as its native gas token instead of ETH.

| Property       | Value                                     |
| -------------- | ----------------------------------------- |
| Chain ID       | `5000` (mainnet), `5003` (Sepolia)        |
| Bridge Type    | OP Stack / CrossDomainMessenger + EigenDA |
| Contract       | `MantleBridgeAdapter.sol`                 |
| VM             | EVM (OP Stack derivative)                 |
| Finality       | ~7 days (optimistic challenge window)     |
| Security Model | Optimistic rollup, EigenDA                |
| Native Token   | MNT                                       |

## Key Features

- Modified OP Stack with EigenDA for data availability
- CrossDomainMessenger for L1↔L2 messaging
- OutputOracle with 7-day challenge period
- MNT native gas token (ERC-20 on L1)
- OutputRootProof verification (version, stateRoot, messagePasserStorageRoot, latestBlockhash)
- `FINALITY_BLOCKS = 50400` (~7 days at 12s blocks)
- `DEFAULT_L2_GAS_LIMIT = 1000000`
- `MAX_PROOF_SIZE = 32768`

## Contract

```solidity
constructor(
    address _crossDomainMessenger,
    address _outputOracle,
    address _mantlePortal,
    address _admin
)
```

## Deployment

```bash
DEPLOY_TARGET=mantle forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $MANTLE_RPC --broadcast --verify -vvv
```

## References

- [Mantle Documentation](https://docs.mantle.xyz/)
- [Mantle Architecture](https://docs.mantle.xyz/network/introduction/a-gentler-introduction)
- [EigenDA](https://docs.eigenlayer.xyz/eigenda/)
