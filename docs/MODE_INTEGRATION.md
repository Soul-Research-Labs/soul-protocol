# Mode Integration

## Overview

ZASEON integrates with **Mode Network**, an OP Stack L2 focused on DeFi with Sequencer Fee Sharing (SFS) that rebates a portion of transaction fees to contract deployers.

| Property       | Value                                 |
| -------------- | ------------------------------------- |
| Chain ID       | `34443` (mainnet), `919` (Sepolia)    |
| Bridge Type    | OP Stack / CrossDomainMessenger       |
| Contract       | `ModeBridgeAdapter.sol`               |
| VM             | EVM (OP Stack Bedrock)                |
| Finality       | ~7 days (optimistic challenge window) |
| Security Model | Optimistic rollup, fraud proofs       |
| Fee Sharing    | Sequencer Fee Sharing (SFS)           |

## Key Features

- Standard OP Stack Bedrock architecture
- CrossDomainMessenger for L1↔L2 messaging
- proveWithdrawal + finalizeWithdrawal
- SFS Register contract for sequencer fee sharing
- `FINALITY_BLOCKS = 50400` (~7 days)
- `DEFAULT_L2_GAS_LIMIT = 1000000`
- `MAX_MESSAGE_SIZE = 32768`

## Contract

```solidity
constructor(
    address _crossDomainMessenger,
    address _modePortal,
    address _outputOracle,
    address _admin
)
```

## Deployment

```bash
DEPLOY_TARGET=mode forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $MODE_RPC --broadcast --verify -vvv
```

## References

- [Mode Documentation](https://docs.mode.network/)
- [Sequencer Fee Sharing](https://docs.mode.network/build-on-mode/sfs-sequencer-fee-sharing)
