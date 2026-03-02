# Blast Integration

## Overview

ZASEON integrates with **Blast**, an OP Stack L2 with native yield for ETH (via Lido stETH) and stablecoins (via MakerDAO sDAI). Contracts can opt into CLAIMABLE yield mode.

| Property       | Value                                    |
| -------------- | ---------------------------------------- |
| Chain ID       | `81457` (mainnet), `168587773` (Sepolia) |
| Bridge Type    | OP Stack / CrossDomainMessenger          |
| Contract       | `BlastBridgeAdapter.sol`                 |
| VM             | EVM (OP Stack Bedrock)                   |
| Finality       | ~7 days (optimistic challenge window)    |
| Security Model | Optimistic rollup, fraud proofs          |
| Native Yield   | ETH (stETH) + USDB (sDAI)                |

## Key Features

- OP Stack Bedrock-based optimistic rollup
- CrossDomainMessenger for L1↔L2 messaging
- Native ETH yield via auto-rebasing (Lido stETH)
- CLAIMABLE yield mode for contracts
- proveWithdrawal + finalizeWithdrawal via OptimismPortal
- `FINALITY_BLOCKS = 50400` (~7 days)
- `DEFAULT_L2_GAS_LIMIT = 1000000`
- `MAX_MESSAGE_SIZE = 32768`

## Contract

```solidity
constructor(
    address _crossDomainMessenger,
    address _blastPortal,
    address _outputOracle,
    address _admin
)
```

## Deployment

```bash
DEPLOY_TARGET=blast forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $BLAST_RPC --broadcast --verify -vvv
```

## References

- [Blast Documentation](https://docs.blast.io/)
- [Blast Architecture](https://docs.blast.io/about-blast)
