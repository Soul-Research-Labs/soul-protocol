# Hyperlane Bridge Integration

## Overview

The `HyperlaneAdapter` integrates Hyperlane's modular Interchain Security Module (ISM) framework for cross-chain messaging with customizable verification. Supports multisig, merkle, aggregation, and custom ISM types.

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                 Hyperlane ISM Integration                      │
│                                                                │
│  Source Chain                     Destination Chain            │
│  ┌────────────┐   ┌──────────┐   ┌────────────┐              │
│  │ Mailbox    │──▶│ Relayer  │──▶│ Mailbox    │              │
│  └────────────┘   └────┬─────┘   └─────┬──────┘              │
│                        │               │                      │
│                  ┌─────▼───────────────▼─────┐               │
│                  │  Interchain Security       │               │
│                  │  Module (ISM)              │               │
│                  │                            │               │
│                  │  ┌──────────────────────┐  │               │
│                  │  │ Multisig ISM         │  │               │
│                  │  │ • m-of-n validators  │  │               │
│                  │  │ • Per-domain config   │  │               │
│                  │  └──────────────────────┘  │               │
│                  │                            │               │
│                  │  ┌──────────────────────┐  │               │
│                  │  │ Merkle ISM           │  │               │
│                  │  │ • Proof verification  │  │               │
│                  │  └──────────────────────┘  │               │
│                  │                            │               │
│                  │  ┌──────────────────────┐  │               │
│                  │  │ Aggregation ISM      │  │               │
│                  │  │ • Combine ISMs       │  │               │
│                  │  └──────────────────────┘  │               │
│                  └───────────────────────────┘               │
└───────────────────────────────────────────────────────────────┘
```

## Contract

- **Path**: `contracts/crosschain/HyperlaneAdapter.sol`
- **Solidity**: `^0.8.24`
- **Lines**: ~694

## Key Features

- Hyperlane Mailbox integration for dispatch/handle pattern
- Modular ISM support (Multisig, Merkle, Aggregation, Routing, Custom)
- Per-domain trusted sender configuration
- Validator signature collection and threshold verification
- Merkle root storage and proof verification
- Nonce tracking (outbound + inbound per domain)
- Fee quoting for cross-chain messages

## ISM Types

| Type | Description |
|------|-------------|
| `MULTISIG` | m-of-n validator signature verification |
| `MERKLE` | Merkle inclusion proof verification |
| `AGGREGATION` | Combine multiple ISMs with AND/OR logic |
| `ROUTING` | Route to different ISMs based on origin |
| `PAUSABLE` | ISM with pause capability |
| `CUSTOM` | External ISM contract integration |

## Roles

| Role | Purpose |
|------|---------|
| `DEFAULT_ADMIN_ROLE` | Core configuration |
| `OPERATOR_ROLE` | Set ISM configs, trusted senders, multisig params |
| `GUARDIAN_ROLE` | Pause/unpause |
| `VALIDATOR_ROLE` | Submit validator signatures |

## Configuration

```solidity
HyperlaneAdapter adapter = new HyperlaneAdapter(
    mailboxAddress,
    localDomain,
    admin
);

// Set trusted sender for a remote domain
adapter.setTrustedSender(remoteDomain, trustedSenderBytes32);

// Configure multisig ISM
adapter.setISMConfig(
    remoteDomain,
    ismAddress,
    ISMType.MULTISIG,
    threshold,
    validators
);

// Set multisig parameters
adapter.setMultisigParams(remoteDomain, validators, threshold, commitment);
```

## SDK Usage

```typescript
import {
    HYPERLANE_ADAPTER_ABI,
    HYPERLANE_DOMAINS,
    addressToBytes32,
    computeMessageId,
    getDomainName
} from '@zaseon/sdk/bridges/hyperlane';

const recipient = addressToBytes32(targetContract);
const domainName = getDomainName(1); // "ethereum"
```

## Testing

```bash
# Run fuzz tests
forge test --match-contract HyperlaneBridgeFuzz -vvv
```

## Deployment

```bash
npx hardhat run scripts/deploy/deploy-hyperlane-adapter.ts --network mainnet
```

## Security Considerations

- Only Mailbox contract can call `handle()` for incoming messages
- Trusted senders validated per domain to prevent spoofing
- Multisig ISM requires sorted, unique signatures
- Processed message tracking prevents replay attacks
- ReentrancyGuard on dispatch function
- Pausable for emergency situations
