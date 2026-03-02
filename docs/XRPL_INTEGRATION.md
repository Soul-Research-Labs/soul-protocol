# XRPL Integration

## Overview

ZASEON integrates with the **XRP Ledger (XRPL)**, one of the oldest and most established blockchain networks. XRPL uses the **Federated Byzantine Agreement (FBA)** consensus algorithm with a Unique Node List (UNL) model, providing 3-5 second finality with no mining or staking.

| Property        | Value                               |
| --------------- | ----------------------------------- |
| ZASEON Chain ID | `18100`                             |
| Bridge Type     | WitnessAttestation-FBA              |
| Contract        | `XRPLBridgeAdapter.sol`             |
| VM              | XRPL Transaction Engine (non-EVM)   |
| Finality        | ~3-5 seconds (FBA consensus round)  |
| Security Model  | Witness attestation (80% threshold) |
| Consensus       | Federated Byzantine Agreement (FBA) |

## Architecture

```
┌─────────────┐    XRPL Bridge    ┌──────────────────┐  Witnesses   ┌─────────────┐
│   ZASEON     │ ──sendMessage────▶│   XRPL Bridge    │ ─attestation▶│   XRPL      │
│   Adapter    │                   │   Hub (ETH)      │              │   Witnesses │
└─────────────┘                   └──────────────────┘              └─────────────┘
       ▲                                                                   │
       │                    Witness signatures + SHAMap proof               │
       └───────────────────────────────────────────────────────────────────┘
```

### Key Concepts

- **FBA Consensus**: Federated Byzantine Agreement — validators agree based on overlapping trusted sets (UNL)
- **UNL (Unique Node List)**: Each node's list of trusted validators (default UNL ≈ 35 validators)
- **Ledger**: XRPL state at a point in time (closes every 3-5 seconds)
- **SHAMap**: Shamir-mapped Merkle trie used for transaction and state proofs
- **Destination Tags**: Numeric tags (uint32) that identify recipients within an account (like memo IDs)
- **Hooks**: Smart-contract-like programs on XRPL (WebAssembly-based, limited execution)
- **Trust Lines**: Bilateral credit relationships for issued tokens
- **Accounts**: Base58-encoded addresses (r-prefix, ~25-35 characters)
- **Reserves**: Minimum XRP required to maintain account and objects

## Contract Details

### XRPLBridgeAdapter

The adapter provides:

1. **Outbound messaging** via XRPL bridge hub `sendMessage`
2. **Inbound verification** using witness attestations (80% threshold matching FBA)
3. **Account whitelisting** for trusted XRPL addresses
4. **Destination tag support** for routing within XRPL accounts
5. **SHAMap proof verification** via optional light client
6. **Nullifier-based replay protection** via ZASEON CDNA

### Key Functions

```solidity
// Send a message to an XRPL account
function sendMessage(
    bytes20 xrplDestination,
    uint32 destinationTag,
    bytes calldata payload
) external payable returns (bytes32 messageHash);

// Receive and verify a message from XRPL
function receiveMessage(
    bytes20 xrplSource,
    uint64 ledgerIndex,
    bytes calldata payload,
    bytes calldata attestation
) external returns (bytes32 messageHash);

// Whitelist an XRPL account
function whitelistAccount(bytes20 xrplAccount, bool enabled) external;

// Set attestation threshold
function setAttestationThreshold(uint256 thresholdBps) external;
```

### Security Features

- Witness attestation model with 80% threshold (mirrors FBA supermajority)
- Optional SHAMap Merkle proof verification via light client
- Account whitelisting (only trusted XRPL addresses accepted)
- Destination tag routing for multi-recipient accounts
- Ledger index tracking to prevent out-of-order processing
- Nullifier tracking prevents double-spending
- Pause/unpause for emergency response
- Role-based access (OPERATOR, RELAYER, GUARDIAN, PAUSER)

## XRPL Accounts & Addressing

XRPL uses Base58Check-encoded addresses:

```
Classic address: rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh
X-address:       X7AcgcsBL6XDcUb289X4mJ8djcdyKaB5hJDWMArnXr61cqh
```

In the adapter, XRPL addresses are represented as `bytes20`:

- Derived from the 20-byte AccountID (RIPEMD160 of SHA-256 of public key)
- The adapter stores raw AccountID without Base58 encoding

Destination tags (uint32) identify sub-accounts:

```
rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh?dt=12345
```

## SDK Usage

```typescript
import {
  XRPL_CHAIN_ID,
  ATTESTATION_THRESHOLD_BPS,
  XRPL_BRIDGE_ADAPTER_ABI,
} from "@zaseon/sdk/bridges/xrpl";

// Send a privacy message to an XRPL account
const tx = await walletClient.writeContract({
  address: adapterAddress,
  abi: XRPL_BRIDGE_ADAPTER_ABI,
  functionName: "sendMessage",
  args: [xrplDestination, destinationTag, payload],
  value: bridgeFee,
});
```

## Deployment

```bash
forge script scripts/deploy/DeployL2Bridges.s.sol \
  --sig "run(string)" "xrpl" \
  --rpc-url $RPC_URL \
  --broadcast
```

## References

- [XRPL Documentation](https://xrpl.org/)
- [XRPL Consensus](https://xrpl.org/consensus.html)
- [XRPL Hooks](https://hooks.xrpl.org/)
- [XRPL SHAMap](https://xrpl.org/serialization.html)
- [XRPL Bridges](https://xrpl.org/docs/concepts/xrpl-sidechains/cross-chain-bridges)
- [Federated Byzantine Agreement](https://www.stellar.org/papers/stellar-consensus-protocol)
