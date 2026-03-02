# Bitcoin Integration

## Overview

ZASEON integrates with **Bitcoin**, the original and largest cryptocurrency network. Bitcoin uses a UTXO model with Proof-of-Work (SHA-256d) consensus. Cross-chain messaging requires SPV Merkle inclusion proofs verified against a Bitcoin header relay on Ethereum.

| Property        | Value                                         |
| --------------- | --------------------------------------------- |
| ZASEON Chain ID | `19100`                                       |
| Bridge Type     | SPV-PoW                                       |
| Contract        | `BitcoinBridgeAdapter.sol`                    |
| VM              | Bitcoin Script (non-Turing-complete)          |
| Finality        | ~60 minutes (6 confirmations)                 |
| Security Model  | SPV proof + header relay + confirmation depth |
| Consensus       | Proof-of-Work (SHA-256d)                      |

## Architecture

```
┌─────────────┐   Bitcoin Bridge  ┌──────────────────┐   Header    ┌─────────────┐
│   ZASEON     │ ──sendMessage────▶│  Bitcoin Bridge   │ ──relay────▶│  Bitcoin    │
│   Adapter    │                   │  Hub (ETH)       │             │  Network    │
└─────────────┘                   └──────────────────┘             └─────────────┘
       ▲                                                                  │
       │                    SPV proof + block header chain                 │
       └──────────────────────────────────────────────────────────────────┘
```

### Key Concepts

- **UTXO Model**: Unspent Transaction Outputs — each transaction consumes inputs and creates outputs
- **Proof-of-Work**: SHA-256d (double SHA-256) mining with difficulty adjustment every 2016 blocks
- **SPV Proofs**: Simplified Payment Verification — Merkle inclusion proofs against block headers
- **Header Relay**: On-chain contract that tracks Bitcoin block headers for trustless verification
- **OP_RETURN**: Output script opcode for embedding up to 80 bytes of arbitrary data
- **Taproot (BIP 341)**: Schnorr signatures + MAST (Merklized Abstract Syntax Tree) for complex scripts
- **SegWit**: Segregated Witness separates signature data from transaction data
- **Block Time**: ~10 minutes average
- **Confirmations**: Number of blocks built on top of a transaction's block (6 = standard finality)

## Contract Details

### BitcoinBridgeAdapter

The adapter provides:

1. **Outbound messaging** via Bitcoin bridge hub (OP_RETURN / Taproot commitments)
2. **Inbound verification** using SPV Merkle proofs + header relay
3. **Confirmation depth** configurable (default: 6 blocks)
4. **Bitcoin address whitelisting** for trusted destinations
5. **Transaction hash tracking** to prevent duplicate processing
6. **Nullifier-based replay protection** via ZASEON CDNA
7. **Optional relay mode** — works with or without on-chain header relay

### Key Functions

```solidity
// Send a message anchored to a Bitcoin transaction
function sendMessage(
    bytes32 btcDestination,
    bytes calldata payload
) external payable returns (bytes32 messageHash);

// Receive and verify a message from Bitcoin
function receiveMessage(
    bytes32 btcTxHash,
    uint256 blockHeight,
    bytes calldata payload,
    bytes calldata spvProof
) external returns (bytes32 messageHash);

// Whitelist a Bitcoin address
function whitelistAddress(bytes32 btcAddress, bool enabled) external;

// Set confirmation depth requirement
function setRequiredConfirmations(uint256 depth) external;
```

### Security Features

- SPV Merkle inclusion proof verification (trustless when relay available)
- Configurable confirmation depth (default 6, min 1)
- Bitcoin header relay validation (block height + tx verification)
- Transaction hash tracking prevents duplicate processing
- Address whitelisting for trusted Bitcoin addresses
- Graceful fallback when relay is unavailable (bridge-only mode)
- Nullifier tracking prevents double-spending
- Pause/unpause for emergency response
- Role-based access (OPERATOR, RELAYER, GUARDIAN, PAUSER)

### BitVM Integration

ZASEON also includes a full **BitVMBridgeAdapter** (in `contracts/adapters/`) for BitVM-based fraud-proof bridging:

- Operator bond-based deposit/withdrawal system
- 7-day challenge period for fraud proofs
- 1-of-N honest operator assumption
- Full deposit lifecycle management

The `BitcoinBridgeAdapter` (in `contracts/crosschain/`) is the general-purpose cross-chain adapter that integrates with `MultiBridgeRouter`, while `BitVMBridgeAdapter` provides a specialized deposit/withdrawal bridge with stronger trust minimization.

## SPV Proof Structure

SPV proofs submitted to the adapter contain:

```
┌────────────────────────────────────────────┐
│  Block Hash (32 bytes)                     │
│  Transaction Index (32 bytes)              │
│  Merkle Siblings (32 bytes each)           │
│  ... (variable number of siblings)         │
└────────────────────────────────────────────┘
```

Verification flow:

1. Extract block hash and tx index from proof
2. Verify block hash exists at the claimed height via header relay
3. Recompute Merkle root from tx hash + siblings
4. Compare computed root against block's Merkle root
5. Verify sufficient confirmations (current height - block height ≥ required)

## Bitcoin Addresses

Bitcoin supports several address formats:

| Format | Prefix | Example                                                          |
| ------ | ------ | ---------------------------------------------------------------- |
| P2PKH  | `1`    | `1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2`                             |
| P2SH   | `3`    | `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy`                             |
| P2WPKH | `bc1q` | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`                     |
| P2TR   | `bc1p` | `bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297` |

In the adapter, Bitcoin addresses are passed as `bytes32` (hash of the address or raw script hash).

## SDK Usage

```typescript
import {
  BITCOIN_CHAIN_ID,
  DEFAULT_CONFIRMATIONS,
  BITCOIN_BRIDGE_ADAPTER_ABI,
} from "@zaseon/sdk/bridges/bitcoin";

// Send a privacy message anchored to Bitcoin
const tx = await walletClient.writeContract({
  address: adapterAddress,
  abi: BITCOIN_BRIDGE_ADAPTER_ABI,
  functionName: "sendMessage",
  args: [btcDestination, payload],
  value: bridgeFee,
});

// Verify and receive a Bitcoin-sourced message
const rx = await walletClient.writeContract({
  address: adapterAddress,
  abi: BITCOIN_BRIDGE_ADAPTER_ABI,
  functionName: "receiveMessage",
  args: [btcTxHash, blockHeight, payload, spvProof],
});
```

## Deployment

```bash
forge script scripts/deploy/DeployL2Bridges.s.sol \
  --sig "run(string)" "bitcoin" \
  --rpc-url $RPC_URL \
  --broadcast
```

## References

- [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf)
- [Bitcoin Developer Documentation](https://developer.bitcoin.org/)
- [BIP 341 — Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [SPV Proof Verification](https://en.bitcoin.it/wiki/Simplified_payment_verification)
- [BitVM](https://bitvm.org/bitvm.pdf)
- [Bitcoin Script](https://en.bitcoin.it/wiki/Script)
