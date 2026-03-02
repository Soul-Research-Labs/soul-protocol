# Aleo Integration

## Overview

ZASEON integrates with **Aleo**, a Layer-1 blockchain that enables private applications using zero-knowledge proofs. Aleo runs programs written in **Leo** (a Rust-like ZK programming language) on the **snarkVM** — a virtual machine that executes programs and produces SNARK proofs of correct execution.

| Property        | Value                                 |
| --------------- | ------------------------------------- |
| ZASEON Chain ID | `17100`                               |
| Bridge Type     | BridgeRelay-AleoBFT                   |
| Contract        | `AleoBridgeAdapter.sol`               |
| VM              | snarkVM (Aleo Virtual Machine)        |
| Finality        | ~15 seconds (AleoBFT committee round) |
| Security Model  | Committee certificate + Marlin proofs |
| Proof System    | Marlin SNARKs (universal setup)       |

## Architecture

```
┌─────────────┐    Aleo Relay     ┌──────────────────┐  Committee   ┌─────────────┐
│   ZASEON     │ ──sendMessage────▶│   Aleo Bridge    │ ─certificate▶│   AleoBFT   │
│   Adapter    │                   │   Relay (ETH)    │              │  Committee  │
└─────────────┘                   └──────────────────┘              └─────────────┘
       ▲                                                                   │
       │                    Marlin SNARK proof + state root                 │
       └───────────────────────────────────────────────────────────────────┘
```

### Key Concepts

- **snarkVM**: Zero-knowledge virtual machine that executes Leo programs and produces proofs
- **Leo**: Rust-like programming language for ZK applications on Aleo
- **Records**: Encrypted UTXO-like data structures (private by default)
- **Transitions**: Program function executions that consume/produce records
- **AleoBFT**: Consensus protocol with rotating validator committee
- **Committee Certificates**: Signed attestations from committee members (⅔+ quorum)
- **Marlin SNARKs**: Universal SNARK proof system with structured reference string
- **Programs**: Smart contracts identified by `programId` (e.g., `credits.aleo`)
- **Networks**: Mainnet (0), Testnet (1), Canary (2)

## Contract Details

### AleoBridgeAdapter

The adapter provides:

1. **Outbound messaging** via Aleo relay `sendMessage`
2. **Inbound verification** using Marlin proofs or light client verification
3. **Program whitelisting** for trusted Aleo programs
4. **Network support management** (mainnet, testnet, canary)
5. **Nullifier-based replay protection** via ZASEON CDNA

### Key Functions

```solidity
// Send a message to an Aleo program
function sendMessage(
    bytes32 programId,
    bytes32 functionName,
    bytes calldata payload
) external payable returns (bytes32 messageHash);

// Receive and verify a message from Aleo
function receiveMessage(
    bytes32 programId,
    uint8 networkId,
    bytes calldata payload,
    bytes calldata proof
) external returns (bytes32 messageHash);

// Whitelist an Aleo program
function whitelistProgram(bytes32 programId, bool enabled) external;

// Enable/disable network support
function setSupportedNetwork(uint8 networkId, bool supported) external;
```

### Security Features

- Dual verification: Marlin proof OR light client state proof
- Committee certificate quorum: 66.67% (AleoBFT ⅔ requirement)
- Program whitelisting (only trusted Aleo programs accepted)
- Network validation (only enabled networks accepted)
- Nullifier tracking prevents double-spending
- Pause/unpause for emergency response
- Role-based access (OPERATOR, RELAYER, GUARDIAN, PAUSER)

## Aleo Privacy Model

Aleo's privacy is fundamentally different from EVM chains:

- **Records** are encrypted: only the owner can decrypt them
- **Transitions** consume and produce records (UTXO model)
- **View keys** allow selective disclosure without revealing private keys
- **Programs** can mix public and private execution modes
- **Serial numbers** (analogous to nullifiers) prevent double-spending

ZASEON bridges these privacy properties:

- Aleo record commitments map to ZASEON shielded pool commitments
- Aleo serial numbers map to ZASEON nullifiers
- Selective disclosure proofs bridge trust boundaries

## SDK Usage

```typescript
import {
  ALEO_CHAIN_ID,
  COMMITTEE_QUORUM_BPS,
  ALEO_BRIDGE_ADAPTER_ABI,
} from "@zaseon/sdk/bridges/aleo";

// Send a privacy message to an Aleo program
const tx = await walletClient.writeContract({
  address: adapterAddress,
  abi: ALEO_BRIDGE_ADAPTER_ABI,
  functionName: "sendMessage",
  args: [programId, functionName, payload],
  value: relayFee,
});
```

## Aleo Identifiers

Aleo uses unique identifiers for programs and addresses:

```
Program ID:    credits.aleo
Address:       aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9dx
View Key:      AViewKey1...
Record:        { owner: aleo1..., amount: 1000u64.private, ... }
```

When passing to the adapter:

- `programId` = keccak256-derived bytes32 of program name
- `networkId` = `0` (mainnet), `1` (testnet), `2` (canary)

## Deployment

```bash
forge script scripts/deploy/DeployL2Bridges.s.sol \
  --sig "run(string)" "aleo" \
  --rpc-url $RPC_URL \
  --broadcast
```

## References

- [Aleo Documentation](https://developer.aleo.org/)
- [Leo Language](https://leo-lang.org/)
- [snarkVM](https://github.com/AleoNet/snarkVM)
- [AleoBFT](https://developer.aleo.org/concepts/network/consensus)
- [Marlin SNARKs](https://eprint.iacr.org/2019/1047)
- [Aleo Records](https://developer.aleo.org/concepts/programs/records)
