# Soul Network - Privacy Interoperability Layer (PIL)

## Type Documentation

This document provides comprehensive type definitions for the Privacy Interoperability Layer (PIL), a cross-chain middleware for private state transfer and zero-knowledge proof verification across heterogeneous blockchain networks.

---

## Table of Contents

1. [Core Types](#core-types)
2. [Proof Types](#proof-types)
3. [Bridge Types](#bridge-types)
4. [Cross-Chain Types](#cross-chain-types)
5. [Privacy Primitives](#privacy-primitives)
6. [Oracle & External Types](#oracle--external-types)
7. [Security Types](#security-types)
8. [Event Types](#event-types)

---

## Core Types

### Confidential State Types

```typescript
/**
 * Represents an encrypted state container with ZK proof verification
 */
interface ConfidentialState {
  /** Unique state identifier (32 bytes) */
  stateId: bytes32;
  
  /** Pedersen commitment to the state data */
  commitment: bytes32;
  
  /** AES-256-GCM encrypted state payload */
  encryptedData: bytes;
  
  /** Nullifier for double-spend prevention */
  nullifier: bytes32;
  
  /** Merkle root of the state tree */
  merkleRoot: bytes32;
  
  /** Block timestamp of state creation */
  timestamp: uint256;
  
  /** Current state status */
  status: StateStatus;
}

/**
 * State lifecycle status
 */
enum StateStatus {
  PENDING = 0,      // Awaiting verification
  ACTIVE = 1,       // Verified and active
  CONSUMED = 2,     // Nullified/spent
  EXPIRED = 3,      // Time-locked and expired
  REVOKED = 4       // Administratively revoked
}

/**
 * State metadata for indexing and querying
 */
interface StateMetadata {
  /** Owner address (may be zero for anonymous) */
  owner: address;
  
  /** Source chain identifier */
  sourceChain: uint256;
  
  /** State type discriminator */
  stateType: bytes4;
  
  /** Optional expiration timestamp */
  expiresAt: uint256;
  
  /** Associated proof hash */
  proofHash: bytes32;
}
```

### Nullifier Types

```typescript
/**
 * Nullifier registry entry
 */
interface NullifierEntry {
  /** Nullifier hash */
  nullifier: bytes32;
  
  /** Domain separator for cross-chain uniqueness */
  domain: bytes32;
  
  /** Registration timestamp */
  registeredAt: uint256;
  
  /** Registering transaction hash */
  txHash: bytes32;
  
  /** Associated state ID (if any) */
  stateId: bytes32;
}

/**
 * Cross-Domain Nullifier Algebra (CDNA) configuration
 */
interface CDNAConfig {
  /** Domain identifier */
  domainId: bytes32;
  
  /** Chain-specific salt */
  chainSalt: bytes32;
  
  /** Nullifier derivation version */
  version: uint8;
  
  /** Hash function selector (0=keccak256, 1=poseidon, 2=pedersen) */
  hashFunction: uint8;
}
```

---

## Proof Types

### Zero-Knowledge Proof Types

```typescript
/**
 * Groth16 proof structure (BN254 curve)
 */
interface Groth16Proof {
  /** Proof point A (G1) */
  a: [uint256, uint256];
  
  /** Proof point B (G2) - 2x2 array */
  b: [[uint256, uint256], [uint256, uint256]];
  
  /** Proof point C (G1) */
  c: [uint256, uint256];
}

/**
 * PLONK proof structure
 */
interface PLONKProof {
  /** Wire commitments */
  wireCommitments: bytes32[];
  
  /** Grand product commitment */
  grandProductCommitment: bytes32;
  
  /** Quotient polynomial commitments */
  quotientCommitments: bytes32[];
  
  /** Wire evaluations at challenge point */
  wireEvaluations: uint256[];
  
  /** Permutation evaluation */
  permutationEvaluation: uint256;
  
  /** Opening proof */
  openingProof: bytes;
}

/**
 * FRI/STARK proof structure
 */
interface STARKProof {
  /** FRI layers */
  friLayers: FRILayer[];
  
  /** Trace commitments */
  traceCommitments: bytes32[];
  
  /** Composition polynomial commitment */
  compositionCommitment: bytes32;
  
  /** Out-of-domain evaluations */
  oodEvaluations: uint256[];
  
  /** Query responses */
  queryResponses: bytes[];
  
  /** Final polynomial */
  finalPoly: uint256[];
}

/**
 * FRI layer data
 */
interface FRILayer {
  /** Layer commitment */
  commitment: bytes32;
  
  /** Evaluation at folding point */
  evaluation: uint256;
  
  /** Authentication path */
  authPath: bytes32[];
}

/**
 * Unified proof wrapper
 */
interface UnifiedProof {
  /** Proof system type */
  proofType: ProofType;
  
  /** Curve/field identifier */
  curveId: CurveId;
  
  /** Raw proof bytes */
  proofData: bytes;
  
  /** Public inputs */
  publicInputs: uint256[];
  
  /** Verification key hash */
  vkHash: bytes32;
}

/**
 * Supported proof systems
 */
enum ProofType {
  GROTH16_BN254 = 0,
  GROTH16_BLS12_381 = 1,
  PLONK = 2,
  FFLONK = 3,
  STARK = 4,
  BULLETPROOFS = 5,
  HALO2 = 6
}

/**
 * Supported elliptic curves
 */
enum CurveId {
  BN254 = 0,
  BLS12_381 = 1,
  BLS12_377 = 2,
  PASTA = 3,          // Pallas/Vesta
  SECP256K1 = 4,
  ED25519 = 5
}
```

---

## Bridge Types

### Cross-Chain Bridge Types

```typescript
/**
 * Bridge adapter interface
 */
interface IBridgeAdapter {
  /** Send message to remote chain */
  sendMessage(
    destinationChain: uint256,
    recipient: bytes32,
    payload: bytes,
    options: MessageOptions
  ): bytes32;
  
  /** Receive message from remote chain */
  receiveMessage(
    sourceChain: uint256,
    sender: bytes32,
    payload: bytes,
    proof: bytes
  ): boolean;
  
  /** Estimate bridge fee */
  estimateFee(
    destinationChain: uint256,
    payloadSize: uint256
  ): uint256;
}

/**
 * Message options for cross-chain calls
 */
interface MessageOptions {
  /** Gas limit on destination */
  gasLimit: uint256;
  
  /** Native value to send */
  value: uint256;
  
  /** Fee payment token (native/specific) */
  feeToken: address;
  
  /** Refund address for excess fees */
  refundAddress: address;
  
  /** Message expiry timestamp */
  expiry: uint256;
  
  /** Custom options data */
  extraOptions: bytes;
}

/**
 * Cross-chain message envelope
 */
interface CrossChainMessage {
  /** Global unique identifier */
  messageId: bytes32;
  
  /** Source chain ID */
  sourceChain: uint256;
  
  /** Destination chain ID */
  destChain: uint256;
  
  /** Sender address (normalized to bytes32) */
  sender: bytes32;
  
  /** Recipient address (normalized to bytes32) */
  recipient: bytes32;
  
  /** Message payload */
  payload: bytes;
  
  /** Message nonce for ordering */
  nonce: uint256;
  
  /** Timestamp of creation */
  timestamp: uint256;
  
  /** Current message status */
  status: MessageStatus;
}

/**
 * Message lifecycle status
 */
enum MessageStatus {
  PENDING = 0,
  SENT = 1,
  DELIVERED = 2,
  EXECUTED = 3,
  FAILED = 4,
  EXPIRED = 5,
  REFUNDED = 6
}
```

---

## Cross-Chain Types

### Solana Integration Types

```typescript
/**
 * Solana address (Ed25519 public key)
 */
type SolanaAddress = bytes32;

/**
 * SPL Token information
 */
interface SPLTokenInfo {
  /** Mint address */
  mintAddress: SolanaAddress;
  
  /** Token decimals */
  decimals: uint8;
  
  /** Total supply */
  supply: uint256;
  
  /** Mapped EVM token address */
  evmToken: address;
  
  /** Freeze status */
  frozen: boolean;
  
  /** Verification status */
  verified: boolean;
}

/**
 * Program Derived Address (PDA) info
 */
interface PDAInfo {
  /** Parent program ID */
  programId: SolanaAddress;
  
  /** Derivation seeds */
  seeds: bytes[];
  
  /** Bump seed */
  bump: uint8;
  
  /** Derived address */
  derivedAddress: SolanaAddress;
  
  /** Verification status */
  verified: boolean;
}

/**
 * Wormhole VAA (Verified Action Approval)
 */
interface WormholeVAA {
  /** VAA version */
  version: uint8;
  
  /** Guardian set index */
  guardianSetIndex: uint32;
  
  /** Guardian signatures */
  signatures: bytes;
  
  /** Message timestamp */
  timestamp: uint32;
  
  /** Nonce */
  nonce: uint32;
  
  /** Emitter chain ID */
  emitterChainId: uint16;
  
  /** Emitter address */
  emitterAddress: bytes32;
  
  /** Sequence number */
  sequence: uint64;
  
  /** Consistency level */
  consistencyLevel: uint8;
  
  /** Payload data */
  payload: bytes;
  
  /** VAA hash */
  hash: bytes32;
}
```

### LayerZero Integration Types

```typescript
/**
 * LayerZero Endpoint ID
 */
type EndpointId = uint32;

/**
 * OApp (Omnichain Application) peer configuration
 */
interface OAppPeer {
  /** Remote endpoint ID */
  eid: EndpointId;
  
  /** Remote peer address */
  peerAddress: bytes32;
  
  /** Chain type */
  chainType: ChainType;
  
  /** Active status */
  active: boolean;
  
  /** Minimum gas for execution */
  minGas: uint256;
  
  /** Security configuration level */
  securityLevel: SecurityLevel;
}

/**
 * Supported chain types
 */
enum ChainType {
  EVM = 0,
  SOLANA = 1,
  APTOS = 2,
  SUI = 3,
  IOTA = 4,
  HYPERLIQUID = 5
}

/**
 * DVN security levels
 */
enum SecurityLevel {
  STANDARD = 0,     // Single DVN
  ENHANCED = 1,     // 2 of N DVNs
  MAXIMUM = 2       // Required + Optional DVNs
}

/**
 * LayerZero message options
 */
interface LzMessageOptions {
  /** Destination gas limit */
  gas: uint128;
  
  /** Native value to forward */
  value: uint128;
  
  /** Composed message data */
  composeMsg: bytes;
  
  /** Extra options */
  extraOptions: bytes;
}

/**
 * OFT (Omnichain Fungible Token) transfer
 */
interface OFTTransfer {
  /** Transfer ID */
  transferId: bytes32;
  
  /** Source endpoint ID */
  srcEid: EndpointId;
  
  /** Destination endpoint ID */
  dstEid: EndpointId;
  
  /** Local token address */
  localToken: address;
  
  /** Remote token representation */
  remoteToken: bytes32;
  
  /** Amount sent */
  amountSent: uint256;
  
  /** Amount received (after fees) */
  amountReceived: uint256;
  
  /** Sender address */
  sender: bytes32;
  
  /** Recipient address */
  recipient: bytes32;
  
  /** Fee amount */
  fee: uint256;
  
  /** Transfer status */
  status: MessageStatus;
}
```

### Chainlink Integration Types

```typescript
/**
 * CCIP chain selector
 */
type ChainSelector = uint64;

/**
 * CCIP chain configuration
 */
interface CCIPChainConfig {
  /** Chain selector */
  chainSelector: ChainSelector;
  
  /** CCIP router address */
  router: address;
  
  /** Our peer contract address */
  peerAddress: bytes32;
  
  /** Active status */
  active: boolean;
  
  /** Default gas limit */
  gasLimit: uint256;
}

/**
 * CCIP message types
 */
enum CCIPMessageType {
  ARBITRARY_MESSAGE = 0,      // Data only
  TOKEN_TRANSFER = 1,         // Tokens only
  PROGRAMMABLE_TRANSFER = 2   // Tokens + Data
}

/**
 * Token amount for CCIP transfers
 */
interface TokenAmount {
  /** Token address */
  token: address;
  
  /** Amount */
  amount: uint256;
}

/**
 * Chainlink Data Feed
 */
interface DataFeed {
  /** Aggregator contract address */
  feedAddress: address;
  
  /** Asset description */
  description: string;
  
  /** Price decimals */
  decimals: uint8;
  
  /** Maximum update interval (heartbeat) */
  heartbeat: uint256;
  
  /** Active status */
  active: boolean;
}

/**
 * VRF request
 */
interface VRFRequest {
  /** Request ID */
  requestId: uint256;
  
  /** Requester address */
  requester: address;
  
  /** Number of random words requested */
  numWords: uint32;
  
  /** Fulfilled random words */
  randomWords: uint256[];
  
  /** Fulfillment status */
  fulfilled: boolean;
  
  /** Request timestamp */
  timestamp: uint256;
}

/**
 * Chainlink Functions request
 */
interface FunctionsRequest {
  /** Request ID */
  requestId: bytes32;
  
  /** Requester address */
  requester: address;
  
  /** JavaScript source code */
  source: string;
  
  /** Encrypted secrets */
  secrets: bytes;
  
  /** Function arguments */
  args: string[];
  
  /** Response data */
  response: bytes;
  
  /** Error data */
  error: bytes;
  
  /** Fulfillment status */
  fulfilled: boolean;
}
```

### StarkNet Integration Types

```typescript
/**
 * StarkNet felt (field element)
 */
type Felt = uint256;

/**
 * StarkNet message direction
 */
enum StarkNetMessageDirection {
  L1_TO_L2 = 0,
  L2_TO_L1 = 1
}

/**
 * L1 to L2 message
 */
interface L1ToL2Message {
  /** Message hash */
  messageHash: bytes32;
  
  /** L2 contract address (felt) */
  toAddress: Felt;
  
  /** Entry point selector */
  selector: Felt;
  
  /** Message payload */
  payload: Felt[];
  
  /** Message nonce */
  nonce: uint256;
  
  /** Fee paid */
  fee: uint256;
  
  /** Message status */
  status: MessageStatus;
}

/**
 * Cairo contract registration
 */
interface CairoContract {
  /** Contract hash */
  contractHash: bytes32;
  
  /** Class hash */
  classHash: bytes32;
  
  /** Cairo version */
  version: CairoVersion;
  
  /** Verification status */
  verified: boolean;
  
  /** Registration timestamp */
  registeredAt: uint256;
}

/**
 * Cairo language versions
 */
enum CairoVersion {
  CAIRO_0 = 0,
  CAIRO_1 = 1,
  CAIRO_2 = 2
}

/**
 * State update from StarkNet
 */
interface StarkNetStateUpdate {
  /** Update ID */
  updateId: bytes32;
  
  /** L2 block number */
  blockNumber: uint256;
  
  /** Block hash */
  blockHash: bytes32;
  
  /** New state root */
  stateRoot: bytes32;
  
  /** Parent state root */
  parentStateRoot: bytes32;
  
  /** Updated contract addresses */
  contractUpdates: Felt[];
  
  /** Update timestamp */
  timestamp: uint256;
  
  /** Verification status */
  verified: boolean;
}
```

### Bitcoin/BitVM Integration Types

```typescript
/**
 * Bitcoin transaction output point
 */
interface BitcoinOutpoint {
  /** Transaction hash */
  txid: bytes32;
  
  /** Output index */
  vout: uint32;
}

/**
 * Bitcoin script types
 */
enum ScriptType {
  P2PKH = 0,        // Pay to Public Key Hash
  P2SH = 1,         // Pay to Script Hash
  P2WPKH = 2,       // Pay to Witness Public Key Hash
  P2WSH = 3,        // Pay to Witness Script Hash
  P2TR = 4          // Pay to Taproot
}

/**
 * BitVM gate types
 */
enum GateType {
  NAND = 0,
  AND = 1,
  OR = 2,
  XOR = 3,
  NOT = 4
}

/**
 * BitVM program
 */
interface BitVMProgram {
  /** Program identifier */
  programId: bytes32;
  
  /** Program hash */
  programHash: bytes32;
  
  /** Gate count */
  gateCount: uint256;
  
  /** Input count */
  inputCount: uint256;
  
  /** Output count */
  outputCount: uint256;
  
  /** Verification status */
  verified: boolean;
  
  /** Registration timestamp */
  registeredAt: uint256;
}

/**
 * BitVM fraud proof
 */
interface BitVMFraudProof {
  /** Proof ID */
  proofId: bytes32;
  
  /** Target program */
  programId: bytes32;
  
  /** Challenged gate index */
  gateIndex: uint256;
  
  /** Expected output */
  expectedOutput: bool;
  
  /** Actual output */
  actualOutput: bool;
  
  /** Witness data */
  witness: bytes;
  
  /** Verification status */
  verified: boolean;
}

/**
 * Supported BitVM chains
 */
enum BitVMChain {
  BITVM = 0,
  BITVM2 = 1,
  CITREA = 2,
  BOB = 3,
  STACKS = 4,
  RGB = 5,
  LIQUID = 6,
  ROOTSTOCK = 7,
  MERLIN = 8,
  B_SQUARED = 9
}
```

---

## Privacy Primitives

### PIL v2 Primitive Types

```typescript
/**
 * PC³ (Proof-Carrying Container)
 * Self-authenticating confidential container with embedded proofs
 */
interface PC3Container {
  /** Container ID */
  containerId: bytes32;
  
  /** Commitment to content */
  commitment: bytes32;
  
  /** Encrypted payload */
  encryptedPayload: bytes;
  
  /** Embedded proof */
  proof: UnifiedProof;
  
  /** Policy binding hash */
  policyHash: bytes32;
  
  /** Creation timestamp */
  createdAt: uint256;
  
  /** Optional expiry */
  expiresAt: uint256;
}

/**
 * PBP (Policy-Bound Proof)
 * Proof cryptographically scoped by disclosure policy
 */
interface PolicyBoundProof {
  /** Proof ID */
  proofId: bytes32;
  
  /** Base proof data */
  proof: bytes;
  
  /** Policy commitment */
  policyCommitment: bytes32;
  
  /** Disclosure flags */
  disclosureFlags: uint256;
  
  /** Bound attributes */
  boundAttributes: bytes32[];
  
  /** Issuer signature */
  issuerSignature: bytes;
}

/**
 * EASC (Execution-Agnostic State Commitment)
 * Backend-independent state verification
 */
interface EASCommitment {
  /** Commitment hash */
  commitmentHash: bytes32;
  
  /** State schema version */
  schemaVersion: uint16;
  
  /** Execution environment ID */
  environmentId: bytes4;
  
  /** State transition proof */
  transitionProof: bytes;
  
  /** Finality attestation */
  finalityAttestation: bytes;
}

/**
 * ZK-SLock (ZK-Bound State Lock)
 * Cross-chain confidential state lock
 */
interface ZKSLock {
  /** Lock ID */
  lockId: bytes32;
  
  /** State commitment */
  stateCommitment: bytes32;
  
  /** Unlock proof hash */
  unlockProofHash: bytes32;
  
  /** Timeout timestamp */
  timeout: uint256;
  
  /** Lock status */
  status: LockStatus;
  
  /** Source chain */
  sourceChain: uint256;
  
  /** Target chain */
  targetChain: uint256;
  
  /** Dispute deadline */
  disputeDeadline: uint256;
}

/**
 * Lock lifecycle status
 */
enum LockStatus {
  PENDING = 0,
  LOCKED = 1,
  UNLOCKED = 2,
  DISPUTED = 3,
  RESOLVED = 4,
  EXPIRED = 5
}
```

---

## Oracle & External Types

### Price Oracle Types

```typescript
/**
 * Price data with metadata
 */
interface PriceData {
  /** Asset identifier */
  asset: bytes32;
  
  /** Price value (scaled by decimals) */
  price: int256;
  
  /** Price decimals */
  decimals: uint8;
  
  /** Data source */
  source: OracleSource;
  
  /** Timestamp of price */
  timestamp: uint256;
  
  /** Round ID (Chainlink) */
  roundId: uint80;
}

/**
 * Oracle data sources
 */
enum OracleSource {
  CHAINLINK = 0,
  PYTH = 1,
  BAND = 2,
  DIA = 3,
  REDSTONE = 4,
  CUSTOM = 5
}
```

---

## Security Types

### Access Control Types

```typescript
/**
 * Role-based access configuration
 */
interface RoleConfig {
  /** Role identifier */
  roleId: bytes32;
  
  /** Admin role for this role */
  adminRole: bytes32;
  
  /** Description */
  description: string;
  
  /** Maximum members allowed */
  maxMembers: uint256;
  
  /** Current member count */
  memberCount: uint256;
}

/**
 * Time-locked operation
 */
interface TimelockOperation {
  /** Operation ID */
  operationId: bytes32;
  
  /** Target contract */
  target: address;
  
  /** Function selector */
  selector: bytes4;
  
  /** Encoded call data */
  data: bytes;
  
  /** ETH value */
  value: uint256;
  
  /** Ready timestamp */
  readyAt: uint256;
  
  /** Expiry timestamp */
  expiresAt: uint256;
  
  /** Confirmation count */
  confirmations: uint256;
  
  /** Execution status */
  executed: boolean;
}

/**
 * TEE attestation data
 */
interface TEEAttestation {
  /** Attestation ID */
  attestationId: bytes32;
  
  /** TEE platform */
  platform: TEEPlatform;
  
  /** Quote data */
  quote: bytes;
  
  /** Report data */
  reportData: bytes;
  
  /** Verification status */
  verified: boolean;
  
  /** Expiry timestamp */
  expiresAt: uint256;
}

/**
 * TEE platforms
 */
enum TEEPlatform {
  SGX_EPID = 0,
  SGX_DCAP = 1,
  TDX = 2,
  SEV_SNP = 3,
  TRUSTZONE = 4
}
```

---

## Event Types

### Core Events

```typescript
/**
 * State registration event
 */
event StateRegistered(
  bytes32 indexed stateId,
  bytes32 indexed commitment,
  address indexed registrar,
  uint256 timestamp
);

/**
 * Nullifier consumption event
 */
event NullifierConsumed(
  bytes32 indexed nullifier,
  bytes32 indexed domain,
  bytes32 stateId
);

/**
 * Cross-chain message event
 */
event CrossChainMessageSent(
  bytes32 indexed messageId,
  uint256 indexed destChain,
  bytes32 recipient,
  uint256 fee
);

/**
 * Proof verification event
 */
event ProofVerified(
  bytes32 indexed proofHash,
  ProofType proofType,
  address verifier,
  bool valid
);

/**
 * Bridge operation event
 */
event BridgeOperationCompleted(
  bytes32 indexed operationId,
  uint256 sourceChain,
  uint256 destChain,
  uint256 amount,
  MessageStatus status
);
```

---

## Type Aliases

```typescript
// Common type aliases used throughout PIL
type bytes32 = string;        // 32-byte hex string
type bytes = string;          // Variable length hex string
type address = string;        // 20-byte Ethereum address
type uint256 = bigint;        // 256-bit unsigned integer
type uint128 = bigint;        // 128-bit unsigned integer
type uint64 = bigint;         // 64-bit unsigned integer
type uint32 = number;         // 32-bit unsigned integer
type uint16 = number;         // 16-bit unsigned integer
type uint8 = number;          // 8-bit unsigned integer
type int256 = bigint;         // 256-bit signed integer
type bool = boolean;          // Boolean value
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01 | Initial type definitions |
| 1.1.0 | 2024-06 | Added PIL v2 primitives |
| 1.2.0 | 2024-09 | Added Bitcoin/BitVM types |
| 1.3.0 | 2025-01 | Added StarkNet types |
| 1.4.0 | 2026-01 | Added Solana, LayerZero, Chainlink types |

---

## License

MIT License - See [LICENSE](../LICENSE) for details.
