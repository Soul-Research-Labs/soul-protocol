/**
 * @module xrpl
 * @description XRPL bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * The XRP Ledger is a decentralized, public blockchain built for payments and
 * tokenization. It uses a unique Federated Byzantine Agreement (FBA) consensus
 * protocol that achieves finality in 3-5 seconds without mining or staking.
 *
 * Network characteristics:
 * - XRPL Consensus (FBA): validators vote in rounds, ≥80% UNL agreement
 * - UNL (Unique Node List): per-node trusted validator set
 * - Ledger snapshots every 3-5 seconds (not traditional blocks)
 * - Classic addresses: r-prefixed (e.g. rN7n3...) from Ed25519/secp256k1
 * - Destination tags: 32-bit integers for address demultiplexing
 * - SHAMap: Merkle tree variant for state objects
 * - Hooks: WASM-based smart contracts (limited functionality)
 * - Amendments: on-chain governance for protocol upgrades
 * - Reserves: 10 XRP account reserve + owner reserve per object
 * - Drops: smallest unit (1 XRP = 1,000,000 drops)
 * - ~150+ validators on mainnet
 *
 * ZASEON integration uses:
 * - Witness-attested bridge (multi-sign attestation model)
 * - Optional light client for ledger header verification
 * - SHAMap proof verification for state attestation
 * - Account whitelisting for authorized XRPL destinations
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for XRPL (mirrors Solidity constant) */
export const XRPL_CHAIN_ID = 18_100;

/** Attestation threshold in BPS (80% matching XRPL consensus) */
export const ATTESTATION_THRESHOLD_BPS = 8_000;

/** Ledger close time ~3-5 seconds */
export const XRPL_FINALITY_LEDGERS = 1;

/** Bridge type identifier */
export const XRPL_BRIDGE_TYPE = "WitnessAttestation-FBA" as const;

/** Minimum attestation length for multi-sign */
export const MIN_ATTESTATION_LENGTH = 64;

// ─── Types ─────────────────────────────────────────────────────────

export interface XRPLBridgeConfig {
  /** XRPL bridge relay contract address on Ethereum */
  xrplBridge: string;
  /** Admin address */
  admin: string;
  /** Optional XRPL Light Client address */
  xrplLightClient?: string;
}

export interface XRPLSendParams {
  /** 20-byte XRPL classic address */
  xrplDestination: string;
  /** XRPL destination tag */
  destinationTag: number;
  /** Payload bytes */
  payload: string;
  /** Value to send (in wei) */
  value: bigint;
}

export interface XRPLReceiveParams {
  /** Source XRPL account (20-byte classic address) */
  xrplSource: string;
  /** XRPL ledger sequence number */
  ledgerIndex: bigint;
  /** Message payload */
  payload: string;
  /** Multi-sign witness attestation or ledger proof */
  attestation: string;
}

export interface XRPLMessageEvent {
  messageHash: string;
  xrplDestination: string;
  destinationTag: number;
  sender: string;
  nonce: bigint;
  fee: bigint;
}

// ─── ABI ───────────────────────────────────────────────────────────

export const XRPL_BRIDGE_ADAPTER_ABI = [
  // Constructor
  "constructor(address _xrplBridge, address _admin)",

  // Send
  "function sendMessage(bytes20 xrplDestination, uint32 destinationTag, bytes payload) payable returns (bytes32 messageHash)",

  // Receive
  "function receiveMessage(bytes20 xrplSource, uint64 ledgerIndex, bytes payload, bytes attestation) returns (bytes32 messageHash)",

  // IBridgeAdapter
  "function bridgeMessage(address targetAddress, bytes payload, address refundAddress) payable returns (bytes32 messageId)",
  "function estimateFee(address targetAddress, bytes payload) view returns (uint256 nativeFee)",
  "function isMessageVerified(bytes32 messageId) view returns (bool verified)",

  // Views
  "function bridgeType() pure returns (string)",
  "function chainId() pure returns (uint256)",
  "function isNullifierUsed(bytes32 nullifier) view returns (bool)",
  "function isAccountWhitelisted(bytes20 account) view returns (bool)",
  "function verifyLedgerProof(bytes32 ledgerHash, bytes proof) view returns (bool)",
  "function totalMessagesSent() view returns (uint256)",
  "function totalMessagesReceived() view returns (uint256)",
  "function totalValueBridged() view returns (uint256)",
  "function accumulatedFees() view returns (uint256)",
  "function senderNonces(address) view returns (uint256)",
  "function bridgeFeeBps() view returns (uint256)",
  "function minMessageFee() view returns (uint256)",
  "function defaultDestinationTag() view returns (uint32)",

  // Constants
  "function XRPL_CHAIN_ID() view returns (uint256)",
  "function MAX_PAYLOAD_LENGTH() view returns (uint256)",
  "function MAX_BRIDGE_FEE_BPS() view returns (uint256)",
  "function ATTESTATION_THRESHOLD_BPS() view returns (uint256)",
  "function MIN_ATTESTATION_LENGTH() view returns (uint256)",

  // Admin
  "function setXRPLBridge(address _bridge)",
  "function setXRPLLightClient(address _client)",
  "function whitelistAccount(bytes20 account, bool enabled)",
  "function setDefaultDestinationTag(uint32 tag)",
  "function setBridgeFee(uint256 feeBps)",
  "function setMinMessageFee(uint256 fee)",

  // Emergency
  "function pause()",
  "function unpause()",
  "function withdrawFees(address to)",
  "function emergencyWithdrawETH(address to, uint256 amount)",
  "function emergencyWithdrawERC20(address token, address to)",

  // Events
  "event MessageSentToXRPL(bytes32 indexed messageHash, bytes20 indexed xrplDestination, uint32 destinationTag, address sender, uint256 nonce, uint256 fee)",
  "event MessageReceivedFromXRPL(bytes32 indexed messageHash, bytes20 indexed xrplSource, address indexed recipient, uint256 ledgerIndex)",
  "event XRPLBridgeUpdated(address indexed oldBridge, address indexed newBridge)",
  "event XRPLLightClientUpdated(address indexed oldClient, address indexed newClient)",
  "event AccountWhitelisted(bytes20 indexed account, bool whitelisted)",
  "event DefaultDestinationTagUpdated(uint32 oldTag, uint32 newTag)",
  "event BridgeFeeUpdated(uint256 oldFee, uint256 newFee)",
  "event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee)",
  "event FeesWithdrawn(address indexed to, uint256 amount)",
] as const;

export type XRPLBridgeAdapterABI = typeof XRPL_BRIDGE_ADAPTER_ABI;
