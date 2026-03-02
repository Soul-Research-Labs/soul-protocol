/**
 * @module bitcoin
 * @description Bitcoin bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Bitcoin is the first and largest cryptocurrency network, using a UTXO model
 * with Proof-of-Work (SHA-256d) consensus. Cross-chain messaging to Bitcoin
 * requires SPV proofs, BitVM fraud proofs, or federation attestations.
 *
 * Network characteristics:
 * - UTXO model: unspent transaction outputs, no account state
 * - PoW consensus: SHA-256d mining, ~10 minute block time
 * - Script: Bitcoin Script (non-Turing-complete) for spending conditions
 * - Taproot (BIP 341): Schnorr signatures + MAST for complex scripts
 * - SegWit: segregated witness for transaction malleability fix
 * - SPV proofs: Merkle inclusion proofs against block headers
 * - 6 confirmations (~60 min) for standard finality
 * - Inscriptions/Ordinals: data embedding via witness space
 * - OP_RETURN: 80-byte data output for message anchoring
 * - ~18,000 reachable nodes worldwide
 *
 * ZASEON integration uses:
 * - SPV proof verification via Bitcoin header relay (trustless)
 * - Optional BitVM fraud-proof based bridging (1-of-N honest)
 * - Federation attestation for faster bridging
 * - Nullifier-based replay protection via ZASEON's CDNA
 *
 * See also: BitVMBridgeAdapter in contracts/adapters/ for full
 * deposit/withdrawal/challenge BitVM implementation.
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Bitcoin (mirrors Solidity constant) */
export const BITCOIN_CHAIN_ID = 19_100;

/** Default confirmation depth (6 blocks ≈ 60 min) */
export const DEFAULT_CONFIRMATIONS = 6;

/** Bitcoin block time ~10 minutes */
export const BITCOIN_BLOCK_TIME_MS = 600_000;

/** Bridge type identifier */
export const BITCOIN_BRIDGE_TYPE = "SPV-PoW" as const;

/** Minimum SPV proof length */
export const MIN_SPV_PROOF_LENGTH = 80;

// ─── Types ─────────────────────────────────────────────────────────

export interface BitcoinBridgeConfig {
  /** Bitcoin bridge relay contract address on Ethereum */
  bitcoinBridge: string;
  /** Admin address */
  admin: string;
  /** Optional Bitcoin block header relay address */
  bitcoinRelay?: string;
}

export interface BitcoinSendParams {
  /** 32-byte Bitcoin address hash (P2PKH/P2SH/P2WPKH/P2TR) */
  btcDestination: string;
  /** Payload bytes */
  payload: string;
  /** Value to send (in wei) */
  value: bigint;
}

export interface BitcoinReceiveParams {
  /** Bitcoin transaction hash (double SHA-256, LE) */
  btcTxHash: string;
  /** Bitcoin block height containing the transaction */
  blockHeight: bigint;
  /** Message payload (from OP_RETURN or Taproot commitment) */
  payload: string;
  /** SPV Merkle inclusion proof */
  spvProof: string;
}

export interface BitcoinMessageEvent {
  messageHash: string;
  btcDestination: string;
  sender: string;
  nonce: bigint;
  fee: bigint;
}

// ─── ABI ───────────────────────────────────────────────────────────

export const BITCOIN_BRIDGE_ADAPTER_ABI = [
  // Constructor
  "constructor(address _bitcoinBridge, address _bitcoinRelay, address _admin)",

  // Send
  "function sendMessage(bytes32 btcDestination, bytes payload) payable returns (bytes32 messageHash)",

  // Receive
  "function receiveMessage(bytes32 btcTxHash, uint256 blockHeight, bytes payload, bytes spvProof) returns (bytes32 messageHash)",

  // IBridgeAdapter
  "function bridgeMessage(address targetAddress, bytes payload, address refundAddress) payable returns (bytes32 messageId)",
  "function estimateFee(address targetAddress, bytes payload) view returns (uint256 nativeFee)",
  "function isMessageVerified(bytes32 messageId) view returns (bool verified)",

  // Views
  "function bridgeType() pure returns (string)",
  "function chainId() pure returns (uint256)",
  "function isNullifierUsed(bytes32 nullifier) view returns (bool)",
  "function isBtcTxProcessed(bytes32 txHash) view returns (bool)",
  "function isAddressWhitelisted(bytes32 addr) view returns (bool)",
  "function totalMessagesSent() view returns (uint256)",
  "function totalMessagesReceived() view returns (uint256)",
  "function totalValueBridged() view returns (uint256)",
  "function accumulatedFees() view returns (uint256)",
  "function senderNonces(address) view returns (uint256)",
  "function bridgeFeeBps() view returns (uint256)",
  "function minMessageFee() view returns (uint256)",
  "function requiredConfirmations() view returns (uint256)",

  // Constants
  "function BITCOIN_CHAIN_ID() view returns (uint256)",
  "function MAX_PAYLOAD_LENGTH() view returns (uint256)",
  "function MAX_BRIDGE_FEE_BPS() view returns (uint256)",
  "function DEFAULT_CONFIRMATIONS() view returns (uint256)",
  "function MIN_SPV_PROOF_LENGTH() view returns (uint256)",

  // Admin
  "function setBitcoinBridge(address _bridge)",
  "function setBitcoinRelay(address _relay)",
  "function whitelistAddress(bytes32 btcAddress, bool enabled)",
  "function setRequiredConfirmations(uint256 depth)",
  "function setBridgeFee(uint256 feeBps)",
  "function setMinMessageFee(uint256 fee)",

  // Emergency
  "function pause()",
  "function unpause()",
  "function withdrawFees(address to)",
  "function emergencyWithdrawETH(address to, uint256 amount)",
  "function emergencyWithdrawERC20(address token, address to)",

  // Events
  "event MessageSentToBitcoin(bytes32 indexed messageHash, bytes32 indexed btcDestination, address sender, uint256 nonce, uint256 fee)",
  "event MessageReceivedFromBitcoin(bytes32 indexed messageHash, bytes32 indexed btcTxHash, uint256 blockHeight, address indexed recipient, uint256 nonce)",
  "event BitcoinBridgeUpdated(address indexed oldBridge, address indexed newBridge)",
  "event BitcoinRelayUpdated(address indexed oldRelay, address indexed newRelay)",
  "event AddressWhitelisted(bytes32 indexed btcAddress, bool whitelisted)",
  "event ConfirmationsUpdated(uint256 oldDepth, uint256 newDepth)",
  "event BridgeFeeUpdated(uint256 oldFee, uint256 newFee)",
  "event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee)",
  "event FeesWithdrawn(address indexed to, uint256 amount)",
] as const;

export type BitcoinBridgeAdapterABI = typeof BITCOIN_BRIDGE_ADAPTER_ABI;
