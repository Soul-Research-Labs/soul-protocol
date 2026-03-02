/**
 * @module aleo
 * @description Aleo bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Aleo is a privacy-preserving blockchain that executes all programs inside a
 * zero-knowledge proof system (snarkVM). Every transaction produces a SNARK
 * proof verifying correct execution without revealing inputs or outputs.
 *
 * Network characteristics:
 * - snarkVM: ZK-native virtual machine executing Leo/Aleo instructions
 * - Records: encrypted UTXO-like state objects owned by addresses
 * - Programs: on-chain programs written in Leo (Rust-like ZK language)
 * - Transitions: state changes with inputs consumed + outputs created
 * - AleoBFT: DAG-based BFT consensus (Narwhal-Bullshark variant)
 * - Coinbase proof: proof-of-succinct-work for block production
 * - Credits: native token (1 credit = 1,000,000 microcredits)
 * - Addresses: Bech32m-encoded (aleo1...) derived from private keys
 * - Committee: ~200 validators, stake-weighted
 * - Block time: ~10 seconds
 * - Proofs: Marlin universal-setup SNARKs (constant verification time)
 *
 * ZASEON integration uses:
 * - Relay contract for Ethereum ↔ Aleo message passing
 * - Optional light client for committee certificate verification
 * - SNARK proof verification for state transition attestation
 * - Program ID whitelisting for authorized Aleo programs
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Aleo (mirrors Solidity constant) */
export const ALEO_CHAIN_ID = 17_100;

/** Minimum committee quorum in BPS (66.67%) */
export const COMMITTEE_QUORUM_BPS = 6_667;

/** Block time ~10 seconds */
export const ALEO_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const ALEO_BRIDGE_TYPE = "AleoRelay-AleoBFT" as const;

/** Minimum SNARK proof length */
export const MIN_PROOF_LENGTH = 64;

// ─── Types ─────────────────────────────────────────────────────────

export interface AleoBridgeConfig {
  /** Aleo relay contract address on Ethereum */
  aleoRelay: string;
  /** Admin address */
  admin: string;
  /** Optional Aleo Light Client address */
  aleoLightClient?: string;
}

export interface AleoSendParams {
  /** Target Aleo program ID (bytes32-encoded) */
  programId: string;
  /** Aleo function name to invoke (bytes32-encoded) */
  functionName: string;
  /** Payload bytes */
  payload: string;
  /** Value to send (in wei) */
  value: bigint;
}

export interface AleoReceiveParams {
  /** Source Aleo program ID */
  programId: string;
  /** Aleo network identifier (0 = mainnet) */
  networkId: number;
  /** Message payload */
  payload: string;
  /** Committee certificate or SNARK proof */
  proof: string;
}

export interface AleoMessageEvent {
  messageHash: string;
  programId: string;
  functionName: string;
  sender: string;
  nonce: bigint;
  fee: bigint;
}

// ─── ABI ───────────────────────────────────────────────────────────

export const ALEO_BRIDGE_ADAPTER_ABI = [
  // Constructor
  "constructor(address _aleoRelay, address _admin)",

  // Send
  "function sendMessage(bytes32 programId, bytes32 functionName, bytes payload) payable returns (bytes32 messageHash)",

  // Receive
  "function receiveMessage(bytes32 programId, uint8 networkId, bytes payload, bytes proof) returns (bytes32 messageHash)",

  // IBridgeAdapter
  "function bridgeMessage(address targetAddress, bytes payload, address refundAddress) payable returns (bytes32 messageId)",
  "function estimateFee(address targetAddress, bytes payload) view returns (uint256 nativeFee)",
  "function isMessageVerified(bytes32 messageId) view returns (bool verified)",

  // Views
  "function bridgeType() pure returns (string)",
  "function chainId() pure returns (uint256)",
  "function isNullifierUsed(bytes32 nullifier) view returns (bool)",
  "function isProgramWhitelisted(bytes32 programId) view returns (bool)",
  "function verifyStateProof(bytes32 stateRoot, bytes proof) view returns (bool)",
  "function totalMessagesSent() view returns (uint256)",
  "function totalMessagesReceived() view returns (uint256)",
  "function totalValueBridged() view returns (uint256)",
  "function accumulatedFees() view returns (uint256)",
  "function senderNonces(address) view returns (uint256)",
  "function bridgeFeeBps() view returns (uint256)",
  "function minMessageFee() view returns (uint256)",

  // Constants
  "function ALEO_CHAIN_ID() view returns (uint256)",
  "function MAX_PAYLOAD_LENGTH() view returns (uint256)",
  "function MAX_BRIDGE_FEE_BPS() view returns (uint256)",
  "function COMMITTEE_QUORUM_BPS() view returns (uint256)",
  "function MIN_PROOF_LENGTH() view returns (uint256)",

  // Admin
  "function setAleoRelay(address _relay)",
  "function setAleoLightClient(address _client)",
  "function whitelistProgram(bytes32 programId, bool enabled)",
  "function setAleoBridgeProgram(bytes32 programId)",
  "function setSupportedNetwork(uint8 networkId, bool supported)",
  "function setBridgeFee(uint256 feeBps)",
  "function setMinMessageFee(uint256 fee)",

  // Emergency
  "function pause()",
  "function unpause()",
  "function withdrawFees(address to)",
  "function emergencyWithdrawETH(address to, uint256 amount)",
  "function emergencyWithdrawERC20(address token, address to)",

  // Events
  "event MessageSentToAleo(bytes32 indexed messageHash, bytes32 indexed programId, bytes32 functionName, address sender, uint256 nonce, uint256 fee)",
  "event MessageReceivedFromAleo(bytes32 indexed messageHash, bytes32 indexed programId, address indexed recipient, uint256 nonce)",
  "event AleoRelayUpdated(address indexed oldRelay, address indexed newRelay)",
  "event AleoLightClientUpdated(address indexed oldClient, address indexed newClient)",
  "event ProgramWhitelisted(bytes32 indexed programId, bool whitelisted)",
  "event AleoBridgeProgramSet(bytes32 indexed programId)",
  "event NetworkSupportUpdated(uint8 networkId, bool supported)",
  "event BridgeFeeUpdated(uint256 oldFee, uint256 newFee)",
  "event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee)",
  "event FeesWithdrawn(address indexed to, uint256 amount)",
] as const;

export type AleoBridgeAdapterABI = typeof ALEO_BRIDGE_ADAPTER_ABI;
