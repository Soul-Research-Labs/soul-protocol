/**
 * Zaseon SDK — Secret Network Bridge Adapter
 *
 * Secret Network is a privacy-first independent L1 blockchain built on
 * Cosmos SDK / Tendermint BFT with Intel SGX TEE-based encrypted
 * computation ("Secret Contracts"). This module provides constants,
 * types, and utilities for interacting with the SecretBridgeAdapter contract.
 *
 * Key Characteristics:
 * - Independent L1 (Cosmos SDK + Tendermint BFT consensus)
 * - Privacy model: Intel SGX TEE-encrypted state & computation
 * - Smart contracts: CosmWasm "Secret Contracts" with encrypted inputs/state
 * - Cross-chain: IBC (Cosmos) + Secret–Ethereum Gateway (EVM bridge)
 * - Native token: SCRT
 *
 * ZASEON virtual chain ID: 5100 (internal identifier, not an EVM chain ID)
 */

// ─── Constants ────────────────────────────────────────────────────────

/** ZASEON-internal chain ID for Secret Network (not an EVM chain ID) */
export const SECRET_CHAIN_ID = 5100;

/** Finality blocks — Tendermint instant finality */
export const SECRET_FINALITY_BLOCKS = 1;

/** Minimum TEE attestation size in bytes */
export const MIN_ATTESTATION_SIZE = 64;

/** Max bridge fee in basis points (1% = 100) */
export const MAX_BRIDGE_FEE_BPS = 100;

/** Max payload length in bytes */
export const MAX_PAYLOAD_LENGTH = 10_000;

/** Secret Network privacy model identifier */
export const SECRET_PRIVACY_MODEL = "TEE-SGX";

/**
 * Secret Network Cosmos chain ID (mainnet).
 * Used for IBC routing and Secret–Ethereum Gateway identification.
 */
export const SECRET_COSMOS_CHAIN_ID = "secret-4";

// ─── Types ────────────────────────────────────────────────────────────

/** Configuration for the Secret Network bridge adapter */
export interface SecretConfig {
  /** SecretBridgeAdapter contract address (on EVM host chain) */
  adapterAddress: string;
  /** Secret–Ethereum Gateway contract address (on EVM host chain) */
  gatewayAddress: string;
  /** Secret TEE Attestation Verifier contract address */
  verifierAddress: string;
  /** EVM chain ID where the adapter is deployed (e.g. 1 for mainnet) */
  hostChainId: number;
}

/** Secret Network message metadata */
export interface SecretMessage {
  /** Internal message hash */
  messageHash: string;
  /** Gateway task ID */
  taskId: string;
  /** Validator set hash at time of message */
  validatorSetHash: string;
  /** Nullifier (for replay protection) */
  nullifier?: string;
  /** Message status: PENDING | SENT | DELIVERED | FAILED */
  status: number;
  /** Timestamp (Unix seconds) */
  timestamp: number;
}

/** TEE attestation for Secret Network message verification */
export interface SecretAttestation {
  /** Serialized attestation bytes (hex) */
  attestation: string;
  /** Public inputs: [validatorSetHash, nullifier, taskId, payloadHash] */
  publicInputs: bigint[];
  /** ZASEON payload (hex) */
  payload: string;
}

/** Secret Network routing information */
export interface SecretRoutingInfo {
  /** Secret contract address (bech32, e.g. secret1xxx...) */
  contractAddress: string;
  /** Contract code hash (hex) */
  codeHash: string;
}

// ─── ABI ──────────────────────────────────────────────────────────────

/**
 * Minimal ABI for SecretBridgeAdapter (covers public interface).
 * Mirrors the Solidity contract's external functions.
 */
export const SECRET_BRIDGE_ADAPTER_ABI = [
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "routingInfo", type: "bytes" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
  {
    name: "receiveMessage",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "attestation", type: "bytes" },
      { name: "publicInputs", type: "uint256[]" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
  {
    name: "bridgeMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "targetAddress", type: "address" },
      { name: "payload", type: "bytes" },
      { name: "refundAddress", type: "address" },
    ],
    outputs: [{ name: "messageId", type: "bytes32" }],
  },
  {
    name: "estimateFee",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "targetAddress", type: "address" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "nativeFee", type: "uint256" }],
  },
  {
    name: "isMessageVerified",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "messageId", type: "bytes32" }],
    outputs: [{ name: "verified", type: "bool" }],
  },
  {
    name: "chainId",
    type: "function",
    stateMutability: "pure",
    inputs: [],
    outputs: [{ name: "", type: "uint16" }],
  },
  {
    name: "chainName",
    type: "function",
    stateMutability: "pure",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
  },
  {
    name: "isConfigured",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "getFinalityBlocks",
    type: "function",
    stateMutability: "pure",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "getValidatorSetHash",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "secretGateway",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "secretVerifier",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "totalMessagesSent",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalMessagesReceived",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalValueBridged",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "usedNullifiers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "accumulatedFees",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

// ─── Utilities ────────────────────────────────────────────────────────

/**
 * Get the ZASEON universal chain ID for Secret Network.
 * Secret Network does not have an EVM chain ID; it uses the ZASEON-internal 5100.
 */
export function getUniversalChainId(): number {
  return SECRET_CHAIN_ID;
}

/**
 * Get the Secret Network nullifier tag for ZASEON nullifier domains.
 * Matches SECRET_TEE = 3 in NullifierClient.ts.
 */
export function getSecretNullifierTag(): string {
  return "SECRET";
}

/**
 * Estimate total fee for a Secret Network bridge message (protocol fee + min fee).
 * @param value - The message value in wei
 * @param bridgeFeeBps - Bridge fee in basis points (0-100)
 * @param minFee - Minimum message fee in wei
 */
export function estimateTotalFee(
  value: bigint,
  bridgeFeeBps: number = 0,
  minFee: bigint = 0n,
): bigint {
  const protocolFee =
    bridgeFeeBps > 0 ? (value * BigInt(bridgeFeeBps)) / 10_000n : 0n;
  return protocolFee + minFee;
}

/**
 * Encode a ZASEON payload for Secret Network messaging.
 * Wraps arbitrary data in the standard ZASEON cross-chain envelope.
 */
export function encodeZaseonPayload(
  sourceChainId: number,
  targetContract: string,
  data: Uint8Array,
): Uint8Array {
  const header = new Uint8Array(8);
  const view = new DataView(header.buffer);
  view.setUint32(0, sourceChainId, false);
  view.setUint32(4, SECRET_CHAIN_ID, false);

  const contractBytes = new TextEncoder().encode(targetContract);
  const result = new Uint8Array(
    header.length + contractBytes.length + data.length,
  );
  result.set(header, 0);
  result.set(contractBytes, header.length);
  result.set(data, header.length + contractBytes.length);
  return result;
}

/**
 * Check if Secret–Ethereum Gateway is deployed on a given chain.
 * The Gateway currently exists on Ethereum mainnet.
 */
export function isSecretDeployed(hostChainId: number): boolean {
  // Secret–Ethereum Gateway is deployed on Ethereum mainnet
  return hostChainId === 1;
}
