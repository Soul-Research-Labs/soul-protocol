/**
 * @fileoverview Linea bridge utilities for Zaseon SDK
 * @module bridges/linea
 */

import { keccak256, toBytes, encodePacked, type Address, type Hash, type Hex } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** Linea mainnet chain ID */
export const LINEA_CHAIN_ID = 59144;

/** Linea Sepolia testnet chain ID */
export const LINEA_SEPOLIA_CHAIN_ID = 59141;

/** Proof finality seconds (~8-32 hours) */
export const PROOF_FINALITY_SECONDS = 28800;

/** Default message fee */
export const DEFAULT_MESSAGE_FEE = 1_000_000_000_000_000n; // 0.001 ETH

/** Fee denominator (basis points) */
export const FEE_DENOMINATOR = 10_000n;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus = 'PENDING' | 'SENT' | 'CLAIMED' | 'FAILED';

export interface LineaConfig {
  chainId: number;
  messageService: Address;
  tokenBridge: Address;
  rollup: Address;
}

export interface L1ToL2Message {
  messageHash: Hash;
  sender: Address;
  target: Address;
  fee: bigint;
  value: bigint;
  nonce: bigint;
  data: Hex;
  status: MessageStatus;
  initiatedAt: number;
}

export interface L2ToL1Message {
  messageHash: Hash;
  sender: Address;
  target: Address;
  value: bigint;
  messageNumber: bigint;
  merkleProof: Hash[];
  leafIndex: bigint;
  status: MessageStatus;
  initiatedAt: number;
  claimedAt: number;
}

export interface ClaimProof {
  messageNumber: bigint;
  leafIndex: bigint;
  merkleProof: Hash[];
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const LINEA_MESSAGE_SERVICE_ABI = [
  {
    name: 'sendMessage',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      { name: '_to', type: 'address' },
      { name: '_fee', type: 'uint256' },
      { name: '_calldata', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    name: 'claimMessage',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: '_from', type: 'address' },
      { name: '_to', type: 'address' },
      { name: '_fee', type: 'uint256' },
      { name: '_value', type: 'uint256' },
      { name: '_feeRecipient', type: 'address' },
      { name: '_calldata', type: 'bytes' },
      { name: '_nonce', type: 'uint256' },
    ],
    outputs: [],
  },
  {
    name: 'sender',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
] as const;

export const LINEA_BRIDGE_ADAPTER_ABI = [
  {
    name: 'sendMessage',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      { name: 'target', type: 'address' },
      { name: 'data', type: 'bytes' },
      { name: 'messageFee', type: 'uint256' },
    ],
    outputs: [{ name: 'messageHash', type: 'bytes32' }],
  },
  {
    name: 'verifyMessage',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'messageHash', type: 'bytes32' },
      { name: 'proof', type: 'bytes' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    name: 'getLastFinalizedBlock',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'isConfigured',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    name: 'chainId',
    type: 'function',
    stateMutability: 'pure',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'chainName',
    type: 'function',
    stateMutability: 'pure',
    inputs: [],
    outputs: [{ name: '', type: 'string' }],
  },
] as const;

/*//////////////////////////////////////////////////////////////
                          UTILITIES
//////////////////////////////////////////////////////////////*/

/** Default Linea mainnet config */
export const LINEA_MAINNET_CONFIG: LineaConfig = {
  chainId: LINEA_CHAIN_ID,
  messageService: '0xd19d4B5d358258f05D7B411E21A1460D11B0876F' as Address,
  tokenBridge: '0x051F1D88f0aF5763fB888eC4378b4D8B29ea3319' as Address,
  rollup: '0xd19d4B5d358258f05D7B411E21A1460D11B0876F' as Address,
};

/** Default Linea Sepolia config */
export const LINEA_SEPOLIA_CONFIG: LineaConfig = {
  chainId: LINEA_SEPOLIA_CHAIN_ID,
  messageService: '0x971e727e956690b9957be6d51Ec16E73AcAC83A7' as Address,
  tokenBridge: '0x0000000000000000000000000000000000000000' as Address,
  rollup: '0x0000000000000000000000000000000000000000' as Address,
};

/**
 * Compute a message hash for tracking
 */
export function computeMessageHash(
  sender: Address,
  target: Address,
  fee: bigint,
  value: bigint,
  nonce: bigint,
  data: Hex
): Hash {
  return keccak256(
    encodePacked(
      ['address', 'address', 'uint256', 'uint256', 'uint256', 'bytes'],
      [sender, target, fee, value, nonce, data]
    )
  );
}

/**
 * Get default config for a chain ID
 */
export function getLineaConfig(chainId: number): LineaConfig {
  switch (chainId) {
    case LINEA_CHAIN_ID:
      return LINEA_MAINNET_CONFIG;
    case LINEA_SEPOLIA_CHAIN_ID:
      return LINEA_SEPOLIA_CONFIG;
    default:
      throw new Error(`Unsupported Linea chain ID: ${chainId}`);
  }
}
