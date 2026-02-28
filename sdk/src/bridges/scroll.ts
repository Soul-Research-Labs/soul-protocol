/**
 * @fileoverview Scroll bridge utilities for Zaseon SDK
 * @module bridges/scroll
 */

import { keccak256, toBytes, encodePacked, type Address, type Hash, type Hex } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** Scroll mainnet chain ID */
export const SCROLL_CHAIN_ID = 534352;

/** Scroll Sepolia testnet chain ID */
export const SCROLL_SEPOLIA_CHAIN_ID = 534351;

/** ZK proof finality (blocks) */
export const FINALITY_BLOCKS = 1;

/** Default L2 gas limit */
export const DEFAULT_L2_GAS_LIMIT = 1_000_000n;

/** Fee denominator (basis points) */
export const FEE_DENOMINATOR = 10_000n;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus = 'PENDING' | 'SENT' | 'RELAYED' | 'FAILED';

export interface ScrollConfig {
  chainId: number;
  l1ScrollMessenger: Address;
  l1GatewayRouter: Address;
  scrollChain: Address;
  l1MessageQueue: Address;
}

export interface L1ToL2Message {
  messageHash: Hash;
  sender: Address;
  target: Address;
  value: bigint;
  nonce: bigint;
  data: Hex;
  gasLimit: bigint;
  status: MessageStatus;
  initiatedAt: number;
}

export interface L2ToL1Message {
  messageHash: Hash;
  sender: Address;
  target: Address;
  value: bigint;
  nonce: bigint;
  batchIndex: bigint;
  merkleProof: Hash[];
  status: MessageStatus;
  initiatedAt: number;
  claimedAt: number;
}

export interface BatchInfo {
  batchIndex: bigint;
  batchHash: Hash;
  stateRoot: Hash;
  withdrawRoot: Hash;
  timestamp: bigint;
  finalized: boolean;
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const SCROLL_MESSENGER_ABI = [
  {
    name: 'sendMessage',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      { name: '_to', type: 'address' },
      { name: '_value', type: 'uint256' },
      { name: '_message', type: 'bytes' },
      { name: '_gasLimit', type: 'uint256' },
    ],
    outputs: [],
  },
  {
    name: 'relayMessageWithProof',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: '_from', type: 'address' },
      { name: '_to', type: 'address' },
      { name: '_value', type: 'uint256' },
      { name: '_nonce', type: 'uint256' },
      { name: '_message', type: 'bytes' },
      {
        name: '_proof',
        type: 'tuple',
        components: [
          { name: 'batchIndex', type: 'uint256' },
          { name: 'merkleProof', type: 'bytes' },
        ],
      },
    ],
    outputs: [],
  },
  {
    name: 'xDomainMessageSender',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
] as const;

export const SCROLL_BRIDGE_ADAPTER_ABI = [
  {
    name: 'sendMessage',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      { name: 'target', type: 'address' },
      { name: 'data', type: 'bytes' },
      { name: 'gasLimit', type: 'uint256' },
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

/** Default Scroll mainnet config */
export const SCROLL_MAINNET_CONFIG: ScrollConfig = {
  chainId: SCROLL_CHAIN_ID,
  l1ScrollMessenger: '0x6774Bcbd5ceCeF1336b5300fb5186a12DDD8b367' as Address,
  l1GatewayRouter: '0xF8B1378579659D8F7EE5f3C929c2f3E332E41Fd6' as Address,
  scrollChain: '0xa13BAF47339d63B743e7Da8741db5456DAc1E556' as Address,
  l1MessageQueue: '0x0d7E906BD9cAFa154b048cFa766Cc1E54E39AF9B' as Address,
};

/** Default Scroll Sepolia config */
export const SCROLL_SEPOLIA_CONFIG: ScrollConfig = {
  chainId: SCROLL_SEPOLIA_CHAIN_ID,
  l1ScrollMessenger: '0x50c7d3e7f7c656493D1D76aaa1a836CedfCbb16A' as Address,
  l1GatewayRouter: '0x13FBE0D0e5552b8c9c4AE9e2435F38f37355998a' as Address,
  scrollChain: '0x2D567EcE699Eabe5afCd141eDB7A4f2D0163FB87' as Address,
  l1MessageQueue: '0xF0B2293F5D834eAe920c6974D50e0f10B2C0736b' as Address,
};

/**
 * Compute a message hash for tracking
 */
export function computeMessageHash(
  sender: Address,
  target: Address,
  value: bigint,
  nonce: bigint,
  data: Hex
): Hash {
  return keccak256(
    encodePacked(
      ['address', 'address', 'uint256', 'uint256', 'bytes'],
      [sender, target, value, nonce, data]
    )
  );
}

/**
 * Get default config for a chain ID
 */
export function getScrollConfig(chainId: number): ScrollConfig {
  switch (chainId) {
    case SCROLL_CHAIN_ID:
      return SCROLL_MAINNET_CONFIG;
    case SCROLL_SEPOLIA_CHAIN_ID:
      return SCROLL_SEPOLIA_CONFIG;
    default:
      throw new Error(`Unsupported Scroll chain ID: ${chainId}`);
  }
}
