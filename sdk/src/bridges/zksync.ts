/**
 * @fileoverview zkSync Era bridge utilities for Soul SDK
 * @module bridges/zksync
 */

import { keccak256, toBytes, encodePacked, type Address, type Hash, type Hex } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** zkSync Era mainnet chain ID */
export const ZKSYNC_ERA_CHAIN_ID = 324;

/** zkSync Era Sepolia testnet chain ID */
export const ZKSYNC_SEPOLIA_CHAIN_ID = 300;

/** Proof finality time (~1 hour) */
export const PROOF_FINALITY_SECONDS = 3600;

/** Default L2 gas limit */
export const DEFAULT_L2_GAS_LIMIT = 800_000n;

/** Default gas per pubdata byte limit */
export const DEFAULT_GAS_PER_PUBDATA = 800n;

/** Fee denominator (basis points) */
export const FEE_DENOMINATOR = 10_000n;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type TransferStatus = 'PENDING' | 'COMMITTED' | 'PROVED' | 'EXECUTED' | 'FAILED';

export interface ZkSyncConfig {
  chainId: number;
  diamondProxy: Address;
  l1ERC20Bridge: Address;
  l2SharedBridge: Address;
}

export interface L1ToL2Deposit {
  depositHash: Hash;
  sender: Address;
  l2Recipient: Address;
  l1Token: Address;
  amount: bigint;
  l2TxHash: Hash;
  l2GasLimit: bigint;
  gasPerPubdata: bigint;
  status: TransferStatus;
  chainId: number;
  initiatedAt: number;
}

export interface L2ToL1Withdrawal {
  withdrawalHash: Hash;
  l2Sender: Address;
  l1Recipient: Address;
  l2Token: Address;
  amount: bigint;
  batchNumber: bigint;
  messageIndex: bigint;
  l2TxHash: Hash;
  status: TransferStatus;
  initiatedAt: number;
  provedAt: number;
}

export interface L2LogProof {
  batchNumber: bigint;
  messageIndex: bigint;
  txNumberInBatch: number;
  merkleProof: Hash[];
}

export interface BatchInfo {
  batchNumber: bigint;
  timestamp: bigint;
  commitment: Hash;
  status: 'COMMITTED' | 'PROVED' | 'EXECUTED';
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const ZKSYNC_MAILBOX_ABI = [
  {
    name: 'requestL2Transaction',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      { name: '_contractL2', type: 'address' },
      { name: '_l2Value', type: 'uint256' },
      { name: '_calldata', type: 'bytes' },
      { name: '_l2GasLimit', type: 'uint256' },
      { name: '_l2GasPerPubdataByteLimit', type: 'uint256' },
      { name: '_factoryDeps', type: 'bytes[]' },
      { name: '_refundRecipient', type: 'address' },
    ],
    outputs: [{ name: 'canonicalTxHash', type: 'bytes32' }],
  },
  {
    name: 'l2TransactionBaseCost',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: '_gasPrice', type: 'uint256' },
      { name: '_l2GasLimit', type: 'uint256' },
      { name: '_l2GasPerPubdataByteLimit', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'proveL2LogInclusion',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: '_batchNumber', type: 'uint256' },
      { name: '_index', type: 'uint256' },
      {
        name: '_log',
        type: 'tuple',
        components: [
          { name: 'l2ShardId', type: 'uint8' },
          { name: 'isService', type: 'bool' },
          { name: 'txNumberInBatch', type: 'uint16' },
          { name: 'sender', type: 'address' },
          { name: 'key', type: 'bytes32' },
          { name: 'value', type: 'bytes32' },
        ],
      },
      { name: '_proof', type: 'bytes32[]' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
] as const;

export const ZKSYNC_BRIDGE_ADAPTER_ABI = [
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
    name: 'estimateL2TransactionCost',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'gasLimit', type: 'uint256' }],
    outputs: [{ name: 'baseCost', type: 'uint256' }],
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

/** Default zkSync Era mainnet config */
export const ZKSYNC_MAINNET_CONFIG: ZkSyncConfig = {
  chainId: ZKSYNC_ERA_CHAIN_ID,
  diamondProxy: '0x32400084C286CF3E17e7B677ea9583e60a000324' as Address,
  l1ERC20Bridge: '0x57891966931Eb4Bb6FB81430E6cE0A03AAbDe063' as Address,
  l2SharedBridge: '0x11f943b2c77b743AB90f4A0Ae7d5A4e7FCA3E102' as Address,
};

/** Default zkSync Era Sepolia config */
export const ZKSYNC_SEPOLIA_CONFIG: ZkSyncConfig = {
  chainId: ZKSYNC_SEPOLIA_CHAIN_ID,
  diamondProxy: '0x9A6DE0f62Aa270A8bCB8e98e44Da02dD96AA448b' as Address,
  l1ERC20Bridge: '0x0000000000000000000000000000000000000000' as Address,
  l2SharedBridge: '0x0000000000000000000000000000000000000000' as Address,
};

/**
 * Compute a deposit hash for tracking
 */
export function computeDepositHash(
  sender: Address,
  l2Recipient: Address,
  l1Token: Address,
  amount: bigint,
  nonce: bigint
): Hash {
  return keccak256(
    encodePacked(
      ['address', 'address', 'address', 'uint256', 'uint256'],
      [sender, l2Recipient, l1Token, amount, nonce]
    )
  );
}

/**
 * Get default config for a chain ID
 */
export function getZkSyncConfig(chainId: number): ZkSyncConfig {
  switch (chainId) {
    case ZKSYNC_ERA_CHAIN_ID:
      return ZKSYNC_MAINNET_CONFIG;
    case ZKSYNC_SEPOLIA_CHAIN_ID:
      return ZKSYNC_SEPOLIA_CONFIG;
    default:
      throw new Error(`Unsupported zkSync chain ID: ${chainId}`);
  }
}

/**
 * Estimate L1 -> L2 transaction base cost
 */
export function estimateL1ToL2BaseCost(
  l1GasPrice: bigint,
  l2GasLimit: bigint = DEFAULT_L2_GAS_LIMIT,
  gasPerPubdata: bigint = DEFAULT_GAS_PER_PUBDATA
): bigint {
  // Simplified estimation: baseCost = l2GasLimit * l1GasPrice + overhead
  return l2GasLimit * l1GasPrice + gasPerPubdata * 100n;
}
