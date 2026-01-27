/**
 * @fileoverview Bitcoin bridge utilities for PIL SDK
 * @module bridges/bitcoin
 */

import { keccak256, toBytes, toHex, type Address, type Hash } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** Bitcoin mainnet chain ID (virtual) */
export const BTC_MAINNET_CHAIN_ID = 0x426974636F696E;

/** Bitcoin testnet chain ID (virtual) */
export const BTC_TESTNET_CHAIN_ID = 0x5465737442544;

/** Satoshis per BTC */
export const SATOSHIS_PER_BTC = 100_000_000n;

/** Minimum deposit in satoshis */
export const MIN_DEPOSIT_SATOSHIS = 100_000n;

/** Maximum deposit in satoshis */
export const MAX_DEPOSIT_SATOSHIS = 10_000_000_000n;

/** Default HTLC timelock (24 hours) */
export const DEFAULT_HTLC_TIMELOCK = 86400;

/** Required confirmations */
export const REQUIRED_CONFIRMATIONS = 6;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type BTCNetwork = 'mainnet' | 'testnet' | 'regtest';

export interface BTCDeposit {
  depositId: Hash;
  btcTxId: Hash;
  satoshis: bigint;
  netAmount: bigint;
  fee: bigint;
  ethRecipient: Address;
  status: 'pending' | 'completed' | 'failed';
  initiatedAt: number;
  completedAt?: number;
}

export interface BTCWithdrawal {
  withdrawalId: Hash;
  ethSender: Address;
  btcRecipientPubKeyHash: `0x${string}`;
  satoshis: bigint;
  hashlock: Hash;
  timelock: number;
  preimage?: Hash;
  btcTxId?: Hash;
  status: 'pending' | 'completed' | 'refunded' | 'failed';
  initiatedAt: number;
  completedAt?: number;
}

export interface HTLC {
  htlcId: Hash;
  sender: Address;
  recipient: Address;
  amount: bigint;
  hashlock: Hash;
  timelock: number;
  preimage?: Hash;
  status: 'active' | 'redeemed' | 'refunded';
  createdAt: number;
  completedAt?: number;
}

export interface BTCBlockHeader {
  blockHash: Hash;
  prevBlockHash: Hash;
  merkleRoot: Hash;
  timestamp: number;
  height: number;
  verified: boolean;
}

export interface SPVProof {
  txId: Hash;
  txRaw: `0x${string}`;
  merkleProof: Hash[];
  txIndex: number;
  blockHeader: `0x${string}`;
  blockHeight: number;
}

/*//////////////////////////////////////////////////////////////
                          UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

/**
 * Convert BTC to satoshis
 */
export function btcToSatoshis(btc: number): bigint {
  return BigInt(Math.floor(btc * Number(SATOSHIS_PER_BTC)));
}

/**
 * Convert satoshis to BTC
 */
export function satoshisToBtc(satoshis: bigint): number {
  return Number(satoshis) / Number(SATOSHIS_PER_BTC);
}

/**
 * Generate a random preimage for HTLC
 */
export function generatePreimage(): Hash {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  return toHex(randomBytes) as Hash;
}

/**
 * Compute hashlock from preimage
 */
export function computeHashlock(preimage: Hash): Hash {
  return keccak256(toBytes(preimage));
}

/**
 * Validate Bitcoin transaction ID format
 */
export function isValidBtcTxId(txId: string): boolean {
  return /^[a-fA-F0-9]{64}$/.test(txId.replace('0x', ''));
}

/**
 * Convert Bitcoin txid to bytes32 (reverse byte order)
 */
export function btcTxIdToBytes32(txId: string): Hash {
  const cleanTxId = txId.replace('0x', '');
  if (!isValidBtcTxId(cleanTxId)) {
    throw new Error('Invalid Bitcoin transaction ID');
  }
  
  // Reverse byte order (Bitcoin uses little-endian)
  const reversed = cleanTxId
    .match(/.{2}/g)!
    .reverse()
    .join('');
  
  return `0x${reversed}` as Hash;
}

/**
 * Convert bytes32 to Bitcoin txid (reverse byte order)
 */
export function bytes32ToBtcTxId(hash: Hash): string {
  const cleanHash = hash.replace('0x', '');
  
  // Reverse byte order back to Bitcoin format
  const reversed = cleanHash
    .match(/.{2}/g)!
    .reverse()
    .join('');
  
  return reversed;
}

/**
 * Validate Bitcoin public key hash (20 bytes)
 */
export function isValidPubKeyHash(pkh: string): boolean {
  const cleanPkh = pkh.replace('0x', '');
  return /^[a-fA-F0-9]{40}$/.test(cleanPkh);
}

/**
 * Encode public key hash as bytes20
 */
export function encodePubKeyHash(pkh: string): `0x${string}` {
  const cleanPkh = pkh.replace('0x', '');
  if (!isValidPubKeyHash(cleanPkh)) {
    throw new Error('Invalid public key hash');
  }
  return `0x${cleanPkh}` as `0x${string}`;
}

/**
 * Calculate bridge fee
 */
export function calculateBridgeFee(satoshis: bigint, feeBps: number = 25): bigint {
  return (satoshis * BigInt(feeBps)) / 10000n;
}

/**
 * Parse raw Bitcoin block header (80 bytes)
 */
export function parseBlockHeader(headerHex: `0x${string}`): {
  version: number;
  prevBlockHash: Hash;
  merkleRoot: Hash;
  timestamp: number;
  bits: number;
  nonce: number;
} {
  const header = headerHex.replace('0x', '');
  
  if (header.length !== 160) {
    throw new Error('Invalid block header length (expected 80 bytes)');
  }
  
  // Parse little-endian fields
  const version = parseInt(reverseHex(header.slice(0, 8)), 16);
  const prevBlockHash = `0x${reverseHex(header.slice(8, 72))}` as Hash;
  const merkleRoot = `0x${reverseHex(header.slice(72, 136))}` as Hash;
  const timestamp = parseInt(reverseHex(header.slice(136, 144)), 16);
  const bits = parseInt(reverseHex(header.slice(144, 152)), 16);
  const nonce = parseInt(reverseHex(header.slice(152, 160)), 16);
  
  return {
    version,
    prevBlockHash,
    merkleRoot,
    timestamp,
    bits,
    nonce,
  };
}

/**
 * Reverse hex string by bytes
 */
function reverseHex(hex: string): string {
  return hex.match(/.{2}/g)!.reverse().join('');
}

/**
 * Validate SPV proof structure
 */
export function validateSPVProof(proof: SPVProof): boolean {
  try {
    // Check tx ID format
    if (!proof.txId.startsWith('0x') || proof.txId.length !== 66) {
      return false;
    }
    
    // Check raw tx exists
    if (!proof.txRaw || proof.txRaw.length < 20) {
      return false;
    }
    
    // Check Merkle proof
    if (!Array.isArray(proof.merkleProof)) {
      return false;
    }
    
    // Check block header size (80 bytes = 160 hex chars + 0x)
    if (proof.blockHeader.length !== 162) {
      return false;
    }
    
    return true;
  } catch {
    return false;
  }
}

/**
 * Estimate confirmation time based on required confirmations
 */
export function estimateConfirmationTime(
  confirmations: number = REQUIRED_CONFIRMATIONS
): number {
  // Bitcoin average block time is 10 minutes
  return confirmations * 10 * 60; // seconds
}

/*//////////////////////////////////////////////////////////////
                          ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const BITCOIN_BRIDGE_ADAPTER_ABI = [
  {
    name: 'initiateBTCDeposit',
    type: 'function',
    inputs: [
      { name: 'btcTxId', type: 'bytes32' },
      { name: 'btcTxRaw', type: 'bytes' },
      { name: 'merkleProof', type: 'bytes32[]' },
      { name: 'blockHeader', type: 'bytes' },
      { name: 'ethRecipient', type: 'address' },
    ],
    outputs: [{ name: 'depositId', type: 'bytes32' }],
  },
  {
    name: 'completeBTCDeposit',
    type: 'function',
    inputs: [{ name: 'depositId', type: 'bytes32' }],
    outputs: [],
  },
  {
    name: 'initiateWithdrawal',
    type: 'function',
    inputs: [
      { name: 'btcRecipientPubKeyHash', type: 'bytes20' },
      { name: 'satoshis', type: 'uint256' },
      { name: 'hashlock', type: 'bytes32' },
      { name: 'timelock', type: 'uint256' },
    ],
    outputs: [{ name: 'withdrawalId', type: 'bytes32' }],
  },
  {
    name: 'createHTLC',
    type: 'function',
    inputs: [
      { name: 'hashlock', type: 'bytes32' },
      { name: 'timelock', type: 'uint256' },
      { name: 'recipient', type: 'address' },
    ],
    outputs: [{ name: 'htlcId', type: 'bytes32' }],
  },
  {
    name: 'redeemHTLC',
    type: 'function',
    inputs: [
      { name: 'htlcId', type: 'bytes32' },
      { name: 'preimage', type: 'bytes32' },
    ],
    outputs: [],
  },
  {
    name: 'refundHTLC',
    type: 'function',
    inputs: [{ name: 'htlcId', type: 'bytes32' }],
    outputs: [],
  },
  {
    name: 'getDeposit',
    type: 'function',
    inputs: [{ name: 'depositId', type: 'bytes32' }],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          { name: 'depositId', type: 'bytes32' },
          { name: 'btcTxId', type: 'bytes32' },
          { name: 'scriptPubKey', type: 'bytes' },
          { name: 'satoshis', type: 'uint256' },
          { name: 'netAmount', type: 'uint256' },
          { name: 'fee', type: 'uint256' },
          { name: 'ethRecipient', type: 'address' },
          { name: 'proofHash', type: 'bytes32' },
          { name: 'status', type: 'uint8' },
          { name: 'initiatedAt', type: 'uint256' },
          { name: 'completedAt', type: 'uint256' },
        ],
      },
    ],
  },
  {
    name: 'getHTLC',
    type: 'function',
    inputs: [{ name: 'htlcId', type: 'bytes32' }],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          { name: 'htlcId', type: 'bytes32' },
          { name: 'sender', type: 'address' },
          { name: 'recipient', type: 'address' },
          { name: 'amount', type: 'uint256' },
          { name: 'hashlock', type: 'bytes32' },
          { name: 'timelock', type: 'uint256' },
          { name: 'preimage', type: 'bytes32' },
          { name: 'status', type: 'uint8' },
          { name: 'createdAt', type: 'uint256' },
          { name: 'completedAt', type: 'uint256' },
        ],
      },
    ],
  },
  {
    name: 'getBridgeStats',
    type: 'function',
    inputs: [],
    outputs: [
      { name: 'deposited', type: 'uint256' },
      { name: 'withdrawn', type: 'uint256' },
      { name: 'htlcsTotal', type: 'uint256' },
      { name: 'htlcsRedeemed', type: 'uint256' },
      { name: 'htlcsRefunded', type: 'uint256' },
      { name: 'fees', type: 'uint256' },
    ],
  },
] as const;

export const BITCOIN_HTLC_ABI = [
  {
    name: 'createSwap',
    type: 'function',
    inputs: [
      { name: 'recipient', type: 'address' },
      { name: 'hashlock', type: 'bytes32' },
      { name: 'timelock', type: 'uint256' },
    ],
    outputs: [{ name: 'swapId', type: 'bytes32' }],
  },
  {
    name: 'redeem',
    type: 'function',
    inputs: [
      { name: 'swapId', type: 'bytes32' },
      { name: 'preimage', type: 'bytes32' },
    ],
    outputs: [],
  },
  {
    name: 'refund',
    type: 'function',
    inputs: [{ name: 'swapId', type: 'bytes32' }],
    outputs: [],
  },
  {
    name: 'getSwap',
    type: 'function',
    inputs: [{ name: 'swapId', type: 'bytes32' }],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          { name: 'swapId', type: 'bytes32' },
          { name: 'sender', type: 'address' },
          { name: 'recipient', type: 'address' },
          { name: 'amount', type: 'uint256' },
          { name: 'hashlock', type: 'bytes32' },
          { name: 'timelock', type: 'uint256' },
          { name: 'preimage', type: 'bytes32' },
          { name: 'redeemed', type: 'bool' },
          { name: 'refunded', type: 'bool' },
        ],
      },
    ],
  },
  {
    name: 'computeHashlock',
    type: 'function',
    inputs: [{ name: 'preimage', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bytes32' }],
  },
] as const;
