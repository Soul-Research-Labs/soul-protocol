/**
 * @fileoverview Aztec bridge utilities for Soul SDK
 * @module bridges/aztec
 */

import { keccak256, encodePacked, type Address, type Hash, type Hex } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

export const MIN_BRIDGE_AMOUNT = 10_000_000_000_000_000n; // 0.01 ether
export const MAX_BRIDGE_AMOUNT = 1_000_000_000_000_000_000_000n; // 1000 ether
export const BRIDGE_FEE_BPS = 10n; // 0.1%
export const FEE_DENOMINATOR = 10_000n;
export const CHALLENGE_PERIOD = 604800; // 7 days
export const PROOF_EXPIRY = 86400; // 24 hours

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type NoteType = 'VALUE_NOTE' | 'DEFI_NOTE' | 'ACCOUNT_NOTE' | 'CUSTOM_NOTE';
export type ProofType = 'SOUL_TO_AZTEC' | 'AZTEC_TO_SOUL' | 'BIDIRECTIONAL';

export interface SoulToAztecRequest {
  requestId: Hash;
  soulCommitment: Hash;
  soulNullifier: Hash;
  aztecRecipient: Hash;
  amount: bigint;
  noteType: NoteType;
  appDataHash: Hash;
  timestamp: number;
  processed: boolean;
  resultingNoteHash: Hash;
}

export interface AztecToSoulRequest {
  requestId: Hash;
  aztecNoteHash: Hash;
  aztecNullifier: Hash;
  soulRecipient: Address;
  amount: bigint;
  soulCommitment: Hash;
  timestamp: number;
  processed: boolean;
}

export interface CrossDomainProof {
  proofId: Hash;
  proofType: ProofType;
  sourceCommitment: Hash;
  targetCommitment: Hash;
  nullifier: Hash;
  verified: boolean;
  verifiedAt: number;
}

export interface AztecStateSync {
  rollupId: bigint;
  dataTreeRoot: Hash;
  nullifierTreeRoot: Hash;
  contractTreeRoot: Hash;
  l1ToL2MessageTreeRoot: Hash;
  blockNumber: bigint;
  timestamp: number;
  finalized: boolean;
}

export interface BridgeStats {
  pendingRequests: bigint;
  totalToAztec: bigint;
  totalFromAztec: bigint;
  fees: bigint;
  latestRollup: bigint;
}

/*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

export function calculateBridgeFee(amount: bigint): bigint {
  return (amount * BRIDGE_FEE_BPS) / FEE_DENOMINATOR;
}

export function validateBridgeAmount(amount: bigint): boolean {
  return amount >= MIN_BRIDGE_AMOUNT && amount <= MAX_BRIDGE_AMOUNT;
}

export function noteTypeToIndex(noteType: NoteType): number {
  const map: Record<NoteType, number> = {
    'VALUE_NOTE': 0,
    'DEFI_NOTE': 1,
    'ACCOUNT_NOTE': 2,
    'CUSTOM_NOTE': 3
  };
  return map[noteType];
}

export function proofTypeToIndex(proofType: ProofType): number {
  const map: Record<ProofType, number> = {
    'SOUL_TO_AZTEC': 0,
    'AZTEC_TO_SOUL': 1,
    'BIDIRECTIONAL': 2
  };
  return map[proofType];
}

export function isProofExpired(verifiedAt: number, expiry: number = PROOF_EXPIRY): boolean {
  return Math.floor(Date.now() / 1000) >= verifiedAt + expiry;
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const AZTEC_BRIDGE_ADAPTER_ABI = [
  {
    type: 'function',
    name: 'configureAztecContracts',
    inputs: [
      { name: '_rollup', type: 'address' },
      { name: '_inbox', type: 'address' },
      { name: '_outbox', type: 'address' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'bridgeSoulToAztec',
    inputs: [
      { name: 'soulCommitment', type: 'bytes32' },
      { name: 'soulNullifier', type: 'bytes32' },
      { name: 'aztecRecipient', type: 'bytes32' },
      { name: 'amount', type: 'uint256' },
      { name: 'noteType', type: 'uint8' },
      { name: 'appDataHash', type: 'bytes32' },
      { name: 'proof', type: 'bytes' }
    ],
    outputs: [],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'bridgeAztecToSoul',
    inputs: [
      { name: 'aztecNoteHash', type: 'bytes32' },
      { name: 'aztecNullifier', type: 'bytes32' },
      { name: 'soulRecipient', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'proof', type: 'bytes' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'completeSoulToAztec',
    inputs: [
      { name: 'requestId', type: 'bytes32' },
      { name: 'resultingNoteHash', type: 'bytes32' },
      { name: 'proof', type: 'bytes' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'verifyCrossDomainProof',
    inputs: [
      { name: 'proofType', type: 'uint8' },
      { name: 'sourceCommitment', type: 'bytes32' },
      { name: 'targetCommitment', type: 'bytes32' },
      { name: 'nullifier', type: 'bytes32' },
      { name: 'proof', type: 'bytes' },
      { name: 'publicInputsHash', type: 'bytes32' }
    ],
    outputs: [{ name: 'proofId', type: 'bytes32' }],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'syncAztecState',
    inputs: [
      { name: 'rollupId', type: 'uint256' },
      { name: 'dataTreeRoot', type: 'bytes32' },
      { name: 'nullifierTreeRoot', type: 'bytes32' },
      { name: 'contractTreeRoot', type: 'bytes32' },
      { name: 'l1ToL2MessageTreeRoot', type: 'bytes32' },
      { name: 'blockNumber', type: 'uint256' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'getBridgeStats',
    inputs: [],
    outputs: [
      { name: 'pendingRequests', type: 'uint256' },
      { name: 'totalToAztec', type: 'uint256' },
      { name: 'totalFromAztec', type: 'uint256' },
      { name: 'fees', type: 'uint256' },
      { name: 'latestRollup', type: 'uint256' }
    ],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'isNullifierUsed',
    inputs: [{ name: 'nullifier', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'pause',
    inputs: [],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'unpause',
    inputs: [],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'event',
    name: 'SoulToAztecInitiated',
    inputs: [
      { name: 'requestId', type: 'bytes32', indexed: true },
      { name: 'soulCommitment', type: 'bytes32', indexed: true },
      { name: 'aztecRecipient', type: 'bytes32', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'AztecToSoulInitiated',
    inputs: [
      { name: 'requestId', type: 'bytes32', indexed: true },
      { name: 'aztecNoteHash', type: 'bytes32', indexed: true },
      { name: 'soulRecipient', type: 'address', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'CrossDomainProofVerified',
    inputs: [
      { name: 'proofId', type: 'bytes32', indexed: true },
      { name: 'proofType', type: 'uint8', indexed: false },
      { name: 'sourceCommitment', type: 'bytes32', indexed: false },
      { name: 'targetCommitment', type: 'bytes32', indexed: false }
    ]
  }
] as const;
