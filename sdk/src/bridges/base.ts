/**
 * @fileoverview Base (OP Stack) bridge utilities for Soul SDK
 * @module bridges/base
 */

import { keccak256, encodePacked, type Address, type Hash } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

export const BASE_MAINNET_CHAIN_ID = 8453;
export const BASE_SEPOLIA_CHAIN_ID = 84532;
export const ETH_MAINNET_CHAIN_ID = 1;
export const ETH_SEPOLIA_CHAIN_ID = 11155111;
export const WITHDRAWAL_PERIOD = 604800; // 7 days
export const DEFAULT_L2_GAS_LIMIT = 1_000_000n;
export const MIN_GAS_LIMIT = 100_000n;
export const CCTP_ETH_DOMAIN = 0;
export const CCTP_BASE_DOMAIN = 6;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageType = 'PROOF_RELAY' | 'STATE_SYNC' | 'NULLIFIER_CHECK' | 'BATCH_VERIFY' | 'USDC_TRANSFER' | 'ATTESTATION_SYNC' | 'EMERGENCY';
export type MessageStatus = 'PENDING' | 'SENT' | 'CONFIRMED' | 'FAILED' | 'WITHDRAWN';

export interface CrossDomainMessage {
  messageId: Hash;
  messageType: MessageType;
  payload: `0x${string}`;
  sourceChainId: number;
  targetChainId: number;
  sender: Address;
  target: Address;
  value: bigint;
  gasLimit: bigint;
  timestamp: number;
  status: MessageStatus;
}

export interface ProofRelayRequest {
  proofHash: Hash;
  proof: `0x${string}`;
  publicInputs: `0x${string}`;
  stateRoot: Hash;
  nonce: bigint;
  deadline: bigint;
}

export interface WithdrawalRequest {
  withdrawalId: Hash;
  user: Address;
  proofHash: Hash;
  amount: bigint;
  requestedAt: number;
  completableAt: number;
  completed: boolean;
}

export interface CCTPTransfer {
  transferId: Hash;
  sender: Address;
  recipient: Address;
  amount: bigint;
  sourceDomain: number;
  destDomain: number;
  nonce: bigint;
  completed: boolean;
}

export interface BridgeStats {
  messagesSent: bigint;
  messagesReceived: bigint;
  valueBridged: bigint;
  usdcBridged: bigint;
  currentNonce: bigint;
}

/*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

export function computeMessageId(
  messageType: number,
  sender: Address,
  target: Address,
  nonce: bigint
): Hash {
  return keccak256(
    encodePacked(
      ['uint8', 'address', 'address', 'uint256'],
      [messageType, sender, target, nonce]
    )
  );
}

export function isWithdrawalReady(requestedAt: number, period: number = WITHDRAWAL_PERIOD): boolean {
  return Math.floor(Date.now() / 1000) >= requestedAt + period;
}

export function getBaseDomain(chainId: number): number {
  switch (chainId) {
    case ETH_MAINNET_CHAIN_ID:
    case ETH_SEPOLIA_CHAIN_ID:
      return CCTP_ETH_DOMAIN;
    case BASE_MAINNET_CHAIN_ID:
    case BASE_SEPOLIA_CHAIN_ID:
      return CCTP_BASE_DOMAIN;
    default:
      throw new Error(`Unknown chain ID: ${chainId}`);
  }
}

export function getBaseNetworkName(chainId: number): string {
  switch (chainId) {
    case BASE_MAINNET_CHAIN_ID: return 'Base Mainnet';
    case BASE_SEPOLIA_CHAIN_ID: return 'Base Sepolia';
    default: return `Unknown Base (${chainId})`;
  }
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const BASE_BRIDGE_ADAPTER_ABI = [
  {
    type: 'function',
    name: 'sendProofToL2',
    inputs: [
      { name: 'proofHash', type: 'bytes32' },
      { name: 'proof', type: 'bytes' },
      { name: 'publicInputs', type: 'bytes' },
      { name: 'gasLimit', type: 'uint256' }
    ],
    outputs: [{ name: 'messageId', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'receiveProofFromL1',
    inputs: [
      { name: 'proofHash', type: 'bytes32' },
      { name: 'proof', type: 'bytes' },
      { name: 'publicInputs', type: 'bytes' },
      { name: 'sourceChainId', type: 'uint256' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'initiateUSDCTransfer',
    inputs: [
      { name: 'recipient', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'destDomain', type: 'uint32' }
    ],
    outputs: [{ name: 'transferId', type: 'bytes32' }],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'initiateWithdrawal',
    inputs: [{ name: 'proofHash', type: 'bytes32' }],
    outputs: [{ name: 'withdrawalId', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'completeWithdrawal',
    inputs: [{ name: 'withdrawalId', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'syncStateToL2',
    inputs: [
      { name: 'stateRoot', type: 'bytes32' },
      { name: 'blockNumber', type: 'uint256' },
      { name: 'gasLimit', type: 'uint256' }
    ],
    outputs: [{ name: 'messageId', type: 'bytes32' }],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'isProofRelayed',
    inputs: [{ name: 'proofHash', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'getStats',
    inputs: [],
    outputs: [
      { name: 'messagesSent', type: 'uint256' },
      { name: 'messagesReceived', type: 'uint256' },
      { name: 'valueBridged', type: 'uint256' },
      { name: 'usdcBridged', type: 'uint256' },
      { name: 'currentNonce', type: 'uint256' }
    ],
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
    name: 'MessageSent',
    inputs: [
      { name: 'messageId', type: 'bytes32', indexed: true },
      { name: 'messageType', type: 'uint8', indexed: false },
      { name: 'sender', type: 'address', indexed: true },
      { name: 'target', type: 'address', indexed: true },
      { name: 'value', type: 'uint256', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'ProofRelayed',
    inputs: [
      { name: 'proofHash', type: 'bytes32', indexed: true },
      { name: 'sourceChainId', type: 'uint256', indexed: false },
      { name: 'targetChainId', type: 'uint256', indexed: false },
      { name: 'relayer', type: 'address', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'CCTPTransferInitiated',
    inputs: [
      { name: 'transferId', type: 'bytes32', indexed: true },
      { name: 'sender', type: 'address', indexed: true },
      { name: 'recipient', type: 'address', indexed: true },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'destDomain', type: 'uint32', indexed: false }
    ]
  }
] as const;
