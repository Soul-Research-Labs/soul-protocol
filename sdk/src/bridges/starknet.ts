/**
 * @fileoverview Starknet bridge utilities for Soul SDK
 * @module bridges/starknet
 */

import { keccak256, encodePacked, type Address, type Hash } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

export const STARKNET_MAINNET_CHAIN_ID = 0x534e5f4d41494e; // SN_MAIN
export const STARKNET_SEPOLIA_CHAIN_ID = 0x534e5f5345504f4c4941; // SN_SEPOLIA
export const DEPOSIT_SELECTOR = '0x0352149076e0f82d29d678ba52eb54a51ef7003c2a4fc6754bdf9cff382f5c5d' as Hash;
export const MESSAGE_SELECTOR = '0x00c73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01' as Hash;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type TransferStatus = 'PENDING' | 'MESSAGE_SENT' | 'CONSUMED' | 'FINALIZED' | 'FAILED';
export type MessageDirection = 'L1_TO_L2' | 'L2_TO_L1';

export interface StarknetConfig {
  starknetCore: Address;
  starknetMessaging: Address;
  l2BridgeAddress: bigint;
  active: boolean;
}

export interface L1ToL2Deposit {
  depositId: Hash;
  sender: Address;
  l2Recipient: bigint;
  l1Token: Address;
  l2Token: bigint;
  amount: bigint;
  nonce: bigint;
  messageHash: Hash;
  status: TransferStatus;
  initiatedAt: number;
  consumedAt: number;
}

export interface L2ToL1Withdrawal {
  withdrawalId: Hash;
  l2Sender: bigint;
  l1Recipient: Address;
  l2Token: bigint;
  l1Token: Address;
  amount: bigint;
  messageHash: Hash;
  status: TransferStatus;
  initiatedAt: number;
  claimedAt: number;
}

export interface TokenMapping {
  l1Token: Address;
  l2Token: bigint;
  decimals: number;
  totalDeposited: bigint;
  totalWithdrawn: bigint;
  active: boolean;
}

/*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

export function feltToHex(felt: bigint): string {
  return '0x' + felt.toString(16).padStart(64, '0');
}

export function addressToFelt(address: Address): bigint {
  return BigInt(address);
}

export function computeStarknetMessageHash(
  fromAddress: bigint,
  toAddress: bigint,
  payload: bigint[]
): Hash {
  const encoded = encodePacked(
    ['uint256', 'uint256', ...payload.map(() => 'uint256' as const)],
    [fromAddress, toAddress, ...payload]
  );
  return keccak256(encoded);
}

export function getStarknetNetworkName(chainId: bigint): string {
  if (chainId === BigInt(STARKNET_MAINNET_CHAIN_ID)) return 'Starknet Mainnet';
  if (chainId === BigInt(STARKNET_SEPOLIA_CHAIN_ID)) return 'Starknet Sepolia';
  return `Unknown Starknet (${chainId})`;
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const STARKNET_BRIDGE_ADAPTER_ABI = [
  {
    type: 'function',
    name: 'configure',
    inputs: [
      { name: 'starknetCore', type: 'address' },
      { name: 'starknetMessaging', type: 'address' },
      { name: 'l2BridgeAddress', type: 'uint256' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'mapToken',
    inputs: [
      { name: 'l1Token', type: 'address' },
      { name: 'l2Token', type: 'uint256' },
      { name: 'decimals', type: 'uint8' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'deposit',
    inputs: [
      { name: 'l2Recipient', type: 'uint256' },
      { name: 'l1Token', type: 'address' },
      { name: 'amount', type: 'uint256' }
    ],
    outputs: [{ name: 'depositId', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'depositETH',
    inputs: [{ name: 'l2Recipient', type: 'uint256' }],
    outputs: [{ name: 'depositId', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'sendMessageToL2',
    inputs: [
      { name: 'toAddress', type: 'uint256' },
      { name: 'selector', type: 'uint256' },
      { name: 'payload', type: 'uint256[]' }
    ],
    outputs: [{ name: 'messageHash', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'claimWithdrawal',
    inputs: [
      { name: 'l2Sender', type: 'uint256' },
      { name: 'l1Recipient', type: 'address' },
      { name: 'l2Token', type: 'uint256' },
      { name: 'amount', type: 'uint256' },
      { name: 'payload', type: 'uint256[]' }
    ],
    outputs: [{ name: 'withdrawalId', type: 'bytes32' }],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'getBridgeStats',
    inputs: [],
    outputs: [
      { name: '', type: 'uint256' },
      { name: '', type: 'uint256' }
    ],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'computeMessageHash',
    inputs: [
      { name: 'fromAddress', type: 'uint256' },
      { name: 'toAddress', type: 'uint256' },
      { name: 'payload', type: 'uint256[]' }
    ],
    outputs: [{ name: '', type: 'bytes32' }],
    stateMutability: 'pure'
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
    name: 'DepositInitiated',
    inputs: [
      { name: 'depositId', type: 'bytes32', indexed: true },
      { name: 'sender', type: 'address', indexed: true },
      { name: 'l2Recipient', type: 'uint256', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'messageHash', type: 'bytes32', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'WithdrawalClaimed',
    inputs: [
      { name: 'withdrawalId', type: 'bytes32', indexed: true }
    ]
  },
  {
    type: 'event',
    name: 'TokenMapped',
    inputs: [
      { name: 'l1Token', type: 'address', indexed: true },
      { name: 'l2Token', type: 'uint256', indexed: false }
    ]
  }
] as const;
