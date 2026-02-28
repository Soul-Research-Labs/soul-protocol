/**
 * @fileoverview Ethereum L1 bridge utilities for Zaseon SDK
 * @module bridges/ethereum
 */

import { keccak256, encodePacked, type Address, type Hash } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

export const ETHEREUM_CHAIN_ID = 1;
export const DEFAULT_CHALLENGE_PERIOD = 604800; // 7 days

/** Supported L2 chain IDs */
export const SUPPORTED_L2_CHAINS = {
  ARBITRUM_ONE: 42161,
  ARBITRUM_NOVA: 42170,
  OPTIMISM: 10,
  BASE: 8453,
  ZKSYNC_ERA: 324,
  SCROLL: 534352,
  LINEA: 59144,
  POLYGON_ZKEVM: 1101,
} as const;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type RollupType = 'OPTIMISTIC' | 'ZK_ROLLUP' | 'VALIDIUM';
export type CommitmentStatus = 'PENDING' | 'CHALLENGED' | 'FINALIZED' | 'REJECTED';

export interface L2Config {
  chainId: number;
  name: string;
  rollupType: RollupType;
  canonicalBridge: Address;
  messenger: Address;
  stateCommitmentChain: Address;
  challengePeriod: number;
  confirmationBlocks: number;
  enabled: boolean;
  gasLimit: bigint;
  lastSyncedBlock: bigint;
}

export interface StateCommitment {
  commitmentId: Hash;
  sourceChainId: number;
  stateRoot: Hash;
  proofRoot: Hash;
  blockNumber: bigint;
  timestamp: number;
  status: CommitmentStatus;
  challengeDeadline: number;
  submitter: Address;
  blobVersionedHash: Hash;
}

export interface EthDeposit {
  depositId: Hash;
  depositor: Address;
  targetChainId: number;
  token: Address;
  amount: bigint;
  commitment: Hash;
  timestamp: number;
  claimed: boolean;
}

export interface EthWithdrawal {
  withdrawalId: Hash;
  recipient: Address;
  sourceChainId: number;
  token: Address;
  amount: bigint;
  nullifier: Hash;
  timestamp: number;
  finalized: boolean;
  claimed: boolean;
}

/*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

export function isCommitmentChallengeExpired(deadline: number): boolean {
  return Math.floor(Date.now() / 1000) >= deadline;
}

export function getRollupTypeName(rollupType: number): RollupType {
  const types: RollupType[] = ['OPTIMISTIC', 'ZK_ROLLUP', 'VALIDIUM'];
  return types[rollupType] ?? 'OPTIMISTIC';
}

export function getL2Name(chainId: number): string {
  const names: Record<number, string> = {
    42161: 'Arbitrum One',
    42170: 'Arbitrum Nova',
    10: 'Optimism',
    8453: 'Base',
    324: 'zkSync Era',
    534352: 'Scroll',
    59144: 'Linea',
    1101: 'Polygon zkEVM',
  };
  return names[chainId] ?? `Unknown L2 (${chainId})`;
}

export function computeCommitmentId(
  sourceChainId: number,
  stateRoot: Hash,
  blockNumber: bigint
): Hash {
  return keccak256(
    encodePacked(
      ['uint256', 'bytes32', 'uint256'],
      [BigInt(sourceChainId), stateRoot, blockNumber]
    )
  );
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const ETHEREUM_L1_BRIDGE_ABI = [
  {
    type: 'function',
    name: 'configureL2Chain',
    inputs: [
      {
        name: 'config',
        type: 'tuple',
        components: [
          { name: 'chainId', type: 'uint256' },
          { name: 'name', type: 'string' },
          { name: 'rollupType', type: 'uint8' },
          { name: 'canonicalBridge', type: 'address' },
          { name: 'messenger', type: 'address' },
          { name: 'stateCommitmentChain', type: 'address' },
          { name: 'challengePeriod', type: 'uint256' },
          { name: 'confirmationBlocks', type: 'uint256' },
          { name: 'enabled', type: 'bool' },
          { name: 'gasLimit', type: 'uint256' },
          { name: 'lastSyncedBlock', type: 'uint256' }
        ]
      }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'submitStateCommitment',
    inputs: [
      { name: 'sourceChainId', type: 'uint256' },
      { name: 'stateRoot', type: 'bytes32' },
      { name: 'proofRoot', type: 'bytes32' },
      { name: 'blockNumber', type: 'uint256' }
    ],
    outputs: [],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'challengeCommitment',
    inputs: [
      { name: 'commitmentId', type: 'bytes32' },
      { name: 'reason', type: 'bytes32' }
    ],
    outputs: [],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'finalizeCommitment',
    inputs: [{ name: 'commitmentId', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'depositETH',
    inputs: [
      { name: 'targetChainId', type: 'uint256' },
      { name: 'commitment', type: 'bytes32' }
    ],
    outputs: [],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'initiateWithdrawal',
    inputs: [
      { name: 'sourceChainId', type: 'uint256' },
      { name: 'amount', type: 'uint256' },
      { name: 'nullifier', type: 'bytes32' },
      { name: 'proof', type: 'bytes32[]' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'finalizeWithdrawal',
    inputs: [{ name: 'withdrawalId', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'claimWithdrawal',
    inputs: [{ name: 'withdrawalId', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'getSupportedChainIds',
    inputs: [],
    outputs: [{ name: '', type: 'uint256[]' }],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'getLatestStateRoot',
    inputs: [{ name: 'chainId', type: 'uint256' }],
    outputs: [{ name: '', type: 'bytes32' }],
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
    name: 'StateCommitmentSubmitted',
    inputs: [
      { name: 'commitmentId', type: 'bytes32', indexed: true },
      { name: 'sourceChainId', type: 'uint256', indexed: true },
      { name: 'stateRoot', type: 'bytes32', indexed: false },
      { name: 'submitter', type: 'address', indexed: false },
      { name: 'blobVersionedHash', type: 'bytes32', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'DepositInitiated',
    inputs: [
      { name: 'depositId', type: 'bytes32', indexed: true },
      { name: 'depositor', type: 'address', indexed: true },
      { name: 'targetChainId', type: 'uint256', indexed: true },
      { name: 'token', type: 'address', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'commitment', type: 'bytes32', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'WithdrawalFinalized',
    inputs: [
      { name: 'withdrawalId', type: 'bytes32', indexed: true },
      { name: 'recipient', type: 'address', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false }
    ]
  }
] as const;
