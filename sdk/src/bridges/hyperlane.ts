/**
 * @fileoverview Hyperlane bridge utilities for Soul SDK
 * @module bridges/hyperlane
 */

import { keccak256, encodePacked, type Address, type Hash, type Hex } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** Common Hyperlane domain IDs */
export const HYPERLANE_DOMAINS = {
  ETHEREUM: 1,
  ARBITRUM: 42161,
  OPTIMISM: 10,
  BASE: 8453,
  POLYGON: 137,
  AVALANCHE: 43114,
  BSC: 56,
  CELO: 42220,
  GNOSIS: 100,
  SCROLL: 534352,
} as const;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type ISMType = 'MULTISIG' | 'MERKLE' | 'AGGREGATION' | 'ROUTING' | 'PAUSABLE' | 'CUSTOM';

export interface ISMConfig {
  ism: Address;
  ismType: ISMType;
  enabled: boolean;
  threshold: number;
  validators: Address[];
}

export interface MultisigISMParams {
  validators: Address[];
  threshold: number;
  commitment: Hash;
}

export interface MerkleProof {
  path: Hash[];
  index: bigint;
  leaf: Hash;
}

export interface MessageMetadata {
  originDomain: number;
  destinationDomain: number;
  sender: Hash;
  recipient: Hash;
  nonce: bigint;
  body: Hex;
  messageId: Hash;
  timestamp: number;
  verified: boolean;
}

/*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

export function addressToBytes32(address: Address): Hash {
  return ('0x' + address.slice(2).padStart(64, '0')) as Hash;
}

export function bytes32ToAddress(bytes32: Hash): Address {
  return ('0x' + bytes32.slice(26)) as Address;
}

export function computeMessageId(
  originDomain: number,
  sender: Hash,
  destinationDomain: number,
  recipient: Hash,
  nonce: bigint,
  body: Hex
): Hash {
  return keccak256(
    encodePacked(
      ['uint32', 'bytes32', 'uint32', 'bytes32', 'uint256', 'bytes'],
      [originDomain, sender, destinationDomain, recipient, nonce, body]
    )
  );
}

export function ismTypeToIndex(ismType: ISMType): number {
  const map: Record<ISMType, number> = {
    'MULTISIG': 0, 'MERKLE': 1, 'AGGREGATION': 2,
    'ROUTING': 3, 'PAUSABLE': 4, 'CUSTOM': 5
  };
  return map[ismType];
}

export function getDomainName(domain: number): string {
  const names: Record<number, string> = {
    1: 'Ethereum', 42161: 'Arbitrum', 10: 'Optimism',
    8453: 'Base', 137: 'Polygon', 43114: 'Avalanche',
    56: 'BSC', 42220: 'Celo', 100: 'Gnosis', 534352: 'Scroll',
  };
  return names[domain] ?? `Unknown (domain: ${domain})`;
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const HYPERLANE_ADAPTER_ABI = [
  {
    type: 'function',
    name: 'dispatch',
    inputs: [
      { name: 'destinationDomain', type: 'uint32' },
      { name: 'recipient', type: 'bytes32' },
      { name: 'message', type: 'bytes' }
    ],
    outputs: [{ name: 'messageId', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'quoteDispatch',
    inputs: [
      { name: 'destinationDomain', type: 'uint32' },
      { name: 'message', type: 'bytes' }
    ],
    outputs: [{ name: 'fee', type: 'uint256' }],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'handle',
    inputs: [
      { name: 'origin', type: 'uint32' },
      { name: 'sender', type: 'bytes32' },
      { name: 'message', type: 'bytes' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'verify',
    inputs: [
      { name: 'messageId', type: 'bytes32' },
      { name: 'metadata', type: 'bytes' }
    ],
    outputs: [{ name: 'verified', type: 'bool' }],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'setISMConfig',
    inputs: [
      { name: 'domain', type: 'uint32' },
      {
        name: 'config',
        type: 'tuple',
        components: [
          { name: 'ism', type: 'address' },
          { name: 'ismType', type: 'uint8' },
          { name: 'enabled', type: 'bool' },
          { name: 'threshold', type: 'uint8' },
          { name: 'validators', type: 'address[]' }
        ]
      }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'setMultisigParams',
    inputs: [
      { name: 'domain', type: 'uint32' },
      { name: 'validators', type: 'address[]' },
      { name: 'threshold', type: 'uint8' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'setTrustedSender',
    inputs: [
      { name: 'domain', type: 'uint32' },
      { name: 'sender', type: 'bytes32' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'getMerkleRoots',
    inputs: [{ name: 'domain', type: 'uint32' }],
    outputs: [{ name: '', type: 'bytes32[]' }],
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
    name: 'MessageDispatched',
    inputs: [
      { name: 'messageId', type: 'bytes32', indexed: true },
      { name: 'destinationDomain', type: 'uint32', indexed: true },
      { name: 'recipient', type: 'bytes32', indexed: false },
      { name: 'message', type: 'bytes', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'MessageProcessed',
    inputs: [
      { name: 'messageId', type: 'bytes32', indexed: true },
      { name: 'originDomain', type: 'uint32', indexed: true },
      { name: 'sender', type: 'bytes32', indexed: false },
      { name: 'message', type: 'bytes', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'ISMConfigured',
    inputs: [
      { name: 'domain', type: 'uint32', indexed: true },
      { name: 'ism', type: 'address', indexed: false },
      { name: 'ismType', type: 'uint8', indexed: false }
    ]
  }
] as const;
