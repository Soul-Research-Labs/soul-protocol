/**
 * @fileoverview LayerZero V2 bridge utilities for Soul SDK
 * @module bridges/layerzero
 */

import { keccak256, encodePacked, type Address, type Hash, type Hex } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

export const MSG_TYPE_SEND = 1;
export const MSG_TYPE_SEND_AND_CALL = 2;
export const MSG_TYPE_OFT_SEND = 3;
export const MSG_TYPE_ONFT_SEND = 4;
export const MAX_MESSAGE_SIZE = 1_048_576; // 1MB
export const MIN_GAS = 100_000n;
export const DEFAULT_COMPOSE_GAS = 200_000n;
export const FEE_DENOMINATOR = 10_000n;

/** Common LayerZero V2 chain endpoint IDs */
export const LZ_EIDS = {
  ETHEREUM: 30101,
  ARBITRUM: 30110,
  OPTIMISM: 30111,
  BASE: 30184,
  POLYGON: 30109,
  AVALANCHE: 30106,
  BSC: 30102,
  SOLANA: 30168,
  APTOS: 30108,
} as const;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus = 'PENDING' | 'INFLIGHT' | 'DELIVERED' | 'FAILED' | 'STORED';
export type ChainType = 'EVM' | 'SOLANA' | 'APTOS' | 'SUI' | 'IOTA' | 'HYPERLIQUID';
export type SecurityLevel = 'STANDARD' | 'ENHANCED' | 'MAXIMUM';

export interface PeerConfig {
  eid: number;
  peerAddress: Hash;
  chainType: ChainType;
  active: boolean;
  minGas: bigint;
  securityLevel: SecurityLevel;
  registeredAt: number;
}

export interface MessageOptions {
  gas: bigint;
  value: bigint;
  composeMsg: Hex;
  extraOptions: Hex;
}

export interface OmniMessage {
  guid: Hash;
  srcEid: number;
  dstEid: number;
  sender: Hash;
  receiver: Hash;
  message: Hex;
  nonce: bigint;
  status: MessageStatus;
  timestamp: number;
  options: Hex;
}

export interface OFTTransfer {
  transferId: Hash;
  srcEid: number;
  dstEid: number;
  localToken: Address;
  remoteToken: Hash;
  amountSent: bigint;
  amountReceived: bigint;
  sender: Hash;
  recipient: Hash;
  fee: bigint;
  status: MessageStatus;
  timestamp: number;
}

export interface MessagingFee {
  nativeFee: bigint;
  lzTokenFee: bigint;
}

export interface BridgeStats {
  sent: bigint;
  received: bigint;
  fees: bigint;
  peerCount: bigint;
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

export function calculateLzFee(amount: bigint, feeBps: bigint = 10n): bigint {
  return (amount * feeBps) / FEE_DENOMINATOR;
}

export function createDefaultOptions(gas: bigint = MIN_GAS): MessageOptions {
  return {
    gas,
    value: 0n,
    composeMsg: '0x' as Hex,
    extraOptions: '0x' as Hex,
  };
}

export function chainTypeToIndex(chainType: ChainType): number {
  const map: Record<ChainType, number> = {
    'EVM': 0, 'SOLANA': 1, 'APTOS': 2, 'SUI': 3, 'IOTA': 4, 'HYPERLIQUID': 5
  };
  return map[chainType];
}

export function securityLevelToIndex(level: SecurityLevel): number {
  const map: Record<SecurityLevel, number> = { 'STANDARD': 0, 'ENHANCED': 1, 'MAXIMUM': 2 };
  return map[level];
}

export function getEidName(eid: number): string {
  const names: Record<number, string> = {
    30101: 'Ethereum', 30110: 'Arbitrum', 30111: 'Optimism',
    30184: 'Base', 30109: 'Polygon', 30106: 'Avalanche',
    30102: 'BSC', 30168: 'Solana', 30108: 'Aptos',
  };
  return names[eid] ?? `Unknown (eid: ${eid})`;
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const LAYERZERO_BRIDGE_ADAPTER_ABI = [
  {
    type: 'function',
    name: 'setEndpoint',
    inputs: [
      { name: '_endpoint', type: 'address' },
      { name: '_localEid', type: 'uint32' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'setPeer',
    inputs: [
      { name: 'eid', type: 'uint32' },
      { name: 'peerAddress', type: 'bytes32' },
      { name: 'chainType', type: 'uint8' },
      { name: 'minGas', type: 'uint256' },
      { name: 'securityLevel', type: 'uint8' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'lzSend',
    inputs: [
      { name: 'dstEid', type: 'uint32' },
      { name: 'receiver', type: 'bytes32' },
      { name: 'message', type: 'bytes' },
      {
        name: 'options',
        type: 'tuple',
        components: [
          { name: 'gas', type: 'uint128' },
          { name: 'value', type: 'uint128' },
          { name: 'composeMsg', type: 'bytes' },
          { name: 'extraOptions', type: 'bytes' }
        ]
      }
    ],
    outputs: [{ name: 'guid', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'lzReceive',
    inputs: [
      { name: 'srcEid', type: 'uint32' },
      { name: 'sender', type: 'bytes32' },
      { name: 'guid', type: 'bytes32' },
      { name: 'message', type: 'bytes' },
      { name: 'extraData', type: 'bytes' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'sendOFT',
    inputs: [
      { name: 'localToken', type: 'address' },
      { name: 'dstEid', type: 'uint32' },
      { name: 'recipient', type: 'bytes32' },
      { name: 'amount', type: 'uint256' },
      {
        name: 'options',
        type: 'tuple',
        components: [
          { name: 'gas', type: 'uint128' },
          { name: 'value', type: 'uint128' },
          { name: 'composeMsg', type: 'bytes' },
          { name: 'extraOptions', type: 'bytes' }
        ]
      }
    ],
    outputs: [{ name: 'transferId', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'quoteSend',
    inputs: [
      { name: 'dstEid', type: 'uint32' },
      { name: 'message', type: 'bytes' },
      {
        name: 'options',
        type: 'tuple',
        components: [
          { name: 'gas', type: 'uint128' },
          { name: 'value', type: 'uint128' },
          { name: 'composeMsg', type: 'bytes' },
          { name: 'extraOptions', type: 'bytes' }
        ]
      }
    ],
    outputs: [
      {
        name: 'fee',
        type: 'tuple',
        components: [
          { name: 'nativeFee', type: 'uint256' },
          { name: 'lzTokenFee', type: 'uint256' }
        ]
      }
    ],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'getStats',
    inputs: [],
    outputs: [
      { name: 'sent', type: 'uint256' },
      { name: 'received', type: 'uint256' },
      { name: 'fees', type: 'uint256' },
      { name: 'peerCount', type: 'uint256' }
    ],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'isPeerActive',
    inputs: [{ name: 'eid', type: 'uint32' }],
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
    name: 'MessageSent',
    inputs: [
      { name: 'guid', type: 'bytes32', indexed: true },
      { name: 'dstEid', type: 'uint32', indexed: true },
      { name: 'receiver', type: 'bytes32', indexed: false },
      { name: 'fee', type: 'uint256', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'MessageReceived',
    inputs: [
      { name: 'guid', type: 'bytes32', indexed: true },
      { name: 'srcEid', type: 'uint32', indexed: true },
      { name: 'sender', type: 'bytes32', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'OFTSent',
    inputs: [
      { name: 'transferId', type: 'bytes32', indexed: true },
      { name: 'dstEid', type: 'uint32', indexed: true },
      { name: 'localToken', type: 'address', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'PeerSet',
    inputs: [
      { name: 'eid', type: 'uint32', indexed: true },
      { name: 'peerAddress', type: 'bytes32', indexed: false },
      { name: 'chainType', type: 'uint8', indexed: false }
    ]
  }
] as const;
