/**
 * @fileoverview L2 bridge utilities (Scroll, Linea, zkSync, Polygon zkEVM) for Soul SDK
 * @module bridges/l2-adapters
 */

import { type Address, type Hash } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

export const L2_CHAIN_IDS = {
  SCROLL_MAINNET: 534352,
  SCROLL_SEPOLIA: 534351,
  LINEA_MAINNET: 59144,
  LINEA_TESTNET: 59140,
  ZKSYNC_ERA: 324,
  POLYGON_ZKEVM_MAINNET: 1101,
  POLYGON_ZKEVM_TESTNET: 1442,
} as const;

export const FINALITY_BLOCKS = 1;
export const DEFAULT_L2_GAS_LIMIT = 1_000_000n;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type L2Network = 'scroll' | 'linea' | 'zksync' | 'polygon-zkevm';
export type MessageStatus = 'PENDING' | 'SENT' | 'RELAYED' | 'FAILED';

export interface L2BridgeConfig {
  network: L2Network;
  chainId: number;
  chainName: string;
  messenger: Address;
  soulHubL2: Address;
  finalityBlocks: number;
  configured: boolean;
}

export interface L2Message {
  messageHash: Hash;
  target: Address;
  nonce: bigint;
  status: MessageStatus;
}

/*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

export function getL2NetworkInfo(network: L2Network): { chainId: number; name: string } {
  const info: Record<L2Network, { chainId: number; name: string }> = {
    'scroll': { chainId: L2_CHAIN_IDS.SCROLL_MAINNET, name: 'Scroll' },
    'linea': { chainId: L2_CHAIN_IDS.LINEA_MAINNET, name: 'Linea' },
    'zksync': { chainId: L2_CHAIN_IDS.ZKSYNC_ERA, name: 'zkSync Era' },
    'polygon-zkevm': { chainId: L2_CHAIN_IDS.POLYGON_ZKEVM_MAINNET, name: 'Polygon zkEVM' },
  };
  return info[network];
}

export function getL2NetworkByChainId(chainId: number): L2Network | undefined {
  const map: Record<number, L2Network> = {
    534352: 'scroll', 534351: 'scroll',
    59144: 'linea', 59140: 'linea',
    324: 'zksync',
    1101: 'polygon-zkevm', 1442: 'polygon-zkevm',
  };
  return map[chainId];
}

export function isL2Supported(chainId: number): boolean {
  return getL2NetworkByChainId(chainId) !== undefined;
}

/*//////////////////////////////////////////////////////////////
                        SCROLL ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const SCROLL_BRIDGE_ADAPTER_ABI = [
  {
    type: 'function',
    name: 'sendMessage',
    inputs: [
      { name: 'target', type: 'address' },
      { name: 'data', type: 'bytes' },
      { name: 'gasLimit', type: 'uint256' }
    ],
    outputs: [{ name: '', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'verifyMessage',
    inputs: [
      { name: 'messageHash', type: 'bytes32' },
      { name: 'proof', type: 'bytes' }
    ],
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'chainId',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'pure'
  },
  {
    type: 'function',
    name: 'chainName',
    inputs: [],
    outputs: [{ name: '', type: 'string' }],
    stateMutability: 'pure'
  },
  {
    type: 'function',
    name: 'isConfigured',
    inputs: [],
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
      { name: 'messageHash', type: 'bytes32', indexed: true },
      { name: 'target', type: 'address', indexed: true },
      { name: 'nonce', type: 'uint256', indexed: false }
    ]
  }
] as const;

export const LINEA_BRIDGE_ADAPTER_ABI = SCROLL_BRIDGE_ADAPTER_ABI;
export const ZKSYNC_BRIDGE_ADAPTER_ABI = SCROLL_BRIDGE_ADAPTER_ABI;
export const POLYGON_ZKEVM_BRIDGE_ADAPTER_ABI = SCROLL_BRIDGE_ADAPTER_ABI;
