/**
 * @fileoverview Polygon zkEVM bridge utilities for Soul SDK
 * @module bridges/polygon-zkevm
 */

import { keccak256, toBytes, encodePacked, type Address, type Hash, type Hex } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** Polygon zkEVM mainnet chain ID */
export const POLYGON_ZKEVM_CHAIN_ID = 1101;

/** Polygon zkEVM Cardona testnet chain ID */
export const POLYGON_ZKEVM_CARDONA_CHAIN_ID = 2442;

/** Proof finality in seconds (~30 minutes for pessimistic proof) */
export const PROOF_FINALITY_SECONDS = 1800;

/** Default gas limit */
export const DEFAULT_GAS_LIMIT = 1_000_000n;

/** Network ID for Polygon zkEVM in the bridge */
export const POLYGON_ZKEVM_NETWORK_ID = 1;

/** Network ID for Ethereum L1 in the bridge */
export const ETHEREUM_NETWORK_ID = 0;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type TransferStatus = 'PENDING' | 'DEPOSITED' | 'CLAIMABLE' | 'CLAIMED' | 'FAILED';

export interface PolygonZkEVMConfig {
  chainId: number;
  polygonZkEVMBridge: Address;
  polygonZkEVMGlobalExitRoot: Address;
  rollupManager: Address;
}

export interface BridgeDeposit {
  depositHash: Hash;
  originNetwork: number;
  originAddress: Address;
  destinationNetwork: number;
  destinationAddress: Address;
  amount: bigint;
  depositCount: bigint;
  metadata: Hex;
  status: TransferStatus;
  initiatedAt: number;
}

export interface BridgeClaim {
  smtProofLocalExitRoot: Hash[];
  smtProofRollupExitRoot: Hash[];
  globalIndex: bigint;
  mainnetExitRoot: Hash;
  rollupExitRoot: Hash;
  originNetwork: number;
  originTokenAddress: Address;
  destinationNetwork: number;
  destinationAddress: Address;
  amount: bigint;
  metadata: Hex;
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const POLYGON_ZKEVM_BRIDGE_ABI = [
  {
    name: 'bridgeAsset',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      { name: 'destinationNetwork', type: 'uint32' },
      { name: 'destinationAddress', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'token', type: 'address' },
      { name: 'forceUpdateGlobalExitRoot', type: 'bool' },
      { name: 'permitData', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    name: 'bridgeMessage',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      { name: 'destinationNetwork', type: 'uint32' },
      { name: 'destinationAddress', type: 'address' },
      { name: 'forceUpdateGlobalExitRoot', type: 'bool' },
      { name: 'metadata', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    name: 'claimAsset',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'smtProofLocalExitRoot', type: 'bytes32[32]' },
      { name: 'smtProofRollupExitRoot', type: 'bytes32[32]' },
      { name: 'globalIndex', type: 'uint256' },
      { name: 'mainnetExitRoot', type: 'bytes32' },
      { name: 'rollupExitRoot', type: 'bytes32' },
      { name: 'originNetwork', type: 'uint32' },
      { name: 'originTokenAddress', type: 'address' },
      { name: 'destinationNetwork', type: 'uint32' },
      { name: 'destinationAddress', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'metadata', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    name: 'claimMessage',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'smtProofLocalExitRoot', type: 'bytes32[32]' },
      { name: 'smtProofRollupExitRoot', type: 'bytes32[32]' },
      { name: 'globalIndex', type: 'uint256' },
      { name: 'mainnetExitRoot', type: 'bytes32' },
      { name: 'rollupExitRoot', type: 'bytes32' },
      { name: 'originNetwork', type: 'uint32' },
      { name: 'originAddress', type: 'address' },
      { name: 'destinationNetwork', type: 'uint32' },
      { name: 'destinationAddress', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'metadata', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    name: 'isClaimed',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'leafIndex', type: 'uint32' },
      { name: 'sourceBridgeNetwork', type: 'uint32' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
] as const;

export const POLYGON_ZKEVM_BRIDGE_ADAPTER_ABI = [
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
] as const;

/*//////////////////////////////////////////////////////////////
                          UTILITIES
//////////////////////////////////////////////////////////////*/

/** Default Polygon zkEVM mainnet config */
export const POLYGON_ZKEVM_MAINNET_CONFIG: PolygonZkEVMConfig = {
  chainId: POLYGON_ZKEVM_CHAIN_ID,
  polygonZkEVMBridge: '0x2a3DD3EB832aF982ec71669E178424b10Dca2EDe' as Address,
  polygonZkEVMGlobalExitRoot: '0x580bda1e7A0CFAe92Fa7F6c20A3794F169CE3CFb' as Address,
  rollupManager: '0x5132A183E9F3CB7C848b0AAC5Ae0c4f0491B7aB2' as Address,
};

/** Default Polygon zkEVM Cardona testnet config */
export const POLYGON_ZKEVM_CARDONA_CONFIG: PolygonZkEVMConfig = {
  chainId: POLYGON_ZKEVM_CARDONA_CHAIN_ID,
  polygonZkEVMBridge: '0x528e26b25a34a4A5d0dbDa1d57D318153d2ED582' as Address,
  polygonZkEVMGlobalExitRoot: '0x0000000000000000000000000000000000000000' as Address,
  rollupManager: '0x0000000000000000000000000000000000000000' as Address,
};

/**
 * Compute a deposit hash for tracking
 */
export function computeDepositHash(
  originNetwork: number,
  originAddress: Address,
  destinationNetwork: number,
  destinationAddress: Address,
  amount: bigint,
  metadata: Hex
): Hash {
  return keccak256(
    encodePacked(
      ['uint32', 'address', 'uint32', 'address', 'uint256', 'bytes'],
      [originNetwork, originAddress, destinationNetwork, destinationAddress, amount, metadata]
    )
  );
}

/**
 * Get default config for a chain ID
 */
export function getPolygonZkEVMConfig(chainId: number): PolygonZkEVMConfig {
  switch (chainId) {
    case POLYGON_ZKEVM_CHAIN_ID:
      return POLYGON_ZKEVM_MAINNET_CONFIG;
    case POLYGON_ZKEVM_CARDONA_CHAIN_ID:
      return POLYGON_ZKEVM_CARDONA_CONFIG;
    default:
      throw new Error(`Unsupported Polygon zkEVM chain ID: ${chainId}`);
  }
}
