/**
 * Soul Protocol - Contract Addresses
 * 
 * Deployed contract addresses per network
 */

import { Hex } from "viem";

export interface SoulContractAddresses {
  // Verifiers
  verifier: Hex;
  groth16Verifier: Hex;
  noirVerifier: Hex;
  ultraHonkVerifier: Hex;
  
  // Core Infrastructure
  stateContainer: Hex;
  nullifierRegistry: Hex;
  proofHub: Hex;
  
  // Application Layer
  atomicSwap: Hex;
  compliance: Hex;
  
  // Soul v2 Primitives
  proofCarryingContainer: Hex;
  policyBoundProofs: Hex;
  easc: Hex;
  cdna: Hex;
  
  // Security
  emergencyRecovery: Hex;
  
  // ZK-Bound State Locks
  zkBoundStateLocks: Hex;
  zkSLockIntegration: Hex;
}

/**
 * Sepolia Testnet - Deployed January 22, 2026
 */
export const SEPOLIA_ADDRESSES: SoulContractAddresses = {
  // Verifiers
  verifier: "0x1f830a178020d9d9b968b9f4d13e6e4cdbc9fa57",
  groth16Verifier: "0x09cf3f57c213218446aa49d89236247fbe1d08bd",
  noirVerifier: "0x0000000000000000000000000000000000000000",
  ultraHonkVerifier: "0x0000000000000000000000000000000000000000",
  
  // Core Infrastructure
  stateContainer: "0x5d79991daabf7cd198860a55f3a1f16548687798",
  nullifierRegistry: "0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191",
  proofHub: "0x40eaa5de0c6497c8943c967b42799cb092c26adc",
  
  // Application Layer
  atomicSwap: "0xdefb9a66dc14a6d247b282555b69da7745b0ab57",
  compliance: "0x5d41f63f35babed689a63f7e5c9e2943e1f72067",
  
  // Soul v2 Primitives
  proofCarryingContainer: "0x52f8a660ff436c450b5190a84bc2c1a86f1032cc",
  policyBoundProofs: "0x75e86ee654eae62a93c247e4ab9facf63bc4f328",
  easc: "0x77d22cb55253fea1ccc14ffc86a22e4a5a4592c6",
  cdna: "0x674d0cbfb5bf33981b1656abf6a47cff46430b0c",
  
  // Security
  emergencyRecovery: "0x1995dbb199c26afd73a817aaafbccbf28f070ffc",
  
  // ZK-Bound State Locks
  zkBoundStateLocks: "0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78",
  zkSLockIntegration: "0x668c1a8197d59b5cf4d3802e209d3784c6f69b29",
};

/**
 * Arbitrum Sepolia - Not yet deployed
 */
export const ARBITRUM_SEPOLIA_ADDRESSES: Partial<SoulContractAddresses> = {};

/**
 * Base Sepolia - Not yet deployed
 */
export const BASE_SEPOLIA_ADDRESSES: Partial<SoulContractAddresses> = {};

/**
 * Optimism Sepolia - Not yet deployed
 */
export const OPTIMISM_SEPOLIA_ADDRESSES: Partial<SoulContractAddresses> = {};

/**
 * Get addresses for a specific chain
 * Returns null if chain is not supported or not deployed
 */
export function getAddresses(chainId: number): SoulContractAddresses | null {
  switch (chainId) {
    case 11155111: // Sepolia
      return SEPOLIA_ADDRESSES;
    case 421614: // Arbitrum Sepolia
    case 84532: // Base Sepolia
    case 11155420: // Optimism Sepolia
      return null; // Not yet deployed
    default:
      return null; // Unknown chain
  }
}

export const SUPPORTED_CHAIN_IDS = [11155111] as const;
export type SupportedChainId = typeof SUPPORTED_CHAIN_IDS[number];
