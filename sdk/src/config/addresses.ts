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

  // Privacy Infrastructure
  privacyRouter?: Hex;
  universalShieldedPool?: Hex;
  stealthAddressRegistry?: Hex;
  viewKeyRegistry?: Hex;
  batchAccumulator?: Hex;
  dataAvailabilityOracle?: Hex;

  // Bridge & Cross-Chain
  bridgeCircuitBreaker?: Hex;
  crossChainPrivacyHub?: Hex;

  // Relayer
  relayerFeeMarket?: Hex;
  relayerStaking?: Hex;
  decentralizedRelayerRegistry?: Hex;

  // L2 Cross-Chain Infrastructure
  privacyZoneManager?: Hex;
  soulCrossChainRelay?: Hex;
  optimisticBridgeVerifier?: Hex;
  bridgeRateLimiter?: Hex;
  bridgeWatchtower?: Hex;
  bridgeFraudProof?: Hex;

  // Governance
  governor?: Hex;
  soulToken?: Hex;
  timelock?: Hex;
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
 * Base Sepolia - Deployed July 22, 2026
 * L2 cross-chain & relayer infrastructure
 */
export const BASE_SEPOLIA_ADDRESSES: Partial<SoulContractAddresses> = {
  privacyZoneManager: "0xDFBEe5bB4d4943715D4f8539cbad0a18aA75b602",
  soulCrossChainRelay: "0x65CDCdA5ba98bB0d784c3a69C826cb3B59C20251",
  optimisticBridgeVerifier: "0xBA63a3F3C5568eC6447FBe1b852a613743419D9f",
  bridgeRateLimiter: "0x23824cDbD8Ca773c5DA0202f8f41083F81aF1135",
  bridgeWatchtower: "0x3E556432Ea021046ad4BE22cB94f713f98f4B76E",
  decentralizedRelayerRegistry: "0x2472BDB087590e4F4F4bE1243ec9533828eC0D9d",
  bridgeFraudProof: "0x583E650c0385FEd1E427dF68fa91b2d8E56Df20f",
};

/**
 * Optimism Sepolia - Not yet deployed
 */
export const OPTIMISM_SEPOLIA_ADDRESSES: Partial<SoulContractAddresses> = {};

/**
 * Localhost (Hardhat/Anvil) - Soul v2 Primitives only
 */
export const LOCALHOST_ADDRESSES: Partial<SoulContractAddresses> = {
  verifier: "0x67d269191c92Caf3cD7723F116c85e6E9bf55933",
  groth16Verifier: "0xE6E340D132b5f46d1e472DebcD681B2aBc16e57E",
  proofCarryingContainer: "0xa82fF9aFd8f496c3d6ac40E2a0F282E47488CFc9",
  policyBoundProofs: "0x1613beB3B2C4f22Ee086B2b38C1476A3cE7f78E8",
  easc: "0x851356ae760d987E095750cCeb3bC6014560891C",
  cdna: "0xf5059a5D33d5853360D16C683c16e67980206f36",
};

/**
 * Get addresses for a specific chain
 * Returns null if chain is not supported or not deployed
 */
export function getAddresses(
  chainId: number,
): SoulContractAddresses | Partial<SoulContractAddresses> | null {
  switch (chainId) {
    case 11155111: // Sepolia
      return SEPOLIA_ADDRESSES;
    case 31337: // Localhost (Hardhat/Anvil)
      return LOCALHOST_ADDRESSES;
    case 84532: // Base Sepolia
      return BASE_SEPOLIA_ADDRESSES;
    case 421614: // Arbitrum Sepolia
    case 11155420: // Optimism Sepolia
      return null; // Not yet deployed
    default:
      return null; // Unknown chain
  }
}

export const SUPPORTED_CHAIN_IDS = [11155111, 84532, 31337] as const;
export type SupportedChainId = (typeof SUPPORTED_CHAIN_IDS)[number];
