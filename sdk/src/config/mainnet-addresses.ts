/**
 * ZASEON - Mainnet & L2 Address Configuration
 *
 * ⚠️ WARNING: ALL addresses below are zero (NOT DEPLOYED).
 * This file will be auto-populated by deployment scripts:
 *   scripts/deploy/populate-sdk-addresses.ts
 *
 * Use `verifyAddressesConfigured()` to validate before production use.
 * Current deployment status:
 *   - Sepolia (11155111): DEPLOYED — see config/addresses.ts
 *   - Mainnet (1): NOT DEPLOYED
 *   - Arbitrum (42161): NOT DEPLOYED
 *   - Base (8453): NOT DEPLOYED
 *   - Optimism (10): NOT DEPLOYED
 */

export const MAINNET_ADDRESSES = {
  // Core Infrastructure
  zkBoundStateLocks: "0x0000000000000000000000000000000000000000",
  nullifierRegistry: "0x0000000000000000000000000000000000000000",
  proofHub: "0x0000000000000000000000000000000000000000",
  atomicSwap: "0x0000000000000000000000000000000000000000",

  // Zaseon v2 Primitives
  proofCarryingContainer: "0x0000000000000000000000000000000000000000",
  policyBoundProofs: "0x0000000000000000000000000000000000000000",
  executionAgnosticStateCommitments:
    "0x0000000000000000000000000000000000000000",
  crossDomainNullifierAlgebra: "0x0000000000000000000000000000000000000000",

  // Verifiers
  groth16Verifier: "0x0000000000000000000000000000000000000000",
  noirVerifier: "0x0000000000000000000000000000000000000000",
  ultraHonkVerifier: "0x0000000000000000000000000000000000000000",

  // Security
  emergencyRecovery: "0x0000000000000000000000000000000000000000",

  // Governance
  timelock: "0x0000000000000000000000000000000000000000",
  multisig: "0x0000000000000000000000000000000000000000",
};

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export const ARBITRUM_ADDRESSES = {
  zkBoundStateLocks: ZERO_ADDRESS,
  nullifierRegistry: ZERO_ADDRESS,
  proofHub: ZERO_ADDRESS,
  atomicSwap: ZERO_ADDRESS,
  proofCarryingContainer: ZERO_ADDRESS,
  policyBoundProofs: ZERO_ADDRESS,
  executionAgnosticStateCommitments: ZERO_ADDRESS,
  crossDomainNullifierAlgebra: ZERO_ADDRESS,
  groth16Verifier: ZERO_ADDRESS,
  noirVerifier: ZERO_ADDRESS,
  ultraHonkVerifier: ZERO_ADDRESS,
  emergencyRecovery: ZERO_ADDRESS,
  timelock: ZERO_ADDRESS,
  multisig: ZERO_ADDRESS,
};

export const BASE_ADDRESSES = {
  zkBoundStateLocks: ZERO_ADDRESS,
  nullifierRegistry: ZERO_ADDRESS,
  proofHub: ZERO_ADDRESS,
  atomicSwap: ZERO_ADDRESS,
  proofCarryingContainer: ZERO_ADDRESS,
  policyBoundProofs: ZERO_ADDRESS,
  executionAgnosticStateCommitments: ZERO_ADDRESS,
  crossDomainNullifierAlgebra: ZERO_ADDRESS,
  groth16Verifier: ZERO_ADDRESS,
  noirVerifier: ZERO_ADDRESS,
  ultraHonkVerifier: ZERO_ADDRESS,
  emergencyRecovery: ZERO_ADDRESS,
  timelock: ZERO_ADDRESS,
  multisig: ZERO_ADDRESS,
};

export const OPTIMISM_ADDRESSES = {
  zkBoundStateLocks: ZERO_ADDRESS,
  nullifierRegistry: ZERO_ADDRESS,
  proofHub: ZERO_ADDRESS,
  atomicSwap: ZERO_ADDRESS,
  proofCarryingContainer: ZERO_ADDRESS,
  policyBoundProofs: ZERO_ADDRESS,
  executionAgnosticStateCommitments: ZERO_ADDRESS,
  crossDomainNullifierAlgebra: ZERO_ADDRESS,
  groth16Verifier: ZERO_ADDRESS,
  noirVerifier: ZERO_ADDRESS,
  ultraHonkVerifier: ZERO_ADDRESS,
  emergencyRecovery: ZERO_ADDRESS,
  timelock: ZERO_ADDRESS,
  multisig: ZERO_ADDRESS,
};

// Chain ID to addresses mapping
export const CHAIN_ADDRESSES: Record<number, typeof MAINNET_ADDRESSES> = {
  1: MAINNET_ADDRESSES,
  42161: ARBITRUM_ADDRESSES,
  8453: BASE_ADDRESSES,
  10: OPTIMISM_ADDRESSES,
};

/**
 * Get addresses for a specific chain
 */
export function getAddressesForChain(
  chainId: number,
): typeof MAINNET_ADDRESSES | null {
  return CHAIN_ADDRESSES[chainId] ?? null;
}

/**
 * Check which addresses are set (not zero address).
 * Returns a non-throwing result with missing keys.
 *
 * For a throwing variant, use `verifyAddressesConfigured` from `@zaseon/sdk/privacy`.
 */
export function checkAddressesConfigured(addresses: typeof MAINNET_ADDRESSES): {
  valid: boolean;
  missing: string[];
} {
  const zeroAddress = "0x0000000000000000000000000000000000000000";
  const missing: string[] = [];

  for (const [key, value] of Object.entries(addresses)) {
    if (value === zeroAddress) {
      missing.push(key);
    }
  }

  return {
    valid: missing.length === 0,
    missing,
  };
}
