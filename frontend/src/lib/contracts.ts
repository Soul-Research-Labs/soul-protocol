'use client';

import { useChainId } from 'wagmi';

// Contract addresses per network
// These will be populated after testnet deployment
const CONTRACT_ADDRESSES: Record<number, ContractAddresses> = {
  // Sepolia Testnet
  11155111: {
    verifierRegistry: '',
    groth16VerifierBN254: '',
    proofCarryingContainer: '',
    policyBoundProofs: '',
    executionAgnosticStateCommitments: '',
    crossDomainNullifierAlgebra: '',
    pilv2Orchestrator: '',
    pilTimelock: '',
    timelockAdmin: '',
  },
  // Goerli (deprecated but kept for reference)
  5: {
    verifierRegistry: '',
    groth16VerifierBN254: '',
    proofCarryingContainer: '',
    policyBoundProofs: '',
    executionAgnosticStateCommitments: '',
    crossDomainNullifierAlgebra: '',
    pilv2Orchestrator: '',
    pilTimelock: '',
    timelockAdmin: '',
  },
  // Mumbai (Polygon testnet)
  80001: {
    verifierRegistry: '',
    groth16VerifierBN254: '',
    proofCarryingContainer: '',
    policyBoundProofs: '',
    executionAgnosticStateCommitments: '',
    crossDomainNullifierAlgebra: '',
    pilv2Orchestrator: '',
    pilTimelock: '',
    timelockAdmin: '',
  },
  // Localhost / Hardhat
  31337: {
    verifierRegistry: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    groth16VerifierBN254: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
    proofCarryingContainer: '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0',
    policyBoundProofs: '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9',
    executionAgnosticStateCommitments: '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9',
    crossDomainNullifierAlgebra: '0x5FC8d32690cc91D4c39d9d3abcBD16989F875707',
    pilv2Orchestrator: '0x0165878A594ca255338adfa4d48449f69242Eb8F',
    pilTimelock: '0xa513E6E4b8f2a923D98304ec87F64353C4D5C853',
    timelockAdmin: '0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6',
  },
};

interface ContractAddresses {
  verifierRegistry: string;
  groth16VerifierBN254: string;
  proofCarryingContainer: string;
  policyBoundProofs: string;
  executionAgnosticStateCommitments: string;
  crossDomainNullifierAlgebra: string;
  pilv2Orchestrator: string;
  pilTimelock: string;
  timelockAdmin: string;
}

export function useContracts(): ContractAddresses {
  const chainId = useChainId();
  
  const addresses = CONTRACT_ADDRESSES[chainId];
  
  if (!addresses) {
    console.warn(`No contract addresses configured for chain ${chainId}`);
    return {
      verifierRegistry: '',
      groth16VerifierBN254: '',
      proofCarryingContainer: '',
      policyBoundProofs: '',
      executionAgnosticStateCommitments: '',
      crossDomainNullifierAlgebra: '',
      pilv2Orchestrator: '',
      pilTimelock: '',
      timelockAdmin: '',
    };
  }
  
  return addresses;
}

export function getContractAddress(chainId: number, contractName: keyof ContractAddresses): string {
  const addresses = CONTRACT_ADDRESSES[chainId];
  if (!addresses) return '';
  return addresses[contractName];
}

// Export for use in deployment scripts
export function updateContractAddresses(chainId: number, addresses: Partial<ContractAddresses>) {
  if (!CONTRACT_ADDRESSES[chainId]) {
    CONTRACT_ADDRESSES[chainId] = {
      verifierRegistry: '',
      groth16VerifierBN254: '',
      proofCarryingContainer: '',
      policyBoundProofs: '',
      executionAgnosticStateCommitments: '',
      crossDomainNullifierAlgebra: '',
      pilv2Orchestrator: '',
      pilTimelock: '',
      timelockAdmin: '',
    };
  }
  Object.assign(CONTRACT_ADDRESSES[chainId], addresses);
}
