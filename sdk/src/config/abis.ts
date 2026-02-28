/**
 * ZASEON - Contract ABIs
 * 
 * Minimal ABIs for SDK interactions
 */

export const ZK_BOUND_STATE_LOCKS_ABI = [
  // View functions
  { name: 'locks', type: 'function', stateMutability: 'view', inputs: [{ name: 'lockId', type: 'bytes32' }], outputs: [{ type: 'tuple', components: [{ name: 'commitment', type: 'bytes32' }, { name: 'nullifierHash', type: 'bytes32' }, { name: 'amount', type: 'uint256' }, { name: 'token', type: 'address' }, { name: 'creator', type: 'address' }, { name: 'createdAt', type: 'uint256' }, { name: 'expiresAt', type: 'uint256' }, { name: 'destinationChainId', type: 'uint256' }, { name: 'status', type: 'uint8' }] }] },
  { name: 'nullifierUsed', type: 'function', stateMutability: 'view', inputs: [{ name: 'nullifier', type: 'bytes32' }], outputs: [{ type: 'bool' }] },
  { name: 'totalLocksCreated', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'totalLocksUnlocked', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'getActiveLockCount', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'paused', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'bool' }] },
  
  // State-changing functions
  { name: 'createLock', type: 'function', stateMutability: 'payable', inputs: [{ name: 'commitment', type: 'bytes32' }, { name: 'nullifierHash', type: 'bytes32' }, { name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'destinationChainId', type: 'uint256' }, { name: 'expiresAt', type: 'uint256' }], outputs: [{ name: 'lockId', type: 'bytes32' }] },
  { name: 'unlockWithProof', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'lockId', type: 'bytes32' }, { name: 'nullifier', type: 'bytes32' }, { name: 'recipient', type: 'address' }, { name: 'proof', type: 'bytes' }], outputs: [] },
  { name: 'initiateOptimisticUnlock', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'lockId', type: 'bytes32' }, { name: 'nullifier', type: 'bytes32' }, { name: 'recipient', type: 'address' }], outputs: [] },
  { name: 'challengeUnlock', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'lockId', type: 'bytes32' }, { name: 'fraudProof', type: 'bytes' }], outputs: [] },
  { name: 'refundExpiredLock', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'lockId', type: 'bytes32' }], outputs: [] },
  
  // Events
  { name: 'LockCreated', type: 'event', inputs: [{ name: 'lockId', type: 'bytes32', indexed: true }, { name: 'creator', type: 'address', indexed: true }, { name: 'commitment', type: 'bytes32' }, { name: 'amount', type: 'uint256' }] },
  { name: 'LockUnlocked', type: 'event', inputs: [{ name: 'lockId', type: 'bytes32', indexed: true }, { name: 'recipient', type: 'address', indexed: true }, { name: 'nullifier', type: 'bytes32' }] },
  { name: 'LockRefunded', type: 'event', inputs: [{ name: 'lockId', type: 'bytes32', indexed: true }, { name: 'creator', type: 'address', indexed: true }] },
] as const;

export const NULLIFIER_REGISTRY_ABI = [
  { name: 'isNullifierUsed', type: 'function', stateMutability: 'view', inputs: [{ name: 'nullifier', type: 'bytes32' }], outputs: [{ type: 'bool' }] },
  { name: 'totalNullifiers', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'merkleRoot', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { name: 'historicalRoots', type: 'function', stateMutability: 'view', inputs: [{ name: 'root', type: 'bytes32' }], outputs: [{ type: 'bool' }] },
  { name: 'exists', type: 'function', stateMutability: 'view', inputs: [{ name: 'nullifier', type: 'bytes32' }], outputs: [{ type: 'bool' }] },
  { name: 'isValidRoot', type: 'function', stateMutability: 'view', inputs: [{ name: 'root', type: 'bytes32' }], outputs: [{ type: 'bool' }] },
] as const;

export const CROSS_CHAIN_PROOF_HUB_ABI = [
  { name: 'totalProofs', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'totalBatches', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'challengePeriod', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'minRelayerStake', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'supportedChains', type: 'function', stateMutability: 'view', inputs: [{ name: 'chainId', type: 'uint256' }], outputs: [{ type: 'bool' }] },
  { name: 'relayerStakes', type: 'function', stateMutability: 'view', inputs: [{ name: 'relayer', type: 'address' }], outputs: [{ type: 'uint256' }] },
  { name: 'depositStake', type: 'function', stateMutability: 'payable', inputs: [], outputs: [] },
  { name: 'withdrawStake', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'amount', type: 'uint256' }], outputs: [] },
] as const;

export const ATOMIC_SWAP_ABI = [
  { name: 'swaps', type: 'function', stateMutability: 'view', inputs: [{ name: 'swapId', type: 'bytes32' }], outputs: [{ type: 'tuple', components: [{ name: 'initiator', type: 'address' }, { name: 'participant', type: 'address' }, { name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'hashlock', type: 'bytes32' }, { name: 'timelock', type: 'uint256' }, { name: 'status', type: 'uint8' }] }] },
  { name: 'protocolFeeBps', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'MAX_FEE_BPS', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'initiateSwap', type: 'function', stateMutability: 'payable', inputs: [{ name: 'participant', type: 'address' }, { name: 'hashlock', type: 'bytes32' }, { name: 'timelock', type: 'uint256' }, { name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [{ name: 'swapId', type: 'bytes32' }] },
  { name: 'claimSwap', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'swapId', type: 'bytes32' }, { name: 'preimage', type: 'bytes32' }], outputs: [] },
  { name: 'refundSwap', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'swapId', type: 'bytes32' }], outputs: [] },
] as const;

export const CONFIDENTIAL_STATE_CONTAINER_ABI = [
  { name: 'totalStates', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'getState', type: 'function', stateMutability: 'view', inputs: [{ name: 'stateId', type: 'bytes32' }], outputs: [{ type: 'tuple', components: [{ name: 'encryptedData', type: 'bytes' }, { name: 'commitment', type: 'bytes32' }, { name: 'owner', type: 'address' }, { name: 'createdAt', type: 'uint256' }] }] },
  { name: 'createState', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'encryptedData', type: 'bytes' }, { name: 'commitment', type: 'bytes32' }], outputs: [{ name: 'stateId', type: 'bytes32' }] },
] as const;

// PC3, PBP, EASC, CDNA ABIs are defined in Zaseonv2Primitives.ts
