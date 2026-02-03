/**
 * Soul-Midnight Bridge SDK
 * 
 * TypeScript SDK for bridging assets between Midnight Network and Ethereum/L2s.
 * Provides unified API for cross-chain private transfers.
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  getContract,
  type PublicClient,
  type WalletClient,
  type Hash,
  type Hex,
  type Address,
  keccak256,
  encodePacked,
  toBytes,
  toHex,
  parseEther,
} from 'viem';
import { mainnet, arbitrum, optimism, base, zkSync, scroll, linea, polygonZkEvm } from 'viem/chains';

// =============================================================================
// TYPES
// =============================================================================

/**
 * Supported chains for bridging
 */
export enum SupportedChain {
  Midnight = 0,          // Midnight Network
  Ethereum = 1,
  Arbitrum = 42161,
  ArbitrumSepolia = 421614,
  Optimism = 10,
  Base = 8453,
  ZkSync = 324,
  Scroll = 534352,
  Linea = 59144,
  PolygonZkEVM = 1101,
}

/**
 * Bridge transfer direction
 */
export enum BridgeDirection {
  MidnightToEthereum = 'MIDNIGHT_TO_ETHEREUM',
  EthereumToMidnight = 'ETHEREUM_TO_MIDNIGHT',
  L2ToMidnight = 'L2_TO_MIDNIGHT',
  MidnightToL2 = 'MIDNIGHT_TO_L2',
  L2ToL2ViaMidnight = 'L2_TO_L2_VIA_MIDNIGHT',
}

/**
 * Transfer status
 */
export enum TransferStatus {
  Pending = 'PENDING',
  Locked = 'LOCKED',
  Confirmed = 'CONFIRMED',
  Claimed = 'CLAIMED',
  Refunded = 'REFUNDED',
  Failed = 'FAILED',
}

/**
 * Asset type
 */
export interface Asset {
  address: Address;
  symbol: string;
  decimals: number;
  midnightToken?: string;
}

/**
 * Bridge transfer parameters
 */
export interface BridgeTransferParams {
  sourceChain: SupportedChain;
  destChain: SupportedChain;
  asset: Asset;
  amount: bigint;
  recipient: string;          // Ethereum address or Midnight address
  privateNote?: string;       // Optional private note (encrypted)
}

/**
 * Bridge transfer result
 */
export interface BridgeTransferResult {
  transferId: Hex;
  txHash: Hash;
  commitment: Hex;
  nullifier?: Hex;
  status: TransferStatus;
  sourceChain: SupportedChain;
  destChain: SupportedChain;
  amount: bigint;
  timestamp: number;
}

/**
 * Midnight proof bundle
 */
export interface MidnightProofBundle {
  commitment: Hex;
  nullifier: Hex;
  merkleRoot: Hex;
  proof: Hex;
  midnightBlock: bigint;
  stateRoot: Hex;
}

/**
 * Lock details from Ethereum/L2
 */
export interface LockDetails {
  lockId: Hex;
  token: Address;
  amount: bigint;
  commitment: Hex;
  midnightRecipient: Hex;
  sender: Address;
  createdAt: bigint;
  deadline: bigint;
  status: number;
}

/**
 * Bridge statistics
 */
export interface BridgeStats {
  totalLocks: bigint;
  totalValueLockedETH: bigint;
  totalValueLockedTokens: Map<Address, bigint>;
  activeTransfers: number;
  completedTransfers: number;
}

/**
 * SDK Configuration
 */
export interface MidnightBridgeConfig {
  ethereumRpcUrl: string;
  midnightRpcUrl?: string;
  privateKey?: Hex;
  bridgeHubAddress: Address;
  proofVerifierAddress: Address;
  l2AdapterAddress?: Address;
  chainId: SupportedChain;
}

// =============================================================================
// CONTRACT ABIs
// =============================================================================

const BRIDGE_HUB_ABI = [
  {
    type: 'function',
    name: 'lockETHForMidnight',
    inputs: [
      { name: 'commitment', type: 'bytes32' },
      { name: 'midnightRecipient', type: 'bytes32' }
    ],
    outputs: [{ name: 'lockId', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'lockTokenForMidnight',
    inputs: [
      { name: 'token', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'commitment', type: 'bytes32' },
      { name: 'midnightRecipient', type: 'bytes32' }
    ],
    outputs: [{ name: 'lockId', type: 'bytes32' }],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'claimFromMidnight',
    inputs: [
      { name: 'proof', type: 'tuple', components: [
        { name: 'commitment', type: 'bytes32' },
        { name: 'nullifier', type: 'bytes32' },
        { name: 'merkleRoot', type: 'bytes32' },
        { name: 'proof', type: 'bytes' },
        { name: 'midnightBlock', type: 'uint64' },
        { name: 'stateRoot', type: 'bytes32' }
      ]},
      { name: 'token', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'recipient', type: 'address' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'refundLock',
    inputs: [{ name: 'lockId', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'getLock',
    inputs: [{ name: 'lockId', type: 'bytes32' }],
    outputs: [{
      type: 'tuple',
      components: [
        { name: 'lockId', type: 'bytes32' },
        { name: 'token', type: 'address' },
        { name: 'amount', type: 'uint256' },
        { name: 'commitment', type: 'bytes32' },
        { name: 'midnightRecipient', type: 'bytes32' },
        { name: 'ethSender', type: 'address' },
        { name: 'createdAt', type: 'uint64' },
        { name: 'unlockDeadline', type: 'uint64' },
        { name: 'status', type: 'uint8' }
      ]
    }],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'isNullifierUsed',
    inputs: [{ name: 'nullifier', type: 'bytes32' }],
    outputs: [{ type: 'bool' }],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'getMidnightState',
    inputs: [],
    outputs: [{
      type: 'tuple',
      components: [
        { name: 'depositRoot', type: 'bytes32' },
        { name: 'nullifierRoot', type: 'bytes32' },
        { name: 'blockNumber', type: 'uint64' },
        { name: 'timestamp', type: 'uint64' },
        { name: 'stateHash', type: 'bytes32' }
      ]
    }],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'totalLocks',
    inputs: [],
    outputs: [{ type: 'uint256' }],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'getTVL',
    inputs: [{ name: 'token', type: 'address' }],
    outputs: [{ type: 'uint256' }],
    stateMutability: 'view'
  },
  {
    type: 'event',
    name: 'LockCreated',
    inputs: [
      { name: 'lockId', type: 'bytes32', indexed: true },
      { name: 'sender', type: 'address', indexed: true },
      { name: 'token', type: 'address', indexed: true },
      { name: 'amount', type: 'uint256' },
      { name: 'commitment', type: 'bytes32' },
      { name: 'midnightRecipient', type: 'bytes32' }
    ]
  },
  {
    type: 'event',
    name: 'ClaimProcessed',
    inputs: [
      { name: 'claimId', type: 'bytes32', indexed: true },
      { name: 'nullifier', type: 'bytes32', indexed: true },
      { name: 'recipient', type: 'address', indexed: true },
      { name: 'token', type: 'address' },
      { name: 'amount', type: 'uint256' }
    ]
  }
] as const;

// =============================================================================
// MIDNIGHT BRIDGE CLIENT
// =============================================================================

/**
 * Main client for Midnight Bridge operations
 */
export class MidnightBridgeClient {
  private publicClient: PublicClient;
  private walletClient?: WalletClient;
  private config: MidnightBridgeConfig;

  constructor(config: MidnightBridgeConfig) {
    this.config = config;
    
    // Create public client for reading
    this.publicClient = createPublicClient({
      chain: this.getViemChain(config.chainId),
      transport: http(config.ethereumRpcUrl),
    });

    // Create wallet client if private key provided
    if (config.privateKey) {
      this.walletClient = createWalletClient({
        chain: this.getViemChain(config.chainId),
        transport: http(config.ethereumRpcUrl),
      });
    }
  }

  /**
   * Get viem chain config
   */
  private getViemChain(chainId: SupportedChain) {
    switch (chainId) {
      case SupportedChain.Ethereum: return mainnet;
      case SupportedChain.Arbitrum: return arbitrum;
      case SupportedChain.Optimism: return optimism;
      case SupportedChain.Base: return base;
      case SupportedChain.ZkSync: return zkSync;
      case SupportedChain.Scroll: return scroll;
      case SupportedChain.Linea: return linea;
      case SupportedChain.PolygonZkEVM: return polygonZkEvm;
      default: return mainnet;
    }
  }

  /**
   * Get bridge hub contract
   */
  private getBridgeHub() {
    return getContract({
      address: this.config.bridgeHubAddress,
      abi: BRIDGE_HUB_ABI,
      client: this.publicClient,
    });
  }

  // ===========================================================================
  // ETHEREUM → MIDNIGHT
  // ===========================================================================

  /**
   * Generate commitment for private transfer
   */
  generateCommitment(
    amount: bigint,
    recipient: string,
    secret: Hex
  ): { commitment: Hex; nullifier: Hex } {
    // Generate commitment using Poseidon-like hash
    const commitment = keccak256(
      encodePacked(
        ['bytes32', 'uint256', 'bytes32', 'bytes32'],
        [toHex(toBytes('SOUL_MIDNIGHT_COMMITMENT', { size: 32 })), amount, recipient as Hex, secret]
      )
    );

    // Generate nullifier
    const nullifier = keccak256(
      encodePacked(
        ['bytes32', 'bytes32', 'uint256'],
        [secret, commitment, BigInt(this.config.chainId)]
      )
    );

    return { commitment, nullifier };
  }

  /**
   * Lock ETH for transfer to Midnight
   */
  async lockETHForMidnight(
    amount: bigint,
    midnightRecipient: Hex,
    secret?: Hex
  ): Promise<BridgeTransferResult> {
    if (!this.walletClient) {
      throw new Error('Wallet client required for write operations');
    }

    // Generate commitment
    const userSecret = secret || this.generateSecret();
    const { commitment, nullifier } = this.generateCommitment(amount, midnightRecipient, userSecret);

    // Execute lock
    const hash = await this.walletClient.writeContract({
      address: this.config.bridgeHubAddress,
      abi: BRIDGE_HUB_ABI,
      functionName: 'lockETHForMidnight',
      args: [commitment, midnightRecipient],
      value: amount,
    });

    // Wait for confirmation
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    // Parse lock ID from logs
    const lockId = this.parseLockIdFromReceipt(receipt);

    return {
      transferId: lockId,
      txHash: hash,
      commitment,
      nullifier,
      status: TransferStatus.Pending,
      sourceChain: this.config.chainId,
      destChain: SupportedChain.Midnight,
      amount,
      timestamp: Date.now(),
    };
  }

  /**
   * Lock ERC20 tokens for transfer to Midnight
   */
  async lockTokenForMidnight(
    token: Address,
    amount: bigint,
    midnightRecipient: Hex,
    secret?: Hex
  ): Promise<BridgeTransferResult> {
    if (!this.walletClient) {
      throw new Error('Wallet client required for write operations');
    }

    const userSecret = secret || this.generateSecret();
    const { commitment, nullifier } = this.generateCommitment(amount, midnightRecipient, userSecret);

    // Approve token spending first
    await this.approveToken(token, amount);

    // Execute lock
    const hash = await this.walletClient.writeContract({
      address: this.config.bridgeHubAddress,
      abi: BRIDGE_HUB_ABI,
      functionName: 'lockTokenForMidnight',
      args: [token, amount, commitment, midnightRecipient],
    });

    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    const lockId = this.parseLockIdFromReceipt(receipt);

    return {
      transferId: lockId,
      txHash: hash,
      commitment,
      nullifier,
      status: TransferStatus.Pending,
      sourceChain: this.config.chainId,
      destChain: SupportedChain.Midnight,
      amount,
      timestamp: Date.now(),
    };
  }

  // ===========================================================================
  // MIDNIGHT → ETHEREUM
  // ===========================================================================

  /**
   * Claim tokens from Midnight with ZK proof
   */
  async claimFromMidnight(
    proof: MidnightProofBundle,
    token: Address,
    amount: bigint,
    recipient: Address
  ): Promise<{ txHash: Hash; claimId: Hex }> {
    if (!this.walletClient) {
      throw new Error('Wallet client required for write operations');
    }

    // Check nullifier not used
    const isUsed = await this.isNullifierUsed(proof.nullifier);
    if (isUsed) {
      throw new Error('Nullifier already used - possible double-spend attempt');
    }

    // Execute claim
    const hash = await this.walletClient.writeContract({
      address: this.config.bridgeHubAddress,
      abi: BRIDGE_HUB_ABI,
      functionName: 'claimFromMidnight',
      args: [
        {
          commitment: proof.commitment,
          nullifier: proof.nullifier,
          merkleRoot: proof.merkleRoot,
          proof: proof.proof,
          midnightBlock: proof.midnightBlock,
          stateRoot: proof.stateRoot,
        },
        token,
        amount,
        recipient,
      ],
    });

    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    // Parse claim ID from logs
    const claimId = this.parseClaimIdFromReceipt(receipt);

    return { txHash: hash, claimId };
  }

  /**
   * Refund expired lock
   */
  async refundLock(lockId: Hex): Promise<Hash> {
    if (!this.walletClient) {
      throw new Error('Wallet client required for write operations');
    }

    const lock = await this.getLock(lockId);
    if (lock.status !== 1) { // Pending
      throw new Error('Lock is not in pending state');
    }

    const now = BigInt(Math.floor(Date.now() / 1000));
    if (now < lock.deadline) {
      throw new Error('Lock has not expired yet');
    }

    return this.walletClient.writeContract({
      address: this.config.bridgeHubAddress,
      abi: BRIDGE_HUB_ABI,
      functionName: 'refundLock',
      args: [lockId],
    });
  }

  // ===========================================================================
  // READ OPERATIONS
  // ===========================================================================

  /**
   * Get lock details
   */
  async getLock(lockId: Hex): Promise<LockDetails> {
    const bridgeHub = this.getBridgeHub();
    const lock = await bridgeHub.read.getLock([lockId]);
    
    return {
      lockId: lock.lockId,
      token: lock.token,
      amount: lock.amount,
      commitment: lock.commitment,
      midnightRecipient: lock.midnightRecipient,
      sender: lock.ethSender,
      createdAt: lock.createdAt,
      deadline: lock.unlockDeadline,
      status: lock.status,
    };
  }

  /**
   * Check if nullifier is used
   */
  async isNullifierUsed(nullifier: Hex): Promise<boolean> {
    const bridgeHub = this.getBridgeHub();
    return bridgeHub.read.isNullifierUsed([nullifier]);
  }

  /**
   * Get current Midnight state
   */
  async getMidnightState() {
    const bridgeHub = this.getBridgeHub();
    return bridgeHub.read.getMidnightState();
  }

  /**
   * Get bridge statistics
   */
  async getStats(): Promise<BridgeStats> {
    const bridgeHub = this.getBridgeHub();
    
    const totalLocks = await bridgeHub.read.totalLocks();
    const ethTVL = await bridgeHub.read.getTVL(['0x0000000000000000000000000000000000000000']);

    return {
      totalLocks,
      totalValueLockedETH: ethTVL,
      totalValueLockedTokens: new Map(),
      activeTransfers: 0, // Would need indexer
      completedTransfers: 0,
    };
  }

  // ===========================================================================
  // UTILITY FUNCTIONS
  // ===========================================================================

  /**
   * Generate random secret
   */
  generateSecret(): Hex {
    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);
    return toHex(randomBytes);
  }

  /**
   * Generate Midnight address hash from public key
   */
  generateMidnightAddress(publicKey: Hex): Hex {
    return keccak256(
      encodePacked(['bytes32', 'bytes'], [toHex(toBytes('MIDNIGHT_ADDRESS', { size: 32 })), publicKey])
    );
  }

  /**
   * Approve token for bridge hub
   */
  private async approveToken(token: Address, amount: bigint): Promise<void> {
    if (!this.walletClient) return;

    const ERC20_APPROVE_ABI = [{
      type: 'function',
      name: 'approve',
      inputs: [
        { name: 'spender', type: 'address' },
        { name: 'amount', type: 'uint256' }
      ],
      outputs: [{ type: 'bool' }],
      stateMutability: 'nonpayable'
    }] as const;

    await this.walletClient.writeContract({
      address: token,
      abi: ERC20_APPROVE_ABI,
      functionName: 'approve',
      args: [this.config.bridgeHubAddress, amount],
    });
  }

  /**
   * Parse lock ID from transaction receipt
   */
  private parseLockIdFromReceipt(receipt: any): Hex {
    // Find LockCreated event
    for (const log of receipt.logs) {
      try {
        // First topic is event signature, second is indexed lockId
        if (log.topics.length >= 2) {
          return log.topics[1] as Hex;
        }
      } catch {
        continue;
      }
    }
    throw new Error('Could not parse lock ID from receipt');
  }

  /**
   * Parse claim ID from transaction receipt
   */
  private parseClaimIdFromReceipt(receipt: any): Hex {
    for (const log of receipt.logs) {
      try {
        if (log.topics.length >= 2) {
          return log.topics[1] as Hex;
        }
      } catch {
        continue;
      }
    }
    throw new Error('Could not parse claim ID from receipt');
  }
}

// =============================================================================
// MIDNIGHT CLIENT (Stub for Midnight Network interaction)
// =============================================================================

/**
 * Client for interacting with Midnight Network
 * Note: This is a stub - actual implementation requires Midnight SDK
 */
export class MidnightNetworkClient {
  private rpcUrl: string;

  constructor(rpcUrl: string) {
    this.rpcUrl = rpcUrl;
  }

  /**
   * Lock assets on Midnight for bridge to Ethereum
   */
  async lockForBridge(
    amount: bigint,
    assetType: string,
    destinationChain: SupportedChain,
    destinationAddress: Hex
  ): Promise<{ lockId: string; commitment: Hex; proof: MidnightProofBundle }> {
    // This would use Midnight SDK to:
    // 1. Call the Compact bridge-vault contract
    // 2. Generate ZK proof
    // 3. Return proof bundle for Ethereum claim

    throw new Error('Midnight Network client not implemented - requires Midnight SDK');
  }

  /**
   * Generate bridge proof for Ethereum claim
   */
  async generateBridgeProof(lockId: string): Promise<MidnightProofBundle> {
    // This would:
    // 1. Fetch lock details from Midnight
    // 2. Generate ZK-SNARK proof
    // 3. Return proof bundle

    throw new Error('Midnight Network client not implemented - requires Midnight SDK');
  }

  /**
   * Receive assets from Ethereum on Midnight
   */
  async receiveFromEthereum(
    ethereumLockId: Hex,
    proof: Hex
  ): Promise<{ commitment: Hex; txHash: string }> {
    // This would:
    // 1. Verify Ethereum lock proof
    // 2. Mint shielded tokens on Midnight
    // 3. Return new commitment

    throw new Error('Midnight Network client not implemented - requires Midnight SDK');
  }

  /**
   * Get Midnight state for proof verification
   */
  async getState(): Promise<{ depositRoot: Hex; nullifierRoot: Hex; blockNumber: bigint }> {
    throw new Error('Midnight Network client not implemented - requires Midnight SDK');
  }
}

// =============================================================================
// BRIDGE ORCHESTRATOR
// =============================================================================

/**
 * High-level orchestrator for complete bridge flows
 */
export class MidnightBridgeOrchestrator {
  private ethereumClient: MidnightBridgeClient;
  private midnightClient?: MidnightNetworkClient;

  constructor(
    ethereumConfig: MidnightBridgeConfig,
    midnightRpcUrl?: string
  ) {
    this.ethereumClient = new MidnightBridgeClient(ethereumConfig);
    if (midnightRpcUrl) {
      this.midnightClient = new MidnightNetworkClient(midnightRpcUrl);
    }
  }

  /**
   * Complete Ethereum → Midnight transfer
   */
  async bridgeToMidnight(
    amount: bigint,
    midnightRecipient: Hex,
    isETH: boolean = true,
    token?: Address
  ): Promise<BridgeTransferResult> {
    if (isETH) {
      return this.ethereumClient.lockETHForMidnight(amount, midnightRecipient);
    } else if (token) {
      return this.ethereumClient.lockTokenForMidnight(token, amount, midnightRecipient);
    }
    throw new Error('Token address required for ERC20 transfers');
  }

  /**
   * Complete Midnight → Ethereum transfer
   */
  async bridgeFromMidnight(
    proof: MidnightProofBundle,
    token: Address,
    amount: bigint,
    recipient: Address
  ): Promise<{ txHash: Hash; claimId: Hex }> {
    return this.ethereumClient.claimFromMidnight(proof, token, amount, recipient);
  }

  /**
   * Get transfer status
   */
  async getTransferStatus(lockId: Hex): Promise<TransferStatus> {
    const lock = await this.ethereumClient.getLock(lockId);
    
    switch (lock.status) {
      case 0: return TransferStatus.Pending;
      case 1: return TransferStatus.Pending;
      case 2: return TransferStatus.Confirmed;
      case 3: return TransferStatus.Claimed;
      case 4: return TransferStatus.Refunded;
      default: return TransferStatus.Failed;
    }
  }

  /**
   * Refund expired transfer
   */
  async refundTransfer(lockId: Hex): Promise<Hash> {
    return this.ethereumClient.refundLock(lockId);
  }

  /**
   * Get bridge statistics
   */
  async getStats(): Promise<BridgeStats> {
    return this.ethereumClient.getStats();
  }
}

// =============================================================================
// EXPORTS
// =============================================================================

export {
  MidnightBridgeClient,
  MidnightNetworkClient,
  MidnightBridgeOrchestrator,
};

// Factory function
export function createMidnightBridge(config: MidnightBridgeConfig): MidnightBridgeClient {
  return new MidnightBridgeClient(config);
}

// Read-only client
export function createReadOnlyBridge(
  rpcUrl: string,
  bridgeHubAddress: Address,
  chainId: SupportedChain = SupportedChain.Ethereum
): MidnightBridgeClient {
  return new MidnightBridgeClient({
    ethereumRpcUrl: rpcUrl,
    bridgeHubAddress,
    proofVerifierAddress: '0x0000000000000000000000000000000000000000' as Address,
    chainId,
  });
}
