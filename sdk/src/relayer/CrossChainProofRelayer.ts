import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  type Address,
  type Hash,
  type Hex,
  type Log,
  type Chain,
} from 'viem';
import { arbitrumSepolia, baseSepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';

/**
 * Soul Protocol — Cross-Chain Proof Relayer MVP
 *
 * Monitors CrossChainProofHubV3 for new proof submissions on one chain
 * and relays them to SoulCrossChainRelay for delivery to the destination chain.
 *
 * Phase 4 deliverable: minimal viable relayer that can:
 * 1. Watch ProofSubmitted events on source chain
 * 2. Forward verified proofs to destination via SoulCrossChainRelay
 * 3. Monitor ProofFinalized / ProofRejected / ChallengeCreated events
 * 4. Log relay status and errors
 *
 * @example
 * ```typescript
 * const relayer = new CrossChainProofRelayer({
 *   sourceChain: { rpcUrl: 'https://arb-sepolia.g.alchemy.com/v2/KEY', chainId: 421614 },
 *   destChain:   { rpcUrl: 'https://base-sepolia.g.alchemy.com/v2/KEY', chainId: 84532 },
 *   proofHubAddress: '0x...',
 *   relayAddress: '0x...',
 *   privateKey: '0x...',
 * });
 * await relayer.start();
 * ```
 */

// ─── ABI: CrossChainProofHubV3 ─────────────────────────────────
const PROOF_HUB_ABI = parseAbi([
  'event ProofSubmitted(bytes32 indexed proofId, bytes32 commitment, uint64 sourceChainId, uint64 destChainId, address relayer)',
  'event ProofDataEmitted(bytes32 indexed proofId, bytes proof, bytes publicInputs)',
  'event ProofVerified(bytes32 indexed proofId, uint8 status)',
  'event ProofFinalized(bytes32 indexed proofId)',
  'event ProofRejected(bytes32 indexed proofId, string reason)',
  'event ChallengeCreated(bytes32 indexed proofId, address indexed challenger, string reason)',
  'event ChallengeResolved(bytes32 indexed proofId, bool challengerWon, address winner, uint256 reward)',
  'event RelayerSlashed(address indexed relayer, uint256 amount)',
  'function getProofStatus(bytes32 proofId) external view returns (uint8)',
  'function proofCount() external view returns (uint256)',
]);

// ─── ABI: SoulCrossChainRelay ───────────────────────────────────
const RELAY_ABI = parseAbi([
  'function relayProof(bytes32 proofId, bytes calldata proof, bytes calldata publicInputs, uint256 destChainId) external',
  'event ProofRelayed(bytes32 indexed proofId, uint256 indexed destChainId, bytes32 messageId)',
  'event ProofReceived(bytes32 indexed proofId, uint256 indexed sourceChainId)',
]);

// ─── Types ──────────────────────────────────────────────────────

export interface ChainConfig {
  rpcUrl: string;
  chainId: number;
}

export interface RelayerMVPConfig {
  sourceChain: ChainConfig;
  destChain: ChainConfig;
  proofHubAddress: Address;
  relayAddress: Address;
  privateKey: Hex;
  /** Polling interval in ms (default: 12000 = ~1 block on L2) */
  pollInterval?: number;
  /** Max retries for relay tx (default: 3) */
  maxRetries?: number;
  /** Optional callback for relay events */
  onEvent?: (event: RelayerEvent) => void;
}

export interface RelayerEvent {
  type: 'proof_submitted' | 'proof_relayed' | 'proof_finalized' | 'proof_rejected' | 'challenge' | 'slashed' | 'error';
  proofId?: string;
  message: string;
  timestamp: number;
  data?: Record<string, unknown>;
}

export interface RelayerStats {
  startedAt: number;
  proofsDetected: number;
  proofsRelayed: number;
  proofsFailed: number;
  lastBlockProcessed: bigint;
}

// ─── Chain registry ─────────────────────────────────────────────

const SUPPORTED_CHAINS: Record<number, Chain> = {
  421614: arbitrumSepolia,
  84532: baseSepolia,
};

// ─── Relayer Class ──────────────────────────────────────────────

export class CrossChainProofRelayer {
  private config: Required<RelayerMVPConfig>;
  private sourceClient: ReturnType<typeof createPublicClient>;
  private destClient: ReturnType<typeof createPublicClient>;
  private walletClient: ReturnType<typeof createWalletClient>;
  private stats: RelayerStats;
  private running = false;
  private processedProofs = new Set<string>();

  constructor(config: RelayerMVPConfig) {
    this.config = {
      pollInterval: 12_000,
      maxRetries: 3,
      onEvent: () => {},
      ...config,
    };

    const sourceChain = SUPPORTED_CHAINS[config.sourceChain.chainId];
    const destChain = SUPPORTED_CHAINS[config.destChain.chainId];

    this.sourceClient = createPublicClient({
      chain: sourceChain,
      transport: http(config.sourceChain.rpcUrl),
    });

    this.destClient = createPublicClient({
      chain: destChain,
      transport: http(config.destChain.rpcUrl),
    });

    const account = privateKeyToAccount(config.privateKey);
    this.walletClient = createWalletClient({
      account,
      chain: destChain,
      transport: http(config.destChain.rpcUrl),
    });

    this.stats = {
      startedAt: 0,
      proofsDetected: 0,
      proofsRelayed: 0,
      proofsFailed: 0,
      lastBlockProcessed: 0n,
    };
  }

  // ─── Public API ─────────────────────────────────────────────

  /** Start the relayer loop */
  async start(): Promise<void> {
    this.running = true;
    this.stats.startedAt = Date.now();
    this.emit({
      type: 'proof_submitted',
      message: `Relayer started: ${this.config.sourceChain.chainId} → ${this.config.destChain.chainId}`,
      timestamp: Date.now(),
    });

    // Get the current block as starting point
    const startBlock = await this.sourceClient.getBlockNumber();
    this.stats.lastBlockProcessed = startBlock;

    // Start watching events
    this.watchProofSubmissions();
    this.watchProofStatus();
  }

  /** Stop the relayer */
  stop(): void {
    this.running = false;
    this.emit({
      type: 'proof_submitted',
      message: 'Relayer stopped',
      timestamp: Date.now(),
    });
  }

  /** Get current stats */
  getStats(): RelayerStats {
    return { ...this.stats };
  }

  /** Check if relayer is running */
  isRunning(): boolean {
    return this.running;
  }

  // ─── Event Watchers ─────────────────────────────────────────

  private watchProofSubmissions(): void {
    this.sourceClient.watchContractEvent({
      address: this.config.proofHubAddress,
      abi: PROOF_HUB_ABI,
      eventName: 'ProofSubmitted',
      onLogs: async (logs) => {
        for (const log of logs) {
          await this.handleProofSubmitted(log);
        }
      },
      onError: (error) => {
        this.emit({
          type: 'error',
          message: `ProofSubmitted watch error: ${error.message}`,
          timestamp: Date.now(),
        });
      },
    });

    // Also watch for full proof data
    this.sourceClient.watchContractEvent({
      address: this.config.proofHubAddress,
      abi: PROOF_HUB_ABI,
      eventName: 'ProofDataEmitted',
      onLogs: async (logs) => {
        for (const log of logs) {
          await this.handleProofData(log);
        }
      },
      onError: (error) => {
        this.emit({
          type: 'error',
          message: `ProofDataEmitted watch error: ${error.message}`,
          timestamp: Date.now(),
        });
      },
    });
  }

  private watchProofStatus(): void {
    // Watch finalization
    this.sourceClient.watchContractEvent({
      address: this.config.proofHubAddress,
      abi: PROOF_HUB_ABI,
      eventName: 'ProofFinalized',
      onLogs: (logs) => {
        for (const log of logs) {
          const args = (log as any).args;
          this.emit({
            type: 'proof_finalized',
            proofId: args?.proofId,
            message: `Proof finalized: ${args?.proofId}`,
            timestamp: Date.now(),
          });
        }
      },
    });

    // Watch rejections
    this.sourceClient.watchContractEvent({
      address: this.config.proofHubAddress,
      abi: PROOF_HUB_ABI,
      eventName: 'ProofRejected',
      onLogs: (logs) => {
        for (const log of logs) {
          const args = (log as any).args;
          this.emit({
            type: 'proof_rejected',
            proofId: args?.proofId,
            message: `Proof rejected: ${args?.proofId} — ${args?.reason}`,
            timestamp: Date.now(),
            data: { reason: args?.reason },
          });
        }
      },
    });

    // Watch challenges
    this.sourceClient.watchContractEvent({
      address: this.config.proofHubAddress,
      abi: PROOF_HUB_ABI,
      eventName: 'ChallengeCreated',
      onLogs: (logs) => {
        for (const log of logs) {
          const args = (log as any).args;
          this.emit({
            type: 'challenge',
            proofId: args?.proofId,
            message: `Challenge on proof ${args?.proofId}: ${args?.reason}`,
            timestamp: Date.now(),
            data: { challenger: args?.challenger, reason: args?.reason },
          });
        }
      },
    });

    // Watch slashing
    this.sourceClient.watchContractEvent({
      address: this.config.proofHubAddress,
      abi: PROOF_HUB_ABI,
      eventName: 'RelayerSlashed',
      onLogs: (logs) => {
        for (const log of logs) {
          const args = (log as any).args;
          this.emit({
            type: 'slashed',
            message: `Relayer slashed: ${args?.relayer} for ${args?.amount}`,
            timestamp: Date.now(),
            data: { relayer: args?.relayer, amount: args?.amount?.toString() },
          });
        }
      },
    });
  }

  // ─── Event Handlers ─────────────────────────────────────────

  private async handleProofSubmitted(log: Log): Promise<void> {
    const args = (log as any).args;
    if (!args) return;

    const proofId: string = args.proofId;
    const destChainId: bigint = args.destChainId;

    // Only relay proofs targeting our destination chain
    if (Number(destChainId) !== this.config.destChain.chainId) return;

    // Skip already-processed proofs
    if (this.processedProofs.has(proofId)) return;

    this.stats.proofsDetected++;
    this.emit({
      type: 'proof_submitted',
      proofId,
      message: `New proof for dest chain ${destChainId}: ${proofId}`,
      timestamp: Date.now(),
      data: {
        sourceChainId: Number(args.sourceChainId),
        destChainId: Number(destChainId),
        commitment: args.commitment,
        relayer: args.relayer,
      },
    });
  }

  private async handleProofData(log: Log): Promise<void> {
    const args = (log as any).args;
    if (!args) return;

    const proofId: string = args.proofId;

    // Skip already-processed proofs
    if (this.processedProofs.has(proofId)) return;
    this.processedProofs.add(proofId);

    // Relay the proof
    await this.relayProofWithRetry(
      proofId,
      args.proof as Hex,
      args.publicInputs as Hex,
    );
  }

  // ─── Relay Logic ────────────────────────────────────────────

  private async relayProofWithRetry(
    proofId: string,
    proof: Hex,
    publicInputs: Hex,
  ): Promise<void> {
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      try {
        const hash = await this.walletClient.writeContract({
            chain: this.walletClient!.chain ?? null,
            account: this.walletClient!.account!,
          address: this.config.relayAddress,
          abi: RELAY_ABI,
          functionName: 'relayProof',
          args: [
            proofId as Hex,
            proof,
            publicInputs,
            BigInt(this.config.destChain.chainId),
          ],
        });

        // Wait for confirmation
        const receipt = await this.destClient.waitForTransactionReceipt({
          hash: hash as Hash,
          confirmations: 1,
        });

        if (receipt.status === 'success') {
          this.stats.proofsRelayed++;
          this.emit({
            type: 'proof_relayed',
            proofId,
            message: `Proof relayed successfully: ${proofId} (tx: ${hash})`,
            timestamp: Date.now(),
            data: { txHash: hash, gasUsed: receipt.gasUsed.toString() },
          });
          return;
        } else {
          throw new Error(`Relay tx reverted: ${hash}`);
        }
      } catch (error) {
        lastError = error as Error;
        this.emit({
          type: 'error',
          proofId,
          message: `Relay attempt ${attempt}/${this.config.maxRetries} failed: ${lastError.message}`,
          timestamp: Date.now(),
        });

        // Exponential backoff
        if (attempt < this.config.maxRetries) {
          await this.sleep(2 ** attempt * 1000);
        }
      }
    }

    this.stats.proofsFailed++;
    this.emit({
      type: 'error',
      proofId,
      message: `Relay failed after ${this.config.maxRetries} attempts: ${lastError?.message}`,
      timestamp: Date.now(),
    });
  }

  // ─── Utilities ──────────────────────────────────────────────

  private emit(event: RelayerEvent): void {
    console.log(`[Relayer ${event.type}] ${event.message}`);
    this.config.onEvent(event);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// ─── CLI Entry Point ──────────────────────────────────────────

export async function startRelayerCLI(): Promise<void> {
  const sourceRpc = process.env.SOURCE_RPC || 'http://localhost:8545';
  const destRpc = process.env.DEST_RPC || 'http://localhost:8546';
  const sourceChainId = parseInt(process.env.SOURCE_CHAIN_ID || '421614', 10);
  const destChainId = parseInt(process.env.DEST_CHAIN_ID || '84532', 10);
  const proofHub = process.env.PROOF_HUB_ADDRESS as Address;
  const relayAddr = process.env.RELAY_ADDRESS as Address;
  const pk = process.env.RELAYER_PRIVATE_KEY as Hex;

  if (!proofHub || !relayAddr || !pk) {
    console.error('Missing required env vars: PROOF_HUB_ADDRESS, RELAY_ADDRESS, RELAYER_PRIVATE_KEY');
    process.exit(1);
  }

  const relayer = new CrossChainProofRelayer({
    sourceChain: { rpcUrl: sourceRpc, chainId: sourceChainId },
    destChain: { rpcUrl: destRpc, chainId: destChainId },
    proofHubAddress: proofHub,
    relayAddress: relayAddr,
    privateKey: pk,
  });

  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log('\nShutting down relayer...');
    relayer.stop();
    const stats = relayer.getStats();
    console.log(`Final stats: ${stats.proofsRelayed} relayed, ${stats.proofsFailed} failed out of ${stats.proofsDetected} detected`);
    process.exit(0);
  });

  await relayer.start();
  console.log(`Relayer running: chain ${sourceChainId} → chain ${destChainId}`);
}

// Run if invoked directly
if (typeof require !== 'undefined' && require.main === module) {
  startRelayerCLI().catch(console.error);
}
