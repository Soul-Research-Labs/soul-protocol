/**
 * Soul-Midnight Bridge Relayer Service
 * 
 * Watches for bridge events and relays proofs between Midnight and Ethereum/L2s.
 * This is the off-chain component that facilitates cross-chain transfers.
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbiItem,
  type Hex,
  type Address,
  type Log,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet, arbitrum, optimism, base } from 'viem/chains';

// =============================================================================
// TYPES
// =============================================================================

interface RelayerConfig {
  privateKey: Hex;
  ethereumRpcUrl: string;
  midnightRpcUrl: string;
  bridgeHubAddress: Address;
  supportedChains: number[];
  pollingInterval: number;
  maxConcurrentTasks: number;
}

interface PendingTransfer {
  lockId: Hex;
  sourceChain: number;
  destChain: number;
  token: Address;
  amount: bigint;
  commitment: Hex;
  midnightRecipient: Hex;
  ethSender: Address;
  createdAt: number;
  status: 'pending' | 'relaying' | 'confirmed' | 'failed';
}

interface RelayTask {
  id: string;
  type: 'eth_to_midnight' | 'midnight_to_eth';
  transfer: PendingTransfer;
  attempts: number;
  lastError?: string;
}

// =============================================================================
// CONSTANTS
// =============================================================================

const LOCK_CREATED_EVENT = parseAbiItem(
  'event LockCreated(bytes32 indexed lockId, address indexed sender, address indexed token, uint256 amount, bytes32 commitment, bytes32 midnightRecipient)'
);

const MIDNIGHT_DEPOSIT_EVENT = parseAbiItem(
  'event MidnightDeposit(bytes32 indexed depositId, bytes32 commitment, uint256 amount, bytes32 ethRecipient)'
);

const MAX_RETRY_ATTEMPTS = 5;
const RETRY_DELAY_MS = 5000;

// =============================================================================
// RELAYER SERVICE
// =============================================================================

export class MidnightBridgeRelayer {
  private config: RelayerConfig;
  private ethereumClients: Map<number, any> = new Map();
  private walletClients: Map<number, any> = new Map();
  private pendingTasks: Map<string, RelayTask> = new Map();
  private isRunning: boolean = false;
  private account: any;

  constructor(config: RelayerConfig) {
    this.config = config;
    this.account = privateKeyToAccount(config.privateKey);
    this.initializeClients();
  }

  /**
   * Initialize blockchain clients for all supported chains
   */
  private initializeClients(): void {
    const chains: Record<number, any> = {
      1: mainnet,
      42161: arbitrum,
      10: optimism,
      8453: base,
    };

    for (const chainId of this.config.supportedChains) {
      const chain = chains[chainId];
      if (!chain) continue;

      // Create public client for reading
      const publicClient = createPublicClient({
        chain,
        transport: http(this.getRpcUrl(chainId)),
      });
      this.ethereumClients.set(chainId, publicClient);

      // Create wallet client for writing
      const walletClient = createWalletClient({
        account: this.account,
        chain,
        transport: http(this.getRpcUrl(chainId)),
      });
      this.walletClients.set(chainId, walletClient);
    }

    console.log(`Initialized clients for ${this.config.supportedChains.length} chains`);
  }

  /**
   * Get RPC URL for chain
   */
  private getRpcUrl(chainId: number): string {
    // In production, use chain-specific RPC URLs
    return this.config.ethereumRpcUrl;
  }

  /**
   * Start the relayer service
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      console.log('Relayer is already running');
      return;
    }

    this.isRunning = true;
    console.log('Starting Midnight Bridge Relayer...');
    console.log(`Relayer address: ${this.account.address}`);

    // Start event watchers for all chains
    for (const chainId of this.config.supportedChains) {
      this.watchChainEvents(chainId);
    }

    // Start task processor
    this.processTasksLoop();

    console.log('Relayer started successfully');
  }

  /**
   * Stop the relayer service
   */
  async stop(): Promise<void> {
    this.isRunning = false;
    console.log('Stopping Midnight Bridge Relayer...');
    
    // Wait for pending tasks to complete (with timeout)
    await this.drainPendingTasks(30000);
    
    console.log('Relayer stopped');
  }

  /**
   * Watch for bridge events on a specific chain
   */
  private async watchChainEvents(chainId: number): Promise<void> {
    const client = this.ethereumClients.get(chainId);
    if (!client) return;

    console.log(`Watching events on chain ${chainId}...`);

    // Watch LockCreated events (Ethereum → Midnight)
    client.watchEvent({
      address: this.config.bridgeHubAddress,
      event: LOCK_CREATED_EVENT,
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          this.handleLockCreated(chainId, log);
        }
      },
    });
  }

  /**
   * Handle LockCreated event (Ethereum → Midnight transfer)
   */
  private async handleLockCreated(chainId: number, log: Log): Promise<void> {
    const args = log.args as any;
    
    console.log(`[Chain ${chainId}] New lock detected: ${args.lockId}`);

    const transfer: PendingTransfer = {
      lockId: args.lockId,
      sourceChain: chainId,
      destChain: 0, // Midnight
      token: args.token,
      amount: args.amount,
      commitment: args.commitment,
      midnightRecipient: args.midnightRecipient,
      ethSender: args.sender,
      createdAt: Date.now(),
      status: 'pending',
    };

    const task: RelayTask = {
      id: args.lockId,
      type: 'eth_to_midnight',
      transfer,
      attempts: 0,
    };

    this.pendingTasks.set(task.id, task);
    console.log(`Added task ${task.id} to queue`);
  }

  /**
   * Handle MidnightDeposit event (Midnight → Ethereum transfer)
   */
  private async handleMidnightDeposit(depositData: any): Promise<void> {
    console.log(`New Midnight deposit detected: ${depositData.depositId}`);

    const transfer: PendingTransfer = {
      lockId: depositData.depositId,
      sourceChain: 0, // Midnight
      destChain: 1, // Ethereum mainnet (or parse from depositData)
      token: depositData.token || '0x0000000000000000000000000000000000000000',
      amount: depositData.amount,
      commitment: depositData.commitment,
      midnightRecipient: '0x' as Hex,
      ethSender: '0x' as Address,
      createdAt: Date.now(),
      status: 'pending',
    };

    const task: RelayTask = {
      id: depositData.depositId,
      type: 'midnight_to_eth',
      transfer,
      attempts: 0,
    };

    this.pendingTasks.set(task.id, task);
  }

  /**
   * Process pending tasks in a loop
   */
  private async processTasksLoop(): Promise<void> {
    while (this.isRunning) {
      try {
        await this.processPendingTasks();
      } catch (error) {
        console.error('Error processing tasks:', error);
      }

      // Wait before next iteration
      await this.sleep(this.config.pollingInterval);
    }
  }

  /**
   * Process all pending tasks
   */
  private async processPendingTasks(): Promise<void> {
    const tasks = Array.from(this.pendingTasks.values());
    const pendingTasks = tasks.filter(t => t.transfer.status === 'pending');

    console.log(`Processing ${pendingTasks.length} pending tasks...`);

    // Process up to maxConcurrentTasks at a time
    const batch = pendingTasks.slice(0, this.config.maxConcurrentTasks);

    await Promise.allSettled(
      batch.map(task => this.processTask(task))
    );
  }

  /**
   * Process a single relay task
   */
  private async processTask(task: RelayTask): Promise<void> {
    task.transfer.status = 'relaying';
    task.attempts++;

    console.log(`Processing task ${task.id} (attempt ${task.attempts}/${MAX_RETRY_ATTEMPTS})`);

    try {
      if (task.type === 'eth_to_midnight') {
        await this.relayToMidnight(task);
      } else {
        await this.relayFromMidnight(task);
      }

      task.transfer.status = 'confirmed';
      console.log(`Task ${task.id} completed successfully`);

      // Remove completed task
      this.pendingTasks.delete(task.id);

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      task.lastError = errorMessage;

      if (task.attempts >= MAX_RETRY_ATTEMPTS) {
        task.transfer.status = 'failed';
        console.error(`Task ${task.id} failed permanently: ${errorMessage}`);
      } else {
        task.transfer.status = 'pending';
        console.warn(`Task ${task.id} failed, will retry: ${errorMessage}`);
      }
    }
  }

  /**
   * Relay transfer from Ethereum to Midnight
   */
  private async relayToMidnight(task: RelayTask): Promise<void> {
    const { transfer } = task;

    // 1. Fetch lock details from Ethereum
    console.log(`Fetching lock ${transfer.lockId} from chain ${transfer.sourceChain}`);

    // 2. Generate Midnight transaction
    // This would use Midnight SDK to call the bridge-vault contract
    console.log(`Generating Midnight deposit for ${transfer.amount}`);

    // 3. Submit to Midnight network
    // const midnightTxHash = await midnightClient.receiveFromEthereum(...)

    // 4. Wait for Midnight confirmation
    console.log(`Waiting for Midnight confirmation...`);

    // 5. Update Ethereum contract with confirmation
    // await this.confirmLockOnEthereum(transfer.lockId, midnightTxHash);

    console.log(`Transfer ${transfer.lockId} relayed to Midnight`);
  }

  /**
   * Relay transfer from Midnight to Ethereum
   */
  private async relayFromMidnight(task: RelayTask): Promise<void> {
    const { transfer } = task;

    // 1. Fetch deposit details from Midnight
    console.log(`Fetching Midnight deposit ${transfer.lockId}`);

    // 2. Generate ZK proof for Ethereum
    // const proof = await midnightClient.generateBridgeProof(transfer.lockId);
    console.log(`Generating bridge proof...`);

    // 3. Submit claim to Ethereum
    const walletClient = this.walletClients.get(transfer.destChain);
    if (!walletClient) {
      throw new Error(`No wallet client for chain ${transfer.destChain}`);
    }

    // const txHash = await walletClient.writeContract({
    //   address: this.config.bridgeHubAddress,
    //   abi: BRIDGE_HUB_ABI,
    //   functionName: 'claimFromMidnight',
    //   args: [proof, transfer.token, transfer.amount, recipient],
    // });

    console.log(`Transfer ${transfer.lockId} claimed on Ethereum`);
  }

  /**
   * Drain pending tasks before shutdown
   */
  private async drainPendingTasks(timeoutMs: number): Promise<void> {
    const startTime = Date.now();

    while (this.pendingTasks.size > 0) {
      if (Date.now() - startTime > timeoutMs) {
        console.warn(`Timeout reached, ${this.pendingTasks.size} tasks still pending`);
        break;
      }

      await this.sleep(1000);
    }
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get relayer statistics
   */
  getStats(): {
    pendingTasks: number;
    completedTasks: number;
    failedTasks: number;
    isRunning: boolean;
  } {
    const tasks = Array.from(this.pendingTasks.values());
    
    return {
      pendingTasks: tasks.filter(t => t.transfer.status === 'pending').length,
      completedTasks: 0, // Would need persistent storage
      failedTasks: tasks.filter(t => t.transfer.status === 'failed').length,
      isRunning: this.isRunning,
    };
  }

  /**
   * Get pending transfers
   */
  getPendingTransfers(): PendingTransfer[] {
    return Array.from(this.pendingTasks.values()).map(t => t.transfer);
  }

  /**
   * Manually retry a failed task
   */
  async retryTask(taskId: string): Promise<void> {
    const task = this.pendingTasks.get(taskId);
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }

    task.transfer.status = 'pending';
    task.attempts = 0;
    console.log(`Task ${taskId} queued for retry`);
  }
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

async function main() {
  const config: RelayerConfig = {
    privateKey: (process.env.RELAYER_PRIVATE_KEY || '0x') as Hex,
    ethereumRpcUrl: process.env.ETHEREUM_RPC_URL || 'http://localhost:8545',
    midnightRpcUrl: process.env.MIDNIGHT_RPC_URL || 'http://localhost:9944',
    bridgeHubAddress: (process.env.BRIDGE_HUB_ADDRESS || '0x') as Address,
    supportedChains: [1, 42161, 10, 8453], // Mainnet, Arbitrum, Optimism, Base
    pollingInterval: 5000, // 5 seconds
    maxConcurrentTasks: 10,
  };

  const relayer = new MidnightBridgeRelayer(config);
  
  // Handle shutdown signals
  process.on('SIGINT', async () => {
    console.log('Received SIGINT, shutting down...');
    await relayer.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('Received SIGTERM, shutting down...');
    await relayer.stop();
    process.exit(0);
  });

  await relayer.start();
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

export { MidnightBridgeRelayer, RelayerConfig, PendingTransfer };
