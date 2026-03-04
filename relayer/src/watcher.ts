/**
 * ZASEON Relayer - Event Watcher
 *
 * Watches on-chain events (deposits, withdrawals, proof submissions)
 * across all configured chains and enqueues relay tasks.
 */

import { createPublicClient, http, type PublicClient, type Log } from 'viem';
import { type RelayerConfig, type ChainConfig } from './config.js';
import { type ProofQueue, type RelayTask } from './queue.js';
import { createLogger } from './logger.js';

const logger = createLogger('watcher');

export class EventWatcher {
  private clients: Map<string, PublicClient> = new Map();
  private unwatchers: Array<() => void> = [];
  private running = false;

  constructor(
    private config: RelayerConfig,
    private queue: ProofQueue,
  ) {}

  async start(): Promise<void> {
    logger.info('Starting event watcher...');
    this.running = true;

    for (const chain of this.config.chains) {
      const client = createPublicClient({
        transport: http(chain.rpcUrl),
      });
      this.clients.set(chain.name, client as PublicClient);

      if (chain.bridgeAddress) {
        this._watchBridgeEvents(chain, client as PublicClient);
      }

      logger.info({ chain: chain.name, chainId: chain.chainId }, 'Watching chain');
    }
  }

  async stop(): Promise<void> {
    logger.info('Stopping event watcher...');
    this.running = false;
    for (const unwatch of this.unwatchers) {
      unwatch();
    }
    this.unwatchers = [];
  }

  private _watchBridgeEvents(chain: ChainConfig, client: PublicClient): void {
    // Watch for deposit events
    const unwatch = client.watchEvent({
      address: chain.bridgeAddress as `0x${string}`,
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          this._handleBridgeEvent(chain, log);
        }
      },
      onError: (error: Error) => {
        logger.error({ chain: chain.name, error: error.message }, 'Watch error');
      },
    });

    this.unwatchers.push(unwatch);
  }

  private _handleBridgeEvent(chain: ChainConfig, log: Log): void {
    const task: RelayTask = {
      id: `${chain.chainId}-${log.transactionHash}-${log.logIndex}`,
      sourceChain: chain.name,
      sourceChainId: chain.chainId,
      txHash: log.transactionHash || '0x',
      blockNumber: Number(log.blockNumber || 0),
      logIndex: Number(log.logIndex || 0),
      timestamp: Date.now(),
      retries: 0,
    };

    logger.info({ task: task.id, chain: chain.name }, 'New bridge event detected');
    this.queue.enqueue(task);
  }
}
