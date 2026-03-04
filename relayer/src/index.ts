/**
 * ZASEON Relayer Node - Entry Point
 *
 * Starts the decentralized relayer that watches for cross-chain events,
 * queues proof relay tasks, and submits proofs to destination chains.
 */

import { EventWatcher } from './watcher.js';
import { ProofQueue } from './queue.js';
import { HealthReporter } from './health.js';
import { RelayerConfig, loadConfig } from './config.js';
import { createLogger } from './logger.js';

const logger = createLogger('relayer');

async function main(): Promise<void> {
  logger.info('Starting ZASEON Relayer Node...');

  const config = loadConfig();
  logger.info({ chains: config.chains }, 'Loaded configuration');

  // Initialize components
  const queue = new ProofQueue(config);
  const watcher = new EventWatcher(config, queue);
  const health = new HealthReporter(config);

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutting down...');
    await watcher.stop();
    await queue.drain();
    await health.stop();
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  // Start services
  await health.start();
  await queue.start();
  await watcher.start();

  logger.info('ZASEON Relayer Node is running');
}

main().catch((err) => {
  logger.fatal({ err }, 'Fatal error');
  process.exit(1);
});
