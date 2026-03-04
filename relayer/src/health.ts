/**
 * ZASEON Relayer - Health Reporter
 *
 * Exposes /health and /metrics endpoints for monitoring.
 * Compatible with Prometheus scraping and standard health checks.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import { type RelayerConfig } from './config.js';
import { createLogger } from './logger.js';

const logger = createLogger('health');

export class HealthReporter {
  private server: ReturnType<typeof createServer> | null = null;
  private startTime = Date.now();

  constructor(private config: RelayerConfig) {}

  async start(): Promise<void> {
    this.server = createServer((req: IncomingMessage, res: ServerResponse) => {
      if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'ok',
          uptime: Date.now() - this.startTime,
          chains: this.config.chains.map((c) => c.name),
          version: '0.1.0',
        }));
      } else if (req.url === '/metrics') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end([
          `# HELP zaseon_relayer_uptime_ms Relayer uptime in milliseconds`,
          `# TYPE zaseon_relayer_uptime_ms gauge`,
          `zaseon_relayer_uptime_ms ${Date.now() - this.startTime}`,
          `# HELP zaseon_relayer_chains_total Number of watched chains`,
          `# TYPE zaseon_relayer_chains_total gauge`,
          `zaseon_relayer_chains_total ${this.config.chains.length}`,
          '',
        ].join('\n'));
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    return new Promise((resolve) => {
      this.server!.listen(this.config.healthPort, () => {
        logger.info({ port: this.config.healthPort }, 'Health server started');
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => {
          logger.info('Health server stopped');
          resolve();
        });
      });
    }
  }
}
