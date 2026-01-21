/**
 * PIL Health Check Service
 * 
 * HTTP endpoints for health checks and monitoring
 */

import express, { Request, Response, NextFunction } from 'express';
import { protocolMonitor, dashboardData } from './ProtocolMonitor';

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// ============================================
// Health Endpoints
// ============================================

interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: number;
  version: string;
  uptime: number;
  checks: Record<string, {
    status: string;
    latency?: number;
    message?: string;
  }>;
}

const startTime = Date.now();

/**
 * Basic liveness probe
 */
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

/**
 * Detailed readiness probe
 */
app.get('/health/ready', async (req: Request, res: Response) => {
  const health: HealthStatus = {
    status: 'healthy',
    timestamp: Date.now(),
    version: process.env.VERSION || '1.0.0',
    uptime: Date.now() - startTime,
    checks: {}
  };

  // Check chain health
  const chainHealth = protocolMonitor.getChainMonitor().getAllHealth();
  let degradedChains = 0;
  let downChains = 0;

  for (const chain of chainHealth) {
    health.checks[`chain_${chain.chainId}`] = {
      status: chain.status,
      latency: chain.latency
    };

    if (chain.status === 'degraded') degradedChains++;
    if (chain.status === 'down') downChains++;
  }

  // Check alerts
  const activeAlerts = protocolMonitor.getAlertManager().getActiveAlerts();
  const criticalAlerts = activeAlerts.filter(a => a.severity === 'critical');
  
  health.checks['alerts'] = {
    status: criticalAlerts.length > 0 ? 'critical' : activeAlerts.length > 0 ? 'warning' : 'ok',
    message: `${activeAlerts.length} active alerts (${criticalAlerts.length} critical)`
  };

  // Determine overall status
  if (downChains > 0 || criticalAlerts.length > 0) {
    health.status = 'unhealthy';
  } else if (degradedChains > 0 || activeAlerts.length > 0) {
    health.status = 'degraded';
  }

  const statusCode = health.status === 'healthy' ? 200 : health.status === 'degraded' ? 200 : 503;
  res.status(statusCode).json(health);
});

/**
 * Kubernetes-style liveness probe
 */
app.get('/healthz', (req: Request, res: Response) => {
  res.status(200).send('OK');
});

/**
 * Kubernetes-style readiness probe
 */
app.get('/readyz', async (req: Request, res: Response) => {
  const chainHealth = protocolMonitor.getChainMonitor().getAllHealth();
  const healthyChains = chainHealth.filter(c => c.status === 'healthy').length;
  
  if (healthyChains === 0 && chainHealth.length > 0) {
    res.status(503).send('No healthy chains');
    return;
  }
  
  res.status(200).send('OK');
});

// ============================================
// Metrics Endpoints
// ============================================

/**
 * Prometheus metrics endpoint
 */
app.get('/metrics', (req: Request, res: Response) => {
  res.set('Content-Type', 'text/plain');
  res.send(protocolMonitor.getPrometheusMetrics());
});

/**
 * JSON metrics endpoint
 */
app.get('/api/metrics', (req: Request, res: Response) => {
  const stats = protocolMonitor.getProtocolStats();
  res.json({
    tvl: stats.tvl.toString(),
    dailyVolume: stats.dailyVolume.toString(),
    uniqueUsers24h: stats.uniqueUsers24h,
    totalTransactions: stats.totalTransactions,
    avgGasUsed: stats.avgGasUsed,
    relayerCount: stats.relayerCount,
    activeRelayers: stats.activeRelayers,
    timestamp: Date.now()
  });
});

// ============================================
// Dashboard Data Endpoints
// ============================================

/**
 * Dashboard overview
 */
app.get('/api/dashboard', (req: Request, res: Response) => {
  res.json(dashboardData.getOverview());
});

/**
 * Volume chart data
 */
app.get('/api/dashboard/volume', (req: Request, res: Response) => {
  const duration = parseInt(req.query.duration as string) || 24 * 60 * 60 * 1000;
  res.json(dashboardData.getVolumeChart(duration));
});

/**
 * Chain breakdown data
 */
app.get('/api/dashboard/chains', (req: Request, res: Response) => {
  res.json(dashboardData.getChainBreakdown());
});

/**
 * Chain health status
 */
app.get('/api/chains', (req: Request, res: Response) => {
  const chainHealth = protocolMonitor.getChainMonitor().getAllHealth();
  res.json(chainHealth);
});

/**
 * Single chain health
 */
app.get('/api/chains/:chainId', (req: Request, res: Response) => {
  const health = protocolMonitor.getChainMonitor().getHealth(req.params.chainId);
  if (!health) {
    res.status(404).json({ error: 'Chain not found' });
    return;
  }
  res.json(health);
});

// ============================================
// Alert Endpoints
// ============================================

/**
 * Active alerts
 */
app.get('/api/alerts', (req: Request, res: Response) => {
  const alerts = protocolMonitor.getAlertManager().getActiveAlerts();
  res.json(alerts);
});

/**
 * Alert history
 */
app.get('/api/alerts/history', (req: Request, res: Response) => {
  const limit = parseInt(req.query.limit as string) || 100;
  const alerts = protocolMonitor.getAlertManager().getAlertHistory(limit);
  res.json(alerts);
});

// ============================================
// Error handling
// ============================================

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// Server startup
// ============================================

export function startHealthServer(): void {
  // Initialize monitoring
  protocolMonitor.start(30000);

  // Add default chains for monitoring
  const chainMonitor = protocolMonitor.getChainMonitor();
  chainMonitor.addChain('ethereum', 'Ethereum', process.env.ETH_RPC_URL || 'https://eth.llamarpc.com');
  chainMonitor.addChain('polygon', 'Polygon', process.env.POLYGON_RPC_URL || 'https://polygon.llamarpc.com');
  chainMonitor.addChain('arbitrum', 'Arbitrum', process.env.ARBITRUM_RPC_URL || 'https://arb1.arbitrum.io/rpc');
  chainMonitor.addChain('optimism', 'Optimism', process.env.OPTIMISM_RPC_URL || 'https://mainnet.optimism.io');

  app.listen(PORT, () => {
    console.log(`[Health] Server running on port ${PORT}`);
    console.log(`[Health] Prometheus metrics at http://localhost:${PORT}/metrics`);
    console.log(`[Health] Health check at http://localhost:${PORT}/health/ready`);
  });
}

// Start if run directly
if (require.main === module) {
  startHealthServer();
}

export default app;
