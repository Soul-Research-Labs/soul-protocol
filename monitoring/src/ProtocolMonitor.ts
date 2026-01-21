/**
 * PIL Monitoring Service
 * 
 * Real-time monitoring, metrics collection, and alerting for PIL protocol
 */

import { ethers } from 'ethers';
import EventEmitter from 'events';

// ============================================
// Types
// ============================================

export interface MetricPoint {
  timestamp: number;
  value: number;
  labels: Record<string, string>;
}

export interface AlertRule {
  id: string;
  name: string;
  metric: string;
  condition: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  threshold: number;
  duration: number; // seconds
  severity: 'info' | 'warning' | 'critical';
  enabled: boolean;
}

export interface Alert {
  id: string;
  ruleId: string;
  metric: string;
  value: number;
  threshold: number;
  severity: string;
  message: string;
  timestamp: number;
  resolved: boolean;
}

export interface ChainHealth {
  chainId: string;
  name: string;
  status: 'healthy' | 'degraded' | 'down';
  latency: number;
  blockHeight: number;
  lastBlock: number;
  pendingTxs: number;
  gasPrice: bigint;
}

export interface BridgeMetrics {
  chainId: string;
  totalVolume24h: bigint;
  totalTransfers24h: number;
  pendingTransfers: number;
  avgTransferTime: number;
  successRate: number;
  failedTransfers24h: number;
}

export interface ProofMetrics {
  totalGenerated: number;
  totalVerified: number;
  avgGenerationTime: number;
  avgVerificationTime: number;
  proofsBySystem: Record<string, number>;
  failureRate: number;
}

export interface ProtocolMetrics {
  tvl: bigint;
  dailyVolume: bigint;
  uniqueUsers24h: number;
  totalTransactions: number;
  avgGasUsed: number;
  relayerCount: number;
  activeRelayers: number;
}

// ============================================
// Metrics Collector
// ============================================

export class MetricsCollector {
  private metrics: Map<string, MetricPoint[]> = new Map();
  private retentionPeriod: number = 24 * 60 * 60 * 1000; // 24 hours

  record(name: string, value: number, labels: Record<string, string> = {}): void {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }

    this.metrics.get(name)!.push({
      timestamp: Date.now(),
      value,
      labels
    });

    // Cleanup old data
    this.cleanup(name);
  }

  get(name: string, duration?: number): MetricPoint[] {
    const points = this.metrics.get(name) || [];
    if (!duration) return points;

    const cutoff = Date.now() - duration;
    return points.filter(p => p.timestamp >= cutoff);
  }

  getLatest(name: string): MetricPoint | undefined {
    const points = this.metrics.get(name);
    return points?.[points.length - 1];
  }

  getAverage(name: string, duration: number): number {
    const points = this.get(name, duration);
    if (points.length === 0) return 0;
    return points.reduce((sum, p) => sum + p.value, 0) / points.length;
  }

  getMin(name: string, duration: number): number {
    const points = this.get(name, duration);
    if (points.length === 0) return 0;
    return Math.min(...points.map(p => p.value));
  }

  getMax(name: string, duration: number): number {
    const points = this.get(name, duration);
    if (points.length === 0) return 0;
    return Math.max(...points.map(p => p.value));
  }

  getPercentile(name: string, percentile: number, duration: number): number {
    const points = this.get(name, duration);
    if (points.length === 0) return 0;

    const sorted = points.map(p => p.value).sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  }

  private cleanup(name: string): void {
    const points = this.metrics.get(name);
    if (!points) return;

    const cutoff = Date.now() - this.retentionPeriod;
    const filtered = points.filter(p => p.timestamp >= cutoff);
    this.metrics.set(name, filtered);
  }

  exportPrometheus(): string {
    let output = '';

    for (const [name, points] of this.metrics.entries()) {
      const latest = points[points.length - 1];
      if (latest) {
        const labels = Object.entries(latest.labels)
          .map(([k, v]) => `${k}="${v}"`)
          .join(',');
        const labelStr = labels ? `{${labels}}` : '';
        output += `pil_${name}${labelStr} ${latest.value}\n`;
      }
    }

    return output;
  }
}

// ============================================
// Alert Manager
// ============================================

export class AlertManager extends EventEmitter {
  private rules: Map<string, AlertRule> = new Map();
  private activeAlerts: Map<string, Alert> = new Map();
  private alertHistory: Alert[] = [];
  private metrics: MetricsCollector;

  constructor(metrics: MetricsCollector) {
    super();
    this.metrics = metrics;
  }

  addRule(rule: AlertRule): void {
    this.rules.set(rule.id, rule);
  }

  removeRule(ruleId: string): void {
    this.rules.delete(ruleId);
  }

  enableRule(ruleId: string): void {
    const rule = this.rules.get(ruleId);
    if (rule) rule.enabled = true;
  }

  disableRule(ruleId: string): void {
    const rule = this.rules.get(ruleId);
    if (rule) rule.enabled = false;
  }

  evaluate(): void {
    for (const rule of this.rules.values()) {
      if (!rule.enabled) continue;

      const avg = this.metrics.getAverage(rule.metric, rule.duration * 1000);
      const triggered = this.checkCondition(avg, rule.condition, rule.threshold);

      if (triggered && !this.activeAlerts.has(rule.id)) {
        const alert: Alert = {
          id: `${rule.id}-${Date.now()}`,
          ruleId: rule.id,
          metric: rule.metric,
          value: avg,
          threshold: rule.threshold,
          severity: rule.severity,
          message: `${rule.name}: ${rule.metric} is ${avg.toFixed(2)} (threshold: ${rule.threshold})`,
          timestamp: Date.now(),
          resolved: false
        };

        this.activeAlerts.set(rule.id, alert);
        this.alertHistory.push(alert);
        this.emit('alert', alert);
      } else if (!triggered && this.activeAlerts.has(rule.id)) {
        const alert = this.activeAlerts.get(rule.id)!;
        alert.resolved = true;
        this.activeAlerts.delete(rule.id);
        this.emit('resolved', alert);
      }
    }
  }

  private checkCondition(value: number, condition: string, threshold: number): boolean {
    switch (condition) {
      case 'gt': return value > threshold;
      case 'lt': return value < threshold;
      case 'eq': return value === threshold;
      case 'gte': return value >= threshold;
      case 'lte': return value <= threshold;
      default: return false;
    }
  }

  getActiveAlerts(): Alert[] {
    return Array.from(this.activeAlerts.values());
  }

  getAlertHistory(limit?: number): Alert[] {
    const history = [...this.alertHistory].reverse();
    return limit ? history.slice(0, limit) : history;
  }
}

// ============================================
// Chain Monitor
// ============================================

export class ChainMonitor {
  private providers: Map<string, ethers.Provider> = new Map();
  private health: Map<string, ChainHealth> = new Map();
  private metrics: MetricsCollector;
  private checkInterval: NodeJS.Timeout | null = null;

  constructor(metrics: MetricsCollector) {
    this.metrics = metrics;
  }

  addChain(chainId: string, name: string, rpcUrl: string): void {
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    this.providers.set(chainId, provider);
    this.health.set(chainId, {
      chainId,
      name,
      status: 'healthy',
      latency: 0,
      blockHeight: 0,
      lastBlock: 0,
      pendingTxs: 0,
      gasPrice: 0n
    });
  }

  async checkHealth(chainId: string): Promise<ChainHealth> {
    const provider = this.providers.get(chainId);
    const health = this.health.get(chainId);
    
    if (!provider || !health) {
      throw new Error(`Chain ${chainId} not configured`);
    }

    const startTime = Date.now();

    try {
      const [blockNumber, feeData] = await Promise.all([
        provider.getBlockNumber(),
        provider.getFeeData()
      ]);

      const latency = Date.now() - startTime;

      health.latency = latency;
      health.blockHeight = blockNumber;
      health.lastBlock = Date.now();
      health.gasPrice = feeData.gasPrice || 0n;
      health.status = latency < 1000 ? 'healthy' : latency < 5000 ? 'degraded' : 'down';

      // Record metrics
      this.metrics.record('chain_latency', latency, { chain: chainId });
      this.metrics.record('chain_block_height', blockNumber, { chain: chainId });
      this.metrics.record('chain_gas_price', Number(health.gasPrice / 1_000_000_000n), { chain: chainId });

    } catch (error) {
      health.status = 'down';
      health.latency = Date.now() - startTime;
    }

    return health;
  }

  async checkAllChains(): Promise<Map<string, ChainHealth>> {
    const promises = Array.from(this.providers.keys()).map(id => this.checkHealth(id));
    await Promise.allSettled(promises);
    return this.health;
  }

  startMonitoring(intervalMs: number = 30000): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }
    this.checkInterval = setInterval(() => this.checkAllChains(), intervalMs);
    this.checkAllChains(); // Initial check
  }

  stopMonitoring(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  getHealth(chainId: string): ChainHealth | undefined {
    return this.health.get(chainId);
  }

  getAllHealth(): ChainHealth[] {
    return Array.from(this.health.values());
  }
}

// ============================================
// Protocol Monitor
// ============================================

export class ProtocolMonitor extends EventEmitter {
  private metrics: MetricsCollector;
  private alertManager: AlertManager;
  private chainMonitor: ChainMonitor;
  private updateInterval: NodeJS.Timeout | null = null;

  constructor() {
    super();
    this.metrics = new MetricsCollector();
    this.alertManager = new AlertManager(this.metrics);
    this.chainMonitor = new ChainMonitor(this.metrics);

    this.setupDefaultAlertRules();
    this.setupEventListeners();
  }

  private setupDefaultAlertRules(): void {
    // Chain health alerts
    this.alertManager.addRule({
      id: 'chain_latency_high',
      name: 'High Chain Latency',
      metric: 'chain_latency',
      condition: 'gt',
      threshold: 5000,
      duration: 60,
      severity: 'warning',
      enabled: true
    });

    // Bridge alerts
    this.alertManager.addRule({
      id: 'bridge_success_rate_low',
      name: 'Low Bridge Success Rate',
      metric: 'bridge_success_rate',
      condition: 'lt',
      threshold: 95,
      duration: 300,
      severity: 'critical',
      enabled: true
    });

    this.alertManager.addRule({
      id: 'pending_transfers_high',
      name: 'High Pending Transfers',
      metric: 'pending_transfers',
      condition: 'gt',
      threshold: 100,
      duration: 300,
      severity: 'warning',
      enabled: true
    });

    // Proof alerts
    this.alertManager.addRule({
      id: 'proof_generation_slow',
      name: 'Slow Proof Generation',
      metric: 'proof_generation_time',
      condition: 'gt',
      threshold: 5000,
      duration: 120,
      severity: 'warning',
      enabled: true
    });

    // Gas alerts
    this.alertManager.addRule({
      id: 'gas_price_high',
      name: 'High Gas Price',
      metric: 'chain_gas_price',
      condition: 'gt',
      threshold: 100,
      duration: 60,
      severity: 'info',
      enabled: true
    });
  }

  private setupEventListeners(): void {
    this.alertManager.on('alert', (alert: Alert) => {
      this.emit('alert', alert);
      console.log(`[ALERT] ${alert.severity.toUpperCase()}: ${alert.message}`);
    });

    this.alertManager.on('resolved', (alert: Alert) => {
      this.emit('alert_resolved', alert);
      console.log(`[RESOLVED] ${alert.message}`);
    });
  }

  // Metric recording methods
  recordDeposit(chainId: string, amount: bigint, txHash: string): void {
    this.metrics.record('deposit_count', 1, { chain: chainId });
    this.metrics.record('deposit_volume', Number(amount / BigInt(1e18)), { chain: chainId });
    this.emit('deposit', { chainId, amount, txHash });
  }

  recordWithdrawal(chainId: string, amount: bigint, txHash: string): void {
    this.metrics.record('withdrawal_count', 1, { chain: chainId });
    this.metrics.record('withdrawal_volume', Number(amount / BigInt(1e18)), { chain: chainId });
    this.emit('withdrawal', { chainId, amount, txHash });
  }

  recordBridgeTransfer(
    sourceChain: string,
    destChain: string,
    amount: bigint,
    transferId: string,
    success: boolean
  ): void {
    this.metrics.record('bridge_transfer_count', 1, { source: sourceChain, dest: destChain });
    this.metrics.record('bridge_volume', Number(amount / BigInt(1e18)), { source: sourceChain, dest: destChain });
    this.metrics.record('bridge_success_rate', success ? 100 : 0, { source: sourceChain, dest: destChain });
    this.emit('bridge_transfer', { sourceChain, destChain, amount, transferId, success });
  }

  recordProofGeneration(system: string, duration: number, success: boolean): void {
    this.metrics.record('proof_generation_time', duration, { system });
    this.metrics.record('proof_generation_count', 1, { system, success: String(success) });
    this.emit('proof_generated', { system, duration, success });
  }

  recordRelayerActivity(relayerId: string, txCount: number, gasUsed: bigint): void {
    this.metrics.record('relayer_tx_count', txCount, { relayer: relayerId });
    this.metrics.record('relayer_gas_used', Number(gasUsed), { relayer: relayerId });
    this.emit('relayer_activity', { relayerId, txCount, gasUsed });
  }

  // Query methods
  getMetrics(): MetricsCollector {
    return this.metrics;
  }

  getAlertManager(): AlertManager {
    return this.alertManager;
  }

  getChainMonitor(): ChainMonitor {
    return this.chainMonitor;
  }

  getProtocolStats(): ProtocolMetrics {
    const hour = 60 * 60 * 1000;
    const day = 24 * hour;

    return {
      tvl: BigInt(Math.round(this.metrics.getLatest('tvl')?.value || 0)),
      dailyVolume: BigInt(Math.round(
        this.metrics.getAverage('bridge_volume', day) * 
        this.metrics.get('bridge_volume', day).length
      )),
      uniqueUsers24h: Math.round(this.metrics.getLatest('unique_users')?.value || 0),
      totalTransactions: Math.round(
        this.metrics.get('bridge_transfer_count', day).reduce((sum, p) => sum + p.value, 0)
      ),
      avgGasUsed: Math.round(this.metrics.getAverage('relayer_gas_used', day)),
      relayerCount: Math.round(this.metrics.getLatest('relayer_count')?.value || 0),
      activeRelayers: Math.round(this.metrics.getLatest('active_relayers')?.value || 0)
    };
  }

  // Lifecycle methods
  start(checkIntervalMs: number = 30000): void {
    this.chainMonitor.startMonitoring(checkIntervalMs);
    this.updateInterval = setInterval(() => {
      this.alertManager.evaluate();
    }, checkIntervalMs);
    console.log('[Monitor] Protocol monitoring started');
  }

  stop(): void {
    this.chainMonitor.stopMonitoring();
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
    console.log('[Monitor] Protocol monitoring stopped');
  }

  // Prometheus endpoint data
  getPrometheusMetrics(): string {
    return this.metrics.exportPrometheus();
  }
}

// ============================================
// Dashboard Data Provider
// ============================================

export class DashboardDataProvider {
  private monitor: ProtocolMonitor;

  constructor(monitor: ProtocolMonitor) {
    this.monitor = monitor;
  }

  getOverview(): object {
    const stats = this.monitor.getProtocolStats();
    const chainHealth = this.monitor.getChainMonitor().getAllHealth();
    const alerts = this.monitor.getAlertManager().getActiveAlerts();

    return {
      stats: {
        tvl: stats.tvl.toString(),
        dailyVolume: stats.dailyVolume.toString(),
        uniqueUsers: stats.uniqueUsers24h,
        transactions: stats.totalTransactions,
        relayers: {
          total: stats.relayerCount,
          active: stats.activeRelayers
        }
      },
      chains: chainHealth.map(h => ({
        id: h.chainId,
        name: h.name,
        status: h.status,
        latency: h.latency,
        blockHeight: h.blockHeight
      })),
      alerts: alerts.map(a => ({
        severity: a.severity,
        message: a.message,
        timestamp: a.timestamp
      })),
      timestamp: Date.now()
    };
  }

  getVolumeChart(duration: number = 24 * 60 * 60 * 1000): object {
    const metrics = this.monitor.getMetrics();
    const points = metrics.get('bridge_volume', duration);

    // Aggregate by hour
    const hourly: Record<number, number> = {};
    for (const point of points) {
      const hour = Math.floor(point.timestamp / (60 * 60 * 1000)) * (60 * 60 * 1000);
      hourly[hour] = (hourly[hour] || 0) + point.value;
    }

    return {
      data: Object.entries(hourly).map(([ts, value]) => ({
        timestamp: Number(ts),
        volume: value
      })),
      period: duration
    };
  }

  getChainBreakdown(): object {
    const chainHealth = this.monitor.getChainMonitor().getAllHealth();
    const metrics = this.monitor.getMetrics();

    return chainHealth.map(h => ({
      chain: h.name,
      status: h.status,
      volume24h: metrics.getAverage('bridge_volume', 24 * 60 * 60 * 1000),
      transfers24h: metrics.get('bridge_transfer_count', 24 * 60 * 60 * 1000)
        .filter(p => p.labels.source === h.chainId || p.labels.dest === h.chainId)
        .reduce((sum, p) => sum + p.value, 0)
    }));
  }
}

// Export singleton
export const protocolMonitor = new ProtocolMonitor();
export const dashboardData = new DashboardDataProvider(protocolMonitor);
