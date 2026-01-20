'use client';

import { useState, useEffect } from 'react';
import { useAccount } from 'wagmi';

interface NetworkStatus {
  chainId: number;
  name: string;
  icon: string;
  status: 'healthy' | 'degraded' | 'down';
  latency: number;
  blockHeight: number;
  lastUpdate: number;
  pendingMessages: number;
}

interface BridgeMetrics {
  totalBridged: string;
  totalTransactions: number;
  averageTime: string;
  successRate: number;
}

interface RecentEvent {
  id: string;
  type: 'bridge' | 'proof' | 'nullifier' | 'state';
  description: string;
  timestamp: number;
  status: 'success' | 'pending' | 'failed';
  txHash?: string;
}

const MOCK_NETWORKS: NetworkStatus[] = [
  { chainId: 1, name: 'Ethereum', icon: '⟠', status: 'healthy', latency: 45, blockHeight: 19234567, lastUpdate: Date.now(), pendingMessages: 3 },
  { chainId: 42161, name: 'Arbitrum', icon: '🔵', status: 'healthy', latency: 23, blockHeight: 187654321, lastUpdate: Date.now(), pendingMessages: 12 },
  { chainId: 10, name: 'Optimism', icon: '🔴', status: 'healthy', latency: 31, blockHeight: 115234567, lastUpdate: Date.now(), pendingMessages: 5 },
  { chainId: 8453, name: 'Base', icon: '🔷', status: 'healthy', latency: 28, blockHeight: 9876543, lastUpdate: Date.now(), pendingMessages: 8 },
  { chainId: 324, name: 'zkSync Era', icon: '⚡', status: 'healthy', latency: 52, blockHeight: 32456789, lastUpdate: Date.now(), pendingMessages: 2 },
  { chainId: 534352, name: 'Scroll', icon: '📜', status: 'degraded', latency: 180, blockHeight: 4567890, lastUpdate: Date.now(), pendingMessages: 45 },
  { chainId: 677868, name: 'Aztec', icon: '🔮', status: 'healthy', latency: 67, blockHeight: 1234567, lastUpdate: Date.now(), pendingMessages: 1 },
];

export default function AnalyticsPanel() {
  const { address } = useAccount();
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('24h');
  const [networks, setNetworks] = useState<NetworkStatus[]>(MOCK_NETWORKS);
  const [metrics, setMetrics] = useState<BridgeMetrics>({
    totalBridged: '$12,456,789',
    totalTransactions: 45678,
    averageTime: '4.2 min',
    successRate: 99.7,
  });
  const [events, setEvents] = useState<RecentEvent[]>([
    { id: '1', type: 'bridge', description: 'Bridge 1.5 ETH from Ethereum to Arbitrum', timestamp: Date.now() - 60000, status: 'success', txHash: '0x123...' },
    { id: '2', type: 'proof', description: 'ZK proof verified for container #4521', timestamp: Date.now() - 120000, status: 'success' },
    { id: '3', type: 'nullifier', description: 'Nullifier registered across 3 domains', timestamp: Date.now() - 180000, status: 'success' },
    { id: '4', type: 'state', description: 'State commitment synced from zkSync', timestamp: Date.now() - 240000, status: 'pending' },
    { id: '5', type: 'bridge', description: 'Bridge 0.5 ETH from Optimism to Base', timestamp: Date.now() - 300000, status: 'success' },
  ]);

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setNetworks(prev => prev.map(n => ({
        ...n,
        latency: Math.max(10, n.latency + Math.floor(Math.random() * 20) - 10),
        blockHeight: n.blockHeight + Math.floor(Math.random() * 3),
        lastUpdate: Date.now(),
        pendingMessages: Math.max(0, n.pendingMessages + Math.floor(Math.random() * 3) - 1),
      })));
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: NetworkStatus['status']) => {
    switch (status) {
      case 'healthy': return 'bg-green-400';
      case 'degraded': return 'bg-yellow-400';
      case 'down': return 'bg-red-400';
    }
  };

  const getEventIcon = (type: RecentEvent['type']) => {
    switch (type) {
      case 'bridge': return '🌉';
      case 'proof': return '🔐';
      case 'nullifier': return '🔑';
      case 'state': return '🔄';
    }
  };

  const formatTimeAgo = (timestamp: number) => {
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  return (
    <div className="space-y-6">
      {/* Header with Time Range */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Analytics Dashboard</h2>
        <div className="flex items-center gap-2 bg-white/5 rounded-lg p-1">
          {(['24h', '7d', '30d'] as const).map((range) => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                timeRange === range
                  ? 'bg-gradient-pil text-white'
                  : 'text-white/60 hover:text-white hover:bg-white/10'
              }`}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard
          title="Total Bridged"
          value={metrics.totalBridged}
          change="+12.5%"
          positive
          icon="💰"
        />
        <MetricCard
          title="Transactions"
          value={metrics.totalTransactions.toLocaleString()}
          change="+8.3%"
          positive
          icon="📊"
        />
        <MetricCard
          title="Avg. Time"
          value={metrics.averageTime}
          change="-15%"
          positive
          icon="⏱️"
        />
        <MetricCard
          title="Success Rate"
          value={`${metrics.successRate}%`}
          change="+0.2%"
          positive
          icon="✅"
        />
      </div>

      {/* Network Health */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <span>🌐</span>
            Network Status
          </h3>
          <div className="flex items-center gap-4 text-sm">
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-400"></span>
              <span className="text-white/60">Healthy</span>
            </span>
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-yellow-400"></span>
              <span className="text-white/60">Degraded</span>
            </span>
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-400"></span>
              <span className="text-white/60">Down</span>
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {networks.map((network) => (
            <div
              key={network.chainId}
              className="p-4 bg-white/5 rounded-xl border border-white/10 hover:bg-white/10 transition-all"
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{network.icon}</span>
                  <div>
                    <div className="text-white font-medium">{network.name}</div>
                    <div className="text-xs text-white/50">Chain ID: {network.chainId}</div>
                  </div>
                </div>
                <span className={`w-3 h-3 rounded-full ${getStatusColor(network.status)} ${
                  network.status === 'degraded' ? 'animate-pulse' : ''
                }`}></span>
              </div>
              <div className="grid grid-cols-3 gap-2 text-xs">
                <div>
                  <div className="text-white/50">Latency</div>
                  <div className={`font-mono ${
                    network.latency > 100 ? 'text-yellow-400' : 'text-white'
                  }`}>{network.latency}ms</div>
                </div>
                <div>
                  <div className="text-white/50">Block</div>
                  <div className="text-white font-mono">{(network.blockHeight / 1000000).toFixed(2)}M</div>
                </div>
                <div>
                  <div className="text-white/50">Pending</div>
                  <div className={`font-mono ${
                    network.pendingMessages > 20 ? 'text-yellow-400' : 'text-white'
                  }`}>{network.pendingMessages}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Volume Chart Placeholder */}
      <div className="glass-card p-6">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <span>📈</span>
          Bridge Volume ({timeRange})
        </h3>
        <div className="h-64 flex items-end justify-between gap-2 px-4">
          {Array.from({ length: timeRange === '24h' ? 24 : timeRange === '7d' ? 7 : 30 }).map((_, i) => {
            const height = 20 + Math.random() * 80;
            return (
              <div
                key={i}
                className="flex-1 bg-gradient-to-t from-pil-purple to-pil-cyan rounded-t-sm opacity-80 hover:opacity-100 transition-all cursor-pointer group relative"
                style={{ height: `${height}%` }}
              >
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-pil-dark rounded text-xs text-white opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                  ${(Math.random() * 500000).toFixed(0)}
                </div>
              </div>
            );
          })}
        </div>
        <div className="flex justify-between mt-4 text-xs text-white/50">
          <span>{timeRange === '24h' ? '00:00' : timeRange === '7d' ? 'Mon' : '1st'}</span>
          <span>{timeRange === '24h' ? '12:00' : timeRange === '7d' ? 'Thu' : '15th'}</span>
          <span>{timeRange === '24h' ? '23:00' : timeRange === '7d' ? 'Sun' : '30th'}</span>
        </div>
      </div>

      {/* Recent Events */}
      <div className="glass-card p-6">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <span>📋</span>
          Recent Events
        </h3>
        <div className="space-y-3">
          {events.map((event) => (
            <div
              key={event.id}
              className="flex items-center justify-between p-4 bg-white/5 rounded-lg border border-white/10 hover:bg-white/10 transition-all"
            >
              <div className="flex items-center gap-4">
                <span className="text-2xl">{getEventIcon(event.type)}</span>
                <div>
                  <div className="text-white">{event.description}</div>
                  <div className="text-xs text-white/50 flex items-center gap-2">
                    <span>{formatTimeAgo(event.timestamp)}</span>
                    {event.txHash && (
                      <>
                        <span>•</span>
                        <span className="font-mono text-pil-cyan">{event.txHash}</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                event.status === 'success' 
                  ? 'bg-green-500/20 text-green-400'
                  : event.status === 'pending'
                  ? 'bg-yellow-500/20 text-yellow-400'
                  : 'bg-red-500/20 text-red-400'
              }`}>
                {event.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Chain Distribution */}
      <div className="grid md:grid-cols-2 gap-6">
        <div className="glass-card p-6">
          <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <span>🥧</span>
            Volume by Chain
          </h3>
          <div className="space-y-3">
            {[
              { name: 'Ethereum', percentage: 35, color: '#627EEA' },
              { name: 'Arbitrum', percentage: 28, color: '#28A0F0' },
              { name: 'Optimism', percentage: 18, color: '#FF0420' },
              { name: 'Base', percentage: 12, color: '#0052FF' },
              { name: 'Others', percentage: 7, color: '#8B8DFC' },
            ].map((chain) => (
              <div key={chain.name}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-white">{chain.name}</span>
                  <span className="text-white/60">{chain.percentage}%</span>
                </div>
                <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${chain.percentage}%`, backgroundColor: chain.color }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="glass-card p-6">
          <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <span>🔐</span>
            Proof Types
          </h3>
          <div className="space-y-3">
            {[
              { name: 'Groth16 (BN254)', count: 12456, color: '#06B6D4' },
              { name: 'PLONK', count: 8234, color: '#6366F1' },
              { name: 'UltraPLONK (Aztec)', count: 3456, color: '#8B5CF6' },
              { name: 'FRI (STARKs)', count: 1234, color: '#EC4899' },
            ].map((proof) => (
              <div
                key={proof.name}
                className="flex items-center justify-between p-3 bg-white/5 rounded-lg"
              >
                <div className="flex items-center gap-3">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: proof.color }}
                  />
                  <span className="text-white">{proof.name}</span>
                </div>
                <span className="text-white/60 font-mono">{proof.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  title,
  value,
  change,
  positive,
  icon,
}: {
  title: string;
  value: string;
  change: string;
  positive: boolean;
  icon: string;
}) {
  return (
    <div className="glass-card p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-2xl">{icon}</span>
        <span className={`text-xs font-medium ${positive ? 'text-green-400' : 'text-red-400'}`}>
          {change}
        </span>
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="text-sm text-white/50">{title}</div>
    </div>
  );
}
