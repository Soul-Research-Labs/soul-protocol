/**
 * PIL Frontend - Dashboard
 * 
 * Main dashboard component with network stats and activity
 */

import React, { useState, useMemo, useEffect } from 'react';

// Types
export interface NetworkStats {
  totalValueLocked: string;
  dailyVolume: string;
  totalTransfers: number;
  activeUsers: number;
  avgTransferTime: number;
  successRate: number;
}

export interface ChainStats {
  chainId: string;
  name: string;
  icon: string;
  tvl: string;
  volume24h: string;
  transfers24h: number;
  avgTime: number;
  status: 'online' | 'degraded' | 'offline';
}

export interface RecentActivity {
  id: string;
  type: 'deposit' | 'withdraw' | 'bridge';
  amount: string;
  sourceChain: string;
  destChain?: string;
  timestamp: number;
  status: 'pending' | 'completed' | 'failed';
  txHash: string;
}

// Styles
const styles = {
  dashboard: {
    fontFamily: 'system-ui, -apple-system, sans-serif',
    padding: '24px',
    backgroundColor: '#0f0f1a',
    minHeight: '100vh',
    color: '#ffffff',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '32px',
  },
  logo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  logoText: {
    fontSize: '24px',
    fontWeight: 'bold',
  },
  nav: {
    display: 'flex',
    gap: '24px',
  },
  navLink: (active: boolean) => ({
    color: active ? '#8B5CF6' : '#a0a0a0',
    textDecoration: 'none',
    fontSize: '14px',
    cursor: 'pointer',
    borderBottom: active ? '2px solid #8B5CF6' : 'none',
    paddingBottom: '4px',
  }),
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
    gap: '24px',
    marginBottom: '32px',
  },
  card: {
    padding: '24px',
    backgroundColor: '#1a1a2e',
    borderRadius: '16px',
  },
  cardTitle: {
    fontSize: '12px',
    color: '#a0a0a0',
    textTransform: 'uppercase' as const,
    letterSpacing: '1px',
    marginBottom: '8px',
  },
  cardValue: {
    fontSize: '32px',
    fontWeight: 'bold',
  },
  cardSubtext: {
    fontSize: '12px',
    color: '#10B981',
    marginTop: '8px',
  },
  sectionTitle: {
    fontSize: '18px',
    fontWeight: 'bold',
    marginBottom: '16px',
  },
  chainGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '16px',
    marginBottom: '32px',
  },
  chainCard: {
    padding: '16px',
    backgroundColor: '#1a1a2e',
    borderRadius: '12px',
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '12px',
  },
  chainHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  chainName: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '16px',
    fontWeight: 'bold',
  },
  statusDot: (status: string) => {
    const colors: Record<string, string> = {
      online: '#10B981',
      degraded: '#F59E0B',
      offline: '#EF4444',
    };
    return {
      width: '8px',
      height: '8px',
      borderRadius: '50%',
      backgroundColor: colors[status] || '#a0a0a0',
    };
  },
  chainStat: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '12px',
  },
  activityTable: {
    width: '100%',
    borderCollapse: 'collapse' as const,
  },
  th: {
    textAlign: 'left' as const,
    padding: '12px',
    borderBottom: '1px solid #333',
    color: '#a0a0a0',
    fontSize: '12px',
    textTransform: 'uppercase' as const,
  },
  td: {
    padding: '12px',
    borderBottom: '1px solid #222',
    fontSize: '14px',
  },
  badge: (type: string) => {
    const colors: Record<string, string> = {
      deposit: '#10B981',
      withdraw: '#8B5CF6',
      bridge: '#F59E0B',
      pending: '#F59E0B',
      completed: '#10B981',
      failed: '#EF4444',
    };
    return {
      padding: '4px 8px',
      borderRadius: '4px',
      backgroundColor: `${colors[type]}20` || '#33333320',
      color: colors[type] || '#a0a0a0',
      fontSize: '12px',
      textTransform: 'uppercase' as const,
    };
  },
  txHash: {
    fontFamily: 'monospace',
    fontSize: '12px',
    color: '#8B5CF6',
    cursor: 'pointer',
  },
  chart: {
    height: '200px',
    backgroundColor: '#0f0f23',
    borderRadius: '12px',
    display: 'flex',
    alignItems: 'flex-end',
    padding: '16px',
    gap: '4px',
  },
  chartBar: (height: number, color: string) => ({
    flex: 1,
    height: `${height}%`,
    backgroundColor: color,
    borderRadius: '4px 4px 0 0',
    minWidth: '8px',
    transition: 'height 0.3s',
  }),
  footer: {
    marginTop: '48px',
    padding: '24px',
    borderTop: '1px solid #333',
    textAlign: 'center' as const,
    color: '#a0a0a0',
    fontSize: '12px',
  },
};

// Sample data
const sampleNetworkStats: NetworkStats = {
  totalValueLocked: '$142.5M',
  dailyVolume: '$8.2M',
  totalTransfers: 125847,
  activeUsers: 12543,
  avgTransferTime: 45,
  successRate: 99.7,
};

const sampleChainStats: ChainStats[] = [
  { chainId: 'ethereum', name: 'Ethereum', icon: '⟠', tvl: '$52.3M', volume24h: '$3.1M', transfers24h: 1247, avgTime: 180, status: 'online' },
  { chainId: 'polkadot', name: 'Polkadot', icon: '●', tvl: '$28.7M', volume24h: '$1.8M', transfers24h: 892, avgTime: 180, status: 'online' },
  { chainId: 'cosmos', name: 'Cosmos', icon: '⚛', tvl: '$18.4M', volume24h: '$1.2M', transfers24h: 567, avgTime: 105, status: 'online' },
  { chainId: 'cardano', name: 'Cardano', icon: '₳', tvl: '$15.2M', volume24h: '$0.9M', transfers24h: 423, avgTime: 400, status: 'online' },
  { chainId: 'zksync', name: 'zkSync Era', icon: '⚡', tvl: '$12.8M', volume24h: '$0.7M', transfers24h: 1892, avgTime: 10, status: 'online' },
  { chainId: 'avalanche', name: 'Avalanche', icon: '🔺', tvl: '$8.9M', volume24h: '$0.3M', transfers24h: 312, avgTime: 2, status: 'online' },
  { chainId: 'arbitrum', name: 'Arbitrum', icon: '🔵', tvl: '$4.2M', volume24h: '$0.2M', transfers24h: 198, avgTime: 600, status: 'degraded' },
  { chainId: 'near', name: 'NEAR', icon: 'Ⓝ', tvl: '$2.0M', volume24h: '$0.05M', transfers24h: 87, avgTime: 240, status: 'online' },
];

const sampleActivity: RecentActivity[] = [
  { id: '1', type: 'bridge', amount: '5.2 ETH', sourceChain: 'Ethereum', destChain: 'zkSync', timestamp: Date.now() - 120000, status: 'completed', txHash: '0xabc...123' },
  { id: '2', type: 'deposit', amount: '10 ETH', sourceChain: 'Ethereum', timestamp: Date.now() - 300000, status: 'completed', txHash: '0xdef...456' },
  { id: '3', type: 'bridge', amount: '1000 DOT', sourceChain: 'Polkadot', destChain: 'Cosmos', timestamp: Date.now() - 600000, status: 'pending', txHash: '0xghi...789' },
  { id: '4', type: 'withdraw', amount: '2.5 ETH', sourceChain: 'Ethereum', timestamp: Date.now() - 900000, status: 'completed', txHash: '0xjkl...012' },
  { id: '5', type: 'bridge', amount: '500 ATOM', sourceChain: 'Cosmos', destChain: 'Avalanche', timestamp: Date.now() - 1200000, status: 'failed', txHash: '0xmno...345' },
];

// Components
const StatCard: React.FC<{
  title: string;
  value: string;
  change?: string;
  positive?: boolean;
}> = ({ title, value, change, positive = true }) => (
  <div style={styles.card}>
    <div style={styles.cardTitle}>{title}</div>
    <div style={styles.cardValue}>{value}</div>
    {change && (
      <div style={{ ...styles.cardSubtext, color: positive ? '#10B981' : '#EF4444' }}>
        {positive ? '↑' : '↓'} {change}
      </div>
    )}
  </div>
);

const ChainCard: React.FC<{ chain: ChainStats }> = ({ chain }) => (
  <div style={styles.chainCard}>
    <div style={styles.chainHeader}>
      <div style={styles.chainName}>
        <span>{chain.icon}</span>
        <span>{chain.name}</span>
      </div>
      <div style={styles.statusDot(chain.status)} title={chain.status} />
    </div>
    <div style={styles.chainStat}>
      <span style={{ color: '#a0a0a0' }}>TVL</span>
      <span>{chain.tvl}</span>
    </div>
    <div style={styles.chainStat}>
      <span style={{ color: '#a0a0a0' }}>24h Volume</span>
      <span>{chain.volume24h}</span>
    </div>
    <div style={styles.chainStat}>
      <span style={{ color: '#a0a0a0' }}>Transfers</span>
      <span>{chain.transfers24h}</span>
    </div>
  </div>
);

const VolumeChart: React.FC = () => {
  // Generate mock hourly volume data
  const data = useMemo(() => {
    return Array.from({ length: 24 }, (_, i) => ({
      hour: i,
      volume: Math.random() * 80 + 20,
      private: Math.random() * 40 + 10,
    }));
  }, []);

  return (
    <div style={styles.card}>
      <h3 style={styles.sectionTitle}>24h Volume</h3>
      <div style={styles.chart}>
        {data.map((d, i) => (
          <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '2px', alignItems: 'center' }}>
            <div style={styles.chartBar(d.volume, '#8B5CF6')} title={`${d.volume.toFixed(0)}% total`} />
            <div style={styles.chartBar(d.private, '#10B981')} title={`${d.private.toFixed(0)}% private`} />
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', gap: '16px', marginTop: '12px', justifyContent: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
          <div style={{ width: '12px', height: '12px', backgroundColor: '#8B5CF6', borderRadius: '2px' }} />
          <span>Total Volume</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
          <div style={{ width: '12px', height: '12px', backgroundColor: '#10B981', borderRadius: '2px' }} />
          <span>Private Transfers</span>
        </div>
      </div>
    </div>
  );
};

const ActivityTable: React.FC<{ activities: RecentActivity[] }> = ({ activities }) => {
  const formatTime = (timestamp: number) => {
    const diff = Date.now() - timestamp;
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return new Date(timestamp).toLocaleDateString();
  };

  return (
    <div style={styles.card}>
      <h3 style={styles.sectionTitle}>Recent Activity</h3>
      <table style={styles.activityTable}>
        <thead>
          <tr>
            <th style={styles.th}>Type</th>
            <th style={styles.th}>Amount</th>
            <th style={styles.th}>Route</th>
            <th style={styles.th}>Time</th>
            <th style={styles.th}>Status</th>
            <th style={styles.th}>TX</th>
          </tr>
        </thead>
        <tbody>
          {activities.map(activity => (
            <tr key={activity.id}>
              <td style={styles.td}>
                <span style={styles.badge(activity.type)}>{activity.type}</span>
              </td>
              <td style={styles.td}>{activity.amount}</td>
              <td style={styles.td}>
                {activity.sourceChain}
                {activity.destChain && ` → ${activity.destChain}`}
              </td>
              <td style={styles.td}>{formatTime(activity.timestamp)}</td>
              <td style={styles.td}>
                <span style={styles.badge(activity.status)}>{activity.status}</span>
              </td>
              <td style={styles.td}>
                <span style={styles.txHash}>{activity.txHash}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

// Main Dashboard Component
export const Dashboard: React.FC<{
  networkStats?: NetworkStats;
  chainStats?: ChainStats[];
  recentActivity?: RecentActivity[];
}> = ({
  networkStats = sampleNetworkStats,
  chainStats = sampleChainStats,
  recentActivity = sampleActivity,
}) => {
  const [activeNav, setActiveNav] = useState('overview');
  const [lastUpdate, setLastUpdate] = useState(new Date());

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setLastUpdate(new Date());
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={styles.dashboard}>
      {/* Header */}
      <header style={styles.header}>
        <div style={styles.logo}>
          <span style={{ fontSize: '32px' }}>🔒</span>
          <span style={styles.logoText}>PIL Dashboard</span>
        </div>
        <nav style={styles.nav}>
          {['overview', 'bridges', 'proofs', 'analytics'].map(nav => (
            <span
              key={nav}
              style={styles.navLink(activeNav === nav)}
              onClick={() => setActiveNav(nav)}
            >
              {nav.charAt(0).toUpperCase() + nav.slice(1)}
            </span>
          ))}
        </nav>
        <div style={{ fontSize: '12px', color: '#a0a0a0' }}>
          Last updated: {lastUpdate.toLocaleTimeString()}
        </div>
      </header>

      {/* Stats Grid */}
      <div style={styles.grid}>
        <StatCard title="Total Value Locked" value={networkStats.totalValueLocked} change="12.5% this week" />
        <StatCard title="24h Volume" value={networkStats.dailyVolume} change="8.2% vs yesterday" />
        <StatCard title="Total Transfers" value={networkStats.totalTransfers.toLocaleString()} change="1,247 today" />
        <StatCard title="Active Users" value={networkStats.activeUsers.toLocaleString()} change="543 new this week" />
        <StatCard title="Avg Transfer Time" value={`${networkStats.avgTransferTime}s`} change="15% faster" />
        <StatCard title="Success Rate" value={`${networkStats.successRate}%`} change="0.1% improvement" />
      </div>

      {/* Volume Chart */}
      <VolumeChart />

      {/* Chain Stats */}
      <div style={{ marginTop: '32px' }}>
        <h3 style={styles.sectionTitle}>Network Status</h3>
        <div style={styles.chainGrid}>
          {chainStats.map(chain => (
            <ChainCard key={chain.chainId} chain={chain} />
          ))}
        </div>
      </div>

      {/* Activity Table */}
      <ActivityTable activities={recentActivity} />

      {/* Footer */}
      <footer style={styles.footer}>
        <p>Privacy Interoperability Layer • Version 1.0.0</p>
        <p style={{ marginTop: '8px' }}>
          Powered by ZK proofs • Cross-chain privacy for Web3
        </p>
      </footer>
    </div>
  );
};

export default Dashboard;
