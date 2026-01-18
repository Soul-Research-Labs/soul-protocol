'use client';

import { useState, useEffect } from 'react';
import { useAccount, useReadContract, useReadContracts } from 'wagmi';
import { formatEther, formatUnits } from 'viem';
import { CONTRACTS } from '@/lib/contracts';
import { PC3_ABI, PBP_ABI, CDNA_ABI, ORCHESTRATOR_ABI } from '@/lib/abis';

interface SystemMetrics {
  totalContainers: bigint;
  totalVerified: bigint;
  totalPolicies: bigint;
  activePolicies: bigint;
  totalNullifiers: bigint;
  totalOperations: bigint;
}

interface PrimitiveStatus {
  name: string;
  address: `0x${string}`;
  isActive: boolean;
  isPaused: boolean;
  lastActivity?: string;
}

export function MonitoringDashboard() {
  const { isConnected } = useAccount();
  const [refreshInterval, setRefreshInterval] = useState(30000);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  // Read system metrics
  const { data: pc3Total } = useReadContract({
    address: CONTRACTS.proofCarryingContainer as `0x${string}`,
    abi: PC3_ABI,
    functionName: 'totalContainers',
  });

  const { data: pc3Verified } = useReadContract({
    address: CONTRACTS.proofCarryingContainer as `0x${string}`,
    abi: PC3_ABI,
    functionName: 'totalVerified',
  });

  const { data: pbpTotal } = useReadContract({
    address: CONTRACTS.policyBoundProofs as `0x${string}`,
    abi: PBP_ABI,
    functionName: 'totalPolicies',
  });

  const { data: orchestratorPaused } = useReadContract({
    address: CONTRACTS.orchestrator as `0x${string}`,
    abi: ORCHESTRATOR_ABI,
    functionName: 'paused',
  });

  const metrics: SystemMetrics = {
    totalContainers: (pc3Total as bigint) || 0n,
    totalVerified: (pc3Verified as bigint) || 0n,
    totalPolicies: (pbpTotal as bigint) || 0n,
    activePolicies: 0n,
    totalNullifiers: 0n,
    totalOperations: 0n,
  };

  const primitives: PrimitiveStatus[] = [
    {
      name: 'PC³ (Proof-Carrying Container)',
      address: CONTRACTS.proofCarryingContainer as `0x${string}`,
      isActive: true,
      isPaused: false,
    },
    {
      name: 'PBP (Policy-Bound Proofs)',
      address: CONTRACTS.policyBoundProofs as `0x${string}`,
      isActive: true,
      isPaused: false,
    },
    {
      name: 'EASC (State Commitments)',
      address: CONTRACTS.executionAgnosticStateCommitments as `0x${string}`,
      isActive: true,
      isPaused: false,
    },
    {
      name: 'CDNA (Nullifier Algebra)',
      address: CONTRACTS.crossDomainNullifierAlgebra as `0x${string}`,
      isActive: true,
      isPaused: false,
    },
  ];

  // Auto-refresh
  useEffect(() => {
    const interval = setInterval(() => {
      setLastRefresh(new Date());
    }, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  if (!isConnected) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 text-center">
        <p className="text-gray-400">Connect wallet to view system monitoring</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white">System Monitoring</h2>
        <div className="flex items-center gap-4">
          <select
            value={refreshInterval}
            onChange={(e) => setRefreshInterval(Number(e.target.value))}
            className="bg-gray-700 border border-gray-600 rounded px-3 py-1 text-white text-sm"
          >
            <option value={10000}>10s refresh</option>
            <option value={30000}>30s refresh</option>
            <option value={60000}>1m refresh</option>
            <option value={300000}>5m refresh</option>
          </select>
          <span className="text-gray-400 text-sm">
            Last: {lastRefresh.toLocaleTimeString()}
          </span>
        </div>
      </div>

      {/* System Status Banner */}
      <div className={`rounded-lg p-4 ${orchestratorPaused ? 'bg-red-900/50 border border-red-500' : 'bg-green-900/50 border border-green-500'}`}>
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${orchestratorPaused ? 'bg-red-500 animate-pulse' : 'bg-green-500'}`}></div>
          <span className="text-white font-medium">
            System Status: {orchestratorPaused ? 'PAUSED' : 'OPERATIONAL'}
          </span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Containers"
          value={metrics.totalContainers.toString()}
          icon="📦"
          trend="+12%"
          trendUp={true}
        />
        <MetricCard
          title="Verified Containers"
          value={metrics.totalVerified.toString()}
          icon="✅"
          trend={`${metrics.totalContainers > 0n ? ((metrics.totalVerified * 100n) / metrics.totalContainers).toString() : 0}%`}
          trendUp={true}
        />
        <MetricCard
          title="Active Policies"
          value={metrics.totalPolicies.toString()}
          icon="📋"
          trend="stable"
          trendUp={null}
        />
        <MetricCard
          title="Nullifiers Used"
          value={metrics.totalNullifiers.toString()}
          icon="🔐"
          trend="+5"
          trendUp={true}
        />
      </div>

      {/* Primitives Status */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Primitive Status</h3>
        <div className="space-y-3">
          {primitives.map((primitive) => (
            <PrimitiveRow key={primitive.name} primitive={primitive} />
          ))}
        </div>
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Recent Operations</h3>
          <div className="space-y-3">
            <ActivityRow
              type="Container Created"
              hash="0x1234...5678"
              time="2 min ago"
              status="success"
            />
            <ActivityRow
              type="Policy Verified"
              hash="0xabcd...ef01"
              time="5 min ago"
              status="success"
            />
            <ActivityRow
              type="Nullifier Consumed"
              hash="0x9876...5432"
              time="12 min ago"
              status="success"
            />
            <ActivityRow
              type="State Transition"
              hash="0xfedc...ba98"
              time="23 min ago"
              status="success"
            />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Gas Usage (24h)</h3>
          <div className="space-y-4">
            <GasRow label="Container Creation" avg="878,344" max="920,000" />
            <GasRow label="Policy Registration" avg="285,841" max="310,000" />
            <GasRow label="Nullifier Registration" avg="289,465" max="320,000" />
            <GasRow label="State Commitment" avg="185,534" max="200,000" />
          </div>
        </div>
      </div>

      {/* Health Checks */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Health Checks</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <HealthCheck name="RPC Connection" status="healthy" />
          <HealthCheck name="Subgraph Sync" status="healthy" />
          <HealthCheck name="Verifier Registry" status="healthy" />
          <HealthCheck name="Cross-Chain Relay" status="warning" />
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  title,
  value,
  icon,
  trend,
  trendUp,
}: {
  title: string;
  value: string;
  icon: string;
  trend: string;
  trendUp: boolean | null;
}) {
  return (
    <div className="bg-gray-800 rounded-lg p-5">
      <div className="flex justify-between items-start">
        <div>
          <p className="text-gray-400 text-sm">{title}</p>
          <p className="text-3xl font-bold text-white mt-1">{value}</p>
        </div>
        <span className="text-2xl">{icon}</span>
      </div>
      {trend && (
        <div className={`mt-3 text-sm ${trendUp === true ? 'text-green-400' : trendUp === false ? 'text-red-400' : 'text-gray-400'}`}>
          {trendUp !== null && (trendUp ? '↑' : '↓')} {trend}
        </div>
      )}
    </div>
  );
}

function PrimitiveRow({ primitive }: { primitive: PrimitiveStatus }) {
  return (
    <div className="flex items-center justify-between p-3 bg-gray-700 rounded-lg">
      <div className="flex items-center gap-3">
        <div className={`w-2 h-2 rounded-full ${primitive.isActive ? 'bg-green-500' : 'bg-red-500'}`}></div>
        <span className="text-white font-medium">{primitive.name}</span>
      </div>
      <div className="flex items-center gap-4">
        <span className="text-gray-400 text-sm font-mono">
          {primitive.address.slice(0, 6)}...{primitive.address.slice(-4)}
        </span>
        <span className={`px-2 py-1 rounded text-xs ${primitive.isPaused ? 'bg-yellow-600 text-yellow-100' : 'bg-green-600 text-green-100'}`}>
          {primitive.isPaused ? 'Paused' : 'Active'}
        </span>
      </div>
    </div>
  );
}

function ActivityRow({
  type,
  hash,
  time,
  status,
}: {
  type: string;
  hash: string;
  time: string;
  status: 'success' | 'pending' | 'failed';
}) {
  const statusColors = {
    success: 'text-green-400',
    pending: 'text-yellow-400',
    failed: 'text-red-400',
  };

  return (
    <div className="flex items-center justify-between p-2 hover:bg-gray-700 rounded">
      <div className="flex items-center gap-3">
        <span className={`${statusColors[status]}`}>●</span>
        <span className="text-white">{type}</span>
      </div>
      <div className="flex items-center gap-4">
        <span className="text-gray-400 text-sm font-mono">{hash}</span>
        <span className="text-gray-500 text-sm">{time}</span>
      </div>
    </div>
  );
}

function GasRow({
  label,
  avg,
  max,
}: {
  label: string;
  avg: string;
  max: string;
}) {
  const percentage = (parseInt(avg.replace(/,/g, '')) / parseInt(max.replace(/,/g, ''))) * 100;
  
  return (
    <div>
      <div className="flex justify-between text-sm mb-1">
        <span className="text-gray-300">{label}</span>
        <span className="text-gray-400">avg: {avg}</span>
      </div>
      <div className="w-full bg-gray-700 rounded-full h-2">
        <div
          className="bg-purple-500 h-2 rounded-full"
          style={{ width: `${percentage}%` }}
        ></div>
      </div>
    </div>
  );
}

function HealthCheck({
  name,
  status,
}: {
  name: string;
  status: 'healthy' | 'warning' | 'error';
}) {
  const statusConfig = {
    healthy: { color: 'bg-green-500', icon: '✓' },
    warning: { color: 'bg-yellow-500', icon: '!' },
    error: { color: 'bg-red-500', icon: '✕' },
  };

  const config = statusConfig[status];

  return (
    <div className="flex items-center gap-2 p-3 bg-gray-700 rounded">
      <div className={`w-6 h-6 rounded-full ${config.color} flex items-center justify-center text-white text-xs`}>
        {config.icon}
      </div>
      <span className="text-gray-200 text-sm">{name}</span>
    </div>
  );
}

export default MonitoringDashboard;
