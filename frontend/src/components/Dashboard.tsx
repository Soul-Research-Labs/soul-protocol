'use client';

import { useState } from 'react';
import { useAccount, useChainId, useBalance } from 'wagmi';
import ContainerPanel from './panels/ContainerPanel';
import PolicyPanel from './panels/PolicyPanel';
import NullifierPanel from './panels/NullifierPanel';
import StatePanel from './panels/StatePanel';
import OrchestratorPanel from './panels/OrchestratorPanel';
import BridgePanel from './panels/BridgePanel';
import AnalyticsPanel from './panels/AnalyticsPanel';

type TabId = 'containers' | 'bridge' | 'policies' | 'nullifiers' | 'state' | 'orchestrator' | 'analytics';

const tabs: { id: TabId; label: string; icon: string; badge?: string }[] = [
  { id: 'containers', label: 'PC³ Containers', icon: '📦' },
  { id: 'bridge', label: 'Cross-Chain Bridge', icon: '🌉', badge: 'New' },
  { id: 'policies', label: 'Policy Proofs', icon: '📋' },
  { id: 'nullifiers', label: 'Nullifiers', icon: '🔑' },
  { id: 'state', label: 'State Commits', icon: '🔄' },
  { id: 'orchestrator', label: 'Orchestrator', icon: '🎛️' },
  { id: 'analytics', label: 'Analytics', icon: '📊' },
];

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<TabId>('containers');
  const { address } = useAccount();
  const chainId = useChainId();
  const { data: balance } = useBalance({ address });

  return (
    <div className="pt-24 pb-16">
      <div className="container mx-auto px-6">
        {/* User Info Header */}
        <div className="glass-card p-6 mb-8">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 rounded-full bg-gradient-pil flex items-center justify-center text-2xl">
                🛡️
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">PIL v2 Dashboard</h2>
                <p className="text-white/60">
                  {address?.slice(0, 6)}...{address?.slice(-4)} • Chain {chainId}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-6">
              <div className="text-right">
                <div className="text-sm text-white/50">Balance</div>
                <div className="text-lg font-bold text-white">
                  {balance ? `${parseFloat(balance.formatted).toFixed(4)} ${balance.symbol}` : '0.00 ETH'}
                </div>
              </div>
              <div className="h-10 w-px bg-white/20"></div>
              <div className="text-right">
                <div className="text-sm text-white/50">Network Status</div>
                <div className="flex items-center gap-2">
                  <span className="status-dot status-success"></span>
                  <span className="text-green-400">Connected</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <QuickStat icon="📦" label="Containers" value="12" />
          <QuickStat icon="🌉" label="Bridges" value="5" />
          <QuickStat icon="🔐" label="Proofs" value="48" />
          <QuickStat icon="🔑" label="Nullifiers" value="23" />
        </div>

        {/* Tabs */}
        <div className="glass-card p-2 mb-8 overflow-x-auto">
          <div className="flex gap-2 min-w-max">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-200 whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'bg-gradient-pil text-white'
                    : 'text-white/60 hover:text-white hover:bg-white/10'
                }`}
              >
                <span>{tab.icon}</span>
                <span>{tab.label}</span>
                {tab.badge && (
                  <span className="px-1.5 py-0.5 text-xs bg-pil-cyan/20 text-pil-cyan rounded-full">
                    {tab.badge}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="animate-fadeIn">
          {activeTab === 'containers' && <ContainerPanel />}
          {activeTab === 'bridge' && <BridgePanel />}
          {activeTab === 'policies' && <PolicyPanel />}
          {activeTab === 'nullifiers' && <NullifierPanel />}
          {activeTab === 'state' && <StatePanel />}
          {activeTab === 'orchestrator' && <OrchestratorPanel />}
          {activeTab === 'analytics' && <AnalyticsPanel />}
        </div>
      </div>
    </div>
  );
}

function QuickStat({ icon, label, value }: { icon: string; label: string; value: string }) {
  return (
    <div className="glass-card p-4 flex items-center gap-3">
      <span className="text-2xl">{icon}</span>
      <div>
        <div className="text-xl font-bold text-white">{value}</div>
        <div className="text-sm text-white/50">{label}</div>
      </div>
    </div>
  );
}
