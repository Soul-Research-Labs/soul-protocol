'use client';

import { useState } from 'react';
import { useAccount, useChainId } from 'wagmi';
import ContainerPanel from './panels/ContainerPanel';
import PolicyPanel from './panels/PolicyPanel';
import NullifierPanel from './panels/NullifierPanel';
import StatePanel from './panels/StatePanel';
import OrchestratorPanel from './panels/OrchestratorPanel';

type TabId = 'containers' | 'policies' | 'nullifiers' | 'state' | 'orchestrator';

const tabs: { id: TabId; label: string; icon: string }[] = [
  { id: 'containers', label: 'PC³ Containers', icon: '📦' },
  { id: 'policies', label: 'Policy Proofs', icon: '📋' },
  { id: 'nullifiers', label: 'Nullifiers', icon: '🔑' },
  { id: 'state', label: 'State Commits', icon: '🔄' },
  { id: 'orchestrator', label: 'Orchestrator', icon: '🎛️' },
];

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<TabId>('containers');
  const { address } = useAccount();
  const chainId = useChainId();

  return (
    <div className="pt-24 pb-16">
      <div className="container mx-auto px-6">
        {/* User Info */}
        <div className="glass-card p-6 mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-bold text-white">PIL v2 Dashboard</h2>
              <p className="text-white/60">
                Connected as {address?.slice(0, 6)}...{address?.slice(-4)} on chain {chainId}
              </p>
            </div>
            <div className="flex items-center gap-4">
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

        {/* Tabs */}
        <div className="glass-card p-2 mb-8">
          <div className="flex flex-wrap gap-2">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-200 ${
                  activeTab === tab.id
                    ? 'bg-gradient-pil text-white'
                    : 'text-white/60 hover:text-white hover:bg-white/10'
                }`}
              >
                <span>{tab.icon}</span>
                <span>{tab.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="animate-fadeIn">
          {activeTab === 'containers' && <ContainerPanel />}
          {activeTab === 'policies' && <PolicyPanel />}
          {activeTab === 'nullifiers' && <NullifierPanel />}
          {activeTab === 'state' && <StatePanel />}
          {activeTab === 'orchestrator' && <OrchestratorPanel />}
        </div>
      </div>
    </div>
  );
}
