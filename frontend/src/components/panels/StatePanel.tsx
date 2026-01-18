'use client';

import { useState } from 'react';
import { useWriteContract, useWaitForTransactionReceipt } from 'wagmi';
import { keccak256, toHex } from 'viem';
import { EASC_ABI } from '@/lib/abis';
import { useContracts } from '@/lib/contracts';

export default function StatePanel() {
  const [stateData, setStateData] = useState('');
  const [executionEnv, setExecutionEnv] = useState<'evm' | 'cairo' | 'move' | 'cosmwasm'>('evm');
  const contracts = useContracts();

  const { writeContract, data: txHash, isPending } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({
    hash: txHash,
  });

  const handleCreateCommitment = () => {
    if (!stateData || !contracts.executionAgnosticStateCommitments) return;

    const stateRoot = keccak256(toHex(stateData));
    const envHash = keccak256(toHex(executionEnv));

    writeContract({
      address: contracts.executionAgnosticStateCommitments as `0x${string}`,
      abi: EASC_ABI,
      functionName: 'createCommitment',
      args: [stateRoot, envHash, toHex(stateData)],
    });
  };

  return (
    <div className="space-y-6">
      {/* EASC Info */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>🔄</span>
          Execution Agnostic State Commitments (EASC)
        </h3>
        <p className="text-white/60 mb-6">
          State commitments that are verifiable across any execution environment - EVM, Cairo, Move, or CosmWasm.
          The commitment structure: <code className="text-pil-cyan">C = H(state_root || env_hash || metadata)</code>
        </p>

        {/* Environment Support */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <EnvCard 
            name="EVM" 
            icon="⟠" 
            supported={true}
            selected={executionEnv === 'evm'}
            onClick={() => setExecutionEnv('evm')}
          />
          <EnvCard 
            name="Cairo" 
            icon="🔺" 
            supported={true}
            selected={executionEnv === 'cairo'}
            onClick={() => setExecutionEnv('cairo')}
          />
          <EnvCard 
            name="Move" 
            icon="◆" 
            supported={true}
            selected={executionEnv === 'move'}
            onClick={() => setExecutionEnv('move')}
          />
          <EnvCard 
            name="CosmWasm" 
            icon="🌌" 
            supported={true}
            selected={executionEnv === 'cosmwasm'}
            onClick={() => setExecutionEnv('cosmwasm')}
          />
        </div>
      </div>

      {/* Create Commitment */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>➕</span>
          Create State Commitment
        </h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-white/70 mb-2">State Data</label>
            <textarea
              className="input-field h-32 resize-none font-mono"
              placeholder="Enter state data (JSON, bytes, or any serialized format)..."
              value={stateData}
              onChange={(e) => setStateData(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-sm text-white/70 mb-2">Target Environment</label>
            <select
              className="input-field"
              value={executionEnv}
              onChange={(e) => setExecutionEnv(e.target.value as any)}
            >
              <option value="evm">EVM (Ethereum, Polygon, etc.)</option>
              <option value="cairo">Cairo (StarkNet)</option>
              <option value="move">Move (Sui, Aptos)</option>
              <option value="cosmwasm">CosmWasm (Cosmos)</option>
            </select>
          </div>

          <button
            onClick={handleCreateCommitment}
            disabled={isPending || isConfirming || !stateData}
            className="btn-primary w-full"
          >
            {isPending ? 'Confirming...' : isConfirming ? 'Creating Commitment...' : 'Create Commitment'}
          </button>

          {isSuccess && (
            <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
              <p className="text-green-400">✅ State commitment created!</p>
              <p className="text-sm text-white/60 mt-1">
                The state can now be verified on any {executionEnv.toUpperCase()} compatible chain.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* State Transitions */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>📊</span>
          State Transition History
        </h3>
        
        <div className="space-y-3">
          <TransitionRow 
            from="0x1234...abcd" 
            to="0x5678...ef01" 
            env="EVM"
            time="5 min ago"
            valid={true}
          />
          <TransitionRow 
            from="0x5678...ef01" 
            to="0x9abc...2345" 
            env="Cairo"
            time="12 min ago"
            valid={true}
          />
          <TransitionRow 
            from="0x9abc...2345" 
            to="0xdef0...6789" 
            env="Move"
            time="1 hour ago"
            valid={false}
          />
        </div>
      </div>
    </div>
  );
}

function EnvCard({ 
  name, 
  icon, 
  supported, 
  selected,
  onClick 
}: { 
  name: string; 
  icon: string; 
  supported: boolean;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`p-4 rounded-lg border transition-all ${
        selected 
          ? 'border-pil-cyan bg-pil-cyan/20' 
          : 'border-white/10 bg-white/5 hover:border-white/30'
      }`}
    >
      <div className="text-3xl mb-2">{icon}</div>
      <div className="font-semibold text-white">{name}</div>
      <div className={`text-xs mt-1 ${supported ? 'text-green-400' : 'text-white/40'}`}>
        {supported ? '✓ Supported' : 'Coming Soon'}
      </div>
    </button>
  );
}

function TransitionRow({ 
  from, 
  to, 
  env, 
  time, 
  valid 
}: { 
  from: string; 
  to: string; 
  env: string; 
  time: string;
  valid: boolean;
}) {
  return (
    <div className="p-4 bg-white/5 rounded-lg">
      <div className="flex items-center justify-between mb-2">
        <div className="text-sm text-white/50">{time}</div>
        <div className={`text-xs px-2 py-1 rounded ${valid ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
          {valid ? 'Valid' : 'Invalid'}
        </div>
      </div>
      <div className="flex items-center gap-3 font-mono text-sm">
        <span className="text-white/70">{from}</span>
        <span className="text-pil-cyan">→</span>
        <span className="text-white">{to}</span>
        <span className="text-xs text-pil-purple ml-auto">{env}</span>
      </div>
    </div>
  );
}
