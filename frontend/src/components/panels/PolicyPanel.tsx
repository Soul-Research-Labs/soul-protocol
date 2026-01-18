'use client';

import { useState } from 'react';
import { useWriteContract, useWaitForTransactionReceipt } from 'wagmi';
import { keccak256, toHex } from 'viem';
import { PBP_ABI } from '@/lib/abis';
import { useContracts } from '@/lib/contracts';

const POLICY_TYPES = [
  { id: 'kyc', name: 'KYC Verification', description: 'Prove identity verification without revealing personal data' },
  { id: 'age', name: 'Age Check', description: 'Prove you are above a certain age threshold' },
  { id: 'jurisdiction', name: 'Jurisdiction', description: 'Prove residence in allowed jurisdictions' },
  { id: 'accredited', name: 'Accredited Investor', description: 'Prove accredited investor status' },
  { id: 'aml', name: 'AML Compliance', description: 'Prove clean transaction history' },
];

export default function PolicyPanel() {
  const [selectedPolicy, setSelectedPolicy] = useState<string>('');
  const [threshold, setThreshold] = useState('');
  const contracts = useContracts();

  const { writeContract, data: txHash, isPending } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({
    hash: txHash,
  });

  const handleCreatePolicy = async () => {
    if (!selectedPolicy || !contracts.policyBoundProofs) return;

    const policyType = keccak256(toHex(selectedPolicy));
    
    writeContract({
      address: contracts.policyBoundProofs as `0x${string}`,
      abi: PBP_ABI,
      functionName: 'createPolicy',
      args: [
        policyType,
        BigInt(threshold || '0'),
        true, // active
        Math.floor(Date.now() / 1000) + 86400 * 365, // 1 year expiry
      ],
    });
  };

  return (
    <div className="space-y-6">
      {/* Create Policy */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>📋</span>
          Create Policy-Bound Proof
        </h3>
        <p className="text-white/60 mb-6">
          Create a policy that can be attached to containers for compliance verification.
        </p>

        <div className="space-y-4">
          {/* Policy Type Selection */}
          <div>
            <label className="block text-sm text-white/70 mb-2">Policy Type</label>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
              {POLICY_TYPES.map((policy) => (
                <button
                  key={policy.id}
                  onClick={() => setSelectedPolicy(policy.id)}
                  className={`p-4 rounded-lg border transition-all text-left ${
                    selectedPolicy === policy.id
                      ? 'border-pil-purple bg-pil-purple/20'
                      : 'border-white/10 bg-white/5 hover:border-white/30'
                  }`}
                >
                  <div className="font-semibold text-white">{policy.name}</div>
                  <div className="text-xs text-white/50 mt-1">{policy.description}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Threshold */}
          <div>
            <label className="block text-sm text-white/70 mb-2">Threshold (if applicable)</label>
            <input
              type="number"
              className="input-field"
              placeholder="e.g., 18 for age, 1000000 for amount"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
            />
          </div>

          <button
            onClick={handleCreatePolicy}
            disabled={isPending || isConfirming || !selectedPolicy}
            className="btn-primary w-full"
          >
            {isPending ? 'Confirming...' : isConfirming ? 'Creating Policy...' : 'Create Policy'}
          </button>

          {isSuccess && (
            <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
              <p className="text-green-400">✅ Policy created successfully!</p>
            </div>
          )}
        </div>
      </div>

      {/* Active Policies */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>📜</span>
          Active Policies
        </h3>
        
        <div className="space-y-3">
          <PolicyRow name="Default (No Policy)" hash="0x0000...0000" status="active" />
          <PolicyRow name="KYC Required" hash="0x1234...5678" status="active" />
          <PolicyRow name="US Jurisdiction" hash="0xabcd...ef01" status="pending" />
        </div>
      </div>
    </div>
  );
}

function PolicyRow({ name, hash, status }: { name: string; hash: string; status: 'active' | 'pending' | 'expired' }) {
  const statusColors = {
    active: 'text-green-400',
    pending: 'text-yellow-400',
    expired: 'text-red-400',
  };

  return (
    <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
      <div>
        <div className="font-medium text-white">{name}</div>
        <div className="text-xs text-white/50 font-mono">{hash}</div>
      </div>
      <div className={`text-sm font-medium ${statusColors[status]}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </div>
    </div>
  );
}
