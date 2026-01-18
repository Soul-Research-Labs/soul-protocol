'use client';

import { useState } from 'react';
import { useWriteContract, useReadContract, useWaitForTransactionReceipt } from 'wagmi';
import { keccak256, toHex, encodePacked } from 'viem';
import { PC3_ABI } from '@/lib/abis';
import { useContracts } from '@/lib/contracts';

export default function ContainerPanel() {
  const [encryptedPayload, setEncryptedPayload] = useState('');
  const [policyHash, setPolicyHash] = useState('');
  const [containerId, setContainerId] = useState('');
  const contracts = useContracts();

  const { writeContract, data: txHash, isPending } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({
    hash: txHash,
  });

  // Generate mock proof for demo
  const generateMockProof = () => {
    const proof = new Uint8Array(256);
    crypto.getRandomValues(proof);
    return toHex(proof);
  };

  const handleCreateContainer = async () => {
    if (!encryptedPayload || !contracts.proofCarryingContainer) return;

    const payload = toHex(encryptedPayload);
    const stateCommitment = keccak256(payload);
    const nullifier = keccak256(encodePacked(['bytes32', 'uint256'], [stateCommitment, BigInt(Date.now())]));
    
    const validityProof = generateMockProof();
    const policyProof = generateMockProof();
    const nullifierProof = generateMockProof();
    
    const proofHash = keccak256(encodePacked(
      ['bytes', 'bytes', 'bytes'],
      [validityProof as `0x${string}`, policyProof as `0x${string}`, nullifierProof as `0x${string}`]
    ));

    const proofBundle = {
      validityProof,
      policyProof,
      nullifierProof,
      proofHash,
      proofTimestamp: BigInt(Math.floor(Date.now() / 1000)),
      proofExpiry: BigInt(Math.floor(Date.now() / 1000) + 86400), // 24 hours
    };

    writeContract({
      address: contracts.proofCarryingContainer as `0x${string}`,
      abi: PC3_ABI,
      functionName: 'createContainer',
      args: [payload, stateCommitment, nullifier, proofBundle, policyHash as `0x${string}` || '0x0000000000000000000000000000000000000000000000000000000000000000'],
    });
  };

  return (
    <div className="space-y-6">
      {/* Create Container */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>📦</span>
          Create PC³ Container
        </h3>
        <p className="text-white/60 mb-6">
          Create a self-authenticating confidential container with embedded ZK proofs.
        </p>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-white/70 mb-2">Encrypted Payload</label>
            <textarea
              className="input-field h-24 resize-none"
              placeholder="Enter the confidential data to encrypt..."
              value={encryptedPayload}
              onChange={(e) => setEncryptedPayload(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-sm text-white/70 mb-2">Policy Hash (optional)</label>
            <input
              type="text"
              className="input-field"
              placeholder="0x... (leave empty for no policy)"
              value={policyHash}
              onChange={(e) => setPolicyHash(e.target.value)}
            />
          </div>

          <button
            onClick={handleCreateContainer}
            disabled={isPending || isConfirming || !encryptedPayload}
            className="btn-primary w-full"
          >
            {isPending ? 'Confirming...' : isConfirming ? 'Creating Container...' : 'Create Container'}
          </button>

          {isSuccess && (
            <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
              <p className="text-green-400">✅ Container created successfully!</p>
              <p className="text-sm text-white/60 mt-1">Transaction: {txHash?.slice(0, 20)}...</p>
            </div>
          )}
        </div>
      </div>

      {/* Verify Container */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>🔍</span>
          Verify Container
        </h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-white/70 mb-2">Container ID</label>
            <input
              type="text"
              className="input-field"
              placeholder="0x..."
              value={containerId}
              onChange={(e) => setContainerId(e.target.value)}
            />
          </div>

          <button className="btn-secondary w-full">
            Verify Container
          </button>
        </div>
      </div>

      {/* Container Stats */}
      <div className="grid md:grid-cols-3 gap-4">
        <StatCard title="Total Containers" value="0" icon="📦" />
        <StatCard title="Verified" value="0" icon="✅" />
        <StatCard title="Consumed" value="0" icon="🔒" />
      </div>
    </div>
  );
}

function StatCard({ title, value, icon }: { title: string; value: string; icon: string }) {
  return (
    <div className="glass-card p-4">
      <div className="flex items-center gap-3">
        <span className="text-2xl">{icon}</span>
        <div>
          <div className="text-2xl font-bold text-white">{value}</div>
          <div className="text-sm text-white/50">{title}</div>
        </div>
      </div>
    </div>
  );
}
