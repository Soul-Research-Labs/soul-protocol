'use client';

import { useState } from 'react';
import { useWriteContract, useWaitForTransactionReceipt, useAccount } from 'wagmi';
import { keccak256, toHex, encodePacked } from 'viem';
import { ORCHESTRATOR_ABI } from '@/lib/abis';
import { useContracts } from '@/lib/contracts';

export default function OrchestratorPanel() {
  const [transferAmount, setTransferAmount] = useState('');
  const [recipient, setRecipient] = useState('');
  const [selectedPolicy, setSelectedPolicy] = useState('none');
  const { address } = useAccount();
  const contracts = useContracts();

  const { writeContract, data: txHash, isPending } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({
    hash: txHash,
  });

  const generateMockProof = () => {
    const proof = new Uint8Array(256);
    crypto.getRandomValues(proof);
    return toHex(proof);
  };

  const handlePrivateTransfer = () => {
    if (!transferAmount || !recipient || !contracts.pilv2Orchestrator) return;

    // Generate mock values for demo
    const stateCommitment = keccak256(encodePacked(
      ['address', 'uint256', 'uint256'],
      [address!, BigInt(transferAmount), BigInt(Date.now())]
    ));
    const nullifier = keccak256(encodePacked(
      ['bytes32', 'address'],
      [stateCommitment, address!]
    ));

    const validityProof = generateMockProof();
    const policyProof = generateMockProof();
    const nullifierProof = generateMockProof();
    const proofHash = keccak256(encodePacked(
      ['bytes', 'bytes', 'bytes'],
      [validityProof as `0x${string}`, policyProof as `0x${string}`, nullifierProof as `0x${string}`]
    ));

    writeContract({
      address: contracts.pilv2Orchestrator as `0x${string}`,
      abi: ORCHESTRATOR_ABI,
      functionName: 'executePrivateTransfer',
      args: [
        stateCommitment,
        nullifier,
        validityProof,
        policyProof,
        nullifierProof,
        proofHash,
        recipient as `0x${string}`,
        BigInt(transferAmount),
      ],
    });
  };

  return (
    <div className="space-y-6">
      {/* Orchestrator Overview */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>🎛️</span>
          PIL v2 Orchestrator
        </h3>
        <p className="text-white/60 mb-6">
          The orchestrator coordinates all PIL v2 primitives for seamless privacy-preserving operations.
          It manages the lifecycle of containers, policies, state commitments, and nullifiers.
        </p>

        {/* Primitive Status */}
        <div className="grid md:grid-cols-4 gap-4">
          <PrimitiveStatus name="PC³" status="active" description="Container management" />
          <PrimitiveStatus name="PBP" status="active" description="Policy verification" />
          <PrimitiveStatus name="EASC" status="active" description="State tracking" />
          <PrimitiveStatus name="CDNA" status="active" description="Nullifier registry" />
        </div>
      </div>

      {/* Execute Private Transfer */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>🔒</span>
          Execute Private Transfer
        </h3>
        <p className="text-white/60 mb-6">
          Perform a privacy-preserving transfer using all PIL v2 primitives.
        </p>

        <div className="space-y-4">
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-white/70 mb-2">Amount</label>
              <input
                type="number"
                className="input-field"
                placeholder="Amount to transfer"
                value={transferAmount}
                onChange={(e) => setTransferAmount(e.target.value)}
              />
            </div>
            <div>
              <label className="block text-sm text-white/70 mb-2">Recipient</label>
              <input
                type="text"
                className="input-field"
                placeholder="0x..."
                value={recipient}
                onChange={(e) => setRecipient(e.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="block text-sm text-white/70 mb-2">Policy Requirement</label>
            <select
              className="input-field"
              value={selectedPolicy}
              onChange={(e) => setSelectedPolicy(e.target.value)}
            >
              <option value="none">No Policy (Open Transfer)</option>
              <option value="kyc">KYC Verified</option>
              <option value="jurisdiction">US Only</option>
              <option value="accredited">Accredited Investor</option>
            </select>
          </div>

          {/* Transfer Flow Visualization */}
          <div className="p-4 bg-white/5 rounded-lg">
            <div className="text-sm text-white/50 mb-3">Transfer Flow</div>
            <div className="flex items-center justify-between text-sm">
              <FlowStep num={1} label="Create Container" active={true} />
              <FlowArrow />
              <FlowStep num={2} label="Generate Proofs" active={true} />
              <FlowArrow />
              <FlowStep num={3} label="Verify Policy" active={selectedPolicy !== 'none'} />
              <FlowArrow />
              <FlowStep num={4} label="Consume Nullifier" active={true} />
              <FlowArrow />
              <FlowStep num={5} label="Update State" active={true} />
            </div>
          </div>

          <button
            onClick={handlePrivateTransfer}
            disabled={isPending || isConfirming || !transferAmount || !recipient}
            className="btn-primary w-full"
          >
            {isPending ? 'Confirming...' : isConfirming ? 'Executing Transfer...' : 'Execute Private Transfer'}
          </button>

          {isSuccess && (
            <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
              <p className="text-green-400 font-medium">✅ Private Transfer Complete!</p>
              <div className="mt-2 space-y-1 text-sm text-white/60">
                <p>• Container created and verified</p>
                <p>• Policy compliance confirmed</p>
                <p>• Nullifier consumed (double-spend prevented)</p>
                <p>• State commitment updated</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Recent Operations */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>📜</span>
          Recent Operations
        </h3>
        
        <div className="space-y-3">
          <OperationRow 
            type="Private Transfer"
            status="success"
            time="2 min ago"
            details="1000 tokens to 0x1234...5678"
          />
          <OperationRow 
            type="Container Created"
            status="success"
            time="5 min ago"
            details="ID: 0xabcd...ef01"
          />
          <OperationRow 
            type="Policy Verification"
            status="pending"
            time="8 min ago"
            details="KYC check for 0x9876...5432"
          />
        </div>
      </div>
    </div>
  );
}

function PrimitiveStatus({ 
  name, 
  status, 
  description 
}: { 
  name: string; 
  status: 'active' | 'paused' | 'error';
  description: string;
}) {
  const statusColors = {
    active: 'bg-green-400',
    paused: 'bg-yellow-400',
    error: 'bg-red-400',
  };

  return (
    <div className="p-4 bg-white/5 rounded-lg border border-white/10">
      <div className="flex items-center justify-between mb-2">
        <span className="font-bold text-white">{name}</span>
        <span className={`w-2 h-2 rounded-full ${statusColors[status]}`}></span>
      </div>
      <div className="text-xs text-white/50">{description}</div>
    </div>
  );
}

function FlowStep({ num, label, active }: { num: number; label: string; active: boolean }) {
  return (
    <div className={`text-center ${active ? 'text-white' : 'text-white/30'}`}>
      <div className={`w-8 h-8 rounded-full flex items-center justify-center mx-auto mb-1 ${
        active ? 'bg-pil-purple' : 'bg-white/10'
      }`}>
        {num}
      </div>
      <div className="text-xs">{label}</div>
    </div>
  );
}

function FlowArrow() {
  return <div className="text-white/30 text-xl">→</div>;
}

function OperationRow({ 
  type, 
  status, 
  time, 
  details 
}: { 
  type: string; 
  status: 'success' | 'pending' | 'failed';
  time: string;
  details: string;
}) {
  const statusIcons = {
    success: '✅',
    pending: '⏳',
    failed: '❌',
  };

  return (
    <div className="p-4 bg-white/5 rounded-lg flex items-center justify-between">
      <div className="flex items-center gap-3">
        <span className="text-xl">{statusIcons[status]}</span>
        <div>
          <div className="font-medium text-white">{type}</div>
          <div className="text-xs text-white/50">{details}</div>
        </div>
      </div>
      <div className="text-sm text-white/40">{time}</div>
    </div>
  );
}
