'use client';

import { useState, useEffect } from 'react';
import { useAccount, useChainId, useWriteContract, useWaitForTransactionReceipt } from 'wagmi';
import { parseEther, formatEther, keccak256, toHex, encodePacked } from 'viem';

type BridgeDirection = 'l1-to-l2' | 'l2-to-l1' | 'pil-to-aztec' | 'aztec-to-pil';

interface Chain {
  id: number;
  name: string;
  icon: string;
  type: 'l1' | 'l2-optimistic' | 'l2-zk' | 'privacy';
  color: string;
}

const CHAINS: Chain[] = [
  { id: 1, name: 'Ethereum', icon: '⟠', type: 'l1', color: '#627EEA' },
  { id: 42161, name: 'Arbitrum', icon: '🔵', type: 'l2-optimistic', color: '#28A0F0' },
  { id: 10, name: 'Optimism', icon: '🔴', type: 'l2-optimistic', color: '#FF0420' },
  { id: 8453, name: 'Base', icon: '🔷', type: 'l2-optimistic', color: '#0052FF' },
  { id: 324, name: 'zkSync Era', icon: '⚡', type: 'l2-zk', color: '#8B8DFC' },
  { id: 534352, name: 'Scroll', icon: '📜', type: 'l2-zk', color: '#FFEEDA' },
  { id: 59144, name: 'Linea', icon: '🟢', type: 'l2-zk', color: '#61DFFF' },
  { id: 1101, name: 'Polygon zkEVM', icon: '🟣', type: 'l2-zk', color: '#8247E5' },
  { id: 677868, name: 'Aztec Network', icon: '🔮', type: 'privacy', color: '#5B21B6' },
];

interface BridgeRequest {
  id: string;
  fromChain: Chain;
  toChain: Chain;
  amount: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  timestamp: number;
  txHash?: string;
}

export default function BridgePanel() {
  const { address } = useAccount();
  const chainId = useChainId();
  
  const [fromChain, setFromChain] = useState<Chain>(CHAINS[0]);
  const [toChain, setToChain] = useState<Chain>(CHAINS[1]);
  const [amount, setAmount] = useState('');
  const [commitment, setCommitment] = useState('');
  const [isPrivate, setIsPrivate] = useState(true);
  const [bridgeRequests, setBridgeRequests] = useState<BridgeRequest[]>([]);
  const [estimatedGas, setEstimatedGas] = useState('~0.001 ETH');
  const [estimatedTime, setEstimatedTime] = useState('~10 min');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const { writeContract, data: txHash, isPending } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({
    hash: txHash,
  });

  // Update estimates based on chains
  useEffect(() => {
    if (fromChain && toChain) {
      // Estimate based on rollup type
      if (toChain.type === 'l2-zk' || fromChain.type === 'l2-zk') {
        setEstimatedTime('~1 min');
        setEstimatedGas('~0.0005 ETH');
      } else if (toChain.type === 'l2-optimistic' || fromChain.type === 'l2-optimistic') {
        setEstimatedTime('~7 days (challenge period)');
        setEstimatedGas('~0.002 ETH');
      } else if (toChain.type === 'privacy' || fromChain.type === 'privacy') {
        setEstimatedTime('~15 min');
        setEstimatedGas('~0.003 ETH');
      }
    }
  }, [fromChain, toChain]);

  const swapChains = () => {
    const temp = fromChain;
    setFromChain(toChain);
    setToChain(temp);
  };

  const generateCommitment = () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const nullifier = crypto.getRandomValues(new Uint8Array(32));
    const hash = keccak256(encodePacked(['bytes32', 'bytes32'], [toHex(secret), toHex(nullifier)]));
    setCommitment(hash);
  };

  const handleBridge = async () => {
    if (!amount || !address) return;

    // Generate commitment if private mode
    if (isPrivate && !commitment) {
      generateCommitment();
    }

    const newRequest: BridgeRequest = {
      id: `0x${Date.now().toString(16)}`,
      fromChain,
      toChain,
      amount,
      status: 'pending',
      timestamp: Date.now(),
    };

    setBridgeRequests(prev => [newRequest, ...prev]);

    // Simulate bridge transaction
    setTimeout(() => {
      setBridgeRequests(prev => 
        prev.map(r => r.id === newRequest.id ? { ...r, status: 'processing' } : r)
      );
    }, 2000);

    setTimeout(() => {
      setBridgeRequests(prev => 
        prev.map(r => r.id === newRequest.id ? { ...r, status: 'completed', txHash: `0x${Math.random().toString(16).slice(2)}` } : r)
      );
    }, 5000);
  };

  const getStatusColor = (status: BridgeRequest['status']) => {
    switch (status) {
      case 'pending': return 'text-yellow-400';
      case 'processing': return 'text-blue-400';
      case 'completed': return 'text-green-400';
      case 'failed': return 'text-red-400';
    }
  };

  const getStatusIcon = (status: BridgeRequest['status']) => {
    switch (status) {
      case 'pending': return '⏳';
      case 'processing': return '🔄';
      case 'completed': return '✅';
      case 'failed': return '❌';
    }
  };

  return (
    <div className="space-y-6">
      {/* Bridge Card */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-bold text-white flex items-center gap-2">
            <span>🌉</span>
            Cross-Chain Bridge
          </h3>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsPrivate(!isPrivate)}
              className={`px-3 py-1 rounded-full text-sm font-medium transition-all ${
                isPrivate 
                  ? 'bg-pil-purple/20 text-pil-purple border border-pil-purple/50' 
                  : 'bg-white/10 text-white/60 border border-white/20'
              }`}
            >
              {isPrivate ? '🔒 Private' : '🔓 Public'}
            </button>
          </div>
        </div>

        {/* Chain Selection */}
        <div className="space-y-4">
          {/* From Chain */}
          <div className="p-4 bg-white/5 rounded-xl border border-white/10">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-white/50">From</span>
              <span className="text-sm text-white/50">Balance: 0.00 ETH</span>
            </div>
            <div className="flex items-center gap-4">
              <ChainSelector
                selected={fromChain}
                chains={CHAINS.filter(c => c.id !== toChain.id)}
                onSelect={setFromChain}
              />
              <input
                type="number"
                placeholder="0.0"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                className="flex-1 bg-transparent text-2xl font-bold text-white text-right outline-none placeholder-white/30"
              />
            </div>
          </div>

          {/* Swap Button */}
          <div className="flex justify-center -my-2 relative z-10">
            <button
              onClick={swapChains}
              className="w-10 h-10 bg-pil-dark border-4 border-[#1a1a2e] rounded-xl flex items-center justify-center hover:bg-white/10 transition-all group"
            >
              <span className="text-xl group-hover:rotate-180 transition-transform duration-300">⇅</span>
            </button>
          </div>

          {/* To Chain */}
          <div className="p-4 bg-white/5 rounded-xl border border-white/10">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-white/50">To</span>
              <span className="text-sm text-white/50">You will receive</span>
            </div>
            <div className="flex items-center gap-4">
              <ChainSelector
                selected={toChain}
                chains={CHAINS.filter(c => c.id !== fromChain.id)}
                onSelect={setToChain}
              />
              <div className="flex-1 text-2xl font-bold text-white text-right">
                {amount || '0.0'}
              </div>
            </div>
          </div>
        </div>

        {/* Privacy Commitment */}
        {isPrivate && (
          <div className="mt-4 p-4 bg-pil-purple/10 rounded-xl border border-pil-purple/20">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-pil-purple font-medium">Privacy Commitment</span>
              <button
                onClick={generateCommitment}
                className="text-xs text-pil-cyan hover:text-pil-blue transition-colors"
              >
                Generate New
              </button>
            </div>
            <input
              type="text"
              value={commitment}
              onChange={(e) => setCommitment(e.target.value)}
              placeholder="Auto-generated on bridge"
              className="w-full bg-transparent text-sm text-white/80 font-mono outline-none placeholder-white/30"
            />
            <p className="text-xs text-white/40 mt-2">
              Your commitment is stored on-chain. Save your secret to claim on the destination chain.
            </p>
          </div>
        )}

        {/* Estimates */}
        <div className="mt-4 p-4 bg-white/5 rounded-xl space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-white/50">Estimated Gas</span>
            <span className="text-white">{estimatedGas}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-white/50">Estimated Time</span>
            <span className="text-white">{estimatedTime}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-white/50">Bridge Fee</span>
            <span className="text-white">0.1%</span>
          </div>
          {toChain.type === 'l2-optimistic' && (
            <div className="flex items-center gap-2 pt-2 border-t border-white/10">
              <span className="text-yellow-400">⚠️</span>
              <span className="text-xs text-yellow-400/80">
                Optimistic rollup: 7-day challenge period for L2→L1
              </span>
            </div>
          )}
        </div>

        {/* Advanced Options */}
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="w-full mt-4 text-sm text-white/50 hover:text-white transition-colors flex items-center justify-center gap-1"
        >
          Advanced Options
          <span className={`transition-transform ${showAdvanced ? 'rotate-180' : ''}`}>▼</span>
        </button>

        {showAdvanced && (
          <div className="mt-4 p-4 bg-white/5 rounded-xl space-y-4">
            <div>
              <label className="block text-sm text-white/70 mb-2">Custom Gas Limit</label>
              <input
                type="number"
                placeholder="Auto"
                className="input-field"
              />
            </div>
            <div>
              <label className="block text-sm text-white/70 mb-2">Recipient Address (optional)</label>
              <input
                type="text"
                placeholder={address}
                className="input-field font-mono text-sm"
              />
            </div>
            <div className="flex items-center gap-3">
              <input type="checkbox" id="force-relay" className="w-4 h-4" />
              <label htmlFor="force-relay" className="text-sm text-white/70">
                Force relay through specific relayer
              </label>
            </div>
          </div>
        )}

        {/* Bridge Button */}
        <button
          onClick={handleBridge}
          disabled={!amount || isPending || isConfirming}
          className="btn-primary w-full mt-6 py-4 text-lg"
        >
          {isPending ? 'Confirming...' : isConfirming ? 'Bridging...' : `Bridge ${amount || '0'} ETH`}
        </button>
      </div>

      {/* Recent Bridge Requests */}
      {bridgeRequests.length > 0 && (
        <div className="glass-card p-6">
          <h3 className="text-lg font-bold text-white mb-4">Your Bridge Requests</h3>
          <div className="space-y-3">
            {bridgeRequests.map((request) => (
              <div
                key={request.id}
                className="p-4 bg-white/5 rounded-lg border border-white/10 flex items-center justify-between"
              >
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <span className="text-2xl">{request.fromChain.icon}</span>
                    <span className="text-white/50">→</span>
                    <span className="text-2xl">{request.toChain.icon}</span>
                  </div>
                  <div>
                    <div className="text-white font-medium">{request.amount} ETH</div>
                    <div className="text-xs text-white/50">
                      {new Date(request.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
                <div className={`flex items-center gap-2 ${getStatusColor(request.status)}`}>
                  <span>{getStatusIcon(request.status)}</span>
                  <span className="capitalize">{request.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Supported Chains */}
      <div className="glass-card p-6">
        <h3 className="text-lg font-bold text-white mb-4">Supported Networks</h3>
        <div className="grid grid-cols-3 md:grid-cols-5 gap-3">
          {CHAINS.map((chain) => (
            <div
              key={chain.id}
              className="p-3 bg-white/5 rounded-lg text-center hover:bg-white/10 transition-all cursor-pointer"
            >
              <div className="text-2xl mb-1">{chain.icon}</div>
              <div className="text-xs text-white/80 truncate">{chain.name}</div>
              <div className={`text-xs mt-1 px-2 py-0.5 rounded-full inline-block ${
                chain.type === 'l1' ? 'bg-blue-500/20 text-blue-400' :
                chain.type === 'l2-optimistic' ? 'bg-orange-500/20 text-orange-400' :
                chain.type === 'l2-zk' ? 'bg-purple-500/20 text-purple-400' :
                'bg-pink-500/20 text-pink-400'
              }`}>
                {chain.type === 'l1' ? 'L1' : 
                 chain.type === 'l2-optimistic' ? 'Optimistic' : 
                 chain.type === 'l2-zk' ? 'ZK' : 'Privacy'}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ChainSelector({
  selected,
  chains,
  onSelect,
}: {
  selected: Chain;
  chains: Chain[];
  onSelect: (chain: Chain) => void;
}) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2 bg-white/10 rounded-xl hover:bg-white/20 transition-all"
      >
        <span className="text-xl">{selected.icon}</span>
        <span className="text-white font-medium">{selected.name}</span>
        <span className="text-white/50">▼</span>
      </button>

      {isOpen && (
        <>
          <div
            className="fixed inset-0 z-10"
            onClick={() => setIsOpen(false)}
          />
          <div className="absolute top-full left-0 mt-2 w-56 bg-pil-dark/95 backdrop-blur-xl border border-white/20 rounded-xl shadow-2xl z-20 overflow-hidden">
            {chains.map((chain) => (
              <button
                key={chain.id}
                onClick={() => {
                  onSelect(chain);
                  setIsOpen(false);
                }}
                className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/10 transition-all text-left"
              >
                <span className="text-xl">{chain.icon}</span>
                <div>
                  <div className="text-white font-medium">{chain.name}</div>
                  <div className="text-xs text-white/50">Chain ID: {chain.id}</div>
                </div>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
