'use client';

import { useState } from 'react';
import { useReadContract } from 'wagmi';
import { CDNA_ABI } from '@/lib/abis';
import { useContracts } from '@/lib/contracts';

export default function NullifierPanel() {
  const [nullifierToCheck, setNullifierToCheck] = useState('');
  const [searchResult, setSearchResult] = useState<'used' | 'available' | null>(null);
  const contracts = useContracts();

  const handleCheckNullifier = () => {
    // In a real implementation, this would call the contract
    // For demo, we simulate the result
    setSearchResult(Math.random() > 0.5 ? 'used' : 'available');
  };

  return (
    <div className="space-y-6">
      {/* Nullifier Info */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>🔑</span>
          Cross-Domain Nullifier Algebra (CDNA)
        </h3>
        <p className="text-white/60 mb-6">
          Unified nullifier system that prevents double-spending across all connected chains.
          Nullifiers are computed using the formula: <code className="text-pil-cyan">N = H(secret || domain || counter)</code>
        </p>

        {/* Domain Chain Visualization */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <DomainCard chain="Ethereum" domain={1} nullifiers={1234} color="blue" />
          <DomainCard chain="Polygon" domain={137} nullifiers={892} color="purple" />
          <DomainCard chain="Arbitrum" domain={42161} nullifiers={567} color="orange" />
          <DomainCard chain="Base" domain={8453} nullifiers={345} color="cyan" />
        </div>
      </div>

      {/* Check Nullifier */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>🔍</span>
          Check Nullifier Status
        </h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-white/70 mb-2">Nullifier Hash</label>
            <input
              type="text"
              className="input-field"
              placeholder="0x..."
              value={nullifierToCheck}
              onChange={(e) => {
                setNullifierToCheck(e.target.value);
                setSearchResult(null);
              }}
            />
          </div>

          <button
            onClick={handleCheckNullifier}
            disabled={!nullifierToCheck}
            className="btn-primary w-full"
          >
            Check Nullifier
          </button>

          {searchResult && (
            <div className={`p-4 rounded-lg ${
              searchResult === 'used' 
                ? 'bg-red-500/10 border border-red-500/20' 
                : 'bg-green-500/10 border border-green-500/20'
            }`}>
              {searchResult === 'used' ? (
                <div>
                  <p className="text-red-400 font-medium">❌ Nullifier Already Used</p>
                  <p className="text-sm text-white/60 mt-1">
                    This nullifier has been consumed on chain. The associated value cannot be spent again.
                  </p>
                </div>
              ) : (
                <div>
                  <p className="text-green-400 font-medium">✅ Nullifier Available</p>
                  <p className="text-sm text-white/60 mt-1">
                    This nullifier is unused across all domains and can be safely consumed.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Recent Nullifiers */}
      <div className="glass-card p-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <span>📜</span>
          Recent Nullifier Consumptions
        </h3>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-white/50 text-sm border-b border-white/10">
                <th className="text-left py-3">Nullifier</th>
                <th className="text-left py-3">Domain</th>
                <th className="text-left py-3">Consumed At</th>
                <th className="text-left py-3">Tx</th>
              </tr>
            </thead>
            <tbody>
              <NullifierRow 
                hash="0x1234...abcd" 
                domain="Ethereum" 
                time="2 min ago"
                tx="0x5678...ef01"
              />
              <NullifierRow 
                hash="0x2345...bcde" 
                domain="Polygon" 
                time="5 min ago"
                tx="0x6789...f012"
              />
              <NullifierRow 
                hash="0x3456...cdef" 
                domain="Arbitrum" 
                time="12 min ago"
                tx="0x789a...0123"
              />
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function DomainCard({ 
  chain, 
  domain, 
  nullifiers, 
  color 
}: { 
  chain: string; 
  domain: number; 
  nullifiers: number;
  color: string;
}) {
  const bgColors: Record<string, string> = {
    blue: 'from-blue-500/20 to-blue-600/10',
    purple: 'from-purple-500/20 to-purple-600/10',
    orange: 'from-orange-500/20 to-orange-600/10',
    cyan: 'from-cyan-500/20 to-cyan-600/10',
  };

  return (
    <div className={`p-4 rounded-lg bg-gradient-to-br ${bgColors[color]} border border-white/10`}>
      <div className="text-sm text-white/50">Domain {domain}</div>
      <div className="font-bold text-white">{chain}</div>
      <div className="text-lg text-pil-cyan mt-2">{nullifiers.toLocaleString()}</div>
      <div className="text-xs text-white/40">nullifiers</div>
    </div>
  );
}

function NullifierRow({ hash, domain, time, tx }: { hash: string; domain: string; time: string; tx: string }) {
  return (
    <tr className="border-b border-white/5 hover:bg-white/5">
      <td className="py-3 font-mono text-sm text-white">{hash}</td>
      <td className="py-3 text-white/70">{domain}</td>
      <td className="py-3 text-white/50">{time}</td>
      <td className="py-3 font-mono text-sm text-pil-purple">{tx}</td>
    </tr>
  );
}
