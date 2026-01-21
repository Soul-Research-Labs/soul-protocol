/**
 * PIL Frontend - Proof Explorer
 * 
 * Component for exploring and visualizing ZK proofs
 */

import React, { useState, useMemo } from 'react';

// Types
export interface ProofData {
  id: string;
  type: 'deposit' | 'withdraw' | 'bridge' | 'compliance';
  system: 'groth16' | 'plonk' | 'stark' | 'noir';
  timestamp: number;
  status: 'pending' | 'generating' | 'verified' | 'failed';
  publicInputs: string[];
  proof?: string;
  verificationKey?: string;
  txHash?: string;
  gasUsed?: number;
  generationTime?: number;
}

export interface ProofStats {
  totalProofs: number;
  verified: number;
  pending: number;
  failed: number;
  avgGenerationTime: number;
  avgGasUsed: number;
}

// Styles
const styles = {
  container: {
    fontFamily: 'system-ui, -apple-system, sans-serif',
    padding: '24px',
    backgroundColor: '#1a1a2e',
    borderRadius: '16px',
    color: '#ffffff',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '24px',
  },
  title: {
    fontSize: '20px',
    fontWeight: 'bold',
  },
  tabs: {
    display: 'flex',
    gap: '8px',
    marginBottom: '24px',
  },
  tab: (active: boolean) => ({
    padding: '8px 16px',
    borderRadius: '8px',
    border: 'none',
    backgroundColor: active ? '#8B5CF6' : '#333',
    color: '#fff',
    cursor: 'pointer',
    fontSize: '14px',
  }),
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: '16px',
    marginBottom: '24px',
  },
  statCard: {
    padding: '16px',
    backgroundColor: '#0f0f23',
    borderRadius: '12px',
    textAlign: 'center' as const,
  },
  statValue: {
    fontSize: '24px',
    fontWeight: 'bold',
    marginBottom: '4px',
  },
  statLabel: {
    fontSize: '12px',
    color: '#a0a0a0',
  },
  proofList: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '12px',
  },
  proofCard: {
    padding: '16px',
    backgroundColor: '#0f0f23',
    borderRadius: '12px',
    cursor: 'pointer',
    transition: 'transform 0.2s',
  },
  proofHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '12px',
  },
  proofType: (type: string) => {
    const colors: Record<string, string> = {
      deposit: '#10B981',
      withdraw: '#8B5CF6',
      bridge: '#F59E0B',
      compliance: '#3B82F6',
    };
    return {
      padding: '4px 8px',
      borderRadius: '4px',
      backgroundColor: colors[type] || '#333',
      fontSize: '12px',
      textTransform: 'uppercase' as const,
    };
  },
  proofStatus: (status: string) => {
    const colors: Record<string, string> = {
      pending: '#F59E0B',
      generating: '#3B82F6',
      verified: '#10B981',
      failed: '#EF4444',
    };
    return {
      color: colors[status] || '#a0a0a0',
      fontSize: '12px',
    };
  },
  proofDetails: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '8px',
    fontSize: '12px',
  },
  detailLabel: {
    color: '#a0a0a0',
  },
  codeBlock: {
    padding: '12px',
    backgroundColor: '#000',
    borderRadius: '8px',
    fontFamily: 'monospace',
    fontSize: '11px',
    overflow: 'auto' as const,
    maxHeight: '200px',
    marginTop: '12px',
  },
  expandButton: {
    marginTop: '12px',
    padding: '8px 16px',
    borderRadius: '8px',
    border: '1px solid #333',
    backgroundColor: 'transparent',
    color: '#a0a0a0',
    cursor: 'pointer',
    fontSize: '12px',
    width: '100%',
  },
  modal: {
    position: 'fixed' as const,
    inset: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.8)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
  },
  modalContent: {
    backgroundColor: '#1a1a2e',
    borderRadius: '16px',
    padding: '24px',
    maxWidth: '600px',
    maxHeight: '80vh',
    overflow: 'auto' as const,
    width: '90%',
  },
  closeButton: {
    position: 'absolute' as const,
    top: '16px',
    right: '16px',
    border: 'none',
    backgroundColor: 'transparent',
    color: '#fff',
    fontSize: '24px',
    cursor: 'pointer',
  },
  circuitDiagram: {
    padding: '24px',
    backgroundColor: '#0f0f23',
    borderRadius: '12px',
    textAlign: 'center' as const,
    marginTop: '16px',
  },
  input: {
    padding: '12px 16px',
    borderRadius: '8px',
    border: '1px solid #333',
    backgroundColor: '#0f0f23',
    color: '#fff',
    width: '100%',
    boxSizing: 'border-box' as const,
    marginTop: '8px',
  },
};

// Status icons
const statusIcons: Record<string, string> = {
  pending: '⏳',
  generating: '⚙️',
  verified: '✅',
  failed: '❌',
};

// Proof Card Component
const ProofCard: React.FC<{
  proof: ProofData;
  onClick: () => void;
}> = ({ proof, onClick }) => {
  const formattedDate = useMemo(() => {
    return new Date(proof.timestamp).toLocaleString();
  }, [proof.timestamp]);

  return (
    <div style={styles.proofCard} onClick={onClick}>
      <div style={styles.proofHeader}>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={styles.proofType(proof.type)}>{proof.type}</span>
          <span style={{ color: '#a0a0a0', fontSize: '12px' }}>{proof.system.toUpperCase()}</span>
        </div>
        <span style={styles.proofStatus(proof.status)}>
          {statusIcons[proof.status]} {proof.status}
        </span>
      </div>
      <div style={styles.proofDetails}>
        <div>
          <span style={styles.detailLabel}>ID: </span>
          <span style={{ fontFamily: 'monospace' }}>{proof.id.substring(0, 12)}...</span>
        </div>
        <div>
          <span style={styles.detailLabel}>Time: </span>
          <span>{formattedDate}</span>
        </div>
        <div>
          <span style={styles.detailLabel}>Inputs: </span>
          <span>{proof.publicInputs.length}</span>
        </div>
        {proof.generationTime && (
          <div>
            <span style={styles.detailLabel}>Gen Time: </span>
            <span>{proof.generationTime}ms</span>
          </div>
        )}
      </div>
    </div>
  );
};

// Proof Detail Modal
const ProofDetailModal: React.FC<{
  proof: ProofData;
  onClose: () => void;
}> = ({ proof, onClose }) => {
  const [showRaw, setShowRaw] = useState(false);

  return (
    <div style={styles.modal} onClick={onClose}>
      <div style={styles.modalContent} onClick={e => e.stopPropagation()}>
        <h2 style={{ marginBottom: '16px' }}>Proof Details</h2>
        
        <div style={styles.proofHeader}>
          <span style={styles.proofType(proof.type)}>{proof.type}</span>
          <span style={styles.proofStatus(proof.status)}>
            {statusIcons[proof.status]} {proof.status}
          </span>
        </div>

        <div style={{ marginTop: '24px' }}>
          <h3 style={{ fontSize: '14px', marginBottom: '12px' }}>Details</h3>
          <div style={styles.proofDetails}>
            <div>
              <span style={styles.detailLabel}>Proof ID</span>
              <div style={{ fontFamily: 'monospace', fontSize: '12px', marginTop: '4px' }}>{proof.id}</div>
            </div>
            <div>
              <span style={styles.detailLabel}>System</span>
              <div style={{ marginTop: '4px' }}>{proof.system.toUpperCase()}</div>
            </div>
            <div>
              <span style={styles.detailLabel}>Timestamp</span>
              <div style={{ marginTop: '4px' }}>{new Date(proof.timestamp).toLocaleString()}</div>
            </div>
            {proof.txHash && (
              <div>
                <span style={styles.detailLabel}>TX Hash</span>
                <div style={{ fontFamily: 'monospace', fontSize: '12px', marginTop: '4px' }}>
                  {proof.txHash.substring(0, 20)}...
                </div>
              </div>
            )}
            {proof.gasUsed && (
              <div>
                <span style={styles.detailLabel}>Gas Used</span>
                <div style={{ marginTop: '4px' }}>{proof.gasUsed.toLocaleString()}</div>
              </div>
            )}
            {proof.generationTime && (
              <div>
                <span style={styles.detailLabel}>Generation Time</span>
                <div style={{ marginTop: '4px' }}>{proof.generationTime}ms</div>
              </div>
            )}
          </div>
        </div>

        <div style={{ marginTop: '24px' }}>
          <h3 style={{ fontSize: '14px', marginBottom: '12px' }}>Public Inputs ({proof.publicInputs.length})</h3>
          <div style={styles.codeBlock}>
            {proof.publicInputs.map((input, i) => (
              <div key={i}>
                <span style={{ color: '#8B5CF6' }}>[{i}]</span> {input}
              </div>
            ))}
          </div>
        </div>

        <div style={styles.circuitDiagram}>
          <div style={{ marginBottom: '16px' }}>Circuit Visualization</div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px' }}>
            <div style={{ padding: '12px', backgroundColor: '#333', borderRadius: '8px' }}>
              📥 Inputs
            </div>
            <span>→</span>
            <div style={{ padding: '12px', backgroundColor: '#8B5CF620', borderRadius: '8px', border: '1px solid #8B5CF6' }}>
              ⚡ {proof.system.toUpperCase()}
            </div>
            <span>→</span>
            <div style={{ padding: '12px', backgroundColor: '#333', borderRadius: '8px' }}>
              📤 Proof
            </div>
          </div>
        </div>

        {proof.proof && (
          <div style={{ marginTop: '24px' }}>
            <button
              style={styles.expandButton}
              onClick={() => setShowRaw(!showRaw)}
            >
              {showRaw ? '▲ Hide Raw Proof' : '▼ Show Raw Proof'}
            </button>
            {showRaw && (
              <div style={styles.codeBlock}>
                {proof.proof.match(/.{1,64}/g)?.map((chunk, i) => (
                  <div key={i} style={{ color: '#10B981' }}>{chunk}</div>
                ))}
              </div>
            )}
          </div>
        )}

        <button
          style={{ ...styles.expandButton, marginTop: '24px', backgroundColor: '#8B5CF6', border: 'none', color: '#fff' }}
          onClick={onClose}
        >
          Close
        </button>
      </div>
    </div>
  );
};

// Stats Cards
const StatsCards: React.FC<{ stats: ProofStats }> = ({ stats }) => {
  return (
    <div style={styles.statsGrid}>
      <div style={styles.statCard}>
        <div style={styles.statValue}>{stats.totalProofs}</div>
        <div style={styles.statLabel}>Total Proofs</div>
      </div>
      <div style={styles.statCard}>
        <div style={{ ...styles.statValue, color: '#10B981' }}>{stats.verified}</div>
        <div style={styles.statLabel}>Verified</div>
      </div>
      <div style={styles.statCard}>
        <div style={{ ...styles.statValue, color: '#F59E0B' }}>{stats.pending}</div>
        <div style={styles.statLabel}>Pending</div>
      </div>
      <div style={styles.statCard}>
        <div style={styles.statValue}>{stats.avgGenerationTime.toFixed(0)}ms</div>
        <div style={styles.statLabel}>Avg Gen Time</div>
      </div>
      <div style={styles.statCard}>
        <div style={styles.statValue}>{(stats.avgGasUsed / 1000).toFixed(0)}k</div>
        <div style={styles.statLabel}>Avg Gas</div>
      </div>
      <div style={styles.statCard}>
        <div style={{ ...styles.statValue, color: '#EF4444' }}>{stats.failed}</div>
        <div style={styles.statLabel}>Failed</div>
      </div>
    </div>
  );
};

// Main Proof Explorer Component
export const ProofExplorer: React.FC<{
  proofs?: ProofData[];
  stats?: ProofStats;
}> = ({ proofs = [], stats }) => {
  const [activeTab, setActiveTab] = useState<'all' | 'deposit' | 'withdraw' | 'bridge' | 'compliance'>('all');
  const [selectedProof, setSelectedProof] = useState<ProofData | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const filteredProofs = useMemo(() => {
    return proofs.filter(proof => {
      if (activeTab !== 'all' && proof.type !== activeTab) return false;
      if (searchQuery && !proof.id.includes(searchQuery)) return false;
      return true;
    });
  }, [proofs, activeTab, searchQuery]);

  const computedStats = useMemo(() => {
    if (stats) return stats;
    
    const verified = proofs.filter(p => p.status === 'verified').length;
    const pending = proofs.filter(p => p.status === 'pending' || p.status === 'generating').length;
    const failed = proofs.filter(p => p.status === 'failed').length;
    const withTime = proofs.filter(p => p.generationTime);
    const withGas = proofs.filter(p => p.gasUsed);
    
    return {
      totalProofs: proofs.length,
      verified,
      pending,
      failed,
      avgGenerationTime: withTime.length ? withTime.reduce((a, p) => a + (p.generationTime || 0), 0) / withTime.length : 0,
      avgGasUsed: withGas.length ? withGas.reduce((a, p) => a + (p.gasUsed || 0), 0) / withGas.length : 0,
    };
  }, [proofs, stats]);

  // Sample data for demo
  const sampleProofs: ProofData[] = useMemo(() => {
    if (proofs.length > 0) return proofs;
    
    return [
      {
        id: '0x1a2b3c4d5e6f7890',
        type: 'deposit',
        system: 'groth16',
        timestamp: Date.now() - 300000,
        status: 'verified',
        publicInputs: ['0x123...', '0x456...', '0x789...'],
        proof: '0x' + '0123456789abcdef'.repeat(32),
        gasUsed: 245000,
        generationTime: 1250,
      },
      {
        id: '0x2b3c4d5e6f7890ab',
        type: 'bridge',
        system: 'plonk',
        timestamp: Date.now() - 60000,
        status: 'generating',
        publicInputs: ['0xabc...', '0xdef...'],
        generationTime: 800,
      },
      {
        id: '0x3c4d5e6f7890abcd',
        type: 'withdraw',
        system: 'noir',
        timestamp: Date.now() - 3600000,
        status: 'verified',
        publicInputs: ['0x111...', '0x222...', '0x333...', '0x444...'],
        proof: '0x' + 'fedcba9876543210'.repeat(32),
        txHash: '0xabcdef1234567890',
        gasUsed: 312000,
        generationTime: 2100,
      },
      {
        id: '0x4d5e6f7890abcdef',
        type: 'compliance',
        system: 'stark',
        timestamp: Date.now() - 7200000,
        status: 'failed',
        publicInputs: ['0x555...'],
      },
    ];
  }, [proofs]);

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h2 style={styles.title}>🔍 Proof Explorer</h2>
        <input
          type="text"
          placeholder="Search by ID..."
          style={{ ...styles.input, width: '200px', marginTop: 0 }}
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
        />
      </div>

      <StatsCards stats={computedStats} />

      <div style={styles.tabs}>
        {(['all', 'deposit', 'withdraw', 'bridge', 'compliance'] as const).map(tab => (
          <button
            key={tab}
            style={styles.tab(activeTab === tab)}
            onClick={() => setActiveTab(tab)}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      <div style={styles.proofList}>
        {(filteredProofs.length > 0 ? filteredProofs : sampleProofs).map(proof => (
          <ProofCard
            key={proof.id}
            proof={proof}
            onClick={() => setSelectedProof(proof)}
          />
        ))}
      </div>

      {selectedProof && (
        <ProofDetailModal
          proof={selectedProof}
          onClose={() => setSelectedProof(null)}
        />
      )}
    </div>
  );
};

export default ProofExplorer;
