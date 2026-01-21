/**
 * PIL Frontend - Bridge UI Components
 * 
 * React components for cross-chain privacy bridge interface
 */

import React, { useState, useCallback, useMemo } from 'react';

// Types
export interface Chain {
  id: string;
  name: string;
  icon: string;
  color: string;
  finality: string;
  avgTime: number;
}

export interface TransferStatus {
  id: string;
  state: 'pending' | 'confirming' | 'bridging' | 'completing' | 'completed' | 'failed';
  sourceChain: string;
  destChain: string;
  amount: string;
  recipient: string;
  timestamp: number;
  confirmations: number;
  requiredConfirmations: number;
  txHash?: string;
  error?: string;
}

// Chain definitions
export const SUPPORTED_CHAINS: Chain[] = [
  { id: 'ethereum', name: 'Ethereum', icon: '⟠', color: '#627EEA', finality: '12 blocks', avgTime: 180 },
  { id: 'cardano', name: 'Cardano', icon: '₳', color: '#0033AD', finality: '20 blocks', avgTime: 400 },
  { id: 'polkadot', name: 'Polkadot', icon: '●', color: '#E6007A', finality: '30 blocks', avgTime: 180 },
  { id: 'cosmos', name: 'Cosmos', icon: '⚛', color: '#2E3148', finality: '15 blocks', avgTime: 105 },
  { id: 'near', name: 'NEAR', icon: 'Ⓝ', color: '#000000', finality: '4 epochs', avgTime: 240 },
  { id: 'zksync', name: 'zkSync Era', icon: '⚡', color: '#8B8DFC', finality: 'Instant', avgTime: 10 },
  { id: 'avalanche', name: 'Avalanche', icon: '🔺', color: '#E84142', finality: '2 seconds', avgTime: 2 },
  { id: 'arbitrum', name: 'Arbitrum', icon: '🔵', color: '#28A0F0', finality: '10 mins', avgTime: 600 },
  { id: 'solana', name: 'Solana', icon: '◎', color: '#14F195', finality: '32 slots', avgTime: 13 },
  { id: 'bitcoin', name: 'Bitcoin', icon: '₿', color: '#F7931A', finality: '6 blocks', avgTime: 3600 },
];

// Styles (inline for component portability)
const styles = {
  container: {
    fontFamily: 'system-ui, -apple-system, sans-serif',
    maxWidth: '480px',
    margin: '0 auto',
    padding: '24px',
    backgroundColor: '#1a1a2e',
    borderRadius: '16px',
    color: '#ffffff',
  },
  header: {
    textAlign: 'center' as const,
    marginBottom: '24px',
  },
  title: {
    fontSize: '24px',
    fontWeight: 'bold',
    marginBottom: '8px',
  },
  subtitle: {
    fontSize: '14px',
    color: '#a0a0a0',
  },
  section: {
    marginBottom: '20px',
  },
  label: {
    fontSize: '12px',
    color: '#a0a0a0',
    marginBottom: '8px',
    display: 'block',
  },
  chainSelector: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap' as const,
  },
  chainButton: (selected: boolean, color: string) => ({
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '8px 12px',
    borderRadius: '8px',
    border: selected ? `2px solid ${color}` : '2px solid #333',
    backgroundColor: selected ? `${color}20` : 'transparent',
    color: '#fff',
    cursor: 'pointer',
    fontSize: '14px',
    transition: 'all 0.2s',
  }),
  input: {
    width: '100%',
    padding: '12px 16px',
    borderRadius: '12px',
    border: '2px solid #333',
    backgroundColor: '#0f0f23',
    color: '#fff',
    fontSize: '18px',
    outline: 'none',
    boxSizing: 'border-box' as const,
  },
  button: (disabled: boolean) => ({
    width: '100%',
    padding: '16px',
    borderRadius: '12px',
    border: 'none',
    backgroundColor: disabled ? '#333' : '#8B5CF6',
    color: '#fff',
    fontSize: '16px',
    fontWeight: 'bold',
    cursor: disabled ? 'not-allowed' : 'pointer',
    transition: 'background-color 0.2s',
  }),
  privacyToggle: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '12px 16px',
    backgroundColor: '#0f0f23',
    borderRadius: '12px',
    marginBottom: '20px',
  },
  toggle: (enabled: boolean) => ({
    width: '48px',
    height: '24px',
    borderRadius: '12px',
    backgroundColor: enabled ? '#10B981' : '#333',
    position: 'relative' as const,
    cursor: 'pointer',
    transition: 'background-color 0.2s',
  }),
  toggleKnob: (enabled: boolean) => ({
    width: '20px',
    height: '20px',
    borderRadius: '50%',
    backgroundColor: '#fff',
    position: 'absolute' as const,
    top: '2px',
    left: enabled ? '26px' : '2px',
    transition: 'left 0.2s',
  }),
  feeDisplay: {
    display: 'flex',
    justifyContent: 'space-between',
    padding: '12px 0',
    borderTop: '1px solid #333',
    fontSize: '14px',
  },
  statusCard: {
    padding: '16px',
    backgroundColor: '#0f0f23',
    borderRadius: '12px',
    marginTop: '16px',
  },
  statusRow: {
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: '8px',
  },
  progressBar: {
    width: '100%',
    height: '4px',
    backgroundColor: '#333',
    borderRadius: '2px',
    overflow: 'hidden' as const,
    marginTop: '12px',
  },
  progressFill: (progress: number) => ({
    height: '100%',
    width: `${progress}%`,
    backgroundColor: '#8B5CF6',
    transition: 'width 0.3s',
  }),
};

// Chain Selector Component
export const ChainSelector: React.FC<{
  label: string;
  selected: string;
  onSelect: (chainId: string) => void;
  exclude?: string;
}> = ({ label, selected, onSelect, exclude }) => {
  const chains = useMemo(
    () => SUPPORTED_CHAINS.filter(c => c.id !== exclude),
    [exclude]
  );

  return (
    <div style={styles.section}>
      <label style={styles.label}>{label}</label>
      <div style={styles.chainSelector}>
        {chains.map(chain => (
          <button
            key={chain.id}
            style={styles.chainButton(selected === chain.id, chain.color)}
            onClick={() => onSelect(chain.id)}
          >
            <span>{chain.icon}</span>
            <span>{chain.name}</span>
          </button>
        ))}
      </div>
    </div>
  );
};

// Amount Input Component
export const AmountInput: React.FC<{
  value: string;
  onChange: (value: string) => void;
  symbol?: string;
  balance?: string;
}> = ({ value, onChange, symbol = 'ETH', balance }) => {
  return (
    <div style={styles.section}>
      <label style={styles.label}>
        Amount {balance && <span style={{ float: 'right' }}>Balance: {balance} {symbol}</span>}
      </label>
      <div style={{ position: 'relative' }}>
        <input
          type="number"
          style={styles.input}
          placeholder="0.0"
          value={value}
          onChange={e => onChange(e.target.value)}
        />
        <span style={{ position: 'absolute', right: '16px', top: '50%', transform: 'translateY(-50%)', color: '#a0a0a0' }}>
          {symbol}
        </span>
      </div>
    </div>
  );
};

// Privacy Toggle Component
export const PrivacyToggle: React.FC<{
  enabled: boolean;
  onToggle: () => void;
}> = ({ enabled, onToggle }) => {
  return (
    <div style={styles.privacyToggle}>
      <div style={styles.toggle(enabled)} onClick={onToggle}>
        <div style={styles.toggleKnob(enabled)} />
      </div>
      <div>
        <div style={{ fontWeight: 'bold', fontSize: '14px' }}>
          {enabled ? '🔒 Privacy Mode' : '🔓 Standard Mode'}
        </div>
        <div style={{ fontSize: '12px', color: '#a0a0a0' }}>
          {enabled ? 'ZK proof hides transaction details' : 'Transaction visible on chain'}
        </div>
      </div>
    </div>
  );
};

// Fee Display Component
export const FeeDisplay: React.FC<{
  bridgeFee: string;
  gasFee: string;
  privacyFee?: string;
  total: string;
}> = ({ bridgeFee, gasFee, privacyFee, total }) => {
  return (
    <div style={styles.section}>
      <div style={styles.feeDisplay}>
        <span style={{ color: '#a0a0a0' }}>Bridge Fee</span>
        <span>{bridgeFee}</span>
      </div>
      <div style={styles.feeDisplay}>
        <span style={{ color: '#a0a0a0' }}>Gas Fee</span>
        <span>{gasFee}</span>
      </div>
      {privacyFee && (
        <div style={styles.feeDisplay}>
          <span style={{ color: '#a0a0a0' }}>Privacy Fee</span>
          <span>{privacyFee}</span>
        </div>
      )}
      <div style={{ ...styles.feeDisplay, fontWeight: 'bold', borderTop: '2px solid #333' }}>
        <span>Total</span>
        <span>{total}</span>
      </div>
    </div>
  );
};

// Transfer Status Component
export const TransferStatusCard: React.FC<{
  status: TransferStatus;
}> = ({ status }) => {
  const progress = useMemo(() => {
    switch (status.state) {
      case 'pending': return 10;
      case 'confirming': return 30 + (status.confirmations / status.requiredConfirmations) * 30;
      case 'bridging': return 70;
      case 'completing': return 90;
      case 'completed': return 100;
      case 'failed': return 0;
      default: return 0;
    }
  }, [status]);

  const stateLabel = useMemo(() => {
    switch (status.state) {
      case 'pending': return '⏳ Pending';
      case 'confirming': return `🔄 Confirming (${status.confirmations}/${status.requiredConfirmations})`;
      case 'bridging': return '🌉 Bridging';
      case 'completing': return '✨ Completing';
      case 'completed': return '✅ Completed';
      case 'failed': return '❌ Failed';
      default: return 'Unknown';
    }
  }, [status]);

  return (
    <div style={styles.statusCard}>
      <div style={styles.statusRow}>
        <span style={{ color: '#a0a0a0' }}>Status</span>
        <span>{stateLabel}</span>
      </div>
      <div style={styles.statusRow}>
        <span style={{ color: '#a0a0a0' }}>Amount</span>
        <span>{status.amount}</span>
      </div>
      <div style={styles.statusRow}>
        <span style={{ color: '#a0a0a0' }}>Route</span>
        <span>{status.sourceChain} → {status.destChain}</span>
      </div>
      {status.txHash && (
        <div style={styles.statusRow}>
          <span style={{ color: '#a0a0a0' }}>TX Hash</span>
          <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>
            {status.txHash.substring(0, 10)}...
          </span>
        </div>
      )}
      <div style={styles.progressBar}>
        <div style={styles.progressFill(progress)} />
      </div>
      {status.error && (
        <div style={{ color: '#EF4444', fontSize: '12px', marginTop: '8px' }}>
          {status.error}
        </div>
      )}
    </div>
  );
};

// Main Bridge Widget
export const BridgeWidget: React.FC<{
  onBridge?: (params: {
    sourceChain: string;
    destChain: string;
    amount: string;
    recipient: string;
    privacy: boolean;
  }) => Promise<void>;
  balance?: string;
}> = ({ onBridge, balance }) => {
  const [sourceChain, setSourceChain] = useState('ethereum');
  const [destChain, setDestChain] = useState('zksync');
  const [amount, setAmount] = useState('');
  const [recipient, setRecipient] = useState('');
  const [privacyEnabled, setPrivacyEnabled] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [currentStatus, setCurrentStatus] = useState<TransferStatus | null>(null);

  const estimatedFees = useMemo(() => {
    const amountNum = parseFloat(amount) || 0;
    const bridgeFee = amountNum * 0.001; // 0.1%
    const gasFee = 0.002;
    const privacyFee = privacyEnabled ? 0.001 : 0;
    return {
      bridgeFee: `${bridgeFee.toFixed(4)} ETH`,
      gasFee: `${gasFee.toFixed(4)} ETH`,
      privacyFee: privacyEnabled ? `${privacyFee.toFixed(4)} ETH` : undefined,
      total: `${(bridgeFee + gasFee + privacyFee).toFixed(4)} ETH`,
    };
  }, [amount, privacyEnabled]);

  const canBridge = useMemo(() => {
    return (
      sourceChain &&
      destChain &&
      parseFloat(amount) > 0 &&
      recipient.length > 0
    );
  }, [sourceChain, destChain, amount, recipient]);

  const handleBridge = useCallback(async () => {
    if (!canBridge || !onBridge) return;

    setIsLoading(true);
    setCurrentStatus({
      id: Date.now().toString(),
      state: 'pending',
      sourceChain,
      destChain,
      amount: `${amount} ETH`,
      recipient,
      timestamp: Date.now(),
      confirmations: 0,
      requiredConfirmations: 12,
    });

    try {
      await onBridge({
        sourceChain,
        destChain,
        amount,
        recipient,
        privacy: privacyEnabled,
      });
    } catch (error: any) {
      setCurrentStatus(prev => prev ? {
        ...prev,
        state: 'failed',
        error: error.message,
      } : null);
    } finally {
      setIsLoading(false);
    }
  }, [canBridge, onBridge, sourceChain, destChain, amount, recipient, privacyEnabled]);

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h1 style={styles.title}>🔒 PIL Bridge</h1>
        <p style={styles.subtitle}>Private cross-chain transfers</p>
      </div>

      <ChainSelector
        label="From"
        selected={sourceChain}
        onSelect={setSourceChain}
        exclude={destChain}
      />

      <ChainSelector
        label="To"
        selected={destChain}
        onSelect={setDestChain}
        exclude={sourceChain}
      />

      <AmountInput
        value={amount}
        onChange={setAmount}
        balance={balance}
      />

      <div style={styles.section}>
        <label style={styles.label}>Recipient Address</label>
        <input
          style={styles.input}
          placeholder="0x..."
          value={recipient}
          onChange={e => setRecipient(e.target.value)}
        />
      </div>

      <PrivacyToggle
        enabled={privacyEnabled}
        onToggle={() => setPrivacyEnabled(!privacyEnabled)}
      />

      {parseFloat(amount) > 0 && (
        <FeeDisplay {...estimatedFees} />
      )}

      <button
        style={styles.button(!canBridge || isLoading)}
        disabled={!canBridge || isLoading}
        onClick={handleBridge}
      >
        {isLoading ? '⏳ Processing...' : privacyEnabled ? '🔒 Bridge Privately' : '🌉 Bridge'}
      </button>

      {currentStatus && <TransferStatusCard status={currentStatus} />}
    </div>
  );
};

// Export all components
export default BridgeWidget;
