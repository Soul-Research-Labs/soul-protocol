/**
 * PIL SDK - React Hooks
 * 
 * React hooks for integrating PIL privacy and bridge features into React applications
 */

import { useState, useCallback, useEffect, useMemo } from 'react';
import { ethers } from 'ethers';
import { PILClient } from '../client/PILClient';
import { 
  BridgeFactory, 
  BaseBridgeAdapter, 
  BridgeStatus, 
  BridgeFees,
  SupportedChain 
} from '../bridges';

// ============================================
// Types
// ============================================

export interface UsePILConfig {
  chainId: number;
  privacyPoolAddress: string;
  bridgeRouterAddress: string;
  rpcUrl?: string;
}

export interface DepositNote {
  secret: Uint8Array;
  commitment: string;
  leafIndex: bigint;
  amount: bigint;
  timestamp: number;
}

export interface WithdrawParams {
  depositNote: DepositNote;
  recipient: string;
}

export interface BridgeParams {
  targetChain: SupportedChain;
  recipient: string;
  amount: bigint;
  depositNote?: DepositNote;
}

export interface PILState {
  isConnected: boolean;
  address: string | null;
  balance: bigint;
  poolBalance: bigint;
  deposits: DepositNote[];
}

// ============================================
// Main PIL Hook
// ============================================

export function usePIL(config: UsePILConfig) {
  const [client, setClient] = useState<PILClient | null>(null);
  const [state, setState] = useState<PILState>({
    isConnected: false,
    address: null,
    balance: 0n,
    poolBalance: 0n,
    deposits: []
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Initialize client
  const connect = useCallback(async (signer: ethers.Signer) => {
    try {
      setIsLoading(true);
      setError(null);

      const pilClient = new PILClient({
        chainId: config.chainId,
        signer,
        addresses: {
          privacyPool: config.privacyPoolAddress,
          bridgeRouter: config.bridgeRouterAddress
        }
      });

      setClient(pilClient);

      const address = await signer.getAddress();
      const provider = signer.provider!;
      const balance = await provider.getBalance(address);

      setState(prev => ({
        ...prev,
        isConnected: true,
        address,
        balance
      }));
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  }, [config]);

  const disconnect = useCallback(() => {
    setClient(null);
    setState({
      isConnected: false,
      address: null,
      balance: 0n,
      poolBalance: 0n,
      deposits: []
    });
  }, []);

  return {
    client,
    state,
    isLoading,
    error,
    connect,
    disconnect
  };
}

// ============================================
// Privacy Pool Hook
// ============================================

export function usePrivacyPool(client: PILClient | null) {
  const [deposits, setDeposits] = useState<DepositNote[]>([]);
  const [isDepositing, setIsDepositing] = useState(false);
  const [isWithdrawing, setIsWithdrawing] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const deposit = useCallback(async (amount: bigint): Promise<DepositNote | null> => {
    if (!client) {
      setError(new Error('Client not initialized'));
      return null;
    }

    try {
      setIsDepositing(true);
      setError(null);

      // Generate random secret
      const secret = ethers.randomBytes(32);
      
      // Compute commitment (this would call the actual implementation)
      const commitment = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes32', 'uint256'],
          [secret, amount]
        )
      );

      // Make deposit (this would call the actual contract)
      // const tx = await client.deposit(commitment, { value: amount });
      // const receipt = await tx.wait();

      const depositNote: DepositNote = {
        secret,
        commitment,
        leafIndex: BigInt(deposits.length),
        amount,
        timestamp: Date.now()
      };

      setDeposits(prev => [...prev, depositNote]);
      return depositNote;
    } catch (err) {
      setError(err as Error);
      return null;
    } finally {
      setIsDepositing(false);
    }
  }, [client, deposits.length]);

  const withdraw = useCallback(async (params: WithdrawParams): Promise<string | null> => {
    if (!client) {
      setError(new Error('Client not initialized'));
      return null;
    }

    try {
      setIsWithdrawing(true);
      setError(null);

      // Generate proof (this would call the actual prover)
      // const proof = await client.generateWithdrawProof(...);

      // Execute withdrawal (this would call the actual contract)
      // const tx = await client.withdraw(proof, nullifier, recipient, amount);
      // const receipt = await tx.wait();

      // Remove used deposit
      setDeposits(prev => prev.filter(d => d.commitment !== params.depositNote.commitment));

      return '0x...'; // transaction hash
    } catch (err) {
      setError(err as Error);
      return null;
    } finally {
      setIsWithdrawing(false);
    }
  }, [client]);

  return {
    deposits,
    isDepositing,
    isWithdrawing,
    error,
    deposit,
    withdraw
  };
}

// ============================================
// Bridge Hook
// ============================================

export function useBridge(
  client: PILClient | null,
  provider: ethers.Provider | null,
  signer: ethers.Signer | null
) {
  const [adapters, setAdapters] = useState<Map<SupportedChain, BaseBridgeAdapter>>(new Map());
  const [transfers, setTransfers] = useState<Map<string, BridgeStatus>>(new Map());
  const [isBridging, setIsBridging] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Initialize adapters
  const initializeAdapter = useCallback(async (
    chain: SupportedChain,
    config: Record<string, string>
  ) => {
    if (!provider || !signer) {
      setError(new Error('Provider/signer not available'));
      return;
    }

    try {
      const adapter = BridgeFactory.createAdapter(chain, provider, signer, config);
      setAdapters(prev => new Map(prev).set(chain, adapter));
    } catch (err) {
      setError(err as Error);
    }
  }, [provider, signer]);

  // Bridge transfer
  const bridge = useCallback(async (params: BridgeParams): Promise<string | null> => {
    const adapter = adapters.get(params.targetChain);
    if (!adapter) {
      setError(new Error(`Adapter not initialized for ${params.targetChain}`));
      return null;
    }

    try {
      setIsBridging(true);
      setError(null);

      const result = await adapter.bridgeTransfer({
        targetChainId: adapter.config.chainId,
        recipient: params.recipient,
        amount: params.amount
      });

      // Track transfer
      const status = await adapter.getStatus(result.transferId);
      setTransfers(prev => new Map(prev).set(result.transferId, status));

      return result.transferId;
    } catch (err) {
      setError(err as Error);
      return null;
    } finally {
      setIsBridging(false);
    }
  }, [adapters]);

  // Get transfer status
  const getStatus = useCallback(async (transferId: string, chain: SupportedChain): Promise<BridgeStatus | null> => {
    const adapter = adapters.get(chain);
    if (!adapter) return null;

    try {
      const status = await adapter.getStatus(transferId);
      setTransfers(prev => new Map(prev).set(transferId, status));
      return status;
    } catch (err) {
      setError(err as Error);
      return null;
    }
  }, [adapters]);

  // Estimate fees
  const estimateFees = useCallback(async (
    chain: SupportedChain,
    amount: bigint,
    targetChainId: number
  ): Promise<BridgeFees | null> => {
    const adapter = adapters.get(chain);
    if (!adapter) return null;

    try {
      return await adapter.estimateFees(amount, targetChainId);
    } catch (err) {
      setError(err as Error);
      return null;
    }
  }, [adapters]);

  return {
    adapters,
    transfers,
    isBridging,
    error,
    initializeAdapter,
    bridge,
    getStatus,
    estimateFees
  };
}

// ============================================
// Proof Generation Hook
// ============================================

export function useProofGeneration() {
  const [isGenerating, setIsGenerating] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<Error | null>(null);

  const generateDepositProof = useCallback(async (
    secret: Uint8Array,
    amount: bigint
  ): Promise<Uint8Array | null> => {
    try {
      setIsGenerating(true);
      setProgress(0);
      setError(null);

      // Simulate proof generation stages
      setProgress(20);
      await new Promise(r => setTimeout(r, 500));
      
      setProgress(50);
      await new Promise(r => setTimeout(r, 500));
      
      setProgress(80);
      await new Promise(r => setTimeout(r, 500));
      
      setProgress(100);

      // Return mock proof
      return new Uint8Array(256);
    } catch (err) {
      setError(err as Error);
      return null;
    } finally {
      setIsGenerating(false);
    }
  }, []);

  const generateWithdrawProof = useCallback(async (
    secret: Uint8Array,
    amount: bigint,
    recipient: string,
    merkleRoot: string,
    merklePath: string[]
  ): Promise<Uint8Array | null> => {
    try {
      setIsGenerating(true);
      setProgress(0);
      setError(null);

      // Simulate proof generation (would use actual WASM prover)
      for (let i = 0; i <= 100; i += 10) {
        setProgress(i);
        await new Promise(r => setTimeout(r, 200));
      }

      return new Uint8Array(256);
    } catch (err) {
      setError(err as Error);
      return null;
    } finally {
      setIsGenerating(false);
    }
  }, []);

  return {
    isGenerating,
    progress,
    error,
    generateDepositProof,
    generateWithdrawProof
  };
}

// ============================================
// Transfer History Hook
// ============================================

export function useTransferHistory(address: string | null) {
  const [history, setHistory] = useState<Array<{
    id: string;
    type: 'deposit' | 'withdraw' | 'bridge';
    amount: bigint;
    status: string;
    timestamp: number;
    txHash?: string;
  }>>([]);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (!address) {
      setHistory([]);
      return;
    }

    // Fetch history (would call indexer/subgraph)
    setIsLoading(true);
    // Simulated fetch
    setTimeout(() => {
      setHistory([]);
      setIsLoading(false);
    }, 1000);
  }, [address]);

  return { history, isLoading };
}

// ============================================
// Chain Selection Hook
// ============================================

export function useChainSelection() {
  const [selectedChain, setSelectedChain] = useState<SupportedChain>('zksync');
  
  const supportedChains: Array<{
    id: SupportedChain;
    name: string;
    icon: string;
    finality: string;
  }> = useMemo(() => [
    { id: 'cardano', name: 'Cardano', icon: '₳', finality: '~20 blocks' },
    { id: 'polkadot', name: 'Polkadot', icon: '●', finality: '~30 blocks' },
    { id: 'cosmos', name: 'Cosmos', icon: '⚛', finality: '~15 blocks' },
    { id: 'near', name: 'NEAR', icon: 'Ⓝ', finality: '~4 epochs' },
    { id: 'zksync', name: 'zkSync Era', icon: '⚡', finality: 'Instant' },
    { id: 'avalanche', name: 'Avalanche', icon: '🔺', finality: '~2 seconds' },
    { id: 'arbitrum', name: 'Arbitrum', icon: '🔵', finality: '~10 mins' },
    { id: 'solana', name: 'Solana', icon: '◎', finality: '~32 slots' },
    { id: 'bitcoin', name: 'Bitcoin', icon: '₿', finality: '~6 blocks' },
  ], []);

  return {
    selectedChain,
    setSelectedChain,
    supportedChains
  };
}

// Export all hooks
export {
  usePIL,
  usePrivacyPool,
  useBridge,
  useProofGeneration,
  useTransferHistory,
  useChainSelection
};
