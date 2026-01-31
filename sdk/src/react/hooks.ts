/**
 * Soul SDK - React Hooks
 * 
 * React hooks for integrating Soul privacy and bridge features into React applications
 */

import { useState, useCallback, useEffect, useMemo } from 'react';
import { 
  keccak256, 
  toHex, 
  toBytes, 
  encodeAbiParameters, 
  type PublicClient, 
  type WalletClient,
  type Hex,
  parseEther
} from 'viem';
import { SoulSDK as SoulClient } from '../client/SoulSDK';
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

export interface UseSoulConfig {
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

export interface SoulState {
  isConnected: boolean;
  address: string | null;
  balance: bigint;
  poolBalance: bigint;
  deposits: DepositNote[];
}

// ============================================
// Main Soul Hook
// ============================================

export function useSoul(config: UseSoulConfig) {
  const [client, setClient] = useState<SoulClient | null>(null);
  const [state, setState] = useState<SoulState>({
    isConnected: false,
    address: null,
    balance: 0n,
    poolBalance: 0n,
    deposits: []
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Initialize client
  const connect = useCallback(async (publicClient: PublicClient, walletClient: WalletClient) => {
    try {
      setIsLoading(true);
      setError(null);

      const pilClient = new SoulClient({
        curve: 'bn254',
        relayerEndpoint: config.rpcUrl || 'https://relay.pil.network',
        proverUrl: 'https://prover.pil.network',
        privateKey: '', // Placeholder
      });

      setClient(pilClient);

      const [address] = await walletClient.getAddresses();
      const balance = await publicClient.getBalance({ address });

      setState((prev: SoulState) => ({
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

export function usePrivacyPool(client: SoulClient | null) {
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
      const secret = crypto.getRandomValues(new Uint8Array(32));
      
      // Compute commitment
      const commitment = keccak256(
        encodeAbiParameters(
          [{ type: 'bytes32' }, { type: 'uint256' }],
          [toHex(secret), amount]
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

      setDeposits((prev: DepositNote[]) => [...prev, depositNote]);
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
      setDeposits((prev: DepositNote[]) => prev.filter((d: DepositNote) => d.commitment !== params.depositNote.commitment));

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
  client: SoulClient | null,
  publicClient: PublicClient | null,
  walletClient: WalletClient | null
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
    if (!publicClient || !walletClient) {
      setError(new Error('Clients not available'));
      return;
    }

    try {
      const adapter = BridgeFactory.createAdapter(chain, publicClient, walletClient, config);
      setAdapters((prev: Map<SupportedChain, BaseBridgeAdapter>) => new Map(prev).set(chain, adapter));
    } catch (err) {
      setError(err as Error);
    }
  }, [publicClient, walletClient]);

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
      setTransfers((prev: Map<string, BridgeStatus>) => new Map(prev).set(result.transferId, status));

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
      setTransfers((prev: Map<string, BridgeStatus>) => new Map(prev).set(transferId, status));
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
  const [selectedChain, setSelectedChain] = useState<SupportedChain>('arbitrum');
  
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

