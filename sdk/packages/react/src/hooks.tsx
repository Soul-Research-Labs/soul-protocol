import { useState, useEffect, useCallback, useMemo } from 'react';
import { PILClient, PILClientConfig, Container, ContainerStatus } from '@pil/sdk';
import { ethers } from 'ethers';

// ============================================================
// Context & Provider
// ============================================================

import React, { createContext, useContext, ReactNode } from 'react';

interface PILContextValue {
  client: PILClient | null;
  isConnected: boolean;
  isLoading: boolean;
  error: Error | null;
  address: string | null;
  chainId: number | null;
  connect: () => Promise<void>;
  disconnect: () => void;
}

const PILContext = createContext<PILContextValue | null>(null);

interface PILProviderProps {
  children: ReactNode;
  config?: Partial<PILClientConfig>;
}

export function PILProvider({ children, config }: PILProviderProps) {
  const [client, setClient] = useState<PILClient | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [chainId, setChainId] = useState<number | null>(null);

  const connect = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      if (typeof window === 'undefined' || !window.ethereum) {
        throw new Error('No wallet detected');
      }

      const provider = new ethers.BrowserProvider(window.ethereum);
      const accounts = await provider.send('eth_requestAccounts', []);
      const signer = await provider.getSigner();
      const network = await provider.getNetwork();

      const pilClient = new PILClient({
        network: getNetworkName(Number(network.chainId)),
        rpcUrl: window.ethereum.selectedAddress,
        signer,
        ...config,
      });

      setClient(pilClient);
      setAddress(accounts[0]);
      setChainId(Number(network.chainId));
      setIsConnected(true);
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  }, [config]);

  const disconnect = useCallback(() => {
    setClient(null);
    setAddress(null);
    setChainId(null);
    setIsConnected(false);
  }, []);

  // Listen for account changes
  useEffect(() => {
    if (typeof window === 'undefined' || !window.ethereum) return;

    const handleAccountsChanged = (accounts: string[]) => {
      if (accounts.length === 0) {
        disconnect();
      } else {
        setAddress(accounts[0]);
      }
    };

    const handleChainChanged = (chainIdHex: string) => {
      setChainId(parseInt(chainIdHex, 16));
      // Reconnect with new chain
      connect();
    };

    window.ethereum.on('accountsChanged', handleAccountsChanged);
    window.ethereum.on('chainChanged', handleChainChanged);

    return () => {
      window.ethereum?.removeListener('accountsChanged', handleAccountsChanged);
      window.ethereum?.removeListener('chainChanged', handleChainChanged);
    };
  }, [connect, disconnect]);

  const value = useMemo(
    () => ({
      client,
      isConnected,
      isLoading,
      error,
      address,
      chainId,
      connect,
      disconnect,
    }),
    [client, isConnected, isLoading, error, address, chainId, connect, disconnect]
  );

  return <PILContext.Provider value={value}>{children}</PILContext.Provider>;
}

export function usePIL() {
  const context = useContext(PILContext);
  if (!context) {
    throw new Error('usePIL must be used within a PILProvider');
  }
  return context;
}

// ============================================================
// Container Hooks
// ============================================================

interface UseContainerOptions {
  pollInterval?: number;
  enabled?: boolean;
}

interface UseContainerResult {
  container: Container | null;
  isLoading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
}

export function useContainer(
  containerId: string | undefined,
  options: UseContainerOptions = {}
): UseContainerResult {
  const { client } = usePIL();
  const { pollInterval, enabled = true } = options;
  
  const [container, setContainer] = useState<Container | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchContainer = useCallback(async () => {
    if (!client || !containerId || !enabled) return;

    setIsLoading(true);
    setError(null);

    try {
      const data = await client.getPC3().getContainer(containerId);
      setContainer(data);
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  }, [client, containerId, enabled]);

  useEffect(() => {
    fetchContainer();

    if (pollInterval && pollInterval > 0) {
      const interval = setInterval(fetchContainer, pollInterval);
      return () => clearInterval(interval);
    }
  }, [fetchContainer, pollInterval]);

  return { container, isLoading, error, refetch: fetchContainer };
}

interface UseContainersOptions {
  creator?: string;
  status?: ContainerStatus;
  limit?: number;
  offset?: number;
}

interface UseContainersResult {
  containers: Container[];
  isLoading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
  hasMore: boolean;
  loadMore: () => Promise<void>;
}

export function useContainers(
  options: UseContainersOptions = {}
): UseContainersResult {
  const { client } = usePIL();
  const { creator, status, limit = 20, offset = 0 } = options;

  const [containers, setContainers] = useState<Container[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [hasMore, setHasMore] = useState(true);
  const [currentOffset, setCurrentOffset] = useState(offset);

  const fetchContainers = useCallback(async (reset = false) => {
    if (!client) return;

    setIsLoading(true);
    setError(null);

    try {
      const fetchOffset = reset ? 0 : currentOffset;
      const data = await client.getPC3().listContainers({
        creator,
        status,
        limit,
        offset: fetchOffset,
      });

      if (reset) {
        setContainers(data);
        setCurrentOffset(limit);
      } else {
        setContainers((prev) => [...prev, ...data]);
        setCurrentOffset((prev) => prev + limit);
      }

      setHasMore(data.length === limit);
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  }, [client, creator, status, limit, currentOffset]);

  useEffect(() => {
    fetchContainers(true);
  }, [client, creator, status]);

  const loadMore = useCallback(() => fetchContainers(false), [fetchContainers]);
  const refetch = useCallback(() => fetchContainers(true), [fetchContainers]);

  return { containers, isLoading, error, refetch, hasMore, loadMore };
}

// ============================================================
// Create Container Hook
// ============================================================

interface CreateContainerParams {
  proof: Uint8Array;
  publicInputs: string[];
  metadata?: Record<string, unknown>;
}

interface UseCreateContainerResult {
  createContainer: (params: CreateContainerParams) => Promise<string>;
  isLoading: boolean;
  error: Error | null;
  containerId: string | null;
  txHash: string | null;
  reset: () => void;
}

export function useCreateContainer(): UseCreateContainerResult {
  const { client } = usePIL();
  
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [containerId, setContainerId] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);

  const createContainer = useCallback(
    async (params: CreateContainerParams) => {
      if (!client) throw new Error('Not connected');

      setIsLoading(true);
      setError(null);

      try {
        const result = await client.getPC3().createContainer(params);
        setContainerId(result.containerId);
        setTxHash(result.txHash);
        return result.containerId;
      } catch (err) {
        setError(err as Error);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [client]
  );

  const reset = useCallback(() => {
    setError(null);
    setContainerId(null);
    setTxHash(null);
  }, []);

  return { createContainer, isLoading, error, containerId, txHash, reset };
}

// ============================================================
// Consume Container Hook
// ============================================================

interface UseConsumeContainerResult {
  consumeContainer: (containerId: string) => Promise<string>;
  isLoading: boolean;
  error: Error | null;
  txHash: string | null;
  reset: () => void;
}

export function useConsumeContainer(): UseConsumeContainerResult {
  const { client } = usePIL();
  
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);

  const consumeContainer = useCallback(
    async (containerId: string) => {
      if (!client) throw new Error('Not connected');

      setIsLoading(true);
      setError(null);

      try {
        const result = await client.getPC3().consumeContainer(containerId);
        setTxHash(result.txHash);
        return result.txHash;
      } catch (err) {
        setError(err as Error);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [client]
  );

  const reset = useCallback(() => {
    setError(null);
    setTxHash(null);
  }, []);

  return { consumeContainer, isLoading, error, txHash, reset };
}

// ============================================================
// Nullifier Hooks
// ============================================================

interface UseNullifierResult {
  isSpent: boolean | null;
  isLoading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
}

export function useNullifier(
  nullifier: string | undefined,
  domain: string
): UseNullifierResult {
  const { client } = usePIL();
  
  const [isSpent, setIsSpent] = useState<boolean | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchNullifier = useCallback(async () => {
    if (!client || !nullifier) return;

    setIsLoading(true);
    setError(null);

    try {
      const spent = await client.getCDNA().checkNullifier(nullifier, domain);
      setIsSpent(spent);
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  }, [client, nullifier, domain]);

  useEffect(() => {
    fetchNullifier();
  }, [fetchNullifier]);

  return { isSpent, isLoading, error, refetch: fetchNullifier };
}

// ============================================================
// Policy Hooks
// ============================================================

interface UseVerifyPolicyResult {
  verify: (proof: Uint8Array, policyId: string) => Promise<boolean>;
  isLoading: boolean;
  error: Error | null;
  result: boolean | null;
  reset: () => void;
}

export function useVerifyPolicy(): UseVerifyPolicyResult {
  const { client } = usePIL();
  
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [result, setResult] = useState<boolean | null>(null);

  const verify = useCallback(
    async (proof: Uint8Array, policyId: string) => {
      if (!client) throw new Error('Not connected');

      setIsLoading(true);
      setError(null);

      try {
        const isValid = await client.getPBP().verifyProofAgainstPolicy(
          proof,
          policyId
        );
        setResult(isValid);
        return isValid;
      } catch (err) {
        setError(err as Error);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [client]
  );

  const reset = useCallback(() => {
    setError(null);
    setResult(null);
  }, []);

  return { verify, isLoading, error, result, reset };
}

// ============================================================
// Event Hooks
// ============================================================

type ContainerEventCallback = (event: {
  containerId: string;
  creator?: string;
  consumer?: string;
  blockNumber: number;
  transactionHash: string;
}) => void;

export function useContainerEvents(
  event: 'ContainerCreated' | 'ContainerConsumed',
  callback: ContainerEventCallback
) {
  const { client } = usePIL();

  useEffect(() => {
    if (!client) return;

    const pc3 = client.getPC3();
    pc3.on(event, callback);

    return () => {
      pc3.off(event, callback);
    };
  }, [client, event, callback]);
}

// ============================================================
// Transaction Hooks
// ============================================================

interface UseTransactionResult {
  status: 'idle' | 'pending' | 'success' | 'error';
  txHash: string | null;
  error: Error | null;
  confirmations: number;
  reset: () => void;
}

export function useTransaction(txHash: string | null): UseTransactionResult {
  const { client } = usePIL();
  
  const [status, setStatus] = useState<'idle' | 'pending' | 'success' | 'error'>('idle');
  const [error, setError] = useState<Error | null>(null);
  const [confirmations, setConfirmations] = useState(0);

  useEffect(() => {
    if (!client || !txHash) {
      setStatus('idle');
      return;
    }

    setStatus('pending');

    const checkTransaction = async () => {
      try {
        const receipt = await client.getProvider().getTransactionReceipt(txHash);
        if (receipt) {
          const currentBlock = await client.getProvider().getBlockNumber();
          const confs = currentBlock - receipt.blockNumber + 1;
          setConfirmations(confs);

          if (receipt.status === 1) {
            setStatus('success');
          } else {
            setStatus('error');
            setError(new Error('Transaction failed'));
          }
        }
      } catch (err) {
        setStatus('error');
        setError(err as Error);
      }
    };

    const interval = setInterval(checkTransaction, 2000);
    checkTransaction();

    return () => clearInterval(interval);
  }, [client, txHash]);

  const reset = useCallback(() => {
    setStatus('idle');
    setError(null);
    setConfirmations(0);
  }, []);

  return { status, txHash, error, confirmations, reset };
}

// ============================================================
// Gas Estimation Hook
// ============================================================

interface UseGasEstimateResult {
  estimate: bigint | null;
  estimateUSD: number | null;
  isLoading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
}

export function useGasEstimate(
  method: string,
  params: unknown[]
): UseGasEstimateResult {
  const { client } = usePIL();
  
  const [estimate, setEstimate] = useState<bigint | null>(null);
  const [estimateUSD, setEstimateUSD] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchEstimate = useCallback(async () => {
    if (!client) return;

    setIsLoading(true);
    setError(null);

    try {
      const gas = await client.estimateGas(method, params);
      setEstimate(gas);

      // Get ETH price for USD estimate (simplified)
      const feeData = await client.getProvider().getFeeData();
      const gasCost = gas * (feeData.gasPrice || 0n);
      const ethPrice = 3000; // Would fetch from price oracle
      const usd = Number(ethers.formatEther(gasCost)) * ethPrice;
      setEstimateUSD(usd);
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  }, [client, method, params]);

  useEffect(() => {
    fetchEstimate();
  }, [fetchEstimate]);

  return { estimate, estimateUSD, isLoading, error, refetch: fetchEstimate };
}

// ============================================================
// Utilities
// ============================================================

function getNetworkName(chainId: number): string {
  const networks: Record<number, string> = {
    1: 'mainnet',
    11155111: 'sepolia',
    42161: 'arbitrum',
    10: 'optimism',
    8453: 'base',
    31337: 'localhost',
  };
  return networks[chainId] || 'unknown';
}

// Type augmentation for window.ethereum
declare global {
  interface Window {
    ethereum?: {
      request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
      on: (event: string, callback: (...args: unknown[]) => void) => void;
      removeListener: (event: string, callback: (...args: unknown[]) => void) => void;
      selectedAddress: string | null;
    };
  }
}

export default {
  PILProvider,
  usePIL,
  useContainer,
  useContainers,
  useCreateContainer,
  useConsumeContainer,
  useNullifier,
  useVerifyPolicy,
  useContainerEvents,
  useTransaction,
  useGasEstimate,
};
