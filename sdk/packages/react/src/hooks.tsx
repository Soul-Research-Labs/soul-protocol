import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Soulv2ClientFactory,
  Soulv2Config,
  Container,
  ContainerCreationParams,
  DisclosurePolicy,
  Domain,
} from "../../../src/index";
import {
  createPublicClient,
  createWalletClient,
  custom,
  formatEther,
  Hex,
  Address,
  zeroAddress,
  PublicClient,
  WalletClient,
} from "viem";

export type ContainerStatus = "active" | "consumed" | "expired";

// ============================================================
// Context & Provider
// ============================================================

import React, { createContext, useContext, ReactNode } from "react";

interface SoulContextValue {
  client: Soulv2ClientFactory | null;
  isConnected: boolean;
  isLoading: boolean;
  error: Error | null;
  address: Address | null;
  chainId: number | null;
  connect: () => Promise<void>;
  disconnect: () => void;
}

const SoulContext = createContext<SoulContextValue | null>(null);

interface SoulProviderProps {
  children: ReactNode;
  config?: Partial<Soulv2Config>;
}

function SoulProvider({ children, config }: SoulProviderProps) {
  const [client, setClient] = useState<Soulv2ClientFactory | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [address, setAddress] = useState<Address | null>(null);
  const [chainId, setChainId] = useState<number | null>(null);

  const connect = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      if (typeof window === "undefined" || !window.ethereum) {
        throw new Error("No wallet detected");
      }

      const publicClient = createPublicClient({
        transport: custom(window.ethereum),
      });

      const walletClient = createWalletClient({
        transport: custom(window.ethereum),
      });

      const [account] = await walletClient.requestAddresses();
      const id = await publicClient.getChainId();

      const soulClient = new Soulv2ClientFactory(
        config as Soulv2Config,
        publicClient as any,
        walletClient as any,
      );

      setClient(soulClient);
      setAddress(account);
      setChainId(id);
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
    if (typeof window === "undefined" || !window.ethereum) return;

    const handleAccountsChanged = (accounts: string[]) => {
      if (accounts.length === 0) {
        disconnect();
      } else {
        setAddress(accounts[0] as Address);
      }
    };

    const handleChainChanged = (chainIdHex: string) => {
      setChainId(parseInt(chainIdHex, 16));
      // Reconnect with new chain
      connect();
    };

    (window.ethereum as any).on("accountsChanged", handleAccountsChanged);
    (window.ethereum as any).on("chainChanged", handleChainChanged);

    return () => {
      (window.ethereum as any).removeListener(
        "accountsChanged",
        handleAccountsChanged,
      );
      (window.ethereum as any).removeListener(
        "chainChanged",
        handleChainChanged,
      );
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
    [
      client,
      isConnected,
      isLoading,
      error,
      address,
      chainId,
      connect,
      disconnect,
    ],
  );

  return <SoulContext.Provider value={value}>{children}</SoulContext.Provider>;
}

function useSoul() {
  const context = useContext(SoulContext);
  if (!context) {
    throw new Error("useSoul must be used within a SoulProvider");
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

function useContainer(
  containerId: string | undefined,
  options: UseContainerOptions = {},
): UseContainerResult {
  const { client } = useSoul();
  const { pollInterval, enabled = true } = options;

  const [container, setContainer] = useState<Container | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchContainer = useCallback(async () => {
    if (!client || !containerId || !enabled) return;

    setIsLoading(true);
    setError(null);

    try {
      const data = await client.getPC3().getContainer(containerId as Hex);
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

function useContainers(
  options: UseContainersOptions = {},
): UseContainersResult {
  const { client } = useSoul();
  const { creator, status, limit = 20, offset = 0 } = options;

  const [containers, setContainers] = useState<Container[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [hasMore, setHasMore] = useState(true);
  const [currentOffset, setCurrentOffset] = useState(offset);

  const fetchContainers = useCallback(
    async (reset = false) => {
      if (!client) return;

      setIsLoading(true);
      setError(null);

      try {
        const fetchOffset = reset ? 0 : currentOffset;
        const containerIds = await client
          .getPC3()
          .getContainerIds(fetchOffset, limit);
        const data = (
          await Promise.all(
            containerIds.map((id) => client.getPC3().getContainer(id)),
          )
        ).filter((c): c is Container => c !== null);

        if (reset) {
          setContainers(data);
        } else {
          setContainers((prev) => [...prev, ...data]);
        }
        setCurrentOffset((prev) => prev + limit);

        setHasMore(data.length === limit);
      } catch (err) {
        setError(err as Error);
      } finally {
        setIsLoading(false);
      }
    },
    [client, creator, status, limit, currentOffset],
  );

  useEffect(() => {
    fetchContainers(true);
  }, [client, creator, status, fetchContainers]);

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

function useCreateContainer(): UseCreateContainerResult {
  const { client } = useSoul();

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [containerId, setContainerId] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);

  const createContainer = useCallback(
    async (params: CreateContainerParams) => {
      if (!client) throw new Error("Not connected");

      setIsLoading(true);
      setError(null);

      try {
        const { containerId, txHash } = await client
          .getPC3()
          .createContainer(params as any);
        setContainerId(containerId);
        setTxHash(txHash);
        return containerId as Hex;
      } catch (err) {
        setError(err as Error);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [client],
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

function useConsumeContainer(): UseConsumeContainerResult {
  const { client } = useSoul();

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);

  const consumeContainer = useCallback(
    async (containerId: string) => {
      if (!client) throw new Error("Not connected");

      setIsLoading(true);
      setError(null);

      try {
        const hash = await (client.getPC3() as any).consumeContainer(
          containerId as Hex,
        );
        const txHash =
          typeof hash === "string" &&
          hash.startsWith("0x") &&
          hash.length === 66
            ? (hash as Hex)
            : null;
        setTxHash(txHash);
        return txHash ?? ("0x" as Hex);
      } catch (err) {
        setError(err as Error);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [client],
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

function useNullifier(
  nullifier: string | undefined,
  domain: string,
): UseNullifierResult {
  const { client } = useSoul();

  const [isSpent, setIsSpent] = useState<boolean | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchNullifier = useCallback(async () => {
    if (!client || !nullifier) return;

    setIsLoading(true);
    setError(null);

    try {
      const [exists] = await client
        .getCDNA()
        .batchCheckNullifiers([nullifier as Hex]);
      setIsSpent(exists);
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

function useVerifyPolicy(): UseVerifyPolicyResult {
  const { client } = useSoul();

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [result, setResult] = useState<boolean | null>(null);

  const verify = useCallback(
    async (proof: Uint8Array, policyId: string) => {
      if (!client) throw new Error("Not connected");

      setIsLoading(true);
      setError(null);

      try {
        const isValid = await client.getPBP().verifyBoundProof({
          proof: proof as any,
          policyHash: policyId as Hex,
          domainSeparator: zeroAddress,
          publicInputs: [],
          expiresAt: 0,
        });
        setResult(isValid);
        return isValid;
      } catch (err) {
        setError(err as Error);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [client],
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

function useContainerEvents(
  event: "ContainerCreated" | "ContainerConsumed",
  callback: ContainerEventCallback,
) {
  const { client } = useSoul();

  useEffect(() => {
    if (!client) return;

    const pc3 = client.getPC3();
    const subscriber = (pc3 as any).on(event, callback);

    return () => {
      if (subscriber && subscriber.unsubscribe) subscriber.unsubscribe();
    };
  }, [client, event, callback]);
}

// ============================================================
// Transaction Hooks
// ============================================================

interface UseTransactionResult {
  status: "idle" | "pending" | "success" | "error";
  txHash: string | null;
  error: Error | null;
  confirmations: number;
  reset: () => void;
}

function useTransaction(txHash: string | null): UseTransactionResult {
  const { client } = useSoul();

  const [status, setStatus] = useState<
    "idle" | "pending" | "success" | "error"
  >("idle");
  const [error, setError] = useState<Error | null>(null);
  const [confirmations, setConfirmations] = useState(0);

  useEffect(() => {
    if (!client || !txHash) {
      setStatus("idle");
      return;
    }

    setStatus("pending");

    const checkTransaction = async () => {
      try {
        const receipt = await client
          .getPublicClient()
          .waitForTransactionReceipt({ hash: txHash as Hex });
        if (receipt) {
          const currentBlock = await client.getPublicClient().getBlockNumber();
          const confs = Number(currentBlock - BigInt(receipt.blockNumber) + 1n);
          setConfirmations(confs);

          if (receipt.status === "success") {
            setStatus("success");
          } else {
            setStatus("error");
            setError(new Error("Transaction failed"));
          }
        }
      } catch (err) {
        setStatus("error");
        setError(err as Error);
      }
    };

    checkTransaction();
  }, [client, txHash]);

  const reset = useCallback(() => {
    setStatus("idle");
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

function useGasEstimate(
  method: string,
  params: unknown[],
): UseGasEstimateResult {
  const { client } = useSoul();

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

      // Get gas price for USD estimate (simplified)
      const gasPrice = await client.getPublicClient().getGasPrice();
      const gasCost = gas * gasPrice;
      const ethPrice = 3000; // Would fetch from price oracle
      const usd = Number(formatEther(BigInt(gasCost))) * ethPrice;
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
    1: "mainnet",
    11155111: "sepolia",
    42161: "arbitrum",
    10: "optimism",
    8453: "base",
    31337: "localhost",
  };
  return networks[chainId] || "unknown";
}

// Type augmentation for window.ethereum
declare global {
  interface Window {
    ethereum?: {
      request: (args: {
        method: string;
        params?: unknown[];
      }) => Promise<unknown>;
      on: (event: string, callback: (...args: unknown[]) => void) => void;
      removeListener: (
        event: string,
        callback: (...args: unknown[]) => void,
      ) => void;
      selectedAddress: string | null;
    };
  }
}

export {
  SoulProvider,
  useSoul,
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
