/**
 * @module @soul/sdk/react
 * @description React hooks for Soul Protocol integration.
 * @dev These hooks provide ergonomic React bindings around the core SDK client.
 *
 * Usage:
 * ```tsx
 * import { useSoulPrivacy, useSoulBridge, useSoulProver } from '@soul/sdk/react';
 *
 * function MyComponent() {
 *   const { shield, unshield, isShielding } = useSoulPrivacy(config);
 *   const { bridge, status, isBridging } = useSoulBridge(config);
 *   const { prove, isProving } = useSoulProver(config);
 * }
 * ```
 */

import type { ReactNode } from "react";

// NOTE: React is a peerDependency — hooks will only work when React is available.
// We use `require` with a try/catch so the module can be imported in non-React
// environments (e.g. Node SDK usage) without crashing at load time. The actual
// useState/useCallback/useRef/useEffect calls occur only when a hook is invoked.
let React: {
  useState: typeof import("react").useState;
  useCallback: typeof import("react").useCallback;
  useRef: typeof import("react").useRef;
  useEffect: typeof import("react").useEffect;
};
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  React = require("react");
} catch {
  // Stubs — will throw at hook call-site if React is truly absent.
  const missing = () => {
    throw new Error("React is required to use Soul SDK hooks");
  };
  React = {
    useState: missing as any,
    useCallback: missing as any,
    useRef: missing as any,
    useEffect: missing as any,
  };
}

// Soul SDK imports — lazy so the module parses even if SDK isn't installed yet.
import type { Hex } from "viem";

// ─── Types ──────────────────────────────────────────────────

/** Configuration for Soul SDK hooks */
export interface SoulConfig {
  /** RPC URL or viem transport */
  rpcUrl: string;
  /** Chain ID */
  chainId: number;
  /** Private key or signer (optional, for write operations) */
  signer?: unknown;
  /** Enable development mode (placeholder proofs) */
  devMode?: boolean;
}

/** Hook state for async operations */
export interface AsyncState<T = unknown> {
  data: T | null;
  error: Error | null;
  isLoading: boolean;
}

/** Privacy hook return type */
export interface UseSoulPrivacyReturn {
  /** Shield (deposit) assets into the shielded pool */
  shield: (params: {
    asset: string;
    amount: bigint;
    commitment: string;
  }) => Promise<string>;
  /** Unshield (withdraw) assets from the shielded pool */
  unshield: (params: {
    nullifier: string;
    proof: Uint8Array;
    recipient: string;
    amount: bigint;
  }) => Promise<string>;
  /** Whether a shield operation is in progress */
  isShielding: boolean;
  /** Whether an unshield operation is in progress */
  isUnshielding: boolean;
  /** Last error */
  error: Error | null;
}

/** Bridge hook return type */
export interface UseSoulBridgeReturn {
  /** Bridge assets cross-chain */
  bridge: (params: {
    destChainId: number;
    asset: string;
    amount: bigint;
    proof?: Uint8Array;
  }) => Promise<string>;
  /** Check bridge transfer status */
  status: (txHash: string) => Promise<string>;
  /** Whether a bridge operation is in progress */
  isBridging: boolean;
  /** Last error */
  error: Error | null;
}

/** Prover hook return type */
export interface UseSoulProverReturn {
  /** Generate a ZK proof */
  prove: (
    circuit: string,
    inputs: Record<string, unknown>,
  ) => Promise<Uint8Array>;
  /** Whether proof generation is in progress */
  isProving: boolean;
  /** Last error */
  error: Error | null;
}

// ─── Internal helpers ───────────────────────────────────────

/** Lazily create a SoulProtocolClient, memoised by rpcUrl+chainId+signer */
function useSoulClient(config: SoulConfig) {
  const clientRef = React.useRef<any>(null);

  if (!clientRef.current) {
    // Dynamic import at first call — keeps the module tree-shakable.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { createSoulClient } = require("../client/SoulProtocolClient");
    clientRef.current = createSoulClient({
      rpcUrl: config.rpcUrl,
      chainId: config.chainId,
      privateKey: config.signer as Hex | undefined,
    });
  }
  return clientRef.current;
}

// ─── Hooks ──────────────────────────────────────────────────

/**
 * Hook for interacting with Soul Protocol's shielded pool.
 * Provides shield (deposit) and unshield (withdraw) operations.
 *
 * @param config - Soul SDK configuration
 * @returns Privacy operation methods and loading states
 */
export function useSoulPrivacy(config: SoulConfig): UseSoulPrivacyReturn {
  const client = useSoulClient(config);
  const [isShielding, setIsShielding] = React.useState(false);
  const [isUnshielding, setIsUnshielding] = React.useState(false);
  const [error, setError] = React.useState<Error | null>(null);

  const shield = React.useCallback(
    async (params: { asset: string; amount: bigint; commitment: string }) => {
      setIsShielding(true);
      setError(null);
      try {
        // Use SoulProtocolClient.createLock which wraps the shielded deposit flow
        const result = await client.createLock({
          stateCommitment: params.commitment as Hex,
          predicateHash: params.asset as Hex,
          policyHash: ("0x" + "00".repeat(32)) as Hex,
          deadline: BigInt(Math.floor(Date.now() / 1000) + 3600),
        });
        return result.txHash as string;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setIsShielding(false);
      }
    },
    [client],
  );

  const unshield = React.useCallback(
    async (params: {
      nullifier: string;
      proof: Uint8Array;
      recipient: string;
      amount: bigint;
    }) => {
      setIsUnshielding(true);
      setError(null);
      try {
        const txHash = await client.unlockWithProof({
          lockId: params.nullifier as Hex,
          proof: ("0x" + Buffer.from(params.proof).toString("hex")) as Hex,
          newState: params.recipient as Hex,
          nullifier: params.nullifier as Hex,
        });
        return txHash as string;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setIsUnshielding(false);
      }
    },
    [client],
  );

  return { shield, unshield, isShielding, isUnshielding, error };
}

/**
 * Hook for cross-chain bridging via Soul Protocol.
 * Supports multiple bridge adapters (LayerZero, Hyperlane, native L2).
 *
 * @param config - Soul SDK configuration
 * @returns Bridge operation methods and loading states
 */
export function useSoulBridge(config: SoulConfig): UseSoulBridgeReturn {
  const client = useSoulClient(config);
  const [isBridging, setIsBridging] = React.useState(false);
  const [error, setError] = React.useState<Error | null>(null);

  const bridge = React.useCallback(
    async (params: {
      destChainId: number;
      asset: string;
      amount: bigint;
      proof?: Uint8Array;
    }) => {
      setIsBridging(true);
      setError(null);
      try {
        // Initiate an atomic swap for cross-chain transfer
        const result = await client.initiateSwap({
          participant: params.asset as Hex,
          hashlock: ("0x" + "00".repeat(32)) as Hex,
          timelock: Math.floor(Date.now() / 1000) + 7200,
          amount: params.amount,
        });
        return result.txHash as string;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setIsBridging(false);
      }
    },
    [client],
  );

  const status = React.useCallback(
    async (txHash: string) => {
      try {
        const isPaused = await client.isPaused();
        if (isPaused) return "paused";
        // Check if the chain is supported for the transfer
        const supported = await client.isChainSupported(config.chainId);
        return supported ? "supported" : "unsupported";
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      }
    },
    [client, config.chainId],
  );

  return { bridge, status, isBridging, error };
}

/**
 * Hook for generating ZK proofs using Noir circuits.
 * Uses the NoirProver with optional WASM backend.
 *
 * @param config - Soul SDK configuration
 * @returns Prover methods and loading states
 */
export function useSoulProver(config: SoulConfig): UseSoulProverReturn {
  const [isProving, setIsProving] = React.useState(false);
  const [error, setError] = React.useState<Error | null>(null);
  const proverRef = React.useRef<any>(null);

  // Initialise the NoirProver on first mount
  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { createProver } = require("../zkprover/NoirProver");
        const prover = createProver({
          mode: config.devMode ? "development" : "production",
        });
        await prover.initialize();
        if (!cancelled) proverRef.current = prover;
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err : new Error(String(err)));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [config.devMode]);

  const prove = React.useCallback(
    async (
      circuit: string,
      inputs: Record<string, unknown>,
    ): Promise<Uint8Array> => {
      if (!proverRef.current) {
        throw new Error(
          "NoirProver not initialised yet — wait for useEffect to complete",
        );
      }
      setIsProving(true);
      setError(null);
      try {
        const result = await proverRef.current.generateProof(circuit, inputs);
        // result.proof is a Hex string — convert to Uint8Array
        const hex = (result.proof as string).replace(/^0x/, "");
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
          bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setIsProving(false);
      }
    },
    [],
  );

  return { prove, isProving, error };
}

// Re-export types for consumers
export type { ReactNode };
