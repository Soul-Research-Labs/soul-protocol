/**
 * Chain registry loader.
 *
 * Single source of truth for chain metadata. Integrators add a new L2 by
 * dropping an entry into `chains.json` — no code changes required.
 */
import chainsData from "./chains.json";

export type ChainTier = "mainnet" | "testnet" | "staging" | "local";
export type Finality = "instant" | "safe" | "finalized";

export interface ChainEntry {
  chainId: number;
  name: string;
  nativeToken: string;
  rpcUrlEnv: string;
  explorer: string;
  blockTime: number;
  finality: Finality;
  isL2: boolean;
  parentChainId?: number;
  tier: ChainTier;
  bridgeAdapter?: string;
  addresses: Record<string, `0x${string}`>;
}

type Registry = { chains: Record<string, ChainEntry> };

const REGISTRY = chainsData as unknown as Registry;

/** All known chains keyed by slug (`ethereum`, `arbitrum`, ...). */
export function allChains(): Record<string, ChainEntry> {
  return REGISTRY.chains;
}

/** Lookup a chain entry by slug. Throws if unknown. */
export function chainBySlug(slug: string): ChainEntry {
  const c = REGISTRY.chains[slug];
  if (!c) throw new Error(`Unknown chain slug: ${slug}`);
  return c;
}

/** Lookup by numeric chain id. Returns undefined if unknown. */
export function chainById(chainId: number): ChainEntry | undefined {
  for (const c of Object.values(REGISTRY.chains)) {
    if (c.chainId === chainId) return c;
  }
  return undefined;
}

/** All chains of a given tier. */
export function chainsByTier(tier: ChainTier): ChainEntry[] {
  return Object.values(REGISTRY.chains).filter((c) => c.tier === tier);
}

/** Resolve the RPC URL for a chain from its env-var binding. */
export function rpcUrlFor(slug: string): string | undefined {
  const c = chainBySlug(slug);
  if (typeof process === "undefined" || !process.env) return undefined;
  return process.env[c.rpcUrlEnv];
}
