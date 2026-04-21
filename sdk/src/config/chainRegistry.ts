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

/**
 * Validate that an Ethereum address is syntactically correct AND passes
 * EIP-55 mixed-case checksum. Rejects lowercase / uppercase-only addresses
 * that happen to parse as hex — those may have been corrupted by a
 * checksum-losing copy-paste and should never be loaded from a config
 * file used for on-chain routing.
 *
 * Pure-TS implementation (keccak via a small embedded helper) to avoid
 * pulling viem/ethers into this module's import graph.
 */
export function isChecksumAddress(addr: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return false;
  // All-lower or all-upper (case-insensitive) are only acceptable if the
  // checksum is *intentionally* waived. For a registry that routes value
  // we require a mixed-case EIP-55 address.
  const lower = addr.toLowerCase();
  const upper = addr.toUpperCase();
  if (addr === lower || addr === upper) return false;
  return eip55Checksum(lower) === addr;
}

/** Deterministic EIP-55 checksum using a lightweight keccak256. */
function eip55Checksum(lowerAddr: string): string {
  const body = lowerAddr.slice(2);
  const hash = keccak256Hex(body);
  let out = "0x";
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c >= "0" && c <= "9") {
      out += c;
    } else {
      // If the i-th nibble of the hash is >= 8, uppercase.
      const nibble = parseInt(hash[i], 16);
      out += nibble >= 8 ? c.toUpperCase() : c;
    }
  }
  return out;
}

// Minimal keccak256 implementation operating on an ASCII string and
// returning a 64-char lowercase hex string. Adapted from the public-
// domain SHA3 reference.
function keccak256Hex(asciiHex: string): string {
  const bytes = new Uint8Array(asciiHex.length);
  for (let i = 0; i < asciiHex.length; i++) {
    bytes[i] = asciiHex.charCodeAt(i);
  }
  return keccak256(bytes);
}

// ---- tiny keccak256 (public-domain port) --------------------------------
// Intentionally local: avoids SDK consumers paying the cost of a full
// crypto dep just for a one-shot checksum validator.
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
  0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
  0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
  0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROTC = [
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18,
  39, 61, 20, 44,
];
const PI = [
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14,
  22, 9, 6, 1,
];
const MASK64 = (1n << 64n) - 1n;
function rotl64(x: bigint, n: number): bigint {
  const s = BigInt(n);
  return (((x << s) | (x >> (64n - s))) & MASK64);
}
function keccakF(st: BigUint64Array): void {
  for (let round = 0; round < 24; round++) {
    const bc = new BigUint64Array(5);
    for (let i = 0; i < 5; i++) {
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    }
    for (let i = 0; i < 5; i++) {
      const t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
      for (let j = 0; j < 25; j += 5) st[j + i] = (st[j + i] ^ t) & MASK64;
    }
    let t = st[1];
    for (let i = 0; i < 24; i++) {
      const j = PI[i];
      const tmp = st[j];
      st[j] = rotl64(t, ROTC[i]);
      t = tmp;
    }
    for (let j = 0; j < 25; j += 5) {
      const a0 = st[j], a1 = st[j + 1], a2 = st[j + 2], a3 = st[j + 3], a4 = st[j + 4];
      st[j] = (a0 ^ (~a1 & a2)) & MASK64;
      st[j + 1] = (a1 ^ (~a2 & a3)) & MASK64;
      st[j + 2] = (a2 ^ (~a3 & a4)) & MASK64;
      st[j + 3] = (a3 ^ (~a4 & a0)) & MASK64;
      st[j + 4] = (a4 ^ (~a0 & a1)) & MASK64;
    }
    st[0] = (st[0] ^ RC[round]) & MASK64;
  }
}
function keccak256(data: Uint8Array): string {
  const rate = 136;
  const st = new BigUint64Array(25);
  const buf = new Uint8Array(rate);
  buf.set(data.subarray(0, Math.min(data.length, rate)));
  let off = 0;
  let rem = data.length;
  while (rem >= rate) {
    for (let i = 0; i < rate / 8; i++) {
      let w = 0n;
      for (let b = 0; b < 8; b++) {
        w |= BigInt(data[off + i * 8 + b]) << BigInt(8 * b);
      }
      st[i] ^= w;
    }
    keccakF(st);
    off += rate;
    rem -= rate;
  }
  const tail = new Uint8Array(rate);
  tail.set(data.subarray(off));
  tail[rem] = 0x01;
  tail[rate - 1] |= 0x80;
  for (let i = 0; i < rate / 8; i++) {
    let w = 0n;
    for (let b = 0; b < 8; b++) w |= BigInt(tail[i * 8 + b]) << BigInt(8 * b);
    st[i] ^= w;
  }
  keccakF(st);
  let out = "";
  for (let i = 0; i < 4; i++) {
    const w = st[i];
    for (let b = 0; b < 8; b++) {
      const byte = Number((w >> BigInt(8 * b)) & 0xffn);
      out += byte.toString(16).padStart(2, "0");
    }
  }
  return out;
}
// -------------------------------------------------------------------------

/**
 * Validate every address in the registry. Call once at SDK init to
 * surface any hand-edited `chains.json` entry that lost its EIP-55
 * checksum — a common way for typos and redirects to slip in.
 */
export function validateRegistryAddresses(): void {
  for (const [slug, entry] of Object.entries(REGISTRY.chains)) {
    for (const [name, addr] of Object.entries(entry.addresses)) {
      if (!isChecksumAddress(addr as string)) {
        throw new Error(
          `chainRegistry: ${slug}.${name} has invalid EIP-55 checksum: ${addr}`,
        );
      }
    }
  }
}

/**
 * Probe an RPC endpoint and confirm its reported chain id matches
 * the registry entry. Throws on mismatch — callers should treat
 * mismatch as an abort condition, not a warning.
 */
export async function assertRpcChainMatches(
  slug: string,
  fetchFn: typeof fetch = fetch,
): Promise<void> {
  const entry = chainBySlug(slug);
  const url = rpcUrlFor(slug);
  if (!url) throw new Error(`chainRegistry: missing RPC URL for ${slug}`);
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_chainId",
      params: [],
    }),
  });
  if (!res.ok) {
    throw new Error(`chainRegistry: RPC probe failed (${res.status}) for ${slug}`);
  }
  const body = (await res.json()) as { result?: string };
  if (!body.result) {
    throw new Error(`chainRegistry: RPC probe returned no chainId for ${slug}`);
  }
  const reported = Number.parseInt(body.result, 16);
  if (reported !== entry.chainId) {
    throw new Error(
      `chainRegistry: RPC for ${slug} reports chainId ${reported}, expected ${entry.chainId}`,
    );
  }
}
