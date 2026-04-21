/**
 * Chain registry loader smoke tests.
 */
import { describe, it, expect } from "vitest";
import {
  allChains,
  chainBySlug,
  chainById,
  chainsByTier,
} from "./chainRegistry.js";

describe("chainRegistry", () => {
  it("loads known chains", () => {
    const chains = allChains();
    expect(chains.ethereum.chainId).toBe(1);
    expect(chains.arbitrum.chainId).toBe(42161);
    expect(chains.optimism.isL2).toBe(true);
  });

  it("chainBySlug throws on unknown", () => {
    expect(() => chainBySlug("does-not-exist")).toThrow();
  });

  it("chainById finds entries", () => {
    expect(chainById(8453)?.name).toBe("Base");
    expect(chainById(9999999)).toBeUndefined();
  });

  it("tier filter partitions correctly", () => {
    expect(chainsByTier("mainnet").length).toBeGreaterThanOrEqual(6);
    expect(chainsByTier("local")).toEqual([
      expect.objectContaining({ chainId: 31337 }),
    ]);
  });

  it("every L2 declares a parentChainId", () => {
    for (const c of Object.values(allChains())) {
      if (c.isL2) expect(c.parentChainId).toBeDefined();
    }
  });
});
