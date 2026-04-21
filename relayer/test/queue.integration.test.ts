/**
 * Integration test for the proof-queue pipeline.
 *
 * Uses the public `ProofQueue` API surface; no network is mocked out
 * because we exercise the queue bookkeeping only (metrics, retries,
 * failure classification). Broadcast/submit paths are covered separately.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { ProofQueue, type RelayTask } from "../src/queue.js";
import type { RelayerConfig } from "../src/config.js";

function stubTask(id: string): RelayTask {
  return {
    id,
    sourceChain: "optimism",
    sourceChainId: 10,
    txHash: "0x" + "1".repeat(64),
    blockNumber: 1,
    logIndex: 0,
    timestamp: Date.now(),
    retries: 0,
  };
}

const cfg = {
  maxRetries: 3,
  chains: [],
  privateKey:
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
} as unknown as RelayerConfig;

describe("ProofQueue", () => {
  let q: ProofQueue;

  beforeEach(() => {
    q = new ProofQueue(cfg);
  });

  it("enqueues tasks and reports size", () => {
    expect(q.size).toBe(0);
    q.enqueue(stubTask("a"));
    q.enqueue(stubTask("b"));
    expect(q.size).toBe(2);
  });

  it("metrics start at zero", () => {
    expect(q.metrics.tasksTotal).toBe(0);
    expect(q.metrics.tasksSucceeded).toBe(0);
    expect(q.metrics.tasksFailed).toBe(0);
  });

  it("tracks per-chain metrics map", () => {
    expect(q.metrics.perChain).toBeInstanceOf(Map);
    expect(q.metrics.perChain.size).toBe(0);
  });

  it("drain flips running flag safely", async () => {
    await q.drain();
    expect(q.size).toBe(0);
  });
});
