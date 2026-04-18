import { expect } from "chai";
import {
  WorkerPool,
  type WorkerFactory,
  type WorkerHandle,
} from "../../src/zkprover/WorkerPool";

class StrayMessageWorker implements WorkerHandle {
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  postMessage(msg: unknown): void {
    const job = msg as { id: number };
    setTimeout(() => {
      this.onmessage?.({ data: { id: job.id + 1000, result: "stale" } });
    }, 5);
  }

  terminate(): Promise<number> {
    return Promise.resolve(0);
  }
}

describe("WorkerPool", () => {
  it("still times out when a worker emits a stray reply", async () => {
    const factory: WorkerFactory = {
      create: () => new StrayMessageWorker(),
    };
    const pool = new WorkerPool(factory, { maxWorkers: 1, timeoutMs: 20 });

    try {
      await Promise.race([
        pool.submit({ task: "proof" }),
        new Promise((_, reject) => {
          setTimeout(() => reject(new Error("hung")), 100);
        }),
      ]);
      throw new Error("expected rejection");
    } catch (error) {
      expect((error as Error).message).to.match(/timed out/);
    } finally {
      await pool.close();
    }
  });
});
