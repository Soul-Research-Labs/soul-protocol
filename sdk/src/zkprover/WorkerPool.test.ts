import { describe, it, expect, vi } from "vitest";
import {
  WorkerPool,
  type WorkerHandle,
  type WorkerFactory,
} from "./WorkerPool.js";

class FakeWorker implements WorkerHandle {
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  private timer?: ReturnType<typeof setTimeout>;
  public terminated = false;

  postMessage(msg: unknown): void {
    const m = msg as { id: number; payload: unknown };
    this.timer = setTimeout(() => {
      this.onmessage?.({ data: { id: m.id, result: { echo: m.payload } } });
    }, 5);
  }
  async terminate(): Promise<number> {
    if (this.timer) clearTimeout(this.timer);
    this.terminated = true;
    return 0;
  }
}

function makeFactory(created: FakeWorker[]): WorkerFactory {
  return {
    create: () => {
      const w = new FakeWorker();
      created.push(w);
      return w;
    },
  };
}

describe("WorkerPool", () => {
  it("submits and resolves a single job", async () => {
    const created: FakeWorker[] = [];
    const pool = new WorkerPool(makeFactory(created), { maxWorkers: 2 });
    const r = await pool.submit({ x: 1 });
    expect(r).toEqual({ echo: { x: 1 } });
    await pool.close();
    expect(created.length).toBe(1);
  });

  it("caps worker creation at maxWorkers", async () => {
    const created: FakeWorker[] = [];
    const pool = new WorkerPool(makeFactory(created), { maxWorkers: 2 });
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) => pool.submit({ i })),
    );
    expect(results).toHaveLength(10);
    expect(created.length).toBeLessThanOrEqual(2);
    await pool.close();
  });

  it("fails jobs submitted after close", async () => {
    const pool = new WorkerPool(makeFactory([]), { maxWorkers: 1 });
    await pool.close();
    await expect(pool.submit({})).rejects.toThrow(/closed/);
  });

  it("times out long-running jobs", async () => {
    const factory: WorkerFactory = {
      create: () => ({
        onmessage: null,
        onerror: null,
        postMessage: () => {},
        terminate: () => Promise.resolve(0),
      }),
    };
    const pool = new WorkerPool(factory, { maxWorkers: 1, timeoutMs: 20 });
    await expect(pool.submit({})).rejects.toThrow(/timed out/);
    await pool.close();
  });
});
