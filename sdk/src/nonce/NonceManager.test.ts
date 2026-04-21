/**
 * NonceManager tests.
 *
 * Run via `npm test` or:
 *   node --test test/NonceManager.test.mjs
 */
import { NonceManager } from "./NonceManager";

interface StubClient {
  getTransactionCount: (args: {
    address: `0x${string}`;
    blockTag?: "pending" | "latest";
  }) => Promise<number>;
  count: number;
  calls: number;
}

function stub(initial: number, delayMs = 0): StubClient {
  const c: StubClient = {
    count: initial,
    calls: 0,
    getTransactionCount: async () => {
      c.calls += 1;
      if (delayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
      return c.count;
    },
  };
  return c;
}

async function test_sequentialAcquire() {
  const client = stub(5);
  const mgr = new NonceManager(client);
  const key = {
    chainId: 1,
    address: "0x1111111111111111111111111111111111111111" as const,
  };
  const a = await mgr.next(key);
  const b = await mgr.next(key);
  const c = await mgr.next(key);
  if (a !== 5 || b !== 6 || c !== 7)
    throw new Error(`bad sequence ${a}/${b}/${c}`);
  if (client.calls !== 1)
    throw new Error(`expected 1 RPC call, got ${client.calls}`);
}

async function test_rollback() {
  const client = stub(10);
  const mgr = new NonceManager(client);
  const key = {
    chainId: 1,
    address: "0x2222222222222222222222222222222222222222" as const,
  };
  const a = await mgr.next(key); // 10
  mgr.rollback(key, a);
  const b = await mgr.next(key); // 10 again
  if (a !== b) throw new Error(`rollback failed: ${a} vs ${b}`);
}

async function test_reset() {
  const client = stub(20);
  const mgr = new NonceManager(client);
  const key = {
    chainId: 1,
    address: "0x3333333333333333333333333333333333333333" as const,
  };
  await mgr.next(key);
  client.count = 42;
  await mgr.reset(key);
  const n = await mgr.next(key);
  if (n !== 42) throw new Error(`reset failed, got ${n}`);
}

async function test_concurrencyIsSerialized() {
  const client = stub(100, 5);
  const mgr = new NonceManager(client);
  const key = {
    chainId: 1,
    address: "0x4444444444444444444444444444444444444444" as const,
  };
  const nonces = await Promise.all(
    Array.from({ length: 10 }, () => mgr.next(key)),
  );
  const sorted = [...nonces].sort((a, b) => a - b);
  for (let i = 0; i < sorted.length; ++i) {
    if (sorted[i] !== 100 + i)
      throw new Error(`non-sequential: ${sorted.join(",")}`);
  }
  if (client.calls !== 1)
    throw new Error(`expected 1 RPC call, got ${client.calls}`);
}

async function test_concurrentFirstUseSharesInitialization() {
  const client = stub(7, 5);
  const mgr = new NonceManager(client);
  const key = {
    chainId: 10,
    address: "0x5555555555555555555555555555555555555555" as const,
  };

  const [a, b] = await Promise.all([mgr.next(key), mgr.next(key)]);
  const sorted = [a, b].sort((left, right) => left - right);

  if (sorted[0] !== 7 || sorted[1] !== 8)
    throw new Error(`unexpected nonces: ${sorted.join(",")}`);
  if (client.calls !== 1)
    throw new Error(`expected shared init, got ${client.calls} RPC calls`);
}

export async function runAll(): Promise<void> {
  await test_sequentialAcquire();
  await test_rollback();
  await test_reset();
  await test_concurrencyIsSerialized();
  await test_concurrentFirstUseSharesInitialization();
}

// CLI entry for `node dist/nonce/NonceManager.test.js`
if (typeof require !== "undefined" && require.main === module) {
  runAll()
    .then(() => console.log("NonceManager: all tests passed"))
    .catch((e) => {
      console.error(e);
      process.exitCode = 1;
    });
}
