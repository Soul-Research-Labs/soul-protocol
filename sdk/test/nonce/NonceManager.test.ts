import { expect } from "chai";
import { NonceManager } from "../../src/nonce/NonceManager";

describe("NonceManager", () => {
  it("serializes concurrent first-use allocation behind one RPC read", async () => {
    let releaseRpc!: () => void;
    const rpcGate = new Promise<void>((resolve) => {
      releaseRpc = resolve;
    });

    const client = {
      calls: 0,
      async getTransactionCount() {
        client.calls += 1;
        await rpcGate;
        return 100;
      },
    };

    const mgr = new NonceManager(client);
    const key = {
      chainId: 1,
      address: "0x9999999999999999999999999999999999999999" as const,
    };

    const pending = Promise.all(Array.from({ length: 5 }, () => mgr.next(key)));

    await Promise.resolve();
    expect(client.calls).to.equal(1);

    releaseRpc();

    const nonces = await pending;
    expect([...nonces].sort((a, b) => a - b)).to.deep.equal([
      100, 101, 102, 103, 104,
    ]);
    expect(client.calls).to.equal(1);
  });
});
