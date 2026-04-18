import { expect } from "chai";
import {
  execute,
  type ExecuteParams,
  type ExecuteRouter,
} from "../../src/client/execute";
import { ZaseonError, ZaseonErrorCode } from "../../src/utils/errors";

describe("execute", () => {
  it("routes fallback-coded failures through router.fallback", async () => {
    const params: ExecuteParams = {
      action: "transfer",
      amount: 1n,
      chainId: 1,
      destChainId: 10,
      recipient: "0x1111111111111111111111111111111111111111",
    };

    let transferCalls = 0;
    let fallbackCalls = 0;

    const router: ExecuteRouter = {
      deposit: {
        async deposit() {
          throw new Error("deposit should not be called");
        },
      },
      transfer: {
        async send() {
          transferCalls += 1;
          throw new ZaseonError(
            "relay timed out",
            ZaseonErrorCode.RELAY_TIMEOUT,
          );
        },
      },
      withdraw: {
        async withdraw() {
          throw new Error("withdraw should not be called");
        },
      },
      fallback: async (fallbackParams, error) => {
        fallbackCalls += 1;
        expect(fallbackParams).to.equal(params);
        expect(error.code).to.equal(ZaseonErrorCode.RELAY_TIMEOUT);
        return {
          txHash:
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          proofId: "fallback-proof",
        };
      },
    };

    const result = await execute(router, params);

    expect(result.action).to.equal("transfer");
    expect(result.txHash).to.equal(
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    expect(result.proofId).to.equal("fallback-proof");
    expect(result.attempts).to.equal(1);
    expect(transferCalls).to.equal(1);
    expect(fallbackCalls).to.equal(1);
  });
});
