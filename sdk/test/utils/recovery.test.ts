import { expect } from "chai";
import { ZaseonError, ZaseonErrorCode } from "../../src/utils/errors";
import { withRecovery } from "../../src/utils/recovery";

describe("withRecovery", () => {
  it("uses the caller fallback hook for fallback-coded errors", async () => {
    let fallbackCalls = 0;

    const result = await withRecovery(
      async () => {
        throw new ZaseonError("relay timed out", ZaseonErrorCode.RELAY_TIMEOUT);
      },
      {
        onFallback: async (error) => {
          fallbackCalls += 1;
          expect(error.code).to.equal(ZaseonErrorCode.RELAY_TIMEOUT);
          return "rerouted";
        },
      },
    );

    expect(result).to.equal("rerouted");
    expect(fallbackCalls).to.equal(1);
  });

  it("does not retry fallback-coded errors when no fallback exists", async () => {
    let attempts = 0;

    try {
      await withRecovery(async () => {
        attempts += 1;
        throw new ZaseonError("relay timed out", ZaseonErrorCode.RELAY_TIMEOUT);
      });
      throw new Error("expected recovery failure");
    } catch (error) {
      expect(error).to.be.instanceOf(ZaseonError);
      expect((error as ZaseonError).code).to.equal(
        ZaseonErrorCode.RELAY_TIMEOUT,
      );
      expect(attempts).to.equal(1);
    }
  });
});
