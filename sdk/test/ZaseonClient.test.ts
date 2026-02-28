import { expect } from "chai";
import { ZaseonClient, type ZaseonClientOptions } from "../src/client/ZaseonClient";

/**
 * ZaseonClient tests — validates constructor, input validation, and error
 * handling. Write-path tests are skipped since they require a live chain.
 */
describe("ZaseonClient", () => {
  const makeOpts = (overrides?: Partial<ZaseonClientOptions>): ZaseonClientOptions => ({
    chainId: 31337,
    publicClient: {} as any, // Stubbed — not used in validation paths
    walletClient: undefined,
    addresses: {
      proofHub: "0x" + "11".repeat(20),
      nullifierRegistry: "0x" + "22".repeat(20),
      complianceModule: "0x" + "33".repeat(20),
    },
    ...overrides,
  });

  describe("constructor", () => {
    it("should store options", () => {
      const client = new ZaseonClient(makeOpts());
      expect(client.chainId).to.equal(31337);
      expect(client.addresses.proofHub).to.match(/^0x/);
    });
  });

  describe("registerPrivateState()", () => {
    it("should throw without walletClient", async () => {
      const client = new ZaseonClient(makeOpts());
      try {
        await client.registerPrivateState("0x" + "aa".repeat(32) as `0x${string}`, 0);
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("WalletClient required");
      }
    });
  });

  describe("bridgeProof()", () => {
    it("should throw without walletClient", async () => {
      const client = new ZaseonClient(makeOpts());
      try {
        await client.bridgeProof({
          destChain: 10,
          proof: "0x1234" as `0x${string}`,
          nullifier: "0x" + "bb".repeat(32) as `0x${string}`,
        });
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("WalletClient required");
      }
    });

    it("should throw if proofHub address is missing", async () => {
      const client = new ZaseonClient(
        makeOpts({
          walletClient: { writeContract: async () => "0xhash" } as any,
          addresses: {},
        }),
      );
      try {
        await client.bridgeProof({
          destChain: 10,
          proof: "0x" as `0x${string}`,
          nullifier: "0x" + "cc".repeat(32) as `0x${string}`,
        });
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("proofHub");
      }
    });
  });

  describe("compliance.checkKYC()", () => {
    it("should throw without compliance address", async () => {
      const client = new ZaseonClient(makeOpts({ addresses: {} }));
      try {
        await client.compliance.checkKYC("0x" + "44".repeat(20));
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Compliance module");
      }
    });
  });

  describe("isNullifierSpent()", () => {
    it("should throw without nullifierRegistry address", async () => {
      const client = new ZaseonClient(makeOpts({ addresses: {} }));
      try {
        await client.isNullifierSpent("0x" + "55".repeat(32) as `0x${string}`);
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("nullifierRegistry");
      }
    });
  });
});
