import { expect } from "chai";
import { type Hex, type Address } from "viem";
import {
  UniswapV3AdapterClient,
  UNISWAP_ADAPTER_ABI,
  type AdapterConfig,
} from "../src/adapters/UniswapV3AdapterClient";

// ============================================================
// Helpers
// ============================================================

const MOCK_ADAPTER = ("0x" + "aa".repeat(20)) as Address;
const MOCK_ROUTER = ("0x" + "bb".repeat(20)) as Address;
const MOCK_QUOTER = ("0x" + "cc".repeat(20)) as Address;
const MOCK_FACTORY = ("0x" + "dd".repeat(20)) as Address;
const MOCK_WETH = ("0x" + "ee".repeat(20)) as Address;
const MOCK_USDC = ("0x" + "ff".repeat(20)) as Address;
const MOCK_VAULT = ("0x" + "11".repeat(20)) as Address;

function makeClient(opts?: {
  withWallet?: boolean;
  readStubs?: Record<string, (...args: any[]) => any>;
  writeStub?: (...args: any[]) => Promise<Hex>;
}) {
  const readStubs = opts?.readStubs ?? {};
  const publicClient = {
    readContract: async (call: any) => {
      const fn = call.functionName;
      if (readStubs[fn]) return readStubs[fn](call);
      throw new Error(`No stub for readContract: ${fn}`);
    },
  } as any;

  const walletClient = opts?.withWallet
    ? {
        chain: null,
        account: { address: "0x" + "99".repeat(20) },
        writeContract: opts.writeStub ?? (async () => "0xdeadbeef" as Hex),
      }
    : undefined;

  return new UniswapV3AdapterClient(
    MOCK_ADAPTER,
    publicClient,
    walletClient as any,
  );
}

// ============================================================
// Tests
// ============================================================

describe("UniswapV3AdapterClient", () => {
  // ================================================================
  // Constructor
  // ================================================================

  describe("constructor", () => {
    it("stores the adapter address", () => {
      const client = makeClient();
      expect(client.address).to.equal(MOCK_ADAPTER);
    });
  });

  // ================================================================
  // Read Operations
  // ================================================================

  describe("getQuote", () => {
    it("returns estimated output amount", async () => {
      const client = makeClient({
        readStubs: {
          getQuote: () => BigInt("250000000"), // 250 USDC
        },
      });
      const quote = await client.getQuote(
        MOCK_WETH,
        MOCK_USDC,
        BigInt(10n ** 18n),
      );
      expect(quote).to.equal(BigInt("250000000"));
    });
  });

  describe("isSwapSupported", () => {
    it("returns true for supported pair", async () => {
      const client = makeClient({
        readStubs: {
          isSwapSupported: () => true,
        },
      });
      const supported = await client.isSwapSupported(MOCK_WETH, MOCK_USDC);
      expect(supported).to.be.true;
    });

    it("returns false for unsupported pair", async () => {
      const client = makeClient({
        readStubs: {
          isSwapSupported: () => false,
        },
      });
      const supported = await client.isSwapSupported(
        MOCK_WETH,
        "0x0000000000000000000000000000000000000001" as Address,
      );
      expect(supported).to.be.false;
    });
  });

  describe("isAuthorizedCaller", () => {
    it("returns authorization status", async () => {
      const client = makeClient({
        readStubs: {
          authorizedCallers: (call: any) => call.args[0] === MOCK_VAULT,
        },
      });
      expect(await client.isAuthorizedCaller(MOCK_VAULT)).to.be.true;
      expect(
        await client.isAuthorizedCaller(
          "0x0000000000000000000000000000000000000002" as Address,
        ),
      ).to.be.false;
    });
  });

  describe("getConfig", () => {
    it("returns all immutable addresses", async () => {
      const client = makeClient({
        readStubs: {
          swapRouter: () => MOCK_ROUTER,
          quoter: () => MOCK_QUOTER,
          factory: () => MOCK_FACTORY,
          weth: () => MOCK_WETH,
        },
      });
      const config: AdapterConfig = await client.getConfig();
      expect(config.swapRouter).to.equal(MOCK_ROUTER);
      expect(config.quoter).to.equal(MOCK_QUOTER);
      expect(config.factory).to.equal(MOCK_FACTORY);
      expect(config.weth).to.equal(MOCK_WETH);
    });
  });

  // ================================================================
  // Write Operations
  // ================================================================

  describe("setAuthorizedCaller", () => {
    it("sends the correct write transaction", async () => {
      let capturedCall: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (call: any) => {
          capturedCall = call;
          return "0xabc123" as Hex;
        },
      });
      const hash = await client.setAuthorizedCaller(MOCK_VAULT, true);
      expect(hash).to.equal("0xabc123");
      expect(capturedCall.functionName).to.equal("setAuthorizedCaller");
      expect(capturedCall.args[0]).to.equal(MOCK_VAULT);
      expect(capturedCall.args[1]).to.equal(true);
    });

    it("throws without wallet", async () => {
      const client = makeClient({ withWallet: false });
      try {
        await client.setAuthorizedCaller(MOCK_VAULT, true);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("WalletClient required");
      }
    });
  });

  describe("setFeeTierOverride", () => {
    it("sends the correct write transaction", async () => {
      let capturedCall: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (call: any) => {
          capturedCall = call;
          return "0xdef456" as Hex;
        },
      });
      const hash = await client.setFeeTierOverride(MOCK_WETH, MOCK_USDC, 500);
      expect(hash).to.equal("0xdef456");
      expect(capturedCall.functionName).to.equal("setFeeTierOverride");
      expect(capturedCall.args[0]).to.equal(MOCK_WETH);
      expect(capturedCall.args[1]).to.equal(MOCK_USDC);
      expect(capturedCall.args[2]).to.equal(500);
    });

    it("throws without wallet", async () => {
      const client = makeClient({ withWallet: false });
      try {
        await client.setFeeTierOverride(MOCK_WETH, MOCK_USDC, 500);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("WalletClient required");
      }
    });
  });

  // ================================================================
  // ABI export
  // ================================================================

  describe("UNISWAP_ADAPTER_ABI", () => {
    it("is a non-empty array", () => {
      expect(UNISWAP_ADAPTER_ABI).to.be.an("array");
      expect(UNISWAP_ADAPTER_ABI.length).to.be.greaterThan(0);
    });

    it("contains expected function names", () => {
      const names = UNISWAP_ADAPTER_ABI.filter(
        (e: any) => e.type === "function",
      ).map((e: any) => e.name);
      expect(names).to.include("swap");
      expect(names).to.include("getQuote");
      expect(names).to.include("isSwapSupported");
      expect(names).to.include("setAuthorizedCaller");
      expect(names).to.include("setFeeTierOverride");
    });
  });
});
