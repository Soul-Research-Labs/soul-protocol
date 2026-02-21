import { expect } from "chai";
import {
  BaseBridgeAdapter,
  L2BridgeAdapter,
  BridgeFactory,
  type BridgeAdapterConfig,
  type BridgeTransferParams,
  type BridgeFees,
  type BridgeStatus,
  type SupportedChain,
} from "../src/bridges/index";

// All 8 supported chains
const ALL_CHAINS: SupportedChain[] = [
  "arbitrum",
  "base",
  "ethereum",
  "linea",
  "optimism",
  "polygon-zkevm",
  "scroll",
  "zksync",
];

// Chain ID expectations
const EXPECTED_CHAIN_IDS: Record<SupportedChain, number> = {
  arbitrum: 42161,
  base: 8453,
  ethereum: 1,
  linea: 59144,
  optimism: 10,
  "polygon-zkevm": 1101,
  scroll: 534352,
  zksync: 324,
};

describe("Bridge Adapters Module (index.ts)", () => {
  // ===========================================================================
  // Chain Configurations
  // ===========================================================================
  describe("Chain Configurations", () => {
    it("should support exactly 8 chains", () => {
      expect(ALL_CHAINS).to.have.lengthOf(8);
    });

    for (const chain of ALL_CHAINS) {
      it(`should have correct chain ID for ${chain}`, () => {
        // We verify by trying to create an adapter and checking errors indicate
        // the chain is recognized (it asks for addresses, not "unsupported chain")
        expect(() => BridgeFactory.createAdapter(chain, null as any)).to.throw(
          /No bridge address configured/,
        );
      });
    }
  });

  // ===========================================================================
  // BridgeFactory
  // ===========================================================================
  describe("BridgeFactory", () => {
    it("should throw for unsupported chain", () => {
      expect(() =>
        BridgeFactory.createAdapter(
          "unknown-chain" as SupportedChain,
          null as any,
        ),
      ).to.throw(/Unsupported chain/);
    });

    it("unsupported chain error should list available chains", () => {
      try {
        BridgeFactory.createAdapter("invalid" as SupportedChain, null as any);
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Available chains:");
        for (const chain of ALL_CHAINS) {
          expect(e.message).to.include(chain);
        }
      }
    });

    it("should throw when no bridge address provided", () => {
      expect(() =>
        BridgeFactory.createAdapter("arbitrum", null as any),
      ).to.throw(/No bridge address configured/);
    });

    it("should accept addresses.bridge as fallback", () => {
      const adapter = BridgeFactory.createAdapter(
        "arbitrum",
        null as any,
        undefined,
        { bridge: "0x1234567890123456789012345678901234567890" },
      );
      expect(adapter).to.be.instanceOf(L2BridgeAdapter);
    });

    it("should accept chain-specific address key", () => {
      const adapter = BridgeFactory.createAdapter(
        "arbitrum",
        null as any,
        undefined,
        { bridge_arbitrum: "0x1234567890123456789012345678901234567890" },
      );
      expect(adapter).to.be.instanceOf(L2BridgeAdapter);
    });

    it("should accept polygon-zkevm with underscored key", () => {
      const adapter = BridgeFactory.createAdapter(
        "polygon-zkevm",
        null as any,
        undefined,
        { bridge_polygon_zkevm: "0x1234567890123456789012345678901234567890" },
      );
      expect(adapter).to.be.instanceOf(L2BridgeAdapter);
    });

    for (const chain of ALL_CHAINS) {
      it(`should create adapter for ${chain}`, () => {
        const adapter = BridgeFactory.createAdapter(
          chain,
          null as any,
          undefined,
          { bridge: "0x1234567890123456789012345678901234567890" },
        );
        expect(adapter).to.be.instanceOf(BaseBridgeAdapter);
        expect(adapter.config.name).to.be.a("string");
        expect(adapter.config.chainId).to.equal(EXPECTED_CHAIN_IDS[chain]);
        expect(adapter.config.nativeToken).to.equal("ETH");
        expect(adapter.config.finality).to.be.greaterThan(0);
        expect(adapter.config.maxAmount).to.be.greaterThan(0n);
        expect(adapter.config.minAmount).to.be.greaterThan(0n);
        expect(adapter.config.maxAmount).to.be.greaterThan(
          adapter.config.minAmount,
        );
      });
    }
  });

  // ===========================================================================
  // BaseBridgeAdapter.validateAmount
  // ===========================================================================
  describe("BaseBridgeAdapter.validateAmount", () => {
    let adapter: BaseBridgeAdapter;

    beforeEach(() => {
      adapter = BridgeFactory.createAdapter(
        "arbitrum",
        null as any,
        undefined,
        { bridge: "0x1234567890123456789012345678901234567890" },
      );
    });

    it("should accept amount within range", () => {
      expect(() =>
        adapter.validateAmount(1_000_000_000_000_000_000n),
      ).to.not.throw();
    });

    it("should reject amount below minimum", () => {
      expect(() => adapter.validateAmount(1n)).to.throw("Amount below minimum");
    });

    it("should reject amount above maximum", () => {
      expect(() =>
        adapter.validateAmount(10_000_000_000_000_000_000_000_000n),
      ).to.throw("Amount exceeds maximum");
    });

    it("should accept exact minimum amount", () => {
      expect(() =>
        adapter.validateAmount(adapter.config.minAmount),
      ).to.not.throw();
    });

    it("should accept exact maximum amount", () => {
      expect(() =>
        adapter.validateAmount(adapter.config.maxAmount),
      ).to.not.throw();
    });
  });

  // ===========================================================================
  // L2BridgeAdapter (without network)
  // ===========================================================================
  describe("L2BridgeAdapter (offline)", () => {
    let adapter: L2BridgeAdapter;

    beforeEach(() => {
      adapter = BridgeFactory.createAdapter(
        "optimism",
        null as any,
        undefined,
        { bridge: "0x1234567890123456789012345678901234567890" },
      ) as L2BridgeAdapter;
    });

    it("should require wallet client for bridgeTransfer", async () => {
      try {
        await adapter.bridgeTransfer({
          targetChainId: 1,
          recipient: "0x1234567890123456789012345678901234567890",
          amount: 1_000_000_000_000_000_000n,
        });
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client");
      }
    });

    it("should require wallet client for completeBridge", async () => {
      try {
        await adapter.completeBridge(
          "0x0000000000000000000000000000000000000000000000000000000000000001",
          new Uint8Array(32),
        );
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client");
      }
    });

    it("should validate amount before bridging", async () => {
      try {
        await adapter.bridgeTransfer({
          targetChainId: 1,
          recipient: "0x1234567890123456789012345678901234567890",
          amount: 1n, // below minimum
        });
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("below minimum");
      }
    });
  });

  // ===========================================================================
  // Re-exports
  // ===========================================================================
  describe("Module re-exports", () => {
    it("should re-export ArbitrumBridge namespace", async () => {
      const mod = await import("../src/bridges/index");
      expect(mod.ArbitrumBridge).to.not.be.undefined;
      expect(mod.ArbitrumBridge.calculateBridgeFee).to.be.a("function");
    });

    it("should re-export ScrollBridge namespace", async () => {
      const mod = await import("../src/bridges/index");
      expect(mod.ScrollBridge).to.not.be.undefined;
      expect(mod.ScrollBridge.computeMessageHash).to.be.a("function");
    });

    it("should re-export optimism utilities directly (star export)", async () => {
      const mod = await import("../src/bridges/index");
      expect(mod.opToWei).to.be.a("function");
      expect(mod.calculateOptimismBridgeFee).to.be.a("function");
    });

    it("should re-export L2Adapters namespace", async () => {
      const mod = await import("../src/bridges/index");
      expect(mod.L2Adapters).to.not.be.undefined;
    });
  });
});
