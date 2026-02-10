import { expect } from "chai";
import {
  L2_CHAIN_IDS,
  getL2NetworkInfo,
  getL2NetworkByChainId,
  isL2Supported,
} from "../src/bridges/l2-adapters";

describe("l2-adapters", () => {
  // ═══════════════════════════════════════════════════════════════
  // Constants
  // ═══════════════════════════════════════════════════════════════
  describe("L2_CHAIN_IDS", () => {
    it("should have correct Scroll mainnet chain ID", () => {
      expect(L2_CHAIN_IDS.SCROLL_MAINNET).to.equal(534352);
    });
    it("should have correct Linea mainnet chain ID", () => {
      expect(L2_CHAIN_IDS.LINEA_MAINNET).to.equal(59144);
    });
    it("should have correct zkSync Era chain ID", () => {
      expect(L2_CHAIN_IDS.ZKSYNC_ERA).to.equal(324);
    });
    it("should have correct Polygon zkEVM mainnet chain ID", () => {
      expect(L2_CHAIN_IDS.POLYGON_ZKEVM_MAINNET).to.equal(1101);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // getL2NetworkInfo
  // ═══════════════════════════════════════════════════════════════
  describe("getL2NetworkInfo", () => {
    it("should return Scroll info", () => {
      const info = getL2NetworkInfo("scroll");
      expect(info.chainId).to.equal(534352);
      expect(info.name).to.equal("Scroll");
    });

    it("should return Linea info", () => {
      const info = getL2NetworkInfo("linea");
      expect(info.chainId).to.equal(59144);
      expect(info.name).to.equal("Linea");
    });

    it("should return zkSync info", () => {
      const info = getL2NetworkInfo("zksync");
      expect(info.chainId).to.equal(324);
      expect(info.name).to.equal("zkSync Era");
    });

    it("should return Polygon zkEVM info", () => {
      const info = getL2NetworkInfo("polygon-zkevm");
      expect(info.chainId).to.equal(1101);
      expect(info.name).to.equal("Polygon zkEVM");
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // getL2NetworkByChainId
  // ═══════════════════════════════════════════════════════════════
  describe("getL2NetworkByChainId", () => {
    it("should resolve mainnet chain IDs", () => {
      expect(getL2NetworkByChainId(534352)).to.equal("scroll");
      expect(getL2NetworkByChainId(59144)).to.equal("linea");
      expect(getL2NetworkByChainId(324)).to.equal("zksync");
      expect(getL2NetworkByChainId(1101)).to.equal("polygon-zkevm");
    });

    it("should resolve testnet chain IDs", () => {
      expect(getL2NetworkByChainId(534351)).to.equal("scroll");
      expect(getL2NetworkByChainId(59140)).to.equal("linea");
      expect(getL2NetworkByChainId(1442)).to.equal("polygon-zkevm");
    });

    it("should return undefined for unknown chain ID", () => {
      expect(getL2NetworkByChainId(999999)).to.be.undefined;
      expect(getL2NetworkByChainId(1)).to.be.undefined;
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // isL2Supported
  // ═══════════════════════════════════════════════════════════════
  describe("isL2Supported", () => {
    it("should return true for supported chains", () => {
      expect(isL2Supported(534352)).to.be.true;
      expect(isL2Supported(59144)).to.be.true;
      expect(isL2Supported(324)).to.be.true;
      expect(isL2Supported(1101)).to.be.true;
    });

    it("should return false for unsupported chains", () => {
      expect(isL2Supported(1)).to.be.false;
      expect(isL2Supported(42161)).to.be.false; // Arbitrum not in l2-adapters
      expect(isL2Supported(0)).to.be.false;
    });
  });
});
