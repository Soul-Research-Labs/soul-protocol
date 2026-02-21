import { expect } from "chai";
import { type Address, type Hash, type Hex } from "viem";
import {
  computeMessageHash,
  getScrollConfig,
  SCROLL_CHAIN_ID,
  SCROLL_SEPOLIA_CHAIN_ID,
  FINALITY_BLOCKS,
  DEFAULT_L2_GAS_LIMIT,
  FEE_DENOMINATOR,
  SCROLL_MAINNET_CONFIG,
  SCROLL_SEPOLIA_CONFIG,
  SCROLL_MESSENGER_ABI,
  SCROLL_BRIDGE_ADAPTER_ABI,
} from "../src/bridges/scroll";

describe("Scroll Bridge Adapter", () => {
  // ===========================================================================
  // Constants
  // ===========================================================================
  describe("Constants", () => {
    it("should have correct chain IDs", () => {
      expect(SCROLL_CHAIN_ID).to.equal(534352);
      expect(SCROLL_SEPOLIA_CHAIN_ID).to.equal(534351);
    });

    it("should have 1 finality block (ZK proof instant)", () => {
      expect(FINALITY_BLOCKS).to.equal(1);
    });

    it("should have correct default L2 gas limit", () => {
      expect(DEFAULT_L2_GAS_LIMIT).to.equal(1_000_000n);
    });

    it("should have correct fee denominator", () => {
      expect(FEE_DENOMINATOR).to.equal(10_000n);
    });
  });

  // ===========================================================================
  // Configs
  // ===========================================================================
  describe("Scroll Configs", () => {
    it("should have valid mainnet config addresses", () => {
      expect(SCROLL_MAINNET_CONFIG.chainId).to.equal(SCROLL_CHAIN_ID);
      expect(SCROLL_MAINNET_CONFIG.l1ScrollMessenger).to.match(
        /^0x[0-9a-fA-F]{40}$/,
      );
      expect(SCROLL_MAINNET_CONFIG.l1GatewayRouter).to.match(
        /^0x[0-9a-fA-F]{40}$/,
      );
      expect(SCROLL_MAINNET_CONFIG.scrollChain).to.match(/^0x[0-9a-fA-F]{40}$/);
      expect(SCROLL_MAINNET_CONFIG.l1MessageQueue).to.match(
        /^0x[0-9a-fA-F]{40}$/,
      );
    });

    it("should have valid Sepolia config addresses", () => {
      expect(SCROLL_SEPOLIA_CONFIG.chainId).to.equal(SCROLL_SEPOLIA_CHAIN_ID);
      expect(SCROLL_SEPOLIA_CONFIG.l1ScrollMessenger).to.match(
        /^0x[0-9a-fA-F]{40}$/,
      );
      expect(SCROLL_SEPOLIA_CONFIG.l1GatewayRouter).to.match(
        /^0x[0-9a-fA-F]{40}$/,
      );
    });

    it("mainnet and Sepolia configs should have different addresses", () => {
      expect(SCROLL_MAINNET_CONFIG.l1ScrollMessenger).to.not.equal(
        SCROLL_SEPOLIA_CONFIG.l1ScrollMessenger,
      );
    });
  });

  // ===========================================================================
  // getScrollConfig
  // ===========================================================================
  describe("getScrollConfig", () => {
    it("should return mainnet config for mainnet chain ID", () => {
      const config = getScrollConfig(SCROLL_CHAIN_ID);
      expect(config).to.deep.equal(SCROLL_MAINNET_CONFIG);
    });

    it("should return Sepolia config for Sepolia chain ID", () => {
      const config = getScrollConfig(SCROLL_SEPOLIA_CHAIN_ID);
      expect(config).to.deep.equal(SCROLL_SEPOLIA_CONFIG);
    });

    it("should throw for unsupported chain ID", () => {
      expect(() => getScrollConfig(1)).to.throw(
        "Unsupported Scroll chain ID: 1",
      );
    });

    it("should throw for unrelated chain ID", () => {
      expect(() => getScrollConfig(42161)).to.throw(
        "Unsupported Scroll chain ID",
      );
    });
  });

  // ===========================================================================
  // computeMessageHash
  // ===========================================================================
  describe("computeMessageHash", () => {
    const sender = "0x1234567890123456789012345678901234567890" as Address;
    const target = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" as Address;

    it("should compute deterministic hash", () => {
      const hash1 = computeMessageHash(sender, target, 100n, 1n, "0x" as Hex);
      const hash2 = computeMessageHash(sender, target, 100n, 1n, "0x" as Hex);
      expect(hash1).to.equal(hash2);
    });

    it("should produce different hashes for different nonces", () => {
      const hash1 = computeMessageHash(sender, target, 100n, 1n, "0x" as Hex);
      const hash2 = computeMessageHash(sender, target, 100n, 2n, "0x" as Hex);
      expect(hash1).to.not.equal(hash2);
    });

    it("should produce different hashes for different targets", () => {
      const target2 = "0x0000000000000000000000000000000000000001" as Address;
      const hash1 = computeMessageHash(sender, target, 100n, 1n, "0x" as Hex);
      const hash2 = computeMessageHash(sender, target2, 100n, 1n, "0x" as Hex);
      expect(hash1).to.not.equal(hash2);
    });

    it("should produce different hashes for different data", () => {
      const hash1 = computeMessageHash(
        sender,
        target,
        100n,
        1n,
        "0xdead" as Hex,
      );
      const hash2 = computeMessageHash(
        sender,
        target,
        100n,
        1n,
        "0xbeef" as Hex,
      );
      expect(hash1).to.not.equal(hash2);
    });

    it("should return a valid keccak256 hash (0x + 64 hex chars)", () => {
      const hash = computeMessageHash(sender, target, 0n, 0n, "0x" as Hex);
      expect(hash).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("should produce different hashes for different values", () => {
      const hash1 = computeMessageHash(sender, target, 0n, 1n, "0x" as Hex);
      const hash2 = computeMessageHash(sender, target, 1n, 1n, "0x" as Hex);
      expect(hash1).to.not.equal(hash2);
    });
  });

  // ===========================================================================
  // ABI Integrity
  // ===========================================================================
  describe("ABI Integrity", () => {
    it("SCROLL_MESSENGER_ABI should have sendMessage function", () => {
      const sendMessage = SCROLL_MESSENGER_ABI.find(
        (item) => item.name === "sendMessage",
      );
      expect(sendMessage).to.not.be.undefined;
      expect(sendMessage!.type).to.equal("function");
      expect(sendMessage!.stateMutability).to.equal("payable");
    });

    it("SCROLL_MESSENGER_ABI should have relayMessageWithProof function", () => {
      const relay = SCROLL_MESSENGER_ABI.find(
        (item) => item.name === "relayMessageWithProof",
      );
      expect(relay).to.not.be.undefined;
    });

    it("SCROLL_BRIDGE_ADAPTER_ABI should have sendMessage function", () => {
      const sendMessage = SCROLL_BRIDGE_ADAPTER_ABI.find(
        (item) => item.name === "sendMessage",
      );
      expect(sendMessage).to.not.be.undefined;
      expect(sendMessage!.stateMutability).to.equal("payable");
    });

    it("SCROLL_BRIDGE_ADAPTER_ABI should have verifyMessage function", () => {
      const verify = SCROLL_BRIDGE_ADAPTER_ABI.find(
        (item) => item.name === "verifyMessage",
      );
      expect(verify).to.not.be.undefined;
      expect(verify!.stateMutability).to.equal("view");
    });

    it("SCROLL_BRIDGE_ADAPTER_ABI should have isConfigured function", () => {
      const isConfigured = SCROLL_BRIDGE_ADAPTER_ABI.find(
        (item) => item.name === "isConfigured",
      );
      expect(isConfigured).to.not.be.undefined;
    });
  });
});
