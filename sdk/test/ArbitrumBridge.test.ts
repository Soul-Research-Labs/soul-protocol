import { expect } from "chai";
import { type Address, type Hash } from "viem";
import {
  calculateBridgeFee,
  isChallengeExpired,
  computeDepositId,
  computeWithdrawalId,
  estimateDepositCost,
  validateDepositAmount,
  getArbitrumNetworkName,
  ARB_ONE_CHAIN_ID,
  ARB_NOVA_CHAIN_ID,
  CHALLENGE_PERIOD,
  DEFAULT_L2_GAS_LIMIT,
  DEFAULT_MAX_SUBMISSION_COST,
  FEE_DENOMINATOR,
} from "../src/bridges/arbitrum";

describe("Arbitrum Bridge Adapter", () => {
  describe("Constants", () => {
    it("should have correct chain IDs", () => {
      expect(ARB_ONE_CHAIN_ID).to.equal(42161);
      expect(ARB_NOVA_CHAIN_ID).to.equal(42170);
    });

    it("should have correct challenge period (7 days)", () => {
      expect(CHALLENGE_PERIOD).to.equal(604800);
    });

    it("should have correct default gas limit", () => {
      expect(DEFAULT_L2_GAS_LIMIT).to.equal(1_000_000n);
    });

    it("should have correct fee denominator", () => {
      expect(FEE_DENOMINATOR).to.equal(10_000n);
    });
  });

  describe("calculateBridgeFee", () => {
    it("should calculate correct fee with default bps (15)", () => {
      const fee = calculateBridgeFee(10000n);
      // 10000 * 15 / 10000 = 15
      expect(fee).to.equal(15n);
    });

    it("should calculate correct fee with custom bps", () => {
      const fee = calculateBridgeFee(10000n, 50n);
      // 10000 * 50 / 10000 = 50
      expect(fee).to.equal(50n);
    });

    it("should return 0 fee for 0 amount", () => {
      const fee = calculateBridgeFee(0n);
      expect(fee).to.equal(0n);
    });

    it("should handle small amounts (truncation)", () => {
      const fee = calculateBridgeFee(100n);
      // 100 * 15 / 10000 = 0 (integer division)
      expect(fee).to.equal(0n);
    });

    it("should handle large amounts", () => {
      const fee = calculateBridgeFee(1_000_000_000_000_000_000n); // 1 ETH
      // 1e18 * 15 / 10000 = 1.5e15
      expect(fee).to.equal(1_500_000_000_000_000n);
    });
  });

  describe("isChallengeExpired", () => {
    it("should return true when challenge period has elapsed", () => {
      const oldTimestamp = Math.floor(Date.now() / 1000) - 604801;
      expect(isChallengeExpired(oldTimestamp)).to.be.true;
    });

    it("should return false during active challenge period", () => {
      const recentTimestamp = Math.floor(Date.now() / 1000) - 100;
      expect(isChallengeExpired(recentTimestamp)).to.be.false;
    });

    it("should respect custom challenge period", () => {
      const timestamp = Math.floor(Date.now() / 1000) - 3601;
      expect(isChallengeExpired(timestamp, 3600)).to.be.true;
      expect(isChallengeExpired(timestamp, 7200)).to.be.false;
    });
  });

  describe("computeDepositId", () => {
    it("should compute deterministic deposit ID", () => {
      const sender = "0x1234567890123456789012345678901234567890" as Address;
      const recipient = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" as Address;
      const amount = 1000n;
      const nonce = 1n;

      const id1 = computeDepositId(sender, recipient, amount, nonce);
      const id2 = computeDepositId(sender, recipient, amount, nonce);
      expect(id1).to.equal(id2);
    });

    it("should produce different IDs for different nonces", () => {
      const sender = "0x1234567890123456789012345678901234567890" as Address;
      const recipient = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" as Address;

      const id1 = computeDepositId(sender, recipient, 1000n, 1n);
      const id2 = computeDepositId(sender, recipient, 1000n, 2n);
      expect(id1).to.not.equal(id2);
    });
  });

  describe("computeWithdrawalId", () => {
    it("should compute deterministic withdrawal ID", () => {
      const l2Sender = "0x1234567890123456789012345678901234567890" as Address;
      const l1Recipient =
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" as Address;

      const id = computeWithdrawalId(l2Sender, l1Recipient, 500n, 42n);
      expect(id).to.be.a("string");
      expect(id).to.match(/^0x[a-f0-9]{64}$/);
    });
  });

  describe("estimateDepositCost", () => {
    it("should calculate total cost including all components", () => {
      const result = estimateDepositCost(
        1_000_000_000_000_000_000n, // 1 ETH
        15n,
        10_000_000_000_000_000n, // 0.01 ETH max submission
        1_000_000n, // gas limit
        100_000_000n, // gas price (0.1 gwei)
      );

      expect(result.fee).to.be.greaterThan(0n);
      expect(result.gasEstimate).to.be.greaterThan(0n);
      expect(result.total).to.equal(result.fee + result.gasEstimate);
    });
  });

  describe("validateDepositAmount", () => {
    it("should pass for valid amounts in range", () => {
      expect(validateDepositAmount(500n, 100n, 1000n)).to.be.true;
    });

    it("should fail for amounts below minimum", () => {
      expect(validateDepositAmount(50n, 100n, 1000n)).to.be.false;
    });

    it("should fail for amounts above maximum", () => {
      expect(validateDepositAmount(1500n, 100n, 1000n)).to.be.false;
    });

    it("should pass for boundary values", () => {
      expect(validateDepositAmount(100n, 100n, 1000n)).to.be.true;
      expect(validateDepositAmount(1000n, 100n, 1000n)).to.be.true;
    });
  });

  describe("getArbitrumNetworkName", () => {
    it("should return correct names", () => {
      expect(getArbitrumNetworkName(42161)).to.equal("Arbitrum One");
      expect(getArbitrumNetworkName(42170)).to.equal("Arbitrum Nova");
    });

    it("should handle unknown chain IDs", () => {
      const name = getArbitrumNetworkName(99999);
      expect(name).to.be.a("string");
    });
  });
});
