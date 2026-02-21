import { expect } from "chai";
import {
  opToWei,
  weiToOp,
  formatOPWei,
  isValidL2Address,
  validateOPDepositAmount,
  calculateOptimismBridgeFee,
  calculateOptimismNetAmount,
  generateOptimismPreimage,
  computeOptimismHashlock,
  validateOptimismEscrowTimelocks,
  WEI_PER_OP,
  OP_MIN_DEPOSIT_WEI,
  OP_MAX_DEPOSIT_WEI,
  OP_BRIDGE_FEE_BPS,
  OP_BPS_DENOMINATOR,
  OP_MIN_ESCROW_TIMELOCK,
  OP_MAX_ESCROW_TIMELOCK,
  OP_WITHDRAWAL_REFUND_DELAY,
  OP_DEFAULT_BLOCK_CONFIRMATIONS,
  OP_BLOCK_TIME_MS,
  OPTIMISM_CHAIN_ID,
  OPTIMISM_CHALLENGE_PERIOD_MS,
  OPDepositStatus,
  OPWithdrawalStatus,
  OPEscrowStatus,
  OptimismBridgeOpType,
} from "../src/bridges/optimism";

describe("Optimism Bridge Adapter", () => {
  // ===========================================================================
  // Constants
  // ===========================================================================
  describe("Constants", () => {
    it("should have correct WEI_PER_OP (1e18)", () => {
      expect(WEI_PER_OP).to.equal(10n ** 18n);
    });

    it("should have correct minimum deposit (0.001 ETH)", () => {
      expect(OP_MIN_DEPOSIT_WEI).to.equal(10n ** 15n);
    });

    it("should have correct maximum deposit (10M ETH)", () => {
      expect(OP_MAX_DEPOSIT_WEI).to.equal(10_000_000n * WEI_PER_OP);
    });

    it("should have correct fee BPS (3 = 0.03%)", () => {
      expect(OP_BRIDGE_FEE_BPS).to.equal(3n);
      expect(OP_BPS_DENOMINATOR).to.equal(10_000n);
    });

    it("should have correct escrow timelock bounds", () => {
      expect(OP_MIN_ESCROW_TIMELOCK).to.equal(3600); // 1 hour
      expect(OP_MAX_ESCROW_TIMELOCK).to.equal(30 * 24 * 3600); // 30 days
    });

    it("should have correct withdrawal refund delay (24h)", () => {
      expect(OP_WITHDRAWAL_REFUND_DELAY).to.equal(86400);
    });

    it("should have correct chain ID", () => {
      expect(OPTIMISM_CHAIN_ID).to.equal(10);
    });

    it("should have correct block time (2s)", () => {
      expect(OP_BLOCK_TIME_MS).to.equal(2000);
    });

    it("should have correct challenge period (7 days)", () => {
      expect(OPTIMISM_CHALLENGE_PERIOD_MS).to.equal(7 * 24 * 60 * 60 * 1000);
    });
  });

  // ===========================================================================
  // Enums
  // ===========================================================================
  describe("Enums", () => {
    it("OPDepositStatus should have correct values", () => {
      expect(OPDepositStatus.PENDING).to.equal(0);
      expect(OPDepositStatus.VERIFIED).to.equal(1);
      expect(OPDepositStatus.COMPLETED).to.equal(2);
      expect(OPDepositStatus.FAILED).to.equal(3);
    });

    it("OPWithdrawalStatus should have correct values", () => {
      expect(OPWithdrawalStatus.PENDING).to.equal(0);
      expect(OPWithdrawalStatus.REFUNDED).to.equal(3);
      expect(OPWithdrawalStatus.FAILED).to.equal(4);
    });

    it("OPEscrowStatus should have correct values", () => {
      expect(OPEscrowStatus.ACTIVE).to.equal(0);
      expect(OPEscrowStatus.FINISHED).to.equal(1);
      expect(OPEscrowStatus.CANCELLED).to.equal(2);
    });

    it("OptimismBridgeOpType should have correct values", () => {
      expect(OptimismBridgeOpType.ETH_TRANSFER).to.equal(0);
      expect(OptimismBridgeOpType.EMERGENCY_OP).to.equal(3);
    });
  });

  // ===========================================================================
  // Conversion Utilities
  // ===========================================================================
  describe("opToWei", () => {
    it("should convert whole OP amounts", () => {
      expect(opToWei(1)).to.equal(WEI_PER_OP);
      expect(opToWei(10)).to.equal(10n * WEI_PER_OP);
    });

    it("should convert string whole amounts", () => {
      expect(opToWei("5")).to.equal(5n * WEI_PER_OP);
    });

    it("should convert decimal string amounts", () => {
      expect(opToWei("1.5")).to.equal(WEI_PER_OP + WEI_PER_OP / 2n);
    });

    it("should handle tiny decimals", () => {
      // 0.001 = 1e15 wei
      expect(opToWei("0.001")).to.equal(10n ** 15n);
    });

    it("should convert 0", () => {
      expect(opToWei(0)).to.equal(0n);
    });
  });

  describe("weiToOp", () => {
    it("should convert exact whole amounts", () => {
      expect(weiToOp(WEI_PER_OP)).to.equal("1");
      expect(weiToOp(10n * WEI_PER_OP)).to.equal("10");
    });

    it("should convert fractional amounts", () => {
      const oneAndHalf = WEI_PER_OP + WEI_PER_OP / 2n;
      expect(weiToOp(oneAndHalf)).to.equal("1.5");
    });

    it("should convert 0", () => {
      expect(weiToOp(0n)).to.equal("0");
    });

    it("should preserve precision", () => {
      const tiny = 1n; // 1 wei
      const result = weiToOp(tiny);
      expect(result).to.include("0.");
    });
  });

  describe("formatOPWei", () => {
    it("should format large amounts with ETH suffix", () => {
      const formatted = formatOPWei(2n * WEI_PER_OP);
      expect(formatted).to.equal("2 ETH");
    });

    it("should format sub-ETH amounts with wei suffix", () => {
      const formatted = formatOPWei(500_000n);
      expect(formatted).to.include("wei");
    });
  });

  // ===========================================================================
  // Validation
  // ===========================================================================
  describe("isValidL2Address", () => {
    it("should accept valid checksummed addresses", () => {
      expect(isValidL2Address("0x1234567890abcdef1234567890abcdef12345678")).to
        .be.true;
    });

    it("should accept uppercase hex", () => {
      expect(isValidL2Address("0x1234567890ABCDEF1234567890ABCDEF12345678")).to
        .be.true;
    });

    it("should reject short addresses", () => {
      expect(isValidL2Address("0x1234")).to.be.false;
    });

    it("should reject addresses without 0x prefix", () => {
      expect(isValidL2Address("1234567890abcdef1234567890abcdef12345678")).to.be
        .false;
    });

    it("should reject empty string", () => {
      expect(isValidL2Address("")).to.be.false;
    });
  });

  describe("validateOPDepositAmount", () => {
    it("should accept amount within range", () => {
      const result = validateOPDepositAmount(WEI_PER_OP); // 1 ETH
      expect(result.valid).to.be.true;
      expect(result.error).to.be.undefined;
    });

    it("should reject amount below minimum", () => {
      const result = validateOPDepositAmount(100n); // way below 0.001 ETH
      expect(result.valid).to.be.false;
      expect(result.error).to.include("below minimum");
    });

    it("should reject amount above maximum", () => {
      const result = validateOPDepositAmount(OP_MAX_DEPOSIT_WEI + 1n);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("exceeds maximum");
    });

    it("should accept boundary values", () => {
      expect(validateOPDepositAmount(OP_MIN_DEPOSIT_WEI).valid).to.be.true;
      expect(validateOPDepositAmount(OP_MAX_DEPOSIT_WEI).valid).to.be.true;
    });
  });

  // ===========================================================================
  // Fee Calculations
  // ===========================================================================
  describe("calculateOptimismBridgeFee", () => {
    it("should calculate 0.03% fee", () => {
      const amount = 10_000_000_000_000_000_000n; // 10 ETH
      const fee = calculateOptimismBridgeFee(amount);
      // 10e18 * 3 / 10000 = 3e15
      expect(fee).to.equal(3_000_000_000_000_000n);
    });

    it("should return 0 for 0 amount", () => {
      expect(calculateOptimismBridgeFee(0n)).to.equal(0n);
    });

    it("should handle large amounts", () => {
      const fee = calculateOptimismBridgeFee(1_000_000n * WEI_PER_OP);
      expect(fee).to.be.greaterThan(0n);
    });
  });

  describe("calculateOptimismNetAmount", () => {
    it("should subtract fee from amount", () => {
      const amount = 10_000_000_000_000_000_000n; // 10 ETH
      const net = calculateOptimismNetAmount(amount);
      const fee = calculateOptimismBridgeFee(amount);
      expect(net).to.equal(amount - fee);
    });

    it("should return 0 for 0 amount", () => {
      expect(calculateOptimismNetAmount(0n)).to.equal(0n);
    });
  });

  // ===========================================================================
  // Escrow Utilities
  // ===========================================================================
  describe("generateOptimismPreimage", () => {
    it("should generate a 32-byte hex preimage with 0x prefix", () => {
      const preimage = generateOptimismPreimage();
      expect(preimage).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("should generate unique preimages", () => {
      const p1 = generateOptimismPreimage();
      const p2 = generateOptimismPreimage();
      expect(p1).to.not.equal(p2);
    });
  });

  describe("computeOptimismHashlock", () => {
    it("should compute a deterministic SHA-256 hash", async () => {
      const preimage =
        "0x0000000000000000000000000000000000000000000000000000000000000001" as `0x${string}`;
      const hash1 = await computeOptimismHashlock(preimage);
      const hash2 = await computeOptimismHashlock(preimage);
      expect(hash1).to.equal(hash2);
    });

    it("should return 0x-prefixed 64-char hex", async () => {
      const preimage = generateOptimismPreimage();
      const hash = await computeOptimismHashlock(preimage);
      expect(hash).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("should produce different hashes for different preimages", async () => {
      const p1 =
        "0x0000000000000000000000000000000000000000000000000000000000000001" as `0x${string}`;
      const p2 =
        "0x0000000000000000000000000000000000000000000000000000000000000002" as `0x${string}`;
      const h1 = await computeOptimismHashlock(p1);
      const h2 = await computeOptimismHashlock(p2);
      expect(h1).to.not.equal(h2);
    });
  });

  describe("validateOptimismEscrowTimelocks", () => {
    const now = () => Math.floor(Date.now() / 1000);

    it("should accept valid timelocks", () => {
      const finishAfter = now() + 100;
      const cancelAfter = finishAfter + 7200; // 2 hours after finish
      const result = validateOptimismEscrowTimelocks(finishAfter, cancelAfter);
      expect(result.valid).to.be.true;
    });

    it("should reject finishAfter in the past", () => {
      const finishAfter = now() - 100;
      const cancelAfter = finishAfter + 7200;
      const result = validateOptimismEscrowTimelocks(finishAfter, cancelAfter);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("future");
    });

    it("should reject duration below minimum (1 hour)", () => {
      const finishAfter = now() + 100;
      const cancelAfter = finishAfter + 1800; // 30 min < 1 hour minimum
      const result = validateOptimismEscrowTimelocks(finishAfter, cancelAfter);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("below minimum");
    });

    it("should reject duration above maximum (30 days)", () => {
      const finishAfter = now() + 100;
      const cancelAfter = finishAfter + 31 * 24 * 3600; // 31 days > 30 days max
      const result = validateOptimismEscrowTimelocks(finishAfter, cancelAfter);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("exceeds maximum");
    });

    it("should accept exact minimum duration", () => {
      const finishAfter = now() + 100;
      const cancelAfter = finishAfter + OP_MIN_ESCROW_TIMELOCK;
      const result = validateOptimismEscrowTimelocks(finishAfter, cancelAfter);
      expect(result.valid).to.be.true;
    });

    it("should accept exact maximum duration", () => {
      const finishAfter = now() + 100;
      const cancelAfter = finishAfter + OP_MAX_ESCROW_TIMELOCK;
      const result = validateOptimismEscrowTimelocks(finishAfter, cancelAfter);
      expect(result.valid).to.be.true;
    });
  });
});
