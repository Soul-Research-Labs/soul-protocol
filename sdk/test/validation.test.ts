import { expect } from "chai";
import {
  validateAddress,
  validateBytes32,
  validateBytes,
  validateUint256,
  validateTimestamp,
  validateChainId,
  validateProof,
  validatePolicyConfig,
  validate,
  validateAll,
} from "../src/utils/validation";

describe("validation", () => {
  // ═══════════════════════════════════════════════════════════════
  // validateAddress
  // ═══════════════════════════════════════════════════════════════
  describe("validateAddress", () => {
    it("should accept a valid checksummed address", () => {
      // Use a valid EIP-55 checksummed address
      const r = validateAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7");
      expect(r.valid).to.be.true;
      expect(r.value).to.match(/^0x/);
    });

    it("should accept a lowercase address", () => {
      const r = validateAddress("0x" + "bb".repeat(20));
      expect(r.valid).to.be.true;
    });

    it("should reject non-string", () => {
      expect(validateAddress(42).valid).to.be.false;
      expect(validateAddress(null).valid).to.be.false;
    });

    it("should reject empty string", () => {
      expect(validateAddress("").valid).to.be.false;
      expect(validateAddress("  ").valid).to.be.false;
    });

    it("should reject invalid hex", () => {
      expect(validateAddress("0xZZZZ").valid).to.be.false;
    });

    it("should reject too-short address", () => {
      expect(validateAddress("0x1234").valid).to.be.false;
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // validateBytes32
  // ═══════════════════════════════════════════════════════════════
  describe("validateBytes32", () => {
    const valid32 = "0x" + "ab".repeat(32);

    it("should accept valid bytes32 with 0x prefix", () => {
      const r = validateBytes32(valid32);
      expect(r.valid).to.be.true;
      expect(r.value).to.equal(valid32);
    });

    it("should accept without 0x prefix", () => {
      const r = validateBytes32("ab".repeat(32));
      expect(r.valid).to.be.true;
      expect(r.value).to.equal("0x" + "ab".repeat(32));
    });

    it("should reject wrong length", () => {
      expect(validateBytes32("0x1234").valid).to.be.false;
    });

    it("should reject non-hex characters", () => {
      expect(validateBytes32("0x" + "gg".repeat(32)).valid).to.be.false;
    });

    it("should reject non-string input", () => {
      expect(validateBytes32(123).valid).to.be.false;
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // validateBytes
  // ═══════════════════════════════════════════════════════════════
  describe("validateBytes", () => {
    it("should accept valid hex bytes", () => {
      const r = validateBytes("0xabcd");
      expect(r.valid).to.be.true;
      expect(r.value).to.equal("0xabcd");
    });

    it("should accept empty bytes", () => {
      const r = validateBytes("0x");
      expect(r.valid).to.be.true;
    });

    it("should reject odd-length hex", () => {
      expect(validateBytes("0xabc").valid).to.be.false;
    });

    it("should reject non-hex", () => {
      expect(validateBytes("0xzzzz").valid).to.be.false;
    });

    it("should reject non-string", () => {
      expect(validateBytes(42).valid).to.be.false;
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // validateUint256
  // ═══════════════════════════════════════════════════════════════
  describe("validateUint256", () => {
    it("should accept zero", () => {
      const r = validateUint256(0);
      expect(r.valid).to.be.true;
      expect(r.value).to.equal(0n);
    });

    it("should accept bigint", () => {
      const r = validateUint256(100n);
      expect(r.valid).to.be.true;
      expect(r.value).to.equal(100n);
    });

    it("should accept string number", () => {
      const r = validateUint256("42");
      expect(r.valid).to.be.true;
      expect(r.value).to.equal(42n);
    });

    it("should reject null/undefined", () => {
      expect(validateUint256(null).valid).to.be.false;
      expect(validateUint256(undefined).valid).to.be.false;
    });

    it("should reject negative", () => {
      expect(validateUint256(-1).valid).to.be.false;
    });

    it("should reject overflow", () => {
      expect(validateUint256(2n ** 256n).valid).to.be.false;
    });

    it("should accept max uint256", () => {
      const r = validateUint256(2n ** 256n - 1n);
      expect(r.valid).to.be.true;
    });

    it("should reject non-integer number", () => {
      expect(validateUint256(1.5).valid).to.be.false;
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // validateTimestamp
  // ═══════════════════════════════════════════════════════════════
  describe("validateTimestamp", () => {
    it("should accept a valid unix timestamp", () => {
      const r = validateTimestamp(1700000000);
      expect(r.valid).to.be.true;
      expect(r.value).to.equal(1700000000);
    });

    it("should reject a timestamp too far in future", () => {
      const r = validateTimestamp(8000000000);
      expect(r.valid).to.be.false;
      expect(r.error).to.include("future");
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // validateChainId
  // ═══════════════════════════════════════════════════════════════
  describe("validateChainId", () => {
    it("should accept known chain IDs", () => {
      for (const id of [1, 10, 42161, 8453, 31337]) {
        expect(validateChainId(id).valid).to.be.true;
      }
    });

    it("should still pass for unknown chain IDs (with console warning)", () => {
      const r = validateChainId(999999);
      expect(r.valid).to.be.true;
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // validateProof
  // ═══════════════════════════════════════════════════════════════
  describe("validateProof", () => {
    it("should accept valid proof data", () => {
      const r = validateProof({
        proof: "0xaabb",
        publicInputs: ["0x" + "cc".repeat(32)],
      });
      expect(r.valid).to.be.true;
      expect(r.value!.proof).to.equal("0xaabb");
      expect(r.value!.publicInputs).to.have.lengthOf(1);
    });

    it("should reject non-object", () => {
      expect(validateProof(null).valid).to.be.false;
      expect(validateProof("string").valid).to.be.false;
    });

    it("should reject missing proof field", () => {
      expect(validateProof({ publicInputs: [] }).valid).to.be.false;
    });

    it("should reject non-array publicInputs", () => {
      expect(validateProof({ proof: "0xaa", publicInputs: "bad" }).valid).to.be.false;
    });

    it("should reject invalid public input entry", () => {
      const r = validateProof({ proof: "0xaa", publicInputs: ["0xshort"] });
      expect(r.valid).to.be.false;
    });

    it("should accept optional verificationKey", () => {
      const r = validateProof({
        proof: "0xaa",
        publicInputs: [],
        verificationKey: "0xbeef",
      });
      expect(r.valid).to.be.true;
      expect(r.value!.verificationKey).to.equal("0xbeef");
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // validatePolicyConfig
  // ═══════════════════════════════════════════════════════════════
  describe("validatePolicyConfig", () => {
    const futureTs = Math.floor(Date.now() / 1000) + 86400;

    it("should accept minimal valid policy", () => {
      const r = validatePolicyConfig({ name: "test", expiresAt: futureTs });
      expect(r.valid).to.be.true;
      expect(r.value!.name).to.equal("test");
    });

    it("should reject missing name", () => {
      expect(validatePolicyConfig({ expiresAt: futureTs }).valid).to.be.false;
    });

    it("should reject empty name", () => {
      expect(validatePolicyConfig({ name: "", expiresAt: futureTs }).valid).to.be.false;
    });

    it("should reject name > 100 chars", () => {
      expect(validatePolicyConfig({ name: "x".repeat(101), expiresAt: futureTs }).valid).to.be.false;
    });

    it("should reject past expiresAt", () => {
      expect(validatePolicyConfig({ name: "test", expiresAt: 1000 }).valid).to.be.false;
    });

    it("should reject minAmount > maxAmount", () => {
      const r = validatePolicyConfig({
        name: "test",
        expiresAt: futureTs,
        minAmount: 100n,
        maxAmount: 1n,
      });
      expect(r.valid).to.be.false;
    });

    it("should reject invalid country code", () => {
      const r = validatePolicyConfig({
        name: "test",
        expiresAt: futureTs,
        blockedCountries: ["usa"],
      });
      expect(r.valid).to.be.false;
    });

    it("should accept valid country codes", () => {
      const r = validatePolicyConfig({
        name: "geo-policy",
        expiresAt: futureTs,
        blockedCountries: ["US", "KP"],
      });
      expect(r.valid).to.be.true;
      expect(r.value!.blockedCountries).to.deep.equal(["US", "KP"]);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // validate (throws on invalid)
  // ═══════════════════════════════════════════════════════════════
  describe("validate()", () => {
    it("should return value on valid input", () => {
      const result = validate("0x" + "aa".repeat(20), validateAddress, "addr");
      expect(result).to.match(/^0x/);
    });

    it("should throw ValidationError on invalid input", () => {
      expect(() => validate("bad", validateAddress, "addr")).to.throw(/Validation failed/);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // validateAll (batch)
  // ═══════════════════════════════════════════════════════════════
  describe("validateAll()", () => {
    it("should return all values when all valid", () => {
      const result = validateAll([
        { value: 42, validator: validateUint256, field: "amount" },
        { value: "0x" + "aa".repeat(32), validator: validateBytes32, field: "hash" },
      ]);
      expect(result).to.have.property("amount");
      expect(result).to.have.property("hash");
    });

    it("should throw with all errors when multiple fail", () => {
      try {
        validateAll([
          { value: -1, validator: validateUint256, field: "amount" },
          { value: "bad", validator: validateBytes32, field: "hash" },
        ]);
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("amount");
        expect(e.message).to.include("hash");
      }
    });
  });
});
