import { expect } from "chai";
import {
  ZaseonError,
  ZaseonErrorCode,
  ValidationError,
  ContractError,
  NetworkError,
  ProofError,
  StateError,
  ComplianceError,
  TimeoutError,
  parseContractError,
  isZaseonError,
  withRetry,
  withTimeout,
  withRetryAndTimeout,
} from "../src/utils/errors";

describe("errors", () => {
  // ═══════════════════════════════════════════════════════════════
  // ZaseonError base class
  // ═══════════════════════════════════════════════════════════════
  describe("ZaseonError", () => {
    it("should set defaults correctly", () => {
      const err = new ZaseonError("test");
      expect(err.message).to.equal("test");
      expect(err.code).to.equal(ZaseonErrorCode.UNKNOWN_ERROR);
      expect(err.retryable).to.be.false;
      expect(err.timestamp).to.be.instanceOf(Date);
      expect(err.name).to.equal("ZaseonError");
    });

    it("should accept custom code and options", () => {
      const cause = new Error("root");
      const err = new ZaseonError("fail", ZaseonErrorCode.NETWORK_ERROR, {
        cause,
        retryable: true,
        suggestedAction: "retry",
        context: { key: "val" },
      });
      expect(err.code).to.equal(ZaseonErrorCode.NETWORK_ERROR);
      expect(err.retryable).to.be.true;
      expect(err.cause).to.equal(cause);
      expect(err.suggestedAction).to.equal("retry");
      expect(err.context.key).to.equal("val");
    });

    it("toJSON() should include all fields", () => {
      const err = new ZaseonError("j", ZaseonErrorCode.INVALID_INPUT);
      const json = err.toJSON();
      expect(json).to.have.property("name", "ZaseonError");
      expect(json).to.have.property("code", ZaseonErrorCode.INVALID_INPUT);
      expect(json).to.have.property("codeName", "INVALID_INPUT");
      expect(json).to.have.property("timestamp");
    });

    it("isType() should match code", () => {
      const err = new ZaseonError("x", ZaseonErrorCode.TIMEOUT_ERROR);
      expect(err.isType(ZaseonErrorCode.TIMEOUT_ERROR)).to.be.true;
      expect(err.isType(ZaseonErrorCode.NETWORK_ERROR)).to.be.false;
    });

    it("isCategory() should match code ranges", () => {
      const val = new ValidationError("bad");
      expect(val.isCategory("validation")).to.be.true;
      expect(val.isCategory("contract")).to.be.false;

      const net = new NetworkError("fail");
      expect(net.isCategory("general")).to.be.true;

      const proof = new ProofError("fail");
      expect(proof.isCategory("proof")).to.be.true;
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // Subclass constructors
  // ═══════════════════════════════════════════════════════════════
  describe("subclasses", () => {
    it("ValidationError", () => {
      const err = new ValidationError("bad input");
      expect(err.name).to.equal("ValidationError");
      expect(err.code).to.equal(ZaseonErrorCode.INVALID_INPUT);
      expect(err.retryable).to.be.false;
    });

    it("ContractError", () => {
      const err = new ContractError("reverted", ZaseonErrorCode.TRANSACTION_REVERTED, {
        transactionHash: "0x123",
        revertReason: "Overflow",
      });
      expect(err.name).to.equal("ContractError");
      expect(err.transactionHash).to.equal("0x123");
      expect(err.revertReason).to.equal("Overflow");
    });

    it("ContractError retryable for NONCE_TOO_LOW", () => {
      const err = new ContractError("nonce", ZaseonErrorCode.NONCE_TOO_LOW);
      expect(err.retryable).to.be.true;
    });

    it("NetworkError", () => {
      const err = new NetworkError("timeout", { endpoint: "http://rpc", statusCode: 503 });
      expect(err.name).to.equal("NetworkError");
      expect(err.endpoint).to.equal("http://rpc");
      expect(err.statusCode).to.equal(503);
      expect(err.retryable).to.be.true;
    });

    it("ProofError", () => {
      const err = new ProofError("gen failed", ZaseonErrorCode.PROOF_GENERATION_FAILED, {
        proofType: "groth16",
        circuitId: "nullifier",
      });
      expect(err.name).to.equal("ProofError");
      expect(err.proofType).to.equal("groth16");
      expect(err.circuitId).to.equal("nullifier");
    });

    it("StateError", () => {
      const err = new StateError("not found", ZaseonErrorCode.CONTAINER_NOT_FOUND, {
        entityId: "0xabc",
        entityType: "container",
      });
      expect(err.name).to.equal("StateError");
      expect(err.entityId).to.equal("0xabc");
    });

    it("ComplianceError", () => {
      const err = new ComplianceError("blocked", ZaseonErrorCode.JURISDICTION_BLOCKED, {
        policyId: "p1",
        violation: "US",
      });
      expect(err.name).to.equal("ComplianceError");
      expect(err.policyId).to.equal("p1");
      expect(err.violation).to.equal("US");
    });

    it("TimeoutError", () => {
      const err = new TimeoutError("prove", 5000);
      expect(err.name).to.equal("TimeoutError");
      expect(err.operation).to.equal("prove");
      expect(err.timeoutMs).to.equal(5000);
      expect(err.message).to.include("5000ms");
      expect(err.retryable).to.be.true;
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // parseContractError
  // ═══════════════════════════════════════════════════════════════
  describe("parseContractError", () => {
    it("should parse NullifierAlreadyConsumed", () => {
      const err = parseContractError(new Error("NullifierAlreadyConsumed()"));
      expect(err.code).to.equal(ZaseonErrorCode.NULLIFIER_ALREADY_CONSUMED);
    });

    it("should parse ContainerNotFound", () => {
      const err = parseContractError(new Error("ContainerNotFound(0x...)"));
      expect(err.code).to.equal(ZaseonErrorCode.CONTAINER_NOT_FOUND);
    });

    it("should parse PolicyNotFound", () => {
      const err = parseContractError(new Error("PolicyNotFound"));
      expect(err.code).to.equal(ZaseonErrorCode.POLICY_NOT_FOUND);
    });

    it("should parse PolicyExpired", () => {
      const err = parseContractError(new Error("PolicyExpired"));
      expect(err.code).to.equal(ZaseonErrorCode.POLICY_EXPIRED);
    });

    it("should parse nonce too low", () => {
      const err = parseContractError(new Error("nonce too low"));
      expect(err.code).to.equal(ZaseonErrorCode.NONCE_TOO_LOW);
    });

    it("should parse replacement transaction underpriced", () => {
      const err = parseContractError(new Error("replacement transaction underpriced"));
      expect(err.code).to.equal(ZaseonErrorCode.REPLACEMENT_UNDERPRICED);
    });

    it("should default to CONTRACT_CALL_FAILED", () => {
      const err = parseContractError(new Error("something else"));
      expect(err.code).to.equal(ZaseonErrorCode.CONTRACT_CALL_FAILED);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // isZaseonError type guard
  // ═══════════════════════════════════════════════════════════════
  describe("isZaseonError", () => {
    it("should return true for ZaseonError instances", () => {
      expect(isZaseonError(new ZaseonError("x"))).to.be.true;
      expect(isZaseonError(new ValidationError("x"))).to.be.true;
    });

    it("should return false for plain Error", () => {
      expect(isZaseonError(new Error("x"))).to.be.false;
    });

    it("should return false for non-errors", () => {
      expect(isZaseonError("string")).to.be.false;
      expect(isZaseonError(null)).to.be.false;
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // withRetry
  // ═══════════════════════════════════════════════════════════════
  describe("withRetry", () => {
    it("should return result on first success", async () => {
      const result = await withRetry(async () => 42);
      expect(result).to.equal(42);
    });

    it("should retry on retryable error and succeed", async () => {
      let attempts = 0;
      const result = await withRetry(
        async () => {
          attempts++;
          if (attempts < 2) {
            throw new NetworkError("intermittent");
          }
          return "ok";
        },
        { maxAttempts: 3, initialDelayMs: 10 }
      );
      expect(result).to.equal("ok");
      expect(attempts).to.equal(2);
    });

    it("should throw after max attempts", async () => {
      try {
        await withRetry(
          async () => { throw new NetworkError("always fails"); },
          { maxAttempts: 2, initialDelayMs: 10 }
        );
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(isZaseonError(e)).to.be.true;
        expect(e.code).to.equal(ZaseonErrorCode.NETWORK_ERROR);
      }
    });

    it("should not retry non-retryable errors", async () => {
      let attempts = 0;
      try {
        await withRetry(
          async () => {
            attempts++;
            throw new ValidationError("permanent");
          },
          { maxAttempts: 3, initialDelayMs: 10 }
        );
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(attempts).to.equal(1);
      }
    });

    it("should invoke onRetry callback", async () => {
      const retries: number[] = [];
      let attempts = 0;
      await withRetry(
        async () => {
          attempts++;
          if (attempts < 3) throw new NetworkError("fail");
          return true;
        },
        {
          maxAttempts: 3,
          initialDelayMs: 10,
          onRetry: (_err, attempt) => retries.push(attempt),
        }
      );
      expect(retries).to.deep.equal([1, 2]);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // withTimeout
  // ═══════════════════════════════════════════════════════════════
  describe("withTimeout", () => {
    it("should return result if within timeout", async () => {
      const r = await withTimeout(async () => "fast", 1000, "test");
      expect(r).to.equal("fast");
    });

    it("should throw TimeoutError if exceeded", async () => {
      try {
        await withTimeout(
          () => new Promise((resolve) => setTimeout(resolve, 200)),
          50,
          "slow_op"
        );
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e).to.be.instanceOf(TimeoutError);
        expect(e.operation).to.equal("slow_op");
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // withRetryAndTimeout
  // ═══════════════════════════════════════════════════════════════
  describe("withRetryAndTimeout", () => {
    it("should combine retry and timeout", async () => {
      let attempts = 0;
      const r = await withRetryAndTimeout(
        async () => {
          attempts++;
          if (attempts < 2) throw new NetworkError("retry me");
          return "done";
        },
        { maxAttempts: 3, initialDelayMs: 10, timeoutMs: 5000, operation: "combo" }
      );
      expect(r).to.equal("done");
      expect(attempts).to.equal(2);
    });
  });
});
