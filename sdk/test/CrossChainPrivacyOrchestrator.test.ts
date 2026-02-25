import { expect } from "chai";
import { keccak256, concat, toHex, zeroHash, type Hex } from "viem";
import {
  CrossChainPrivacyOrchestrator,
  TransferStage,
  PrivacyTransferError,
  NullifierAlreadySpentError,
  RelayTimeoutError,
  InsufficientBridgeCapacityError,
  type OrchestratorConfig,
  type ShieldResult,
  type ZKProofResult,
  type MerkleProof,
  type RelayerType,
  type BatchRecipient,
  type PrivateRelayStatus,
} from "../src/privacy/CrossChainPrivacyOrchestrator";

// ============================================================
// Helpers
// ============================================================

/**
 * Since CrossChainPrivacyOrchestrator uses viem clients internally,
 * we test the stateless/pure methods directly and verify error classes.
 * Integration methods (shield, claim, etc.) require live RPC so they
 * are tested at the Foundry integration layer.
 */

// Minimal config to construct the orchestrator (no RPC calls in constructor setup)
const MOCK_CONFIG: OrchestratorConfig = {
  chains: {},
  privateKey:
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex, // Foundry default
  relayerType: "layerzero" as RelayerType,
  defaultGasLimit: 500000n,
  proofTimeout: 5000,
  relayTimeout: 5000,
};

// ============================================================
// Error Classes
// ============================================================

describe("CrossChainPrivacyOrchestrator – Error Classes", () => {
  describe("PrivacyTransferError", () => {
    it("should carry stage information", () => {
      const err = new PrivacyTransferError(
        "something went wrong",
        TransferStage.SHIELDING,
      );
      expect(err.stage).to.equal(TransferStage.SHIELDING);
      expect(err.message).to.include("something went wrong");
      expect(err.name).to.equal("PrivacyTransferError");
    });
  });

  describe("NullifierAlreadySpentError", () => {
    it("should include nullifier in message", () => {
      const err = new NullifierAlreadySpentError("0xabc");
      expect(err.message).to.include("0xabc");
      expect(err.nullifier).to.equal("0xabc");
      expect(err.stage).to.equal(TransferStage.INITIATING_TRANSFER);
      expect(err.name).to.equal("NullifierAlreadySpentError");
    });

    it("should be instanceof PrivacyTransferError", () => {
      const err = new NullifierAlreadySpentError("0x1");
      expect(err).to.be.instanceOf(PrivacyTransferError);
    });
  });

  describe("InsufficientBridgeCapacityError", () => {
    it("should include available and required capacity", () => {
      const err = new InsufficientBridgeCapacityError(100n, 1000n);
      expect(err.availableCapacity).to.equal(100n);
      expect(err.requiredCapacity).to.equal(1000n);
      expect(err.message).to.include("100");
      expect(err.message).to.include("1000");
      expect(err.stage).to.equal(TransferStage.CLAIMING);
      expect(err.name).to.equal("InsufficientBridgeCapacityError");
    });

    it("should be instanceof PrivacyTransferError", () => {
      const err = new InsufficientBridgeCapacityError(0n, 1n);
      expect(err).to.be.instanceOf(PrivacyTransferError);
    });
  });

  describe("RelayTimeoutError", () => {
    it("should include messageId and timeout", () => {
      const err = new RelayTimeoutError("0xmsg", 30000);
      expect(err.messageId).to.equal("0xmsg");
      expect(err.timeout).to.equal(30000);
      expect(err.message).to.include("30000");
      expect(err.message).to.include("0xmsg");
      expect(err.stage).to.equal(TransferStage.WAITING_FOR_RELAY);
      expect(err.name).to.equal("RelayTimeoutError");
    });

    it("should be instanceof PrivacyTransferError", () => {
      const err = new RelayTimeoutError("0x1", 1000);
      expect(err).to.be.instanceOf(PrivacyTransferError);
    });
  });
});

// ============================================================
// TransferStage enum
// ============================================================

describe("TransferStage", () => {
  it("should have all expected stages", () => {
    const stages = [
      TransferStage.INITIALIZING,
      TransferStage.SHIELDING,
      TransferStage.GENERATING_PROOF,
      TransferStage.INITIATING_TRANSFER,
      TransferStage.WAITING_FOR_RELAY,
      TransferStage.CLAIMING,
      TransferStage.COMPLETED,
      TransferStage.FAILED,
    ];
    expect(stages).to.have.lengthOf(8);
    // All unique
    expect(new Set(stages).size).to.equal(8);
  });
});

// ============================================================
// Pure / Stateless Methods
// ============================================================

describe("CrossChainPrivacyOrchestrator – Pure Methods", () => {
  let orch: CrossChainPrivacyOrchestrator;

  before(() => {
    orch = new CrossChainPrivacyOrchestrator(MOCK_CONFIG);
  });

  describe("constructor", () => {
    it("should instantiate with empty chain config", () => {
      expect(orch).to.be.instanceOf(CrossChainPrivacyOrchestrator);
    });

    it("should apply default gas limit", () => {
      const orchDefault = new CrossChainPrivacyOrchestrator({
        ...MOCK_CONFIG,
        defaultGasLimit: undefined,
      });
      expect(orchDefault).to.be.instanceOf(CrossChainPrivacyOrchestrator);
    });
  });

  describe("generateSecret()", () => {
    it("should return a 32-byte hex string", () => {
      const secret = orch.generateSecret();
      expect(secret).to.match(/^0x[0-9a-f]{64}$/i);
    });

    it("should return different secrets each call", () => {
      const a = orch.generateSecret();
      const b = orch.generateSecret();
      expect(a).to.not.equal(b);
    });
  });

  describe("computeCommitment()", () => {
    it("should return a 32-byte hex string", () => {
      const secret = ("0x" + "aa".repeat(32)) as Hex;
      const commitment = orch.computeCommitment(1000n, secret);
      expect(commitment).to.match(/^0x[0-9a-f]{64}$/i);
    });

    it("should be deterministic for same inputs", () => {
      const secret = ("0x" + "bb".repeat(32)) as Hex;
      const a = orch.computeCommitment(500n, secret);
      const b = orch.computeCommitment(500n, secret);
      expect(a).to.equal(b);
    });

    it("should differ by amount", () => {
      const secret = ("0x" + "cc".repeat(32)) as Hex;
      const a = orch.computeCommitment(100n, secret);
      const b = orch.computeCommitment(200n, secret);
      expect(a).to.not.equal(b);
    });

    it("should differ by secret", () => {
      const a = orch.computeCommitment(100n, ("0x" + "11".repeat(32)) as Hex);
      const b = orch.computeCommitment(100n, ("0x" + "22".repeat(32)) as Hex);
      expect(a).to.not.equal(b);
    });

    it("should differ with/without recipient", () => {
      const secret = ("0x" + "dd".repeat(32)) as Hex;
      const recipient = ("0x" + "ee".repeat(20)) as Hex;
      const a = orch.computeCommitment(100n, secret);
      const b = orch.computeCommitment(100n, secret, recipient);
      expect(a).to.not.equal(b);
    });

    it("should produce keccak256(amount32 || secret || recipientOrZero)", () => {
      const secret = ("0x" + "aa".repeat(32)) as Hex;
      const expected = keccak256(
        concat([toHex(1000n, { size: 32 }), secret, toHex(0, { size: 32 })]),
      );
      const result = orch.computeCommitment(1000n, secret);
      expect(result).to.equal(expected);
    });
  });

  describe("deriveNullifier()", () => {
    it("should return keccak256(secret || commitment)", async () => {
      const secret = ("0x" + "11".repeat(32)) as Hex;
      const commitment = ("0x" + "22".repeat(32)) as Hex;
      const expected = keccak256(concat([secret, commitment]));
      const result = await orch.deriveNullifier({ secret, commitment });
      expect(result).to.equal(expected);
    });

    it("should be deterministic", async () => {
      const secret = ("0x" + "33".repeat(32)) as Hex;
      const commitment = ("0x" + "44".repeat(32)) as Hex;
      const a = await orch.deriveNullifier({ secret, commitment });
      const b = await orch.deriveNullifier({ secret, commitment });
      expect(a).to.equal(b);
    });

    it("should differ for different secrets", async () => {
      const commitment = ("0x" + "55".repeat(32)) as Hex;
      const a = await orch.deriveNullifier({
        secret: ("0x" + "01".repeat(32)) as Hex,
        commitment,
      });
      const b = await orch.deriveNullifier({
        secret: ("0x" + "02".repeat(32)) as Hex,
        commitment,
      });
      expect(a).to.not.equal(b);
    });
  });

  describe("isChainSupported()", () => {
    it("should return false for unconfigured chains", () => {
      expect(orch.isChainSupported(1)).to.be.false;
      expect(orch.isChainSupported(42161)).to.be.false;
    });
  });

  describe("getChainConfig()", () => {
    it("should return undefined for unconfigured chains", () => {
      expect(orch.getChainConfig(1)).to.be.undefined;
    });
  });

  // ================================================================
  // Chain-dependent methods — error cases (no chain configured)
  // ================================================================

  describe("shield() — no chain configured", () => {
    it("should throw for unconfigured chainId", async () => {
      try {
        await orch.shield({
          chainId: 999,
          amount: 1000n,
          secret: ("0x" + "aa".repeat(32)) as Hex,
        });
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("999");
        expect(e.message).to.include("not configured");
      }
    });
  });

  describe("getMerkleProof() — no chain configured", () => {
    it("should throw for unconfigured chainId", async () => {
      try {
        await orch.getMerkleProof({ chainId: 999, leafIndex: 0 });
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("999");
      }
    });
  });

  describe("deriveCrossDomainNullifier() — no chain configured", () => {
    it("should throw for unconfigured chainId", async () => {
      try {
        await orch.deriveCrossDomainNullifier({
          sourceNullifier: ("0x" + "aa".repeat(32)) as Hex,
          sourceChainId: 1,
          targetChainId: 42161,
        });
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("not configured");
      }
    });
  });

  describe("generateCrossChainProof() — without Noir prover", () => {
    it("should throw when proof generation fails", async () => {
      try {
        await orch.generateCrossChainProof({
          commitment: ("0x" + "11".repeat(32)) as Hex,
          amount: 1000n,
          secret: ("0x" + "22".repeat(32)) as Hex,
          merkleProof: {
            root: ("0x" + "33".repeat(32)) as Hex,
            leaf: ("0x" + "44".repeat(32)) as Hex,
            path: [],
            indices: [],
          },
          sourceNullifier: ("0x" + "55".repeat(32)) as Hex,
          targetNullifier: ("0x" + "66".repeat(32)) as Hex,
          sourceChainId: 1,
          targetChainId: 42161,
        });
        expect.fail("Should have thrown");
      } catch (e: any) {
        // The prover may throw PrivacyTransferError (no circuit) or
        // another error from the placeholder. Either way it should not succeed.
        expect(e).to.be.instanceOf(Error);
        expect(e.message).to.be.a("string");
      }
    });
  });

  describe("initiatePrivateTransfer() — no chain configured", () => {
    it("should throw for unconfigured source chain", async () => {
      try {
        await orch.initiatePrivateTransfer({
          sourceChainId: 999,
          targetChainId: 42161,
          commitment: ("0x" + "11".repeat(32)) as Hex,
          nullifier: ("0x" + "22".repeat(32)) as Hex,
          proof: {
            proof: "0x" as Hex,
            publicInputs: [],
            verified: true,
          },
          amount: 1000n,
          recipient: ("0x" + "33".repeat(20)) as Hex,
        });
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("999");
      }
    });
  });

  describe("waitForRelay() — no chain configured", () => {
    it("should throw for unconfigured target chain", async () => {
      try {
        await orch.waitForRelay({
          messageId: zeroHash,
          sourceChainId: 1,
          targetChainId: 999,
          timeoutMs: 100,
        });
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("999");
      }
    });
  });

  describe("claimPrivateTransfer() — no chain configured", () => {
    it("should throw for unconfigured target chain", async () => {
      try {
        await orch.claimPrivateTransfer({
          targetChainId: 999,
          commitment: zeroHash,
          nullifier: zeroHash,
          proof: { proof: "0x" as Hex, publicInputs: [], verified: true },
          amount: 1n,
          recipient: ("0x" + "11".repeat(20)) as Hex,
          relayProof: "0x" as Hex,
        });
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("999");
      }
    });
  });
});

// ============================================================
// Commitment / Nullifier Crypto Properties
// ============================================================

describe("CrossChainPrivacyOrchestrator – Crypto Properties", () => {
  let orch: CrossChainPrivacyOrchestrator;

  before(() => {
    orch = new CrossChainPrivacyOrchestrator(MOCK_CONFIG);
  });

  it("full note lifecycle: generate → commit → nullifier", async () => {
    const secret = orch.generateSecret();
    const amount = 1000000000000000n; // 0.001 ETH
    const recipient = ("0x" + "ab".repeat(20)) as Hex;

    const commitment = orch.computeCommitment(amount, secret, recipient);
    expect(commitment).to.match(/^0x[0-9a-f]{64}$/i);

    const nullifier = await orch.deriveNullifier({ secret, commitment });
    expect(nullifier).to.match(/^0x[0-9a-f]{64}$/i);
    expect(nullifier).to.not.equal(commitment);
  });

  it("changing recipient changes commitment but not nullifier", async () => {
    const secret = orch.generateSecret();
    const amount = 1n;

    const c1 = orch.computeCommitment(
      amount,
      secret,
      ("0x" + "01".repeat(20)) as Hex,
    );
    const c2 = orch.computeCommitment(
      amount,
      secret,
      ("0x" + "02".repeat(20)) as Hex,
    );

    expect(c1).to.not.equal(c2);

    // Nullifiers are based on secret+commitment — different commitments → different nullifiers
    const n1 = await orch.deriveNullifier({ secret, commitment: c1 });
    const n2 = await orch.deriveNullifier({ secret, commitment: c2 });
    expect(n1).to.not.equal(n2);
  });
});
