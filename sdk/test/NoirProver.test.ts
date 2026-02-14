import { expect } from "chai";
import {
  NoirProver,
  Circuit,
  createProver,
  getProver,
  type ProofResult,
} from "../src/zkprover/NoirProver";

describe("NoirProver", () => {
  let prover: NoirProver;

  beforeEach(() => {
    prover = createProver();
  });

  describe("initialize()", () => {
    it("should initialize without error", async () => {
      await prover.initialize();
    });

    it("should be idempotent", async () => {
      await prover.initialize();
      await prover.initialize(); // second call should be a no-op
    });
  });

  describe("getProver() singleton", () => {
    it("should return the same instance on multiple calls", async () => {
      const a = await getProver();
      const b = await getProver();
      expect(a).to.equal(b);
    });
  });

  describe("generateProof()", () => {
    it("should generate a state commitment proof", async () => {
      const result = await prover.generateProof(Circuit.StateCommitment, {
        secret: "0x" + "aa".repeat(32),
        nullifier: "0x" + "bb".repeat(32),
        amount: "1000000",
      });

      expect(result).to.have.property("proof");
      expect(result).to.have.property("publicInputs");
      expect(result).to.have.property("proofHex");
      expect(result.proof).to.be.instanceOf(Uint8Array);
      expect(result.proof.length).to.equal(256);
      expect(result.proofHex).to.match(/^0x[0-9a-f]+$/);
    });

    it("should generate a nullifier proof", async () => {
      const result = await prover.generateProof(Circuit.Nullifier, {
        secret: "0x" + "cc".repeat(32),
        leafIndex: 42,
      });

      expect(result.publicInputs.length).to.be.greaterThan(0);
    });

    it("should generate a merkle proof", async () => {
      const result = await prover.generateProof(Circuit.MerkleProof, {
        leaf: "0x" + "11".repeat(32),
        root: "0x" + "22".repeat(32),
        pathElements: ["0x" + "33".repeat(32)],
        pathIndices: [0],
      });

      expect(result.publicInputs).to.include("0x" + "22".repeat(32)); // root
      expect(result.publicInputs).to.include("0x" + "11".repeat(32)); // leaf
    });

    it("should produce deterministic proofs for the same inputs", async () => {
      const inputs = {
        secret: "0x" + "dd".repeat(32),
        nullifier: "0x" + "ee".repeat(32),
        amount: "500",
      };

      const a = await prover.generateProof(Circuit.StateCommitment, inputs);
      const b = await prover.generateProof(Circuit.StateCommitment, inputs);

      expect(a.proofHex).to.equal(b.proofHex);
    });

    it("should produce different proofs for different inputs", async () => {
      const a = await prover.generateProof(Circuit.StateCommitment, {
        secret: "0x" + "11".repeat(32),
        nullifier: "0x" + "22".repeat(32),
        amount: "100",
      });
      const b = await prover.generateProof(Circuit.StateCommitment, {
        secret: "0x" + "33".repeat(32),
        nullifier: "0x" + "44".repeat(32),
        amount: "200",
      });

      expect(a.proofHex).to.not.equal(b.proofHex);
    });
  });

  describe("verifyProof()", () => {
    it("should reject proofs shorter than 256 bytes", async () => {
      const fakeProof: ProofResult = {
        proof: new Uint8Array(100),
        publicInputs: ["0x01"],
        proofHex: "0x" + "00".repeat(100),
      };

      const valid = await prover.verifyProof(
        Circuit.StateCommitment,
        fakeProof,
        ["0x01"],
      );
      expect(valid).to.be.false;
    });

    it("should reject proofs with no public inputs", async () => {
      const fakeProof: ProofResult = {
        proof: new Uint8Array(256),
        publicInputs: [],
        proofHex: "0x" + "00".repeat(256),
      };

      const valid = await prover.verifyProof(
        Circuit.StateCommitment,
        fakeProof,
        [],
      );
      expect(valid).to.be.false;
    });

    it("should reject placeholder proofs without Barretenberg (security)", async () => {
      const result = await prover.generateProof(Circuit.StateCommitment, {
        secret: "0x" + "aa".repeat(32),
        nullifier: "0x" + "bb".repeat(32),
        amount: "1000",
      });

      const valid = await prover.verifyProof(
        Circuit.StateCommitment,
        result,
        result.publicInputs,
      );
      // SECURITY: Without Barretenberg, off-chain verification is disabled.
      // Callers must verify proofs on-chain.
      expect(valid).to.be.false;
    });
  });

  describe("convenience methods", () => {
    it("proveStateCommitment()", async () => {
      const result = await prover.proveStateCommitment({
        secret: ("0x" + "aa".repeat(32)) as `0x${string}`,
        nullifier: ("0x" + "bb".repeat(32)) as `0x${string}`,
        amount: BigInt(1000),
      });
      expect(result.proof.length).to.equal(256);
    });

    it("proveNullifier()", async () => {
      const result = await prover.proveNullifier({
        secret: ("0x" + "cc".repeat(32)) as `0x${string}`,
        leafIndex: 5,
      });
      expect(result.publicInputs.length).to.be.greaterThan(0);
    });

    it("proveBalance()", async () => {
      const result = await prover.proveBalance({
        balance: BigInt(1000),
        minBalance: BigInt(0),
        maxBalance: BigInt(10000),
        commitment: ("0x" + "dd".repeat(32)) as `0x${string}`,
        secret: ("0x" + "ee".repeat(32)) as `0x${string}`,
      });
      expect(result.proof.length).to.equal(256);
    });
  });

  describe("loadCircuit()", () => {
    it("should return placeholder artifact for missing circuits", async () => {
      const artifact = await prover.loadCircuit(Circuit.StateCommitment);
      expect(artifact).to.have.property("bytecode");
      expect(artifact).to.have.property("abi");
    });

    it("should cache loaded circuits", async () => {
      const a = await prover.loadCircuit(Circuit.MerkleProof);
      const b = await prover.loadCircuit(Circuit.MerkleProof);
      expect(a).to.equal(b);
    });
  });
});
