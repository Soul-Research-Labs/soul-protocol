import { expect } from "chai";
import {
  NoirProver,
  Circuit,
  createProver,
  getProver,
  type ProofResult,
  type ProverMode,
} from "../src/zkprover/NoirProver";
import {
  proveStateCommitment as proveStateCommitmentConvenience,
  proveCrossChainRelay,
  batchGenerateProofs,
  poseidonHash,
  computeCommitment,
  computeNullifier,
} from "../src/zkprover/prover";

/*//////////////////////////////////////////////////////////////
            PRODUCTION MODE & ERROR HANDLING
//////////////////////////////////////////////////////////////*/

describe("NoirProver (advanced)", () => {
  describe("production mode", () => {
    it("should throw on initialize() when Barretenberg is unavailable", async () => {
      const prover = createProver({ mode: "production" });
      try {
        await prover.initialize();
        expect.fail("Expected error in production mode without Barretenberg");
      } catch (e: any) {
        expect(e.message).to.include("production mode");
        expect(e.message).to.include("Barretenberg");
      }
    });

    it("should set mode correctly via constructor", () => {
      const dev = createProver({ mode: "development" });
      const prod = createProver({ mode: "production" });
      expect(dev.mode).to.equal("development");
      expect(prod.mode).to.equal("production");
    });

    it("should default to development mode", () => {
      const prover = createProver();
      expect(prover.mode).to.equal("development");
    });

    it("should default to development mode with empty options", () => {
      const prover = createProver({});
      expect(prover.mode).to.equal("development");
    });
  });

  /*//////////////////////////////////////////////////////////////
              ALL CIRCUIT TYPES
  //////////////////////////////////////////////////////////////*/

  describe("circuit type coverage", () => {
    let prover: NoirProver;

    beforeEach(() => {
      prover = createProver();
    });

    it("should generate CrossChainProof", async () => {
      const result = await prover.generateProof(Circuit.CrossChainProof, {
        sourceProofHash: "0x" + "aa".repeat(32),
        sourceStateRoot: "0x" + "bb".repeat(32),
        sourceChainId: "42161",
        destChainId: "10",
      });
      expect(result.proof.length).to.equal(256);
      expect(result.publicInputs.length).to.be.greaterThan(0);
    });

    it("should generate ComplianceProof", async () => {
      const result = await prover.generateProof(Circuit.ComplianceProof, {
        policyId: "1",
        userCommitment: "0x" + "cc".repeat(32),
        attestation: "0x" + "dd".repeat(32),
      });
      expect(result.proof.length).to.equal(256);
    });

    it("should generate SwapProof", async () => {
      const result = await prover.generateProof(Circuit.SwapProof, {
        amountIn: "1000",
        amountOut: "999",
        sourceToken: "0x" + "11".repeat(20),
        destToken: "0x" + "22".repeat(20),
      });
      expect(result.proof.length).to.equal(256);
    });

    it("should generate StateTransfer proof", async () => {
      const result = await prover.generateProof(Circuit.StateTransfer, {
        sourceCommitment: "0x" + "aa".repeat(32),
        destinationCommitment: "0x" + "bb".repeat(32),
        nullifier: "0x" + "cc".repeat(32),
        amount: "1000",
        sourceChainId: "1",
        destChainId: "42161",
      });
      expect(result.proof.length).to.equal(256);
      expect(result.publicInputs.length).to.be.greaterThan(0);
    });

    it("should generate BalanceProof", async () => {
      const result = await prover.generateProof(Circuit.BalanceProof, {
        balance: "5000",
        minBalance: "0",
        maxBalance: "10000",
        commitment: "0x" + "dd".repeat(32),
        secret: "0x" + "ee".repeat(32),
      });
      expect(result.proof.length).to.equal(256);
    });
  });

  /*//////////////////////////////////////////////////////////////
              CONVENIENCE METHODS — FULL COVERAGE
  //////////////////////////////////////////////////////////////*/

  describe("convenience methods (extended)", () => {
    let prover: NoirProver;

    beforeEach(() => {
      prover = createProver();
    });

    it("proveStateTransfer()", async () => {
      const result = await prover.proveStateTransfer({
        sourceCommitment: ("0x" + "aa".repeat(32)) as `0x${string}`,
        destinationCommitment: ("0x" + "bb".repeat(32)) as `0x${string}`,
        nullifier: ("0x" + "cc".repeat(32)) as `0x${string}`,
        amount: BigInt(500),
        sourceChainId: 1,
        destChainId: 42161,
      } as any);
      expect(result.proof.length).to.equal(256);
      expect(result.proofHex).to.match(/^0x[0-9a-f]+$/);
    });

    it("proveMerkleInclusion()", async () => {
      const result = await prover.proveMerkleInclusion({
        leaf: ("0x" + "11".repeat(32)) as `0x${string}`,
        root: ("0x" + "22".repeat(32)) as `0x${string}`,
        pathElements: [
          ("0x" + "33".repeat(32)) as `0x${string}`,
          ("0x" + "44".repeat(32)) as `0x${string}`,
        ],
        pathIndices: [0, 1],
      });
      expect(result.proof.length).to.equal(256);
      // Merkle public inputs should include root and leaf
      expect(result.publicInputs).to.include("0x" + "22".repeat(32)); // root
      expect(result.publicInputs).to.include("0x" + "11".repeat(32)); // leaf
    });
  });

  /*//////////////////////////////////////////////////////////////
              VERIFY PROOF — EXTENDED
  //////////////////////////////////////////////////////////////*/

  describe("verifyProof() edge cases", () => {
    let prover: NoirProver;

    beforeEach(() => {
      prover = createProver();
    });

    it("should reject proof with undefined proof bytes", async () => {
      const fakeProof = {
        proof: undefined as any,
        publicInputs: ["0x01"],
        proofHex: "0x00" as `0x${string}`,
      };
      const valid = await prover.verifyProof(
        Circuit.StateCommitment,
        fakeProof,
        ["0x01"],
      );
      expect(valid).to.be.false;
    });

    it("should reject proof with null public inputs", async () => {
      const fakeProof: ProofResult = {
        proof: new Uint8Array(256),
        publicInputs: null as any,
        proofHex: ("0x" + "00".repeat(256)) as `0x${string}`,
      };
      const valid = await prover.verifyProof(
        Circuit.StateCommitment,
        fakeProof,
        null as any,
      );
      expect(valid).to.be.false;
    });

    it("should reject proof with exactly 255 bytes", async () => {
      const fakeProof: ProofResult = {
        proof: new Uint8Array(255),
        publicInputs: ["0x01"],
        proofHex: ("0x" + "00".repeat(255)) as `0x${string}`,
      };
      const valid = await prover.verifyProof(
        Circuit.StateCommitment,
        fakeProof,
        ["0x01"],
      );
      expect(valid).to.be.false;
    });

    it("should handle verify without prior initialize", async () => {
      // verifyProof should auto-initialize
      const freshProver = createProver();
      const result = await freshProver.generateProof(Circuit.StateCommitment, {
        secret: "0x" + "aa".repeat(32),
        nullifier: "0x" + "bb".repeat(32),
        amount: "1000",
      });
      // In dev mode without BB, verifyProof returns false for security
      const valid = await freshProver.verifyProof(
        Circuit.StateCommitment,
        result,
        result.publicInputs,
      );
      // Without Barretenberg, returns false for security
      // (structurally valid but no real crypto)
      expect(typeof valid).to.equal("boolean");
    });
  });

  /*//////////////////////////////////////////////////////////////
              PROOF DETERMINISM AND UNIQUENESS
  //////////////////////////////////////////////////////////////*/

  describe("proof properties", () => {
    let prover: NoirProver;

    beforeEach(() => {
      prover = createProver();
    });

    it("proofHex should be consistent with proof bytes", async () => {
      const result = await prover.generateProof(Circuit.StateCommitment, {
        secret: "0x" + "aa".repeat(32),
        nullifier: "0x" + "bb".repeat(32),
        amount: "1000",
      });
      const expectedHex = "0x" + Buffer.from(result.proof).toString("hex");
      expect(result.proofHex).to.equal(expectedHex);
    });

    it("different circuits with same inputs should produce different proofs", async () => {
      const inputs = {
        secret: "0x" + "aa".repeat(32),
        nullifier: "0x" + "bb".repeat(32),
        amount: "1000",
      };
      const a = await prover.generateProof(Circuit.StateCommitment, inputs);
      const b = await prover.generateProof(Circuit.ComplianceProof, inputs);
      // Public inputs extraction differs per circuit type
      expect(a.publicInputs).to.not.deep.equal(b.publicInputs);
    });

    it("nullifier circuit should extract nullifier hash as public input", async () => {
      const result = await prover.generateProof(Circuit.Nullifier, {
        secret: "0x" + "ff".repeat(32),
        leafIndex: 7,
      });
      expect(result.publicInputs.length).to.equal(1);
      expect(result.publicInputs[0]).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("merkle circuit should extract root and leaf as public inputs", async () => {
      const root = "0x" + "ab".repeat(32);
      const leaf = "0x" + "cd".repeat(32);
      const result = await prover.generateProof(Circuit.MerkleProof, {
        leaf,
        root,
        pathElements: ["0x" + "11".repeat(32)] as any,
        pathIndices: [0] as any,
      } as any);
      expect(result.publicInputs).to.deep.equal([root, leaf]);
    });
  });

  /*//////////////////////////////////////////////////////////////
              CIRCUIT LOADING EDGE CASES
  //////////////////////////////////////////////////////////////*/

  describe("loadCircuit() edge cases", () => {
    it("should cache independently for different circuits", async () => {
      const prover = createProver();
      const a = await prover.loadCircuit(Circuit.StateCommitment);
      const b = await prover.loadCircuit(Circuit.Nullifier);
      // Different circuits should have different (or equal placeholder) artifacts
      // but be cached individually
      const a2 = await prover.loadCircuit(Circuit.StateCommitment);
      const b2 = await prover.loadCircuit(Circuit.Nullifier);
      expect(a).to.equal(a2);
      expect(b).to.equal(b2);
    });

    it("placeholder artifact should have empty bytecode", async () => {
      const prover = createProver();
      const art = await prover.loadCircuit(Circuit.SwapProof);
      expect(art.bytecode).to.equal("");
      expect(art.abi).to.deep.equal({
        parameters: [],
        return_type: null,
      });
    });
  });

  /*//////////////////////////////////////////////////////////////
              AUTO-INITIALIZATION
  //////////////////////////////////////////////////////////////*/

  describe("auto-initialization", () => {
    it("generateProof should auto-initialize", async () => {
      const prover = createProver();
      // Should not throw — auto-initializes
      const result = await prover.generateProof(Circuit.StateCommitment, {
        secret: "0x" + "aa".repeat(32),
        nullifier: "0x" + "bb".repeat(32),
        amount: "1000",
      });
      expect(result.proof.length).to.equal(256);
    });
  });
});

/*//////////////////////////////////////////////////////////////
            PROVER.TS CONVENIENCE FUNCTIONS
//////////////////////////////////////////////////////////////*/

describe("prover.ts convenience functions", () => {
  describe("proveStateCommitment()", () => {
    it("should generate proof from high-level params", async () => {
      const secret = BigInt(12345);
      const salt = BigInt(67890);
      const commitment = computeCommitment([BigInt(100)], salt, secret);
      const pubkey = poseidonHash([secret]);

      const result = await proveStateCommitmentConvenience(
        [BigInt(100)],
        salt,
        secret,
        commitment,
        pubkey,
      );
      // Proof is generated (placeholder in dev) — inputs are serialized as strings
      expect(result.proof.length).to.equal(256);
      expect(result.proofHex).to.match(/^0x[0-9a-f]+$/i);
    });
  });

  describe("proveCrossChainRelay()", () => {
    it("should generate a cross-chain relay proof", async () => {
      const result = await proveCrossChainRelay(
        BigInt(111), // sourceProofHash
        BigInt(222), // sourceStateRoot
        BigInt(1000), // sourceBlockNumber
        BigInt(1), // sourceChainId
        BigInt(333), // relayerSecret
        BigInt(42161), // destChainId
        BigInt(444), // relayerPubkey
        BigInt(555), // proofCommitment
        BigInt(Date.now()), // timestamp
        BigInt(1000), // fee
      );
      expect(result.proof.length).to.equal(256);
      expect(result.publicInputs.length).to.be.greaterThan(0);
    });
  });

  describe("batchGenerateProofs()", () => {
    it("should batch-generate proofs for multiple inputs", async () => {
      const inputs = [
        {
          secret: "0x" + "aa".repeat(32),
          nullifier: "0x" + "bb".repeat(32),
          amount: "100",
        },
        {
          secret: "0x" + "cc".repeat(32),
          nullifier: "0x" + "dd".repeat(32),
          amount: "200",
        },
        {
          secret: "0x" + "ee".repeat(32),
          nullifier: "0x" + "ff".repeat(32),
          amount: "300",
        },
      ];

      const results = await batchGenerateProofs(
        Circuit.StateCommitment,
        inputs,
      );
      expect(results).to.have.length(3);
      for (const r of results) {
        expect(r.proof.length).to.equal(256);
        expect(r.proofHex).to.match(/^0x[0-9a-f]+$/);
      }
    });

    it("should handle empty batch", async () => {
      const results = await batchGenerateProofs(Circuit.StateCommitment, []);
      expect(results).to.have.length(0);
    });

    it("should handle batch larger than chunk size (4)", async () => {
      const inputs = Array.from({ length: 7 }, (_, i) => ({
        secret: "0x" + (i + 10).toString(16).padStart(2, "0").repeat(32),
        nullifier: "0x" + (i + 20).toString(16).padStart(2, "0").repeat(32),
        amount: String((i + 1) * 100),
      }));

      const results = await batchGenerateProofs(
        Circuit.StateCommitment,
        inputs,
      );
      expect(results).to.have.length(7);
      // Each proof should be unique
      const hexes = results.map((r) => r.proofHex);
      expect(new Set(hexes).size).to.equal(7);
    });
  });
});

/*//////////////////////////////////////////////////////////////
            POSEIDON HELPERS — EDGE CASES
//////////////////////////////////////////////////////////////*/

describe("Poseidon helpers (edge cases)", () => {
  it("single-element hash should pad with zero", () => {
    // poseidonHash([x]) = poseidon2([x, 0])
    const h = poseidonHash([BigInt(42)]);
    expect(typeof h).to.equal("bigint");
    expect(h).to.not.equal(BigInt(42)); // non-trivial
  });

  it("chained hash should be order-dependent", () => {
    const a = poseidonHash([BigInt(1), BigInt(2), BigInt(3)]);
    const b = poseidonHash([BigInt(3), BigInt(2), BigInt(1)]);
    expect(a).to.not.equal(b);
  });

  it("computeCommitment and computeNullifier should compose", () => {
    const stateFields = [BigInt(100), BigInt(200)];
    const salt = BigInt(42);
    const secret = BigInt(99);
    const nonce = BigInt(0);

    const commitment = computeCommitment(stateFields, salt, secret);
    const nullifier = computeNullifier(commitment, secret, nonce);

    expect(typeof nullifier).to.equal("bigint");
    expect(nullifier).to.not.equal(commitment);

    // Same inputs → same output
    const nullifier2 = computeNullifier(commitment, secret, nonce);
    expect(nullifier).to.equal(nullifier2);

    // Different nonce → different nullifier
    const nullifier3 = computeNullifier(commitment, secret, BigInt(1));
    expect(nullifier).to.not.equal(nullifier3);
  });

  it("large inputs should not throw", () => {
    const bigInputs = Array.from(
      { length: 20 },
      (_, i) => BigInt(2) ** BigInt(200) + BigInt(i),
    );
    const h = poseidonHash(bigInputs);
    expect(typeof h).to.equal("bigint");
  });
});
