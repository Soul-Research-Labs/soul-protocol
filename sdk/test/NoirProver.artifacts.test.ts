import { expect } from "chai";
import * as fs from "fs/promises";
import * as path from "path";
import {
  NoirProver,
  Circuit,
  createProver,
  type CircuitArtifact,
} from "../src/zkprover/NoirProver";

/**
 * Tests that verify real Noir circuit artifacts load correctly.
 * Requires `nargo compile --workspace` to have been run from the project root
 * (artifacts at noir/{circuit}/target/{circuit}.json).
 */

const PROJECT_ROOT = path.resolve(__dirname, "..", "..");
const NOIR_TARGET = (circuit: string) =>
  path.join(PROJECT_ROOT, "noir", "target", `${circuit}.json`);

// All 21 circuits in the workspace
const ALL_CIRCUITS = [
  "accredited_investor",
  "aggregator",
  "balance_proof",
  "compliance_proof",
  "container",
  "cross_chain_proof",
  "cross_domain_nullifier",
  "encrypted_transfer",
  "liquidity_proof",
  "merkle_proof",
  "nullifier",
  "pedersen_commitment",
  "policy",
  "policy_bound_proof",
  "private_transfer",
  "ring_signature",
  "sanctions_check",
  "shielded_pool",
  "state_commitment",
  "state_transfer",
  "swap_proof",
];

describe("NoirProver (compiled artifacts)", () => {
  describe("artifact files exist", () => {
    for (const circuit of ALL_CIRCUITS) {
      it(`${circuit}.json exists`, async () => {
        const artifactPath = NOIR_TARGET(circuit);
        const stat = await fs.stat(artifactPath);
        expect(stat.isFile()).to.be.true;
        expect(stat.size).to.be.greaterThan(0);
      });
    }
  });

  describe("artifact structure", () => {
    for (const circuit of ALL_CIRCUITS) {
      it(`${circuit}.json has valid ACIR structure`, async () => {
        const data = await fs.readFile(NOIR_TARGET(circuit), "utf-8");
        const artifact = JSON.parse(data);

        // Nargo compiled artifacts have a bytecode field (base64-encoded ACIR)
        expect(artifact).to.have.property("bytecode");
        expect(artifact.bytecode).to.be.a("string");
        expect(artifact.bytecode.length).to.be.greaterThan(0);

        // ABI describes circuit inputs
        expect(artifact).to.have.property("abi");
        expect(artifact.abi).to.have.property("parameters");
        expect(artifact.abi.parameters).to.be.an("array");

        // Every circuit should have at least one parameter
        expect(artifact.abi.parameters.length).to.be.greaterThan(0);
      });
    }
  });

  describe("loadCircuit() with cwd override", () => {
    let prover: NoirProver;
    let originalCwd: string;

    before(() => {
      originalCwd = process.cwd();
      process.chdir(PROJECT_ROOT);
    });

    after(() => {
      process.chdir(originalCwd);
    });

    beforeEach(() => {
      prover = createProver();
    });

    it("should load balance_proof with non-empty bytecode", async () => {
      const artifact = await prover.loadCircuit(Circuit.BalanceProof);
      expect(artifact.bytecode).to.be.a("string");
      expect(artifact.bytecode.length).to.be.greaterThan(100);
      expect(artifact.abi.parameters!.length).to.be.greaterThan(0);
    });

    it("should load all Circuit enum values", async () => {
      const circuits = Object.values(Circuit);
      for (const circuit of circuits) {
        const artifact = await prover.loadCircuit(circuit);
        expect(artifact.bytecode.length).to.be.greaterThan(0,
          `Circuit ${circuit} has empty bytecode`);
      }
    });

    it("should cache loaded artifacts", async () => {
      const a = await prover.loadCircuit(Circuit.Nullifier);
      const b = await prover.loadCircuit(Circuit.Nullifier);
      expect(a).to.equal(b); // same reference
    });
  });
});
