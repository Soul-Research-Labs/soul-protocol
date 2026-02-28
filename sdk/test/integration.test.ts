/**
 * Zaseon SDK Integration Test
 * 
 * Tests the SDK against deployed Sepolia contracts
 */

import { expect } from "chai";
import {
  ZaseonProtocolClient,
  createReadOnlyZaseonClient,
} from "../dist/client/ZaseonProtocolClient";
import { SEPOLIA_ADDRESSES } from "../dist/config/addresses";
import { NoirProver, Circuit } from "../dist/zkprover/NoirProver";
import type { Hex } from "viem";

const SEPOLIA_RPC = process.env.SEPOLIA_RPC || "https://rpc.sepolia.org";

describe("ZaseonProtocolClient", () => {
  describe("Read-only operations", () => {
    it("should create a read-only client", () => {
      const client = createReadOnlyZaseonClient(SEPOLIA_RPC);
      expect(client).to.exist;
      expect(client.chainId).to.equal(11155111);
      expect(client.addresses).to.deep.equal(SEPOLIA_ADDRESSES);
    });

    it("should have correct contract addresses", () => {
      const client = createReadOnlyZaseonClient(SEPOLIA_RPC);
      expect(client.addresses.zkBoundStateLocks).to.equal("0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78");
      expect(client.addresses.nullifierRegistry).to.equal("0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191");
      expect(client.addresses.proofHub).to.equal("0x40eaa5de0c6497c8943c967b42799cb092c26adc");
    });

    it("should generate secrets", () => {
      const client = createReadOnlyZaseonClient(SEPOLIA_RPC);
      const { secret, nullifier } = client.generateSecrets();
      
      expect(secret).to.match(/^0x[a-f0-9]{64}$/);
      expect(nullifier).to.match(/^0x[a-f0-9]{64}$/);
      expect(secret).to.not.equal(nullifier);
    });

    it("should generate commitment from secrets", () => {
      const client = createReadOnlyZaseonClient(SEPOLIA_RPC);
      const secret = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" as Hex;
      const nullifier = "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321" as Hex;
      
      const { commitment, nullifierHash } = client.generateCommitment(secret, nullifier);
      
      expect(commitment).to.match(/^0x[a-f0-9]{64}$/);
      expect(nullifierHash).to.match(/^0x[a-f0-9]{64}$/);
      
      // Same inputs should produce same outputs
      const { commitment: commitment2 } = client.generateCommitment(secret, nullifier);
      expect(commitment).to.equal(commitment2);
    });
  });

  describe("Contract reads (requires RPC)", () => {
    it("should read protocol stats", async () => {
      const client = createReadOnlyZaseonClient(SEPOLIA_RPC);
      
      try {
        const stats = await client.getStats();
        expect(stats.totalLocks).to.be.a("bigint");
        expect(stats.totalUnlocks).to.be.a("bigint");
        expect(stats.activeLocks).to.be.a("bigint");
      } catch (e: any) {
        // Skip if RPC is not available
        if (e.message?.includes("fetch") || e.message?.includes("network")) {
          console.log("Skipping RPC test - network unavailable");
          return;
        }
        throw e;
      }
    });

    it("should check if chain is supported", async () => {
      const client = createReadOnlyZaseonClient(SEPOLIA_RPC);
      
      try {
        const isSupported = await client.isChainSupported(11155111);
        expect(typeof isSupported).to.equal("boolean");
      } catch (e: any) {
        if (e.message?.includes("fetch") || e.message?.includes("network")) {
          console.log("Skipping RPC test - network unavailable");
          return;
        }
        throw e;
      }
    });
  });
});

describe("NoirProver", () => {
  let prover: NoirProver;

  before(async () => {
    prover = new NoirProver();
    await prover.initialize();
  });

  it("should initialize prover", () => {
    expect(prover).to.exist;
  });

  it("should generate placeholder state commitment proof", async () => {
    const result = await prover.proveStateCommitment({
      secret: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" as Hex,
      nullifier: "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321" as Hex,
      amount: 1000000000000000000n,
    });

    expect(result.proof).to.exist;
    expect(result.proofHex).to.match(/^0x[a-f0-9]+$/);
    expect(result.publicInputs.length).to.be.greaterThan(0);
  });

  it("should generate deterministic proofs", async () => {
    const inputs = {
      secret: "0x1111111111111111111111111111111111111111111111111111111111111111" as Hex,
      nullifier: "0x2222222222222222222222222222222222222222222222222222222222222222" as Hex,
      amount: 500n,
    };

    const result1 = await prover.proveStateCommitment(inputs);
    const result2 = await prover.proveStateCommitment(inputs);

    expect(result1.proofHex).to.equal(result2.proofHex);
    expect(result1.publicInputs).to.deep.equal(result2.publicInputs);
  });

  it("should support all circuit types", async () => {
    const circuits = [
      Circuit.StateCommitment,
      Circuit.StateTransfer,
      Circuit.MerkleProof,
      Circuit.Nullifier,
      Circuit.BalanceProof,
    ];

    for (const circuit of circuits) {
      const result = await prover.generateProof(circuit, { test: "value" });
      expect(result.proof).to.exist;
      expect(result.proofHex).to.match(/^0x/);
    }
  });
});

describe("Contract Addresses", () => {
  it("should export Sepolia addresses", () => {
    expect(SEPOLIA_ADDRESSES).to.exist;
    expect(SEPOLIA_ADDRESSES.verifier).to.exist;
    expect(SEPOLIA_ADDRESSES.zkBoundStateLocks).to.exist;
    expect(SEPOLIA_ADDRESSES.nullifierRegistry).to.exist;
    expect(SEPOLIA_ADDRESSES.proofHub).to.exist;
    expect(SEPOLIA_ADDRESSES.atomicSwap).to.exist;
  });

  it("should have valid address format", () => {
    const addressRegex = /^0x[a-fA-F0-9]{40}$/;
    
    Object.entries(SEPOLIA_ADDRESSES).forEach(([name, address]) => {
      expect(address, `${name} should be a valid address`).to.match(addressRegex);
    });
  });
});
