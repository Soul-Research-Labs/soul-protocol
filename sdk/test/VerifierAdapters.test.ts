import { expect } from "chai";
import hre from "hardhat";
import { getAddress, hashMessage, zeroHash } from "viem";

describe("Noir Verifier Adapters", () => {
  let adapter: any;
  let mockVerifier: any;

  beforeEach(async () => {
    // 1. Deploy a mock Noir verifier (stub)
    mockVerifier = await (hre as any).viem.deployContract("MockNoirVerifier" as any);
    
    // 2. Deploy the adapter pointing to the mock
    adapter = await (hre as any).viem.deployContract("PolicyVerifierAdapter", [mockVerifier.address]);
  });

  it("should format and delegate verification to Noir verifier", async () => {
    const circuitHash = zeroHash;
    const proof = "0x1234";
    
    // Policy Noir circuit has 4 public inputs: [isValid, policy_hash, user_commitment, merkle_root]
    // We encode these manually to match the ASM _prepareSignals expectation:
    // bytes: [32 bytes length][32 bytes signal 0][32 bytes signal 1]...
    
    const signals = [
      "0x0000000000000000000000000000000000000000000000000000000000000001", // isValid = true
      "0x1111111111111111111111111111111111111111111111111111111111111111", // policy_hash
      "0x2222222222222222222222222222222222222222222222222222222222222222", // user_com
      "0x3333333333333333333333333333333333333333333333333333333333333333"  // merkle_root
    ];

    const lenHex = "0000000000000000000000000000000000000000000000000000000000000004";
    const publicInputs = "0x" + lenHex + signals.map(s => s.slice(2)).join("");
    
    // Call the adapter
    const result = await adapter.read.verify([circuitHash, proof, publicInputs as `0x${string}`]);
    expect(result).to.be.true;

    // Verify echoes in mock
    const lastSignals = await mockVerifier.read.lastSignals([0n]);
    expect(lastSignals).to.equal(signals[0]);
  });

  it("should revert if signal is out of field range", async () => {
    const circuitHash = zeroHash;
    const proof = "0x1234";
    const overflowVal = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"; // > r
    
    const lenHex = "0000000000000000000000000000000000000000000000000000000000000001";
    const publicInputs = "0x" + lenHex + overflowVal.slice(2);

    await expect(adapter.read.verify([circuitHash, proof, publicInputs as `0x${string}`]))
      .to.be.rejectedWith("FIELD_OVERFLOW");
  });
});
