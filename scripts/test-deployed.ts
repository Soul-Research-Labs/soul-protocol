/**
 * Zaseon v3 Deployed Contract Integration Tests
 * 
 * Tests against live Sepolia contracts
 * 
 * Usage: npx hardhat run scripts/test-deployed.ts --network sepolia
 */

import hre from "hardhat";
import { keccak256, toBytes, formatEther, type Address, type Hash } from "viem";
import * as fs from "fs";
import * as path from "path";

// Load deployment data using process.cwd() which works in ESM
const deploymentPath = path.join(process.cwd(), "deployments/sepolia-11155111.json");
const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));

// Contract addresses from deployment
const ADDRESSES = {
  mockVerifier: deployment.contracts.verifier as Address,
  groth16Verifier: deployment.contracts.groth16Verifier as Address,
  plonkVerifier: deployment.contracts.plonkVerifier as Address,
  friVerifier: deployment.contracts.friVerifier as Address,
  stateContainer: deployment.contracts.stateContainer as Address,
  nullifierRegistry: deployment.contracts.nullifierRegistry as Address,
  proofHub: deployment.contracts.proofHub as Address,
  atomicSwap: deployment.contracts.atomicSwap as Address,
  compliance: deployment.contracts.compliance as Address,
  proofCarryingContainer: deployment.contracts.proofCarryingContainer as Address,
  policyBoundProofs: deployment.contracts.policyBoundProofs as Address,
  easc: deployment.contracts.easc as Address,
  cdna: deployment.contracts.cdna as Address,
  teeAttestation: deployment.contracts.teeAttestation as Address,
  emergencyRecovery: deployment.contracts.emergencyRecovery as Address,
  zkBoundStateLocks: deployment.contracts.zkBoundStateLocks as Address,
  zkSLockIntegration: deployment.contracts.zkSLockIntegration as Address,
};

async function main() {
  console.log("\n" + "=".repeat(80));
  console.log("Zaseon v3 DEPLOYED CONTRACT INTEGRATION TESTS");
  console.log("=".repeat(80) + "\n");

  const network = await hre.network.connect();
  const viem = (network as any).viem;
  
  const publicClient = await viem.getPublicClient();
  const [deployer] = await viem.getWalletClients();
  
  console.log(`🔑 Tester: ${deployer.account.address}`);
  const balance = await publicClient.getBalance({ address: deployer.account.address });
  console.log(`💰 Balance: ${formatEther(balance)} ETH`);
  console.log(`🌐 Network: Sepolia (Chain ID: 11155111)\n`);

  let passed = 0;
  let failed = 0;

  // Helper function
  const test = async (name: string, fn: () => Promise<void>) => {
    try {
      await fn();
      console.log(`✅ ${name}`);
      passed++;
    } catch (error: any) {
      console.log(`❌ ${name}: ${error.message.slice(0, 100)}`);
      failed++;
    }
  };

  console.log("📦 Testing Core Verifiers...\n");

  // Test 1: MockProofVerifier
  await test("MockProofVerifier - Read verification result", async () => {
    const verifier = await viem.getContractAt("MockProofVerifier", ADDRESSES.mockVerifier);
    const result = await verifier.read.verify([
      "0x" + "00".repeat(32), // proof as hex string
      [0n] // publicInputs as uint256 array
    ]);
    // Should return true or false (contract deployed successfully)
    if (typeof result !== "boolean") throw new Error("Invalid return type");
  });

  // Test 2: Groth16VerifierBLS12381
  await test("Groth16VerifierBLS12381 - Contract accessible", async () => {
    const verifier = await viem.getContractAt("Groth16VerifierBLS12381", ADDRESSES.groth16Verifier);
    // Just verify contract is accessible
    const code = await publicClient.getCode({ address: ADDRESSES.groth16Verifier });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  // Test 3: PLONKVerifier
  await test("PLONKVerifier - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.plonkVerifier });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  // Test 4: FRIVerifier
  await test("FRIVerifier - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.friVerifier });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  console.log("\n📦 Testing Core Infrastructure...\n");

  // Test 5: ConfidentialStateContainerV3
  await test("ConfidentialStateContainerV3 - Read total states", async () => {
    const container = await viem.getContractAt("ConfidentialStateContainerV3", ADDRESSES.stateContainer);
    const total = await container.read.totalStates();
    if (typeof total !== "bigint") throw new Error("Invalid return type");
  });

  // Test 6: NullifierRegistryV3
  await test("NullifierRegistryV3 - Check nullifier not used", async () => {
    const registry = await viem.getContractAt("NullifierRegistryV3", ADDRESSES.nullifierRegistry);
    const testNullifier = keccak256(toBytes("test-nullifier-check"));
    const isUsed = await registry.read.isNullifierUsed([testNullifier]);
    if (isUsed !== false) throw new Error("Nullifier should not be used");
  });

  // Test 7: CrossChainProofHubV3
  await test("CrossChainProofHubV3 - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.proofHub });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  console.log("\n📦 Testing Application Layer...\n");

  // Test 8: ZaseonAtomicSwapV2
  await test("ZaseonAtomicSwapV2 - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.atomicSwap });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  // Test 9: ZaseonComplianceV2
  await test("ZaseonComplianceV2 - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.compliance });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  console.log("\n📦 Testing Zaseon v2 Primitives...\n");

  // Test 10: ProofCarryingContainer (PC³)
  await test("ProofCarryingContainer - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.proofCarryingContainer });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  // Test 11: PolicyBoundProofs
  await test("PolicyBoundProofs - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.policyBoundProofs });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  // Test 12: ExecutionAgnosticStateCommitments
  await test("ExecutionAgnosticStateCommitments - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.easc });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  // Test 13: CrossDomainNullifierAlgebra
  await test("CrossDomainNullifierAlgebra - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.cdna });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  console.log("\n📦 Testing Security & TEE...\n");

  // Test 14: TEEAttestation
  await test("TEEAttestation - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.teeAttestation });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  // Test 15: EmergencyRecovery
  await test("EmergencyRecovery - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.emergencyRecovery });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  console.log("\n📦 Testing ZK-Bound State Locks...\n");

  // Test 16: ZKBoundStateLocks
  await test("ZKBoundStateLocks - Read stats", async () => {
    const zkSlocks = await viem.getContractAt("ZKBoundStateLocks", ADDRESSES.zkBoundStateLocks);
    const stats = await zkSlocks.read.getStats();
    // stats should be a tuple [created, unlocked, active, optimistic, disputed]
    if (!Array.isArray(stats) || stats.length < 5) throw new Error("Invalid stats format");
  });

  // Test 17: ZKBoundStateLocks - Get active locks
  await test("ZKBoundStateLocks - Get active locks", async () => {
    const zkSlocks = await viem.getContractAt("ZKBoundStateLocks", ADDRESSES.zkBoundStateLocks);
    const activeLocks = await zkSlocks.read.getActiveLockIds();
    if (!Array.isArray(activeLocks)) throw new Error("Invalid return type");
  });

  // Test 18: ZKSLockIntegration
  await test("ZKSLockIntegration - Contract accessible", async () => {
    const code = await publicClient.getCode({ address: ADDRESSES.zkSLockIntegration });
    if (!code || code === "0x") throw new Error("No code at address");
  });

  console.log("\n" + "=".repeat(80));
  console.log("INTEGRATION TEST SUMMARY");
  console.log("=".repeat(80));
  console.log(`\n✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📊 Total:  ${passed + failed}`);
  console.log(`\n🎯 Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%\n`);

  if (failed > 0) {
    console.log("⚠️  Some tests failed. Check contract state or network connectivity.");
    process.exit(1);
  } else {
    console.log("🎉 All integration tests passed!");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
