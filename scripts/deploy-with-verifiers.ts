import hre from "hardhat";
import { formatEther, parseEther, keccak256, toBytes } from "viem";

/**
 * ZASEON - Deploy with Real ZK Verifiers
 * 
 * Deploys the bb-generated UltraHonk verifiers from Noir circuits
 * and wires them into the core Zaseon contracts via registerVerifier().
 * 
 * Prerequisites:
 *   1. `cd noir && nargo compile` (compile circuits)
 *   2. `bb write_vk -b target/<circuit>.json -o target/<circuit>_vk --oracle_hash keccak`
 *   3. `bb write_solidity_verifier -k target/<circuit>_vk/vk -o ../contracts/verifiers/generated/<Name>Verifier.sol`
 *   4. `forge build` (compile Solidity)
 * 
 * Verifier Registry Keys:
 *   Each verifier is registered with a keccak256 hash of its circuit name.
 *   Contracts like ZKBoundStateLocks look up verifiers by key hash.
 */

// Circuit -> Contract mapping with public input counts
const VERIFIER_CONFIG = {
  nullifier: { contract: "NullifierVerifier", publicInputs: 20, circuitId: "nullifier" },
  stateTransfer: { contract: "StateTransferVerifier", publicInputs: 23, circuitId: "state_transfer" },
  container: { contract: "ContainerVerifier", publicInputs: 21, circuitId: "container" },
  stateCommitment: { contract: "StateCommitmentVerifier", publicInputs: 19, circuitId: "state_commitment" },
  crossChainProof: { contract: "CrossChainProofVerifier", publicInputs: 23, circuitId: "cross_chain_proof" },
} as const;

async function main() {
  console.log("\n" + "=".repeat(80));
  console.log("ZASEON - REAL ZK VERIFIER DEPLOYMENT");
  console.log("=".repeat(80) + "\n");

  const { viem } = await hre.network.connect();
  const publicClient = await viem.getPublicClient();
  const [deployer] = await viem.getWalletClients();
  
  const balance = await publicClient.getBalance({ address: deployer.account.address });
  const chainId = await publicClient.getChainId();
  
  console.log("Deployer:", deployer.account.address);
  console.log("Balance:", formatEther(balance), "ETH");
  console.log("Chain ID:", chainId);
  console.log("");

  const deployed: Record<string, string> = {};

  // ============================================
  // PHASE 1: Deploy ZKTranscriptLib (shared library)
  // ============================================
  console.log("--- Phase 1: Shared Library ---\n");
  
  // Note: Each generated verifier has ZKTranscriptLib as a public library.
  // In production, these would be linked. For now, each verifier is self-contained.

  // ============================================
  // PHASE 2: Deploy Generated HonkVerifiers
  // ============================================
  console.log("--- Phase 2: UltraHonk Verifiers ---\n");

  for (const [name, config] of Object.entries(VERIFIER_CONFIG)) {
    try {
      console.log(`Deploying ${config.contract}...`);
      const verifier = await viem.deployContract(config.contract as any);
      deployed[name] = verifier.address;
      console.log(`  ${config.contract}: ${verifier.address}`);
      console.log(`  Public inputs: ${config.publicInputs}`);
    } catch (err: any) {
      console.error(`  FAILED to deploy ${config.contract}: ${err.message?.slice(0, 100)}`);
    }
  }

  // ============================================
  // PHASE 3: Deploy UltraHonkAdapters  
  // ============================================
  console.log("\n--- Phase 3: Verifier Adapters (IProofVerifier bridge) ---\n");

  const adapters: Record<string, string> = {};
  
  for (const [name, config] of Object.entries(VERIFIER_CONFIG)) {
    if (!deployed[name]) continue;
    
    try {
      const circuitIdHash = keccak256(toBytes(config.circuitId));
      console.log(`Deploying ${name} adapter...`);
      const adapter = await viem.deployContract("UltraHonkAdapter", [
        deployed[name] as `0x${string}`,
        BigInt(config.publicInputs),
        circuitIdHash as `0x${string}`,
      ]);
      adapters[name] = adapter.address;
      console.log(`  Adapter: ${adapter.address}`);
    } catch (err: any) {
      console.error(`  FAILED: ${err.message?.slice(0, 100)}`);
    }
  }

  // ============================================
  // PHASE 4: Deploy Core Contracts with Real Verifiers
  // ============================================
  console.log("\n--- Phase 4: Core Contracts ---\n");

  // Deploy ZKBoundStateLocks with state_transfer adapter as the proof verifier
  if (adapters.stateTransfer) {
    try {
      console.log("Deploying ZKBoundStateLocks with real verifier...");
      const zkLocks = await viem.deployContract("ZKBoundStateLocks", [
        adapters.stateTransfer as `0x${string}`,
      ]);
      deployed.zkBoundStateLocks = zkLocks.address;
      console.log(`  ZKBoundStateLocks: ${zkLocks.address}`);

      // Register circuit-specific verifiers
      for (const [name, config] of Object.entries(VERIFIER_CONFIG)) {
        if (!deployed[name]) continue;
        const keyHash = keccak256(toBytes(config.circuitId));
        try {
          await zkLocks.write.registerVerifier([keyHash as `0x${string}`, deployed[name] as `0x${string}`]);
          console.log(`  Registered ${name} verifier: ${keyHash.slice(0, 18)}...`);
        } catch (err: any) {
          console.log(`  Skipped ${name} registration: ${err.message?.slice(0, 60)}`);
        }
      }
    } catch (err: any) {
      console.error(`  FAILED: ${err.message?.slice(0, 100)}`);
    }
  }

  // Deploy ConfidentialStateContainerV3 with state_commitment adapter
  if (adapters.stateCommitment) {
    try {
      console.log("\nDeploying ConfidentialStateContainerV3 with real verifier...");
      const container = await viem.deployContract("ConfidentialStateContainerV3", [
        adapters.stateCommitment as `0x${string}`,
      ]);
      deployed.stateContainer = container.address;
      console.log(`  ConfidentialStateContainerV3: ${container.address}`);
    } catch (err: any) {
      console.error(`  FAILED: ${err.message?.slice(0, 100)}`);
    }
  }

  // ============================================
  // Summary
  // ============================================
  console.log("\n" + "=".repeat(80));
  console.log("DEPLOYMENT SUMMARY");
  console.log("=".repeat(80));
  
  console.log("\nVerifiers:");
  for (const [name, addr] of Object.entries(deployed)) {
    console.log(`  ${name}: ${addr}`);
  }
  
  console.log("\nAdapters:");
  for (const [name, addr] of Object.entries(adapters)) {
    console.log(`  ${name}: ${addr}`);
  }

  console.log("\nDone.\n");
}

main().catch(console.error);
