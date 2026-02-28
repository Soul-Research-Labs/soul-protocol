import hre from "hardhat";
import { formatEther, keccak256, toBytes } from "viem";

/**
 * ZASEON - Cross-Chain Deployment Script
 * 
 * Deploys the full ZASEON stack to an L2 pair (Arbitrum Sepolia + Base Sepolia)
 * with real ZK verifiers and cross-chain relay infrastructure.
 * 
 * Deployment order:
 *   1. ZK Verifiers (UltraHonk from Noir circuits)
 *   2. UltraHonk Adapters (IProofVerifier bridge)
 *   3. Core contracts (NullifierRegistryV3, ConfidentialStateContainerV3, ZKBoundStateLocks)
 *   4. CrossChainProofHubV3
 *   5. ZaseonCrossChainRelay
 *   6. CrossChainNullifierSync
 *   7. Bridge adapter configuration
 * 
 * Usage:
 *   npx hardhat run scripts/deploy-cross-chain.ts --network arbitrum-sepolia
 *   npx hardhat run scripts/deploy-cross-chain.ts --network base-sepolia
 */

// Supported L2 networks
const L2_CONFIG: Record<string, { name: string; chainId: number; lzEid: number; hyperlaneDomain: number }> = {
  "arbitrum-sepolia": {
    name: "Arbitrum Sepolia",
    chainId: 421614,
    lzEid: 40231,           // LayerZero V2 endpoint ID
    hyperlaneDomain: 421614, // Hyperlane domain = chain ID
  },
  "base-sepolia": {
    name: "Base Sepolia",
    chainId: 84532,
    lzEid: 40245,
    hyperlaneDomain: 84532,
  },
  "localhost": {
    name: "Localhost",
    chainId: 31337,
    lzEid: 31337,
    hyperlaneDomain: 31337,
  },
};

// Paired chains — each chain relays to these destinations
const RELAY_PAIRS: Record<string, string[]> = {
  "arbitrum-sepolia": ["base-sepolia"],
  "base-sepolia": ["arbitrum-sepolia"],
  "localhost": [],
};

const VERIFIER_CONFIG = {
  nullifier: { contract: "NullifierVerifier", publicInputs: 20, circuitId: "nullifier" },
  stateTransfer: { contract: "StateTransferVerifier", publicInputs: 23, circuitId: "state_transfer" },
  container: { contract: "ContainerVerifier", publicInputs: 21, circuitId: "container" },
  stateCommitment: { contract: "StateCommitmentVerifier", publicInputs: 19, circuitId: "state_commitment" },
  crossChainProof: { contract: "CrossChainProofVerifier", publicInputs: 23, circuitId: "cross_chain_proof" },
} as const;

async function main() {
  const networkName = hre.network.name ?? (chainId === 11155111n ? "sepolia" : chainId === 1n ? "mainnet" : `chain-${chainId}`);
  const l2Config = L2_CONFIG[networkName] || L2_CONFIG["localhost"];

  console.log("\n" + "=".repeat(80));
  console.log(`ZASEON - Cross-Chain Deployment: ${l2Config.name}`);
  console.log("=".repeat(80) + "\n");

  const { viem } = await hre.network.connect();
  const publicClient = await viem.getPublicClient();
  const [deployer] = await viem.getWalletClients();
  
  const balance = await publicClient.getBalance({ address: deployer.account.address });
  const chainId = await publicClient.getChainId();
  
  console.log("Deployer:", deployer.account.address);
  console.log("Balance:", formatEther(balance), "ETH");
  console.log("Chain ID:", chainId);
  console.log("Network:", networkName);
  
  const deployed: Record<string, `0x${string}`> = {};

  // ============================================
  // STEP 1: Deploy ZK Verifiers
  // ============================================
  console.log("\n--- Step 1: ZK Verifiers ---\n");

  for (const [name, config] of Object.entries(VERIFIER_CONFIG)) {
    try {
      const verifier = await viem.deployContract(config.contract as any);
      deployed[`verifier_${name}`] = verifier.address;
      console.log(`  ${config.contract}: ${verifier.address}`);
    } catch (err: any) {
      console.error(`  FAILED ${config.contract}: ${err.message?.slice(0, 80)}`);
    }
  }

  // ============================================
  // STEP 2: Deploy Adapters
  // ============================================
  console.log("\n--- Step 2: UltraHonk Adapters ---\n");

  for (const [name, config] of Object.entries(VERIFIER_CONFIG)) {
    const verifierAddr = deployed[`verifier_${name}`];
    if (!verifierAddr) continue;
    try {
      const circuitIdHash = keccak256(toBytes(config.circuitId)) as `0x${string}`;
      const adapter = await viem.deployContract("UltraHonkAdapter", [
        verifierAddr,
        BigInt(config.publicInputs),
        circuitIdHash,
      ]);
      deployed[`adapter_${name}`] = adapter.address;
      console.log(`  ${name} adapter: ${adapter.address}`);
    } catch (err: any) {
      console.error(`  FAILED ${name} adapter: ${err.message?.slice(0, 80)}`);
    }
  }

  // ============================================
  // STEP 3: Deploy Core Contracts
  // ============================================
  console.log("\n--- Step 3: Core Contracts ---\n");

  // ZKBoundStateLocks - uses stateTransfer adapter as proof verifier
  if (deployed.adapter_stateTransfer) {
    try {
      const zkLocks = await viem.deployContract("ZKBoundStateLocks", [deployed.adapter_stateTransfer]);
      deployed.zkBoundStateLocks = zkLocks.address;
      console.log(`  ZKBoundStateLocks: ${zkLocks.address}`);

      // Register all verifiers
      for (const [name, config] of Object.entries(VERIFIER_CONFIG)) {
        const vAddr = deployed[`verifier_${name}`];
        if (!vAddr) continue;
        const keyHash = keccak256(toBytes(config.circuitId)) as `0x${string}`;
        try {
          await zkLocks.write.registerVerifier([keyHash, vAddr]);
          console.log(`    Registered ${name}: ${keyHash.slice(0, 18)}...`);
        } catch {}
      }
    } catch (err: any) {
      console.error(`  FAILED ZKBoundStateLocks: ${err.message?.slice(0, 80)}`);
    }
  }

  // ConfidentialStateContainerV3
  if (deployed.adapter_stateCommitment) {
    try {
      const container = await viem.deployContract("ConfidentialStateContainerV3", [deployed.adapter_stateCommitment]);
      deployed.stateContainer = container.address;
      console.log(`  ConfidentialStateContainerV3: ${container.address}`);
    } catch (err: any) {
      console.error(`  FAILED ConfidentialStateContainerV3: ${err.message?.slice(0, 80)}`);
    }
  }

  // NullifierRegistryV3 (constructor takes no args or merkle depth)
  try {
    const nullReg = await viem.deployContract("NullifierRegistryV3" as any);
    deployed.nullifierRegistry = nullReg.address;
    console.log(`  NullifierRegistryV3: ${nullReg.address}`);
  } catch (err: any) {
    console.error(`  FAILED NullifierRegistryV3: ${err.message?.slice(0, 80)}`);
  }

  // ============================================
  // STEP 4: Deploy CrossChainProofHubV3
  // ============================================
  console.log("\n--- Step 4: CrossChainProofHubV3 ---\n");
  
  try {
    const proofHub = await viem.deployContract("CrossChainProofHubV3" as any);
    deployed.proofHub = proofHub.address;
    console.log(`  CrossChainProofHubV3: ${proofHub.address}`);
    
    // Register verifiers on the ProofHub
    for (const [name, config] of Object.entries(VERIFIER_CONFIG)) {
      const adapterAddr = deployed[`adapter_${name}`];
      if (!adapterAddr) continue;
      const proofType = keccak256(toBytes(config.circuitId)) as `0x${string}`;
      try {
        await proofHub.write.setVerifier([proofType, adapterAddr]);
        console.log(`    ProofHub verifier ${name}: ${proofType.slice(0, 18)}...`);
      } catch {}
    }
  } catch (err: any) {
    console.error(`  FAILED CrossChainProofHubV3: ${err.message?.slice(0, 80)}`);
  }

  // ============================================
  // STEP 5: Deploy Cross-Chain Relay
  // ============================================
  console.log("\n--- Step 5: ZaseonCrossChainRelay ---\n");

  if (deployed.proofHub) {
    try {
      // BridgeType.LAYERZERO = 0, HYPERLANE = 1
      const relay = await viem.deployContract("ZaseonCrossChainRelay", [
        deployed.proofHub,
        0, // LayerZero as default bridge
      ]);
      deployed.relay = relay.address;
      console.log(`  ZaseonCrossChainRelay: ${relay.address}`);
    } catch (err: any) {
      console.error(`  FAILED ZaseonCrossChainRelay: ${err.message?.slice(0, 80)}`);
    }
  }

  // ============================================
  // STEP 6: Deploy Nullifier Sync
  // ============================================
  console.log("\n--- Step 6: CrossChainNullifierSync ---\n");

  if (deployed.nullifierRegistry) {
    try {
      const nullSync = await viem.deployContract("CrossChainNullifierSync", [
        deployed.nullifierRegistry,
      ]);
      deployed.nullifierSync = nullSync.address;
      console.log(`  CrossChainNullifierSync: ${nullSync.address}`);
    } catch (err: any) {
      console.error(`  FAILED CrossChainNullifierSync: ${err.message?.slice(0, 80)}`);
    }
  }

  // ============================================
  // Summary
  // ============================================
  console.log("\n" + "=".repeat(80));
  console.log("DEPLOYMENT SUMMARY");
  console.log("=".repeat(80));

  console.log(`\nNetwork: ${l2Config.name} (Chain ID: ${chainId})`);
  console.log(`LZ Endpoint ID: ${l2Config.lzEid}`);
  console.log(`Hyperlane Domain: ${l2Config.hyperlaneDomain}\n`);

  for (const [name, addr] of Object.entries(deployed)) {
    console.log(`  ${name}: ${addr}`);
  }

  // Save deployment info
  const deployment = {
    network: networkName,
    chainId: Number(chainId),
    timestamp: new Date().toISOString(),
    deployer: deployer.account.address,
    contracts: deployed,
    l2Config,
    relayPairs: RELAY_PAIRS[networkName] || [],
  };

  const fs = await import("fs");
  const outPath = `./deployments/${networkName}-${chainId}.json`;
  fs.writeFileSync(outPath, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${outPath}`);
  console.log("\nDone.\n");
}

main().catch(console.error);
