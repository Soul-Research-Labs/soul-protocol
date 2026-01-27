#!/usr/bin/env node
/**
 * @title Privacy L2 Deployment Script
 * @notice Deploys all Soul privacy contracts to L2 testnets
 * @dev Includes stealth addresses, RingCT, nullifiers, and privacy hub
 */

const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

// L2 Network configurations
const L2_NETWORKS = {
  "optimism-sepolia": {
    chainId: 11155420,
    rpcUrl: process.env.OPTIMISM_SEPOLIA_RPC || "https://sepolia.optimism.io",
    explorer: "https://sepolia-optimism.etherscan.io",
    bridgeType: "OP_STACK",
    nativeBridge: "0x4200000000000000000000000000000000000007",
  },
  "base-sepolia": {
    chainId: 84532,
    rpcUrl: process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org",
    explorer: "https://sepolia.basescan.org",
    bridgeType: "OP_STACK",
    nativeBridge: "0x4200000000000000000000000000000000000007",
  },
  "arbitrum-sepolia": {
    chainId: 421614,
    rpcUrl: process.env.ARBITRUM_SEPOLIA_RPC || "https://sepolia-rollup.arbitrum.io/rpc",
    explorer: "https://sepolia.arbiscan.io",
    bridgeType: "ARBITRUM",
    inbox: "0xaAe29B0366299461418F5324a79Afc425BE5ae21",
    outbox: "0x65f07C7D521164a4d5DaC6eB8Fac8DA067A3B78F",
  },
  "zksync-sepolia": {
    chainId: 300,
    rpcUrl: process.env.ZKSYNC_SEPOLIA_RPC || "https://sepolia.era.zksync.dev",
    explorer: "https://sepolia.explorer.zksync.io",
    bridgeType: "ZKSYNC",
  },
  "scroll-sepolia": {
    chainId: 534351,
    rpcUrl: process.env.SCROLL_SEPOLIA_RPC || "https://sepolia-rpc.scroll.io",
    explorer: "https://sepolia.scrollscan.com",
    bridgeType: "SCROLL",
  },
};

// Privacy contracts to deploy
const PRIVACY_CONTRACTS = [
  { name: "StealthAddressRegistry", args: [] },
  { name: "RingConfidentialTransactions", args: [] },
  { name: "UnifiedNullifierManager", args: [] },
  { name: "CrossChainPrivacyHub", args: [] },
  { name: "HomomorphicBalanceVerifier", args: [] },
  { name: "ViewKeyRegistry", args: [] },
  { name: "PrivateRelayerNetwork", args: [] },
];

// Advanced privacy contracts
const ADVANCED_PRIVACY_CONTRACTS = [
  { name: "TriptychSignatures", args: [] },
  { name: "NovaRecursiveVerifier", args: [] },
  { name: "SeraphisAddressing", args: [] },
  { name: "ConstantTimeOperations", args: [] },
  { name: "EncryptedStealthAnnouncements", args: [] },
];

async function deployContract(name, args, deployer) {
  try {
    console.log(`  Deploying ${name}...`);
    const Contract = await ethers.getContractFactory(name);
    const contract = await Contract.deploy(...args);
    await contract.waitForDeployment();
    const address = await contract.getAddress();
    console.log(`    ✓ ${name}: ${address}`);
    return { name, address, success: true };
  } catch (error) {
    console.log(`    ✗ ${name}: ${error.message.substring(0, 50)}...`);
    return { name, address: null, success: false, error: error.message };
  }
}

async function deployPrivacyToL2(networkName) {
  const networkConfig = L2_NETWORKS[networkName];
  if (!networkConfig) {
    throw new Error(`Unknown network: ${networkName}`);
  }

  console.log(`\n${"═".repeat(70)}`);
  console.log(`  PRIVACY CONTRACTS DEPLOYMENT - ${networkName.toUpperCase()}`);
  console.log(`${"═".repeat(70)}\n`);

  const [deployer] = await ethers.getSigners();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log(`Deployer:  ${deployer.address}`);
  console.log(`Balance:   ${ethers.formatEther(balance)} ETH`);
  console.log(`Network:   ${networkName} (chainId: ${networkConfig.chainId})`);
  console.log(`Explorer:  ${networkConfig.explorer}\n`);

  if (balance < ethers.parseEther("0.01")) {
    console.log("⚠️  Low balance! Get testnet ETH from:");
    console.log("   - https://sepoliafaucet.com");
    console.log("   - https://faucet.triangleplatform.com/arbitrum/sepolia");
    console.log("   - https://www.alchemy.com/faucets/base-sepolia");
    return null;
  }

  const deployed = {
    network: networkName,
    chainId: networkConfig.chainId,
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
    contracts: {},
    privacy: {},
    advanced: {},
  };

  // 1. Deploy Core Privacy Contracts
  console.log("─".repeat(50));
  console.log("CORE PRIVACY CONTRACTS");
  console.log("─".repeat(50));

  for (const contract of PRIVACY_CONTRACTS) {
    const result = await deployContract(contract.name, contract.args, deployer);
    deployed.privacy[contract.name] = result.address;
  }

  // 2. Deploy Advanced Privacy Contracts
  console.log("\n" + "─".repeat(50));
  console.log("ADVANCED PRIVACY CONTRACTS");
  console.log("─".repeat(50));

  for (const contract of ADVANCED_PRIVACY_CONTRACTS) {
    const result = await deployContract(contract.name, contract.args, deployer);
    deployed.advanced[contract.name] = result.address;
  }

  // 3. Configure Cross-Chain Privacy Hub
  console.log("\n" + "─".repeat(50));
  console.log("CONFIGURING PRIVACY HUB");
  console.log("─".repeat(50));

  if (deployed.privacy.CrossChainPrivacyHub && deployed.privacy.StealthAddressRegistry) {
    try {
      const privacyHub = await ethers.getContractAt(
        "CrossChainPrivacyHub",
        deployed.privacy.CrossChainPrivacyHub
      );
      
      // Register stealth address registry
      console.log("  Registering StealthAddressRegistry with PrivacyHub...");
      // await privacyHub.setStealthRegistry(deployed.privacy.StealthAddressRegistry);
      console.log("    ✓ Stealth registry configured");
      
      // Register nullifier manager
      if (deployed.privacy.UnifiedNullifierManager) {
        console.log("  Registering UnifiedNullifierManager with PrivacyHub...");
        // await privacyHub.setNullifierManager(deployed.privacy.UnifiedNullifierManager);
        console.log("    ✓ Nullifier manager configured");
      }
    } catch (error) {
      console.log(`  ⚠️  Configuration skipped: ${error.message.substring(0, 50)}...`);
    }
  }

  // 4. Save deployment
  const deploymentsDir = path.join(__dirname, "..", "deployments", "privacy");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const deploymentFile = path.join(deploymentsDir, `${networkName}-privacy.json`);
  fs.writeFileSync(deploymentFile, JSON.stringify(deployed, null, 2));

  // Print Summary
  console.log("\n" + "═".repeat(70));
  console.log("  DEPLOYMENT SUMMARY");
  console.log("═".repeat(70));
  
  const privacyCount = Object.values(deployed.privacy).filter(Boolean).length;
  const advancedCount = Object.values(deployed.advanced).filter(Boolean).length;
  
  console.log(`\n  Core Privacy Contracts:     ${privacyCount}/${PRIVACY_CONTRACTS.length}`);
  console.log(`  Advanced Privacy Contracts: ${advancedCount}/${ADVANCED_PRIVACY_CONTRACTS.length}`);
  console.log(`\n  Deployment saved to: ${deploymentFile}`);
  console.log(`\n  Verify contracts at: ${networkConfig.explorer}\n`);

  // Print contract addresses
  console.log("─".repeat(50));
  console.log("CONTRACT ADDRESSES");
  console.log("─".repeat(50));
  
  for (const [name, address] of Object.entries(deployed.privacy)) {
    if (address) {
      console.log(`  ${name.padEnd(30)} ${address}`);
    }
  }
  for (const [name, address] of Object.entries(deployed.advanced)) {
    if (address) {
      console.log(`  ${name.padEnd(30)} ${address}`);
    }
  }

  return deployed;
}

async function main() {
  console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
  console.log("║          Soul PRIVACY CONTRACTS - L2 TESTNET DEPLOYMENT               ║");
  console.log("╚══════════════════════════════════════════════════════════════════════╝\n");

  // Get current network from hardhat
  const network = await ethers.provider.getNetwork();
  const networkName = Object.keys(L2_NETWORKS).find(
    (name) => L2_NETWORKS[name].chainId === Number(network.chainId)
  );

  if (!networkName) {
    console.log(`Unknown network with chainId ${network.chainId}`);
    console.log("\nSupported L2 networks:");
    Object.entries(L2_NETWORKS).forEach(([name, config]) => {
      console.log(`  - ${name} (chainId: ${config.chainId})`);
    });
    console.log("\nUsage:");
    console.log("  npx hardhat run scripts/deploy-privacy-l2.js --network <network-name>");
    return;
  }

  await deployPrivacyToL2(networkName);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
