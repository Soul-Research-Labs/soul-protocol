const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * PIL Mainnet Deployment Script
 * 
 * Prerequisites:
 * 1. Set PRIVATE_KEY and RPC_URL in .env
 * 2. Ensure deployer has sufficient ETH
 * 3. Gnosis Safe multi-sig address configured
 * 
 * Run: npx hardhat run scripts/deploy-mainnet.js --network mainnet
 */

// Configuration
const CONFIG = {
  // Multi-sig addresses (update for production)
  multiSig: {
    admin: process.env.MULTISIG_ADMIN || "0x0000000000000000000000000000000000000000",
    treasury: process.env.MULTISIG_TREASURY || "0x0000000000000000000000000000000000000000",
  },
  
  // Timelock delays
  timelock: {
    minDelay: 48 * 60 * 60, // 48 hours
    emergencyDelay: 6 * 60 * 60, // 6 hours
    gracePeriod: 7 * 24 * 60 * 60, // 7 days
  },
  
  // Token configuration
  token: {
    name: "PIL Token",
    symbol: "PIL",
    initialSupply: ethers.parseEther("5000000"), // 5M for liquidity
  },
  
  // Deployment order matters for dependencies
  contracts: [
    "Groth16VerifierBN254",
    "ProofCarryingContainer",
    "PolicyBoundProofs",
    "ExecutionAgnosticStateCommitments",
    "CrossDomainNullifierAlgebra",
    "PILv2Orchestrator",
    "PILTimelock",
    "PILToken",
    "PILGovernance",
  ],
};

// Deployed addresses
const deployedAddresses = {};

async function main() {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("           PIL Mainnet Deployment");
  console.log("═══════════════════════════════════════════════════════════");
  
  const [deployer] = await ethers.getSigners();
  console.log(`\n📍 Deployer: ${deployer.address}`);
  
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`💰 Balance: ${ethers.formatEther(balance)} ETH`);
  
  const network = await ethers.provider.getNetwork();
  console.log(`🌐 Network: ${network.name} (Chain ID: ${network.chainId})`);
  
  // Safety check
  if (network.chainId === 1n) {
    console.log("\n⚠️  MAINNET DEPLOYMENT - Are you sure? (Ctrl+C to abort)");
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  
  // Estimate total gas
  console.log("\n📊 Estimating deployment costs...");
  const gasPrice = (await ethers.provider.getFeeData()).gasPrice;
  console.log(`   Gas Price: ${ethers.formatUnits(gasPrice, "gwei")} gwei`);
  
  // Deploy contracts
  console.log("\n📦 Deploying Contracts...\n");
  
  // 1. Deploy Verifier
  await deployContract("Groth16VerifierBN254", []);
  
  // 2. Deploy PIL v2 Primitives
  await deployContract("ProofCarryingContainer", []);
  await deployContract("PolicyBoundProofs", []);
  await deployContract("ExecutionAgnosticStateCommitments", []);
  await deployContract("CrossDomainNullifierAlgebra", []);
  
  // 3. Deploy Orchestrator
  await deployContract("PILv2Orchestrator", [
    deployedAddresses.ProofCarryingContainer,
    deployedAddresses.PolicyBoundProofs,
    deployedAddresses.ExecutionAgnosticStateCommitments,
    deployedAddresses.CrossDomainNullifierAlgebra,
  ]);
  
  // 4. Deploy Timelock
  await deployContract("PILTimelock", [
    CONFIG.timelock.minDelay,
    [], // proposers - will be set via multi-sig
    [], // executors - will be set via multi-sig
    deployer.address, // admin (transferred to multi-sig later)
  ]);
  
  // 5. Deploy Token
  await deployContract("PILToken", [deployer.address]);
  
  // 6. Deploy Governance
  await deployContract("PILGovernance", [deployedAddresses.PILToken]);
  
  // Post-deployment configuration
  console.log("\n⚙️  Post-Deployment Configuration...\n");
  
  // Configure orchestrator permissions
  const orchestrator = await ethers.getContractAt(
    "PILv2Orchestrator",
    deployedAddresses.PILv2Orchestrator
  );
  
  console.log("   Setting up primitive registrations...");
  // Additional configuration would go here
  
  // Transfer ownership to timelock/multi-sig
  console.log("   Preparing ownership transfer to multi-sig...");
  
  // Save deployment info
  const deploymentInfo = {
    network: network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
    addresses: deployedAddresses,
    config: CONFIG,
  };
  
  const deploymentDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentDir)) {
    fs.mkdirSync(deploymentDir, { recursive: true });
  }
  
  const filename = `mainnet_${Date.now()}.json`;
  fs.writeFileSync(
    path.join(deploymentDir, filename),
    JSON.stringify(deploymentInfo, null, 2)
  );
  
  // Also save as latest
  fs.writeFileSync(
    path.join(deploymentDir, "mainnet_latest.json"),
    JSON.stringify(deploymentInfo, null, 2)
  );
  
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("           Deployment Complete!");
  console.log("═══════════════════════════════════════════════════════════");
  console.log("\n📁 Deployment saved to:", path.join(deploymentDir, filename));
  console.log("\n📋 Deployed Addresses:");
  for (const [name, address] of Object.entries(deployedAddresses)) {
    console.log(`   ${name}: ${address}`);
  }
  
  console.log("\n⚠️  IMPORTANT NEXT STEPS:");
  console.log("   1. Verify contracts on Etherscan");
  console.log("   2. Transfer admin roles to multi-sig");
  console.log("   3. Configure timelock proposers/executors");
  console.log("   4. Set up monitoring and alerts");
  console.log("   5. Update frontend with new addresses");
  
  return deployedAddresses;
}

async function deployContract(name, args) {
  console.log(`   Deploying ${name}...`);
  
  const factory = await ethers.getContractFactory(name);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  
  const address = await contract.getAddress();
  deployedAddresses[name] = address;
  
  console.log(`   ✅ ${name}: ${address}`);
  
  return contract;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Deployment failed:", error);
    process.exit(1);
  });
