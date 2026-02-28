const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * Zaseon Mainnet Deployment Script
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
    admin:
      process.env.MULTISIG_ADMIN ||
      "0x0000000000000000000000000000000000000000",
    treasury:
      process.env.MULTISIG_TREASURY ||
      "0x0000000000000000000000000000000000000000",
  },

  // Timelock delays (for future governance deployment)
  timelock: {
    minDelay: 48 * 60 * 60, // 48 hours
    emergencyDelay: 6 * 60 * 60, // 6 hours
    gracePeriod: 7 * 24 * 60 * 60, // 7 days
  },

  // Configuration
  contracts: [
    "Groth16VerifierBN254",
    "ProofCarryingContainer",
    "PolicyBoundProofs",
    "ExecutionAgnosticStateCommitments",
    "CrossDomainNullifierAlgebra",
    "Zaseonv2Orchestrator",
    "ZaseonToken",
    "ZaseonUpgradeTimelock",
    "ZaseonGovernor",
  ],
};

// Deployed addresses
const deployedAddresses = {};

async function main() {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("           Zaseon Mainnet Deployment");
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
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }

  // Estimate total gas
  console.log("\n📊 Estimating deployment costs...");
  const gasPrice = (await ethers.provider.getFeeData()).gasPrice;
  console.log(`   Gas Price: ${ethers.formatUnits(gasPrice, "gwei")} gwei`);

  // Deploy contracts
  console.log("\n📦 Deploying Contracts...\n");

  // 1. Deploy Verifier
  await deployContract("Groth16VerifierBN254", []);

  // 2. Deploy Zaseon v2 Primitives
  await deployContract("ProofCarryingContainer", []);
  await deployContract("PolicyBoundProofs", []);
  await deployContract("ExecutionAgnosticStateCommitments", []);
  await deployContract("CrossDomainNullifierAlgebra", []);

  // 3. Deploy Orchestrator
  await deployContract("Zaseonv2Orchestrator", [
    deployedAddresses.ProofCarryingContainer,
    deployedAddresses.PolicyBoundProofs,
    deployedAddresses.ExecutionAgnosticStateCommitments,
    deployedAddresses.CrossDomainNullifierAlgebra,
  ]);

  // 4. Deploy Governance Stack
  console.log("\n📦 Deploying Governance Stack...\n");

  // 4a. Deploy ZaseonToken — initial mint of 100M ZASEON (10% of cap) to treasury multisig
  const initialMintAmount = ethers.parseEther("100000000"); // 100M ZASEON
  const treasuryAddress = CONFIG.multiSig.treasury;
  if (treasuryAddress === "0x0000000000000000000000000000000000000000") {
    console.log(
      "   ⚠️  WARNING: Treasury multi-sig is zero address. Set MULTISIG_TREASURY env var.",
    );
  }
  await deployContract("ZaseonToken", [
    deployer.address, // admin (will transfer to timelock later)
    treasuryAddress, // initial mint recipient
    initialMintAmount, // initial mint amount
  ]);

  // 4b. Deploy ZaseonUpgradeTimelock
  //     proposers = [deployer, admin multisig]
  //     executors = [deployer, admin multisig]
  //     admin = deployer (will renounce after ZaseonGovernor is wired)
  const timelockProposers = [deployer.address, CONFIG.multiSig.admin].filter(
    (addr) => addr !== "0x0000000000000000000000000000000000000000",
  );
  const timelockExecutors = [deployer.address, CONFIG.multiSig.admin].filter(
    (addr) => addr !== "0x0000000000000000000000000000000000000000",
  );
  await deployContract("ZaseonUpgradeTimelock", [
    CONFIG.timelock.minDelay, // 48 hours minimum delay
    timelockProposers, // proposers
    timelockExecutors, // executors
    deployer.address, // admin (temporary — will renounce)
  ]);

  // 4c. Deploy ZaseonGovernor with token + timelock
  //     Passing 0 for voting params uses contract defaults:
  //     - votingDelay: 1 day, votingPeriod: 5 days
  //     - proposalThreshold: 100,000 ZASEON, quorum: 4%
  await deployContract("ZaseonGovernor", [
    deployedAddresses.ZaseonToken, // governance token (IVotes)
    deployedAddresses.ZaseonUpgradeTimelock, // timelock controller
    0, // votingDelay (0 = use default 1 day)
    0, // votingPeriod (0 = use default 5 days)
    0, // proposalThreshold (0 = use default 100k ZASEON)
    0, // quorumPercentage (0 = use default 4%)
  ]);

  // 4d. Wire governance: grant ZaseonGovernor the proposer role on the timelock
  console.log("   Wiring governance roles...");
  const timelock = await ethers.getContractAt(
    "ZaseonUpgradeTimelock",
    deployedAddresses.ZaseonUpgradeTimelock,
  );
  const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
  const EXECUTOR_ROLE = await timelock.EXECUTOR_ROLE();
  const CANCELLER_ROLE = await timelock.CANCELLER_ROLE();

  // Governor gets proposer + canceller roles
  await timelock.grantRole(PROPOSER_ROLE, deployedAddresses.ZaseonGovernor);
  console.log("   ✅ Granted PROPOSER_ROLE to ZaseonGovernor");

  await timelock.grantRole(CANCELLER_ROLE, deployedAddresses.ZaseonGovernor);
  console.log("   ✅ Granted CANCELLER_ROLE to ZaseonGovernor");

  // Allow anyone to execute queued proposals (standard OZ pattern)
  await timelock.grantRole(EXECUTOR_ROLE, ethers.ZeroAddress);
  console.log("   ✅ Granted EXECUTOR_ROLE to address(0) (open execution)");

  // 4e. Transfer ZaseonToken minter role to timelock (governance-controlled minting)
  const zaseonToken = await ethers.getContractAt(
    "ZaseonToken",
    deployedAddresses.ZaseonToken,
  );
  const MINTER_ROLE = await zaseonToken.MINTER_ROLE();
  await zaseonToken.grantRole(MINTER_ROLE, deployedAddresses.ZaseonUpgradeTimelock);
  console.log("   ✅ Granted MINTER_ROLE on ZaseonToken to Timelock");

  // Revoke deployer's minter role (minting now only via governance)
  await zaseonToken.revokeRole(MINTER_ROLE, deployer.address);
  console.log("   ✅ Revoked deployer MINTER_ROLE on ZaseonToken");

  // Post-deployment configuration
  console.log("\n⚙️  Post-Deployment Configuration...\n");

  // Configure orchestrator permissions
  const orchestrator = await ethers.getContractAt(
    "Zaseonv2Orchestrator",
    deployedAddresses.Zaseonv2Orchestrator,
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
    JSON.stringify(deploymentInfo, null, 2),
  );

  // Also save as latest
  fs.writeFileSync(
    path.join(deploymentDir, "mainnet_latest.json"),
    JSON.stringify(deploymentInfo, null, 2),
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
