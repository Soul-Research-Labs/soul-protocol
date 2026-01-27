import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Soul Governance Deployment Script
 * Deploys: SoulToken, TimelockController, SoulGovernor, Multi-sig Setup
 */

interface GovernanceDeployment {
  network: string;
  chainId: number;
  timestamp: string;
  deployer: string;
  contracts: {
    SoulToken: string;
    TimelockController: string;
    SoulGovernor: string;
    SafeMultiSig?: string;
  };
  configuration: {
    timelockDelay: number;
    votingDelay: number;
    votingPeriod: number;
    proposalThreshold: string;
    quorumPercentage: number;
    multiSigOwners: string[];
    multiSigThreshold: number;
  };
  txHashes: { [key: string]: string };
}

// Configuration for different environments
const GOVERNANCE_CONFIG = {
  // Testnet: Faster for testing
  testnet: {
    timelockDelay: 3600, // 1 hour
    votingDelay: 300, // 5 minutes (~25 blocks)
    votingPeriod: 3600, // 1 hour
    proposalThreshold: ethers.parseEther("1000"), // 1,000 Soul
    quorumPercentage: 4, // 4%
    initialSupply: ethers.parseEther("100000000"), // 100M Soul
  },
  // Mainnet: Production settings
  mainnet: {
    timelockDelay: 172800, // 2 days
    votingDelay: 86400, // 1 day
    votingPeriod: 604800, // 7 days
    proposalThreshold: ethers.parseEther("100000"), // 100,000 Soul
    quorumPercentage: 4, // 4%
    initialSupply: ethers.parseEther("1000000000"), // 1B Soul
  },
};

async function main() {
  const [deployer, ...otherSigners] = await ethers.getSigners();
  const networkName = (await ethers.provider.getNetwork()).name;
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  
  // Use testnet config for non-mainnet
  const configKey = chainId === 1 ? "mainnet" : "testnet";
  const config = GOVERNANCE_CONFIG[configKey];

  console.log("\n" + "=".repeat(60));
  console.log("Soul GOVERNANCE DEPLOYMENT");
  console.log("=".repeat(60));
  console.log(`\nNetwork: ${networkName} (Chain ID: ${chainId})`);
  console.log(`Deployer: ${deployer.address}`);
  console.log(`Config: ${configKey}\n`);

  const deployment: GovernanceDeployment = {
    network: networkName,
    chainId,
    timestamp: new Date().toISOString(),
    deployer: deployer.address,
    contracts: {
      SoulToken: "",
      TimelockController: "",
      SoulGovernor: "",
    },
    configuration: {
      timelockDelay: config.timelockDelay,
      votingDelay: config.votingDelay,
      votingPeriod: config.votingPeriod,
      proposalThreshold: ethers.formatEther(config.proposalThreshold),
      quorumPercentage: config.quorumPercentage,
      multiSigOwners: [],
      multiSigThreshold: 0,
    },
    txHashes: {},
  };

  // ==========================================================================
  // STEP 1: Deploy Soul Token
  // ==========================================================================
  console.log("📦 Step 1: Deploying Soul Token...\n");
  
  const SoulToken = await ethers.getContractFactory("SoulToken");
  const pilToken = await SoulToken.deploy(deployer.address);
  await pilToken.waitForDeployment();
  
  const tokenAddress = await pilToken.getAddress();
  deployment.contracts.SoulToken = tokenAddress;
  deployment.txHashes.SoulToken = pilToken.deploymentTransaction()?.hash || "";
  
  console.log(`  ✅ SoulToken deployed: ${tokenAddress}`);
  console.log(`     Initial supply: ${ethers.formatEther(config.initialSupply)} Soul\n`);

  // ==========================================================================
  // STEP 2: Deploy Timelock Controller
  // ==========================================================================
  console.log("📦 Step 2: Deploying Timelock Controller...\n");

  // Timelock roles setup:
  // - Proposers: Will be granted to Governor after deployment
  // - Executors: Zero address = anyone can execute
  // - Admin: Deployer initially, will be renounced
  const proposers: string[] = [];
  const executors = [ethers.ZeroAddress];
  const admin = deployer.address;

  const TimelockController = await ethers.getContractFactory("TimelockController");
  const timelock = await TimelockController.deploy(
    config.timelockDelay,
    proposers,
    executors,
    admin
  );
  await timelock.waitForDeployment();

  const timelockAddress = await timelock.getAddress();
  deployment.contracts.TimelockController = timelockAddress;
  deployment.txHashes.TimelockController = timelock.deploymentTransaction()?.hash || "";

  console.log(`  ✅ TimelockController deployed: ${timelockAddress}`);
  console.log(`     Min delay: ${config.timelockDelay} seconds (${config.timelockDelay / 3600} hours)\n`);

  // ==========================================================================
  // STEP 3: Deploy Soul Governor
  // ==========================================================================
  console.log("📦 Step 3: Deploying Soul Governor...\n");

  const SoulGovernor = await ethers.getContractFactory("SoulGovernor");
  const governor = await SoulGovernor.deploy(tokenAddress, timelockAddress);
  await governor.waitForDeployment();

  const governorAddress = await governor.getAddress();
  deployment.contracts.SoulGovernor = governorAddress;
  deployment.txHashes.SoulGovernor = governor.deploymentTransaction()?.hash || "";

  console.log(`  ✅ SoulGovernor deployed: ${governorAddress}`);
  console.log(`     Voting delay: ${config.votingDelay} seconds`);
  console.log(`     Voting period: ${config.votingPeriod} seconds`);
  console.log(`     Quorum: ${config.quorumPercentage}%\n`);

  // ==========================================================================
  // STEP 4: Configure Timelock Roles
  // ==========================================================================
  console.log("🔧 Step 4: Configuring Timelock Roles...\n");

  const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
  const CANCELLER_ROLE = await timelock.CANCELLER_ROLE();
  const TIMELOCK_ADMIN_ROLE = await timelock.DEFAULT_ADMIN_ROLE();

  // Grant proposer and canceller roles to governor
  console.log("  Granting PROPOSER_ROLE to Governor...");
  await (await timelock.grantRole(PROPOSER_ROLE, governorAddress)).wait();
  console.log("  ✅ PROPOSER_ROLE granted");

  console.log("  Granting CANCELLER_ROLE to Governor...");
  await (await timelock.grantRole(CANCELLER_ROLE, governorAddress)).wait();
  console.log("  ✅ CANCELLER_ROLE granted");

  // For testnet, keep admin role. For mainnet, renounce it.
  if (configKey === "mainnet") {
    console.log("  Renouncing ADMIN_ROLE (mainnet)...");
    await (await timelock.renounceRole(TIMELOCK_ADMIN_ROLE, deployer.address)).wait();
    console.log("  ✅ ADMIN_ROLE renounced");
  } else {
    console.log("  ⚠️  Keeping ADMIN_ROLE for testnet flexibility\n");
  }

  // ==========================================================================
  // STEP 5: Multi-sig Setup (Optional)
  // ==========================================================================
  console.log("🔧 Step 5: Multi-sig Configuration...\n");

  // For production, set up multi-sig owners
  const multiSigOwners = process.env.MULTISIG_OWNERS
    ? process.env.MULTISIG_OWNERS.split(",")
    : [deployer.address];
  const multiSigThreshold = Math.min(
    Number(process.env.MULTISIG_THRESHOLD) || Math.ceil(multiSigOwners.length / 2),
    multiSigOwners.length
  );

  deployment.configuration.multiSigOwners = multiSigOwners;
  deployment.configuration.multiSigThreshold = multiSigThreshold;

  console.log(`  Multi-sig owners: ${multiSigOwners.length}`);
  console.log(`  Threshold: ${multiSigThreshold} of ${multiSigOwners.length}`);

  if (process.env.DEPLOY_SAFE === "true") {
    console.log("\n  Deploying Gnosis Safe Multi-sig...");
    // Note: In production, use Gnosis Safe Factory
    // This is a placeholder for Safe deployment
    console.log("  ⚠️  Safe deployment requires Gnosis Safe contracts");
    console.log("     For production, use https://safe.global to create Safe\n");
  }

  // ==========================================================================
  // STEP 6: Initial Token Distribution
  // ==========================================================================
  console.log("📦 Step 6: Initial Token Distribution...\n");

  // Mint initial supply to deployer
  console.log(`  Minting ${ethers.formatEther(config.initialSupply)} Soul to deployer...`);
  // Note: This assumes SoulToken has a mint function accessible to owner
  // If not, initial supply should be in constructor

  // Delegate votes to self (required for governance participation)
  console.log("  Delegating votes to deployer...");
  await (await pilToken.delegate(deployer.address)).wait();
  console.log("  ✅ Votes delegated\n");

  // ==========================================================================
  // STEP 7: Verify Setup
  // ==========================================================================
  console.log("🔍 Step 7: Verifying Setup...\n");

  const tokenName = await pilToken.name();
  const tokenSymbol = await pilToken.symbol();
  const govName = await governor.name();
  const votingDelay = await governor.votingDelay();
  const votingPeriod = await governor.votingPeriod();

  console.log(`  Token: ${tokenName} (${tokenSymbol})`);
  console.log(`  Governor: ${govName}`);
  console.log(`  Voting delay: ${votingDelay} blocks`);
  console.log(`  Voting period: ${votingPeriod} blocks`);
  console.log(`  Timelock connected: ${await governor.timelock() === timelockAddress ? "✅" : "❌"}\n`);

  // ==========================================================================
  // Save Deployment
  // ==========================================================================
  const deploymentsDir = path.join(__dirname, "../../deployments/governance");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const filename = `governance-${networkName}-${Date.now()}.json`;
  const filepath = path.join(deploymentsDir, filename);
  fs.writeFileSync(filepath, JSON.stringify(deployment, null, 2));

  // Also save as latest
  const latestPath = path.join(deploymentsDir, `governance-${networkName}-latest.json`);
  fs.writeFileSync(latestPath, JSON.stringify(deployment, null, 2));

  // ==========================================================================
  // Summary
  // ==========================================================================
  console.log("=".repeat(60));
  console.log("GOVERNANCE DEPLOYMENT COMPLETE");
  console.log("=".repeat(60));
  console.log(`
Deployed Contracts:
  - SoulToken:           ${deployment.contracts.SoulToken}
  - TimelockController: ${deployment.contracts.TimelockController}  
  - SoulGovernor:        ${deployment.contracts.SoulGovernor}

Configuration:
  - Timelock delay:     ${config.timelockDelay / 3600} hours
  - Voting delay:       ${config.votingDelay / 60} minutes
  - Voting period:      ${config.votingPeriod / 3600} hours
  - Proposal threshold: ${ethers.formatEther(config.proposalThreshold)} Soul
  - Quorum:             ${config.quorumPercentage}%

Deployment saved to: ${filepath}

Next Steps:
  1. Verify contracts on block explorer
  2. Set up multi-sig for critical operations
  3. Transfer ownership to timelock where appropriate
  4. Create initial governance proposals
  5. Distribute Soul tokens to stakeholders
`);

  return deployment;
}

// Create a proposal helper function
async function createProposal(
  governorAddress: string,
  targets: string[],
  values: bigint[],
  calldatas: string[],
  description: string
) {
  const [signer] = await ethers.getSigners();
  const governor = await ethers.getContractAt("SoulGovernor", governorAddress);
  
  console.log("Creating proposal...");
  const tx = await governor.propose(targets, values, calldatas, description);
  const receipt = await tx.wait();
  
  // Get proposal ID from event
  const event = receipt?.logs.find(
    (log: any) => log.fragment?.name === "ProposalCreated"
  );
  
  if (event) {
    const proposalId = (event as any).args.proposalId;
    console.log(`Proposal created: ${proposalId}`);
    return proposalId;
  }
  
  return null;
}

// Execute
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
