import { ethers, network, run } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Zaseon Multi-Chain Testnet Deployment Script
 * Supports: Sepolia, Arbitrum Sepolia, Base Sepolia, Optimism Sepolia
 */

interface DeploymentConfig {
  name: string;
  chainId: number;
  rpcUrl: string;
  explorerUrl: string;
  nativeToken: string;
  gasLimit: bigint;
}

interface DeployedContracts {
  network: string;
  chainId: number;
  timestamp: string;
  deployer: string;
  contracts: {
    // Core
    TokenLocker?: string;
    CrossChainBridge?: string;
    ZKVerifier?: string;
    ComplianceOracle?: string;

    // PQC
    DilithiumVerifier?: string;
    SPHINCSPlusVerifier?: string;
    KyberKEM?: string;
    PQCRegistry?: string;
    PQCProtectedLock?: string;

    // Governance
    ZaseonToken?: string;
    ZaseonGovernor?: string;
    TimelockController?: string;

    // Bridge Adapters
    CCIPAdapter?: string;
    LayerZeroAdapter?: string;
    AxelarAdapter?: string;
  };
  txHashes: { [key: string]: string };
}

const NETWORK_CONFIGS: { [key: string]: DeploymentConfig } = {
  sepolia: {
    name: "Sepolia",
    chainId: 11155111,
    rpcUrl: process.env.SEPOLIA_RPC_URL || "https://sepolia.infura.io/v3/",
    explorerUrl: "https://sepolia.etherscan.io",
    nativeToken: "ETH",
    gasLimit: 30000000n,
  },
  arbitrumSepolia: {
    name: "Arbitrum Sepolia",
    chainId: 421614,
    rpcUrl:
      process.env.ARBITRUM_SEPOLIA_RPC_URL ||
      "https://sepolia-rollup.arbitrum.io/rpc",
    explorerUrl: "https://sepolia.arbiscan.io",
    nativeToken: "ETH",
    gasLimit: 50000000n,
  },
  baseSepolia: {
    name: "Base Sepolia",
    chainId: 84532,
    rpcUrl: process.env.BASE_SEPOLIA_RPC_URL || "https://sepolia.base.org",
    explorerUrl: "https://sepolia.basescan.org",
    nativeToken: "ETH",
    gasLimit: 30000000n,
  },
  optimismSepolia: {
    name: "Optimism Sepolia",
    chainId: 11155420,
    rpcUrl:
      process.env.OPTIMISM_SEPOLIA_RPC_URL || "https://sepolia.optimism.io",
    explorerUrl: "https://sepolia-optimism.etherscan.io",
    nativeToken: "ETH",
    gasLimit: 30000000n,
  },
};

async function main() {
  const networkName = network.name;
  const config = NETWORK_CONFIGS[networkName];

  if (!config) {
    console.log("Available networks:", Object.keys(NETWORK_CONFIGS).join(", "));
    throw new Error(`Unsupported network: ${networkName}`);
  }

  console.log("\n" + "=".repeat(60));
  console.log(`Zaseon TESTNET DEPLOYMENT - ${config.name}`);
  console.log("=".repeat(60) + "\n");

  const [deployer] = await ethers.getSigners();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log(`Network: ${config.name} (Chain ID: ${config.chainId})`);
  console.log(`Deployer: ${deployer.address}`);
  console.log(
    `Balance: ${ethers.formatEther(balance)} ${config.nativeToken}\n`,
  );

  if (balance < ethers.parseEther("0.1")) {
    throw new Error(
      "Insufficient balance for deployment. Need at least 0.1 ETH",
    );
  }

  const deployment: DeployedContracts = {
    network: networkName,
    chainId: config.chainId,
    timestamp: new Date().toISOString(),
    deployer: deployer.address,
    contracts: {},
    txHashes: {},
  };

  // ==========================================================================
  // PHASE 1: Deploy PQC Contracts (Optional — contracts not yet implemented)
  // ==========================================================================
  console.log("📦 Phase 1: Deploying PQC Contracts (if available)...\n");

  let dilithiumAddr = "";
  let sphincsAddr = "";
  let kyberAddr = "";
  let registryAddr = "";

  try {
    const DilithiumVerifier =
      await ethers.getContractFactory("DilithiumVerifier");
    const dilithiumVerifier = await DilithiumVerifier.deploy();
    await dilithiumVerifier.waitForDeployment();
    dilithiumAddr = await dilithiumVerifier.getAddress();
    deployment.contracts.DilithiumVerifier = dilithiumAddr;
    deployment.txHashes.DilithiumVerifier =
      dilithiumVerifier.deploymentTransaction()?.hash || "";
    console.log(`    ✅ DilithiumVerifier: ${dilithiumAddr}`);

    const SPHINCSPlusVerifier = await ethers.getContractFactory(
      "SPHINCSPlusVerifier",
    );
    const sphincsVerifier = await SPHINCSPlusVerifier.deploy();
    await sphincsVerifier.waitForDeployment();
    sphincsAddr = await sphincsVerifier.getAddress();
    deployment.contracts.SPHINCSPlusVerifier = sphincsAddr;
    deployment.txHashes.SPHINCSPlusVerifier =
      sphincsVerifier.deploymentTransaction()?.hash || "";
    console.log(`    ✅ SPHINCSPlusVerifier: ${sphincsAddr}`);

    const KyberKEM = await ethers.getContractFactory("KyberKEM");
    const kyberKEM = await KyberKEM.deploy();
    await kyberKEM.waitForDeployment();
    kyberAddr = await kyberKEM.getAddress();
    deployment.contracts.KyberKEM = kyberAddr;
    deployment.txHashes.KyberKEM = kyberKEM.deploymentTransaction()?.hash || "";
    console.log(`    ✅ KyberKEM: ${kyberAddr}`);

    const PQCRegistry = await ethers.getContractFactory("PQCRegistry");
    const pqcRegistry = await PQCRegistry.deploy(
      dilithiumAddr,
      sphincsAddr,
      kyberAddr,
    );
    await pqcRegistry.waitForDeployment();
    registryAddr = await pqcRegistry.getAddress();
    deployment.contracts.PQCRegistry = registryAddr;
    deployment.txHashes.PQCRegistry =
      pqcRegistry.deploymentTransaction()?.hash || "";
    console.log(`    ✅ PQCRegistry: ${registryAddr}`);
  } catch (e: any) {
    console.log(
      "    ⚠️  PQC contracts not found in source tree — skipping Phase 1",
    );
    console.log(
      "       (DilithiumVerifier, SPHINCSPlusVerifier, KyberKEM, PQCRegistry are not yet implemented)",
    );
  }

  // ==========================================================================
  // PHASE 2: Deploy Core Zaseon Contracts
  // ==========================================================================
  console.log("\n📦 Phase 2: Deploying Core Contracts...\n");

  // ZKVerifier (if exists)
  try {
    console.log("  Deploying ZKVerifier...");
    const ZKVerifier = await ethers.getContractFactory("ZKVerifier");
    const zkVerifier = await ZKVerifier.deploy();
    await zkVerifier.waitForDeployment();
    const zkAddr = await zkVerifier.getAddress();
    deployment.contracts.ZKVerifier = zkAddr;
    deployment.txHashes.ZKVerifier =
      zkVerifier.deploymentTransaction()?.hash || "";
    console.log(`    ✅ ZKVerifier: ${zkAddr}`);
  } catch (e) {
    console.log("    ⚠️ ZKVerifier not found, skipping...");
  }

  // TokenLocker with PQC (if exists and PQC was deployed)
  if (registryAddr) {
    try {
      console.log("  Deploying PQCProtectedLock...");
      const PQCProtectedLock =
        await ethers.getContractFactory("PQCProtectedLock");
      const pqcLock = await PQCProtectedLock.deploy(registryAddr);
      await pqcLock.waitForDeployment();
      const lockAddr = await pqcLock.getAddress();
      deployment.contracts.PQCProtectedLock = lockAddr;
      deployment.txHashes.PQCProtectedLock =
        pqcLock.deploymentTransaction()?.hash || "";
      console.log(`    ✅ PQCProtectedLock: ${lockAddr}`);
    } catch (e) {
      console.log("    ⚠️ PQCProtectedLock deployment issue, skipping...");
    }
  }

  // ==========================================================================
  // PHASE 3: Deploy Governance Contracts
  // ==========================================================================
  console.log("\n📦 Phase 3: Deploying Governance Contracts...\n");

  // ZaseonToken
  try {
    console.log("  Deploying ZaseonToken...");
    const ZaseonToken = await ethers.getContractFactory("ZaseonToken");
    const zaseonToken = await ZaseonToken.deploy(deployer.address);
    await zaseonToken.waitForDeployment();
    const tokenAddr = await zaseonToken.getAddress();
    deployment.contracts.ZaseonToken = tokenAddr;
    deployment.txHashes.ZaseonToken =
      zaseonToken.deploymentTransaction()?.hash || "";
    console.log(`    ✅ ZaseonToken: ${tokenAddr}`);

    // TimelockController
    console.log("  Deploying TimelockController...");
    const minDelay = 3600; // 1 hour for testnet (shorter for testing)
    const proposers = [deployer.address];
    const executors = [deployer.address, ethers.ZeroAddress]; // Anyone can execute
    const admin = deployer.address;

    const Timelock = await ethers.getContractFactory("TimelockController");
    const timelock = await Timelock.deploy(
      minDelay,
      proposers,
      executors,
      admin,
    );
    await timelock.waitForDeployment();
    const timelockAddr = await timelock.getAddress();
    deployment.contracts.TimelockController = timelockAddr;
    deployment.txHashes.TimelockController =
      timelock.deploymentTransaction()?.hash || "";
    console.log(`    ✅ TimelockController: ${timelockAddr}`);

    // ZaseonGovernor
    console.log("  Deploying ZaseonGovernor...");
    const ZaseonGovernor = await ethers.getContractFactory("ZaseonGovernor");
    const governor = await ZaseonGovernor.deploy(tokenAddr, timelockAddr);
    await governor.waitForDeployment();
    const govAddr = await governor.getAddress();
    deployment.contracts.ZaseonGovernor = govAddr;
    deployment.txHashes.ZaseonGovernor =
      governor.deploymentTransaction()?.hash || "";
    console.log(`    ✅ ZaseonGovernor: ${govAddr}`);

    // Grant proposer role to governor
    console.log("  Configuring governance roles...");
    const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
    const CANCELLER_ROLE = await timelock.CANCELLER_ROLE();
    await timelock.grantRole(PROPOSER_ROLE, govAddr);
    await timelock.grantRole(CANCELLER_ROLE, govAddr);
    console.log("    ✅ Governor granted PROPOSER and CANCELLER roles");
  } catch (e: any) {
    console.log(`    ⚠️ Governance deployment issue: ${e.message}`);
  }

  // ==========================================================================
  // PHASE 4: Verification (optional)
  // ==========================================================================
  if (process.env.VERIFY_CONTRACTS === "true") {
    console.log("\n📝 Phase 4: Verifying Contracts on Explorer...\n");

    try {
      if (deployment.contracts.DilithiumVerifier) {
        await run("verify:verify", {
          address: deployment.contracts.DilithiumVerifier,
          constructorArguments: [],
        });
        console.log("  ✅ DilithiumVerifier verified");
      }
    } catch (e) {
      console.log("  ⚠️ DilithiumVerifier verification failed");
    }

    try {
      if (
        deployment.contracts.PQCRegistry &&
        dilithiumAddr &&
        sphincsAddr &&
        kyberAddr
      ) {
        await run("verify:verify", {
          address: deployment.contracts.PQCRegistry,
          constructorArguments: [dilithiumAddr, sphincsAddr, kyberAddr],
        });
        console.log("  ✅ PQCRegistry verified");
      }
    } catch (e) {
      console.log("  ⚠️ PQCRegistry verification failed");
    }
  }

  // ==========================================================================
  // Save Deployment Info
  // ==========================================================================
  const deploymentsDir = path.join(__dirname, "../../deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const filename = `${networkName}-${Date.now()}.json`;
  const filepath = path.join(deploymentsDir, filename);
  fs.writeFileSync(filepath, JSON.stringify(deployment, null, 2));

  // Also update latest deployment
  const latestPath = path.join(deploymentsDir, `${networkName}-latest.json`);
  fs.writeFileSync(latestPath, JSON.stringify(deployment, null, 2));

  // ==========================================================================
  // Summary
  // ==========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("DEPLOYMENT COMPLETE");
  console.log("=".repeat(60));
  console.log(`\nNetwork: ${config.name}`);
  console.log(`Explorer: ${config.explorerUrl}`);
  console.log(`\nDeployed Contracts:`);

  Object.entries(deployment.contracts).forEach(([name, address]) => {
    console.log(`  ${name}: ${address}`);
    console.log(`    └─ ${config.explorerUrl}/address/${address}`);
  });

  console.log(`\nDeployment saved to: ${filepath}`);
  console.log("\n✅ All done!\n");

  return deployment;
}

// Execute
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
