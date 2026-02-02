#!/usr/bin/env node
/**
 * @title L2 Deployment Script
 * @notice Deploys Soul contracts to L2 testnets
 * @dev Supports Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM
 */

const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

// L2 Network configurations
const L2_NETWORKS = {
  // OP Stack L2s
  "optimism-sepolia": {
    chainId: 11155420,
    rpcUrl: process.env.OPTIMISM_SEPOLIA_RPC || "https://sepolia.optimism.io",
    explorer: "https://sepolia-optimism.etherscan.io",
    bridgeType: "OP_STACK",
    nativeBridge: "0x4200000000000000000000000000000000000007", // L2CrossDomainMessenger
  },
  "base-sepolia": {
    chainId: 84532,
    rpcUrl: process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org",
    explorer: "https://sepolia.basescan.org",
    bridgeType: "OP_STACK",
    nativeBridge: "0x4200000000000000000000000000000000000007",
  },
  // Arbitrum
  "arbitrum-sepolia": {
    chainId: 421614,
    rpcUrl: process.env.ARBITRUM_SEPOLIA_RPC || "https://sepolia-rollup.arbitrum.io/rpc",
    explorer: "https://sepolia.arbiscan.io",
    bridgeType: "ARBITRUM",
    inbox: "0xaAe29B0366299461418F5324a79Afc425BE5ae21",
    outbox: "0x65f07C7D521164a4d5DaC6eB8Fac8DA067A3B78F",
  },
  // zkSync Era
  "zksync-sepolia": {
    chainId: 300,
    rpcUrl: process.env.ZKSYNC_SEPOLIA_RPC || "https://sepolia.era.zksync.dev",
    explorer: "https://sepolia.explorer.zksync.io",
    bridgeType: "ZKSYNC",
    l1Bridge: "0x927DdFcc55164a59E0F33918D13a2D559bC10ce7",
  },
  // Scroll
  "scroll-sepolia": {
    chainId: 534351,
    rpcUrl: process.env.SCROLL_SEPOLIA_RPC || "https://sepolia-rpc.scroll.io",
    explorer: "https://sepolia.scrollscan.com",
    bridgeType: "SCROLL",
    messenger: "0x50c7d3e7f7c656493D1D76aaa1a836CedfCBB16A",
  },
  // Linea
  "linea-sepolia": {
    chainId: 59141,
    rpcUrl: process.env.LINEA_SEPOLIA_RPC || "https://rpc.sepolia.linea.build",
    explorer: "https://sepolia.lineascan.build",
    bridgeType: "LINEA",
    messageService: "0xC499a572640B64eA1C8c194c43Bc3E19940719dC",
  },
  // Polygon zkEVM
  "polygon-zkevm-cardona": {
    chainId: 2442,
    rpcUrl: process.env.POLYGON_ZKEVM_RPC || "https://rpc.cardona.zkevm-rpc.com",
    explorer: "https://cardona-zkevm.polygonscan.com",
    bridgeType: "POLYGON_ZKEVM",
    bridge: "0x528e26b25a34a4A5d0dbDa1d57D318153d2ED582",
  },
};

// Core contracts to deploy on each L2
const CORE_CONTRACTS = [
  "MockProofVerifier",
  "NullifierRegistryV3",
  "CrossChainProofHubV3",
  "ProofCarryingContainer",
  "ZKBoundStateLocks",
];

// Security contracts
const SECURITY_CONTRACTS = [
  "MEVProtection",
  "FlashLoanGuard",
  "BridgeRateLimiter",
  "BridgeCircuitBreaker",
];

// Bridge adapters per network type
const BRIDGE_ADAPTERS = {
  OP_STACK: "OptimismBridgeAdapter",
  ARBITRUM: "ArbitrumBridgeAdapter",
  ZKSYNC: "zkSyncBridgeAdapter",
  SCROLL: "ScrollBridgeAdapter",
  LINEA: "LineaBridgeAdapter",
  POLYGON_ZKEVM: "PolygonZkEVMBridgeAdapter",
};

async function deployToL2(networkName) {
  const networkConfig = L2_NETWORKS[networkName];
  if (!networkConfig) {
    throw new Error(`Unknown network: ${networkName}`);
  }

  console.log(`\n${"=".repeat(60)}`);
  console.log(`Deploying to ${networkName} (chainId: ${networkConfig.chainId})`);
  console.log(`${"=".repeat(60)}\n`);

  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");

  const deployed = {
    network: networkName,
    chainId: networkConfig.chainId,
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
    contracts: {},
  };

  // 1. Deploy Core Contracts
  console.log("\n--- Core Contracts ---");

  // MockProofVerifier
  console.log("Deploying MockProofVerifier...");
  const MockVerifier = await ethers.getContractFactory("MockProofVerifier");
  const verifier = await MockVerifier.deploy();
  await verifier.waitForDeployment();
  deployed.contracts.verifier = await verifier.getAddress();
  console.log(`  MockProofVerifier: ${deployed.contracts.verifier}`);

  // NullifierRegistryV3
  console.log("Deploying NullifierRegistryV3...");
  const NullifierRegistry = await ethers.getContractFactory("NullifierRegistryV3");
  const nullifierRegistry = await NullifierRegistry.deploy();
  await nullifierRegistry.waitForDeployment();
  deployed.contracts.nullifierRegistry = await nullifierRegistry.getAddress();
  console.log(`  NullifierRegistryV3: ${deployed.contracts.nullifierRegistry}`);

  // CrossChainProofHubV3
  console.log("Deploying CrossChainProofHubV3...");
  const minimumStake = ethers.parseEther("0.01"); // Lower for testnet
  const challengePeriod = 300; // 5 minutes for testing
  const ProofHub = await ethers.getContractFactory("CrossChainProofHubV3");
  const proofHub = await ProofHub.deploy(deployed.contracts.verifier, minimumStake, challengePeriod);
  await proofHub.waitForDeployment();
  deployed.contracts.proofHub = await proofHub.getAddress();
  console.log(`  CrossChainProofHubV3: ${deployed.contracts.proofHub}`);

  // ProofCarryingContainer
  console.log("Deploying ProofCarryingContainer...");
  const ProofCarryingContainer = await ethers.getContractFactory("ProofCarryingContainer");
  const proofCarryingContainer = await ProofCarryingContainer.deploy(deployed.contracts.verifier);
  await proofCarryingContainer.waitForDeployment();
  deployed.contracts.proofCarryingContainer = await proofCarryingContainer.getAddress();
  console.log(`  ProofCarryingContainer: ${deployed.contracts.proofCarryingContainer}`);

  // ZKBoundStateLocks
  console.log("Deploying ZKBoundStateLocks...");
  const ZKBoundStateLocks = await ethers.getContractFactory("ZKBoundStateLocks");
  const zkBoundStateLocks = await ZKBoundStateLocks.deploy(
    deployed.contracts.verifier,
    deployed.contracts.proofCarryingContainer
  );
  await zkBoundStateLocks.waitForDeployment();
  deployed.contracts.zkBoundStateLocks = await zkBoundStateLocks.getAddress();
  console.log(`  ZKBoundStateLocks: ${deployed.contracts.zkBoundStateLocks}`);

  // 2. Deploy Security Contracts
  console.log("\n--- Security Contracts ---");

  // MEVProtection
  console.log("Deploying MEVProtection...");
  const MEVProtection = await ethers.getContractFactory("MEVProtection");
  const mevProtection = await MEVProtection.deploy();
  await mevProtection.waitForDeployment();
  deployed.contracts.mevProtection = await mevProtection.getAddress();
  console.log(`  MEVProtection: ${deployed.contracts.mevProtection}`);

  // FlashLoanGuard
  console.log("Deploying FlashLoanGuard...");
  const FlashLoanGuard = await ethers.getContractFactory("FlashLoanGuard");
  const flashLoanGuard = await FlashLoanGuard.deploy();
  await flashLoanGuard.waitForDeployment();
  deployed.contracts.flashLoanGuard = await flashLoanGuard.getAddress();
  console.log(`  FlashLoanGuard: ${deployed.contracts.flashLoanGuard}`);

  // BridgeRateLimiter
  console.log("Deploying BridgeRateLimiter...");
  const BridgeRateLimiter = await ethers.getContractFactory("BridgeRateLimiter");
  const bridgeRateLimiter = await BridgeRateLimiter.deploy(
    ethers.parseEther("100"), // 100 ETH daily limit
    ethers.parseEther("10"),  // 10 ETH per tx
    ethers.parseEther("1"),   // 1 ETH min tx
    3600                      // 1 hour window
  );
  await bridgeRateLimiter.waitForDeployment();
  deployed.contracts.bridgeRateLimiter = await bridgeRateLimiter.getAddress();
  console.log(`  BridgeRateLimiter: ${deployed.contracts.bridgeRateLimiter}`);

  // BridgeCircuitBreaker
  console.log("Deploying BridgeCircuitBreaker...");
  const BridgeCircuitBreaker = await ethers.getContractFactory("BridgeCircuitBreaker");
  const bridgeCircuitBreaker = await BridgeCircuitBreaker.deploy(
    ethers.parseEther("50"), // 50 ETH anomaly threshold
    10,                       // Max 10 failures
    300                       // 5 minute recovery
  );
  await bridgeCircuitBreaker.waitForDeployment();
  deployed.contracts.bridgeCircuitBreaker = await bridgeCircuitBreaker.getAddress();
  console.log(`  BridgeCircuitBreaker: ${deployed.contracts.bridgeCircuitBreaker}`);

  // 3. Deploy Network-Specific Bridge Adapter
  console.log("\n--- Bridge Adapter ---");
  const adapterName = BRIDGE_ADAPTERS[networkConfig.bridgeType];
  console.log(`Deploying ${adapterName}...`);

  let bridgeAdapter;
  try {
    const BridgeAdapter = await ethers.getContractFactory(adapterName);

    switch (networkConfig.bridgeType) {
      case "OP_STACK":
        bridgeAdapter = await BridgeAdapter.deploy(networkConfig.nativeBridge);
        break;
      case "ARBITRUM":
        bridgeAdapter = await BridgeAdapter.deploy(networkConfig.inbox, networkConfig.outbox);
        break;
      case "ZKSYNC":
        bridgeAdapter = await BridgeAdapter.deploy(networkConfig.l1Bridge);
        break;
      case "SCROLL":
        bridgeAdapter = await BridgeAdapter.deploy(networkConfig.messenger);
        break;
      case "LINEA":
        bridgeAdapter = await BridgeAdapter.deploy(networkConfig.messageService);
        break;
      case "POLYGON_ZKEVM":
        bridgeAdapter = await BridgeAdapter.deploy(networkConfig.bridge);
        break;
      default:
        throw new Error(`Unknown bridge type: ${networkConfig.bridgeType}`);
    }

    await bridgeAdapter.waitForDeployment();
    deployed.contracts.bridgeAdapter = await bridgeAdapter.getAddress();
    console.log(`  ${adapterName}: ${deployed.contracts.bridgeAdapter}`);
  } catch (error) {
    console.log(`  Warning: Could not deploy ${adapterName}: ${error.message}`);
    deployed.contracts.bridgeAdapter = "NOT_DEPLOYED";
  }

  // 4. Deploy CrossL2Atomicity
  console.log("\n--- Cross-L2 Atomicity ---");
  console.log("Deploying CrossL2Atomicity...");
  try {
    const CrossL2Atomicity = await ethers.getContractFactory("CrossL2Atomicity");
    const crossL2Atomicity = await CrossL2Atomicity.deploy();
    await crossL2Atomicity.waitForDeployment();
    deployed.contracts.crossL2Atomicity = await crossL2Atomicity.getAddress();
    console.log(`  CrossL2Atomicity: ${deployed.contracts.crossL2Atomicity}`);
  } catch (error) {
    console.log(`  Warning: Could not deploy CrossL2Atomicity: ${error.message}`);
    deployed.contracts.crossL2Atomicity = "NOT_DEPLOYED";
  }

  // 5. Configure permissions
  console.log("\n--- Configuring Permissions ---");

  // Grant RELAYER role to bridge adapter
  if (deployed.contracts.bridgeAdapter !== "NOT_DEPLOYED") {
    try {
      const RELAYER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("RELAYER_ROLE"));
      await proofHub.grantRole(RELAYER_ROLE, deployed.contracts.bridgeAdapter);
      console.log("  Granted RELAYER_ROLE to bridge adapter");
    } catch (error) {
      console.log(`  Warning: Could not grant RELAYER_ROLE: ${error.message}`);
    }
  }

  // 6. Save deployment
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const deploymentFile = path.join(deploymentsDir, `${networkName}-${networkConfig.chainId}.json`);
  fs.writeFileSync(deploymentFile, JSON.stringify(deployed, null, 2));
  console.log(`\nDeployment saved to: ${deploymentFile}`);

  // Print summary
  console.log("\n--- Deployment Summary ---");
  console.log(`Network: ${networkName}`);
  console.log(`Chain ID: ${networkConfig.chainId}`);
  console.log(`Explorer: ${networkConfig.explorer}`);
  console.log(`Contracts deployed: ${Object.keys(deployed.contracts).length}`);

  return deployed;
}

async function deployAll() {
  console.log("Soul L2 Deployment Script");
  console.log("========================\n");

  const results = {};
  const networks = process.argv.slice(2);

  if (networks.length === 0) {
    console.log("Usage: npx hardhat run scripts/deploy-l2.js --network <network>");
    console.log("\nAvailable networks:");
    Object.keys(L2_NETWORKS).forEach((net) => {
      console.log(`  - ${net} (chainId: ${L2_NETWORKS[net].chainId})`);
    });
    return;
  }

  // Get current network from hardhat
  const network = await ethers.provider.getNetwork();
  const networkName = Object.keys(L2_NETWORKS).find(
    (name) => L2_NETWORKS[name].chainId === Number(network.chainId)
  );

  if (!networkName) {
    console.log(`Unknown network with chainId ${network.chainId}`);
    console.log("Please use one of the supported L2 networks.");
    return;
  }

  results[networkName] = await deployToL2(networkName);

  console.log("\n" + "=".repeat(60));
  console.log("All deployments complete!");
  console.log("=".repeat(60));
}

async function main() {
  try {
    await deployAll();
  } catch (error) {
    console.error("Deployment failed:", error);
    process.exit(1);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
