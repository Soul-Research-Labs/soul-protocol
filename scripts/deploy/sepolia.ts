import { ethers, run, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Sepolia Deployment Script for Soul Private Exchange
 * 
 * Prerequisites:
 * 1. Set SEPOLIA_RPC_URL and PRIVATE_KEY in .env
 * 2. Have testnet ETH in deployer account
 * 3. Run: npx hardhat run scripts/deploy/sepolia.ts --network sepolia
 */

interface DeployedContracts {
  network: string;
  chainId: number;
  deployer: string;
  timestamp: string;
  contracts: {
    tokenA: string;
    tokenB: string;
    tokenC: string;
    exchange: string;
    stealthRegistry: string;
    mpcOrderMatcher: string;
    gasOptimizedVerifier: string;
  };
  txHashes: {
    [key: string]: string;
  };
}

async function main() {
  console.log("\n🚀 Soul Private Exchange - Sepolia Deployment\n");
  console.log("=".repeat(60));

  // Verify network
  if (network.name !== "sepolia") {
    console.log("⚠️  Warning: Not on Sepolia network. Current network:", network.name);
    console.log("   Run with: npx hardhat run scripts/deploy/sepolia.ts --network sepolia\n");
  }

  const [deployer] = await ethers.getSigners();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log("\n📋 Deployment Configuration:");
  console.log(`   Network:   ${network.name}`);
  console.log(`   Chain ID:  ${network.config.chainId}`);
  console.log(`   Deployer:  ${deployer.address}`);
  console.log(`   Balance:   ${ethers.formatEther(balance)} ETH`);

  if (balance < ethers.parseEther("0.1")) {
    console.log("\n❌ Insufficient balance. Need at least 0.1 ETH for deployment.");
    return;
  }

  const deployed: DeployedContracts = {
    network: network.name,
    chainId: network.config.chainId || 11155111,
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
    contracts: {
      tokenA: "",
      tokenB: "",
      tokenC: "",
      exchange: "",
      stealthRegistry: "",
      mpcOrderMatcher: "",
      gasOptimizedVerifier: "",
    },
    txHashes: {},
  };

  // =========================================================================
  // Step 1: Deploy Test Tokens
  // =========================================================================
  console.log("\n\n🪙 Step 1: Deploying Test Tokens...");
  console.log("-".repeat(40));

  const MockToken = await ethers.getContractFactory("MockToken");

  // Token A
  console.log("   Deploying Token A...");
  const tokenA = await MockToken.deploy("Soul Test Token A", "SoulA", 18);
  await tokenA.waitForDeployment();
  deployed.contracts.tokenA = await tokenA.getAddress();
  deployed.txHashes.tokenA = tokenA.deploymentTransaction()?.hash || "";
  console.log(`   ✅ Token A: ${deployed.contracts.tokenA}`);

  // Token B
  console.log("   Deploying Token B...");
  const tokenB = await MockToken.deploy("Soul Test Token B", "SoulB", 18);
  await tokenB.waitForDeployment();
  deployed.contracts.tokenB = await tokenB.getAddress();
  deployed.txHashes.tokenB = tokenB.deploymentTransaction()?.hash || "";
  console.log(`   ✅ Token B: ${deployed.contracts.tokenB}`);

  // Token C (6 decimals for USDC-like token)
  console.log("   Deploying Token C...");
  const tokenC = await MockToken.deploy("Soul Stablecoin", "SoulUSD", 6);
  await tokenC.waitForDeployment();
  deployed.contracts.tokenC = await tokenC.getAddress();
  deployed.txHashes.tokenC = tokenC.deploymentTransaction()?.hash || "";
  console.log(`   ✅ Token C: ${deployed.contracts.tokenC}`);

  // =========================================================================
  // Step 2: Deploy Core Contracts
  // =========================================================================
  console.log("\n\n🏗️  Step 2: Deploying Core Contracts...");
  console.log("-".repeat(40));

  // Gas Optimized Verifier (Library)
  console.log("   Deploying GasOptimizedVerifier library...");
  const GasOptimizedVerifier = await ethers.getContractFactory("GasOptimizedVerifier");
  // Library is automatically linked when used

  // BatchProofVerifier
  console.log("   Deploying BatchProofVerifier...");
  const BatchProofVerifier = await ethers.getContractFactory("BatchProofVerifier");
  const batchVerifier = await BatchProofVerifier.deploy();
  await batchVerifier.waitForDeployment();
  deployed.contracts.gasOptimizedVerifier = await batchVerifier.getAddress();
  console.log(`   ✅ BatchProofVerifier: ${deployed.contracts.gasOptimizedVerifier}`);

  // Exchange
  console.log("   Deploying SoulPrivateExchange...");
  const Exchange = await ethers.getContractFactory("SoulPrivateExchange");
  const exchange = await Exchange.deploy(deployer.address);
  await exchange.waitForDeployment();
  deployed.contracts.exchange = await exchange.getAddress();
  deployed.txHashes.exchange = exchange.deploymentTransaction()?.hash || "";
  console.log(`   ✅ Exchange: ${deployed.contracts.exchange}`);

  // Stealth Address Registry
  console.log("   Deploying StealthAddressRegistry...");
  const StealthRegistry = await ethers.getContractFactory("StealthAddressRegistry");
  const stealthRegistry = await StealthRegistry.deploy(deployer.address);
  await stealthRegistry.waitForDeployment();
  deployed.contracts.stealthRegistry = await stealthRegistry.getAddress();
  deployed.txHashes.stealthRegistry = stealthRegistry.deploymentTransaction()?.hash || "";
  console.log(`   ✅ StealthRegistry: ${deployed.contracts.stealthRegistry}`);

  // MPC Order Matcher
  console.log("   Deploying MPCOrderMatcher...");
  const MPCMatcher = await ethers.getContractFactory("MPCOrderMatcher");
  const mpcMatcher = await MPCMatcher.deploy(
    deployed.contracts.tokenA, // Staking token
    ethers.parseEther("100"),  // Min stake
    3,                          // Threshold (3-of-n)
    deployer.address            // Admin
  );
  await mpcMatcher.waitForDeployment();
  deployed.contracts.mpcOrderMatcher = await mpcMatcher.getAddress();
  deployed.txHashes.mpcOrderMatcher = mpcMatcher.deploymentTransaction()?.hash || "";
  console.log(`   ✅ MPCOrderMatcher: ${deployed.contracts.mpcOrderMatcher}`);

  // =========================================================================
  // Step 3: Configure Exchange
  // =========================================================================
  console.log("\n\n⚙️  Step 3: Configuring Exchange...");
  console.log("-".repeat(40));

  // Add supported tokens
  console.log("   Adding Token A support...");
  await exchange.addSupportedToken(
    deployed.contracts.tokenA,
    ethers.parseEther("0.001"),
    ethers.parseEther("1000000")
  );

  console.log("   Adding Token B support...");
  await exchange.addSupportedToken(
    deployed.contracts.tokenB,
    ethers.parseEther("0.001"),
    ethers.parseEther("1000000")
  );

  console.log("   Adding Token C (stablecoin) support...");
  await exchange.addSupportedToken(
    deployed.contracts.tokenC,
    1000n,                      // Min: 0.001 (6 decimals)
    1000000000000n              // Max: 1M tokens
  );

  console.log("   ✅ All tokens added to exchange");

  // =========================================================================
  // Step 4: Mint Test Tokens
  // =========================================================================
  console.log("\n\n🪙 Step 4: Minting Test Tokens...");
  console.log("-".repeat(40));

  const mintAmount = ethers.parseEther("1000000");
  
  await tokenA.mint(deployer.address, mintAmount);
  console.log(`   ✅ Minted ${ethers.formatEther(mintAmount)} Token A`);
  
  await tokenB.mint(deployer.address, mintAmount);
  console.log(`   ✅ Minted ${ethers.formatEther(mintAmount)} Token B`);
  
  await tokenC.mint(deployer.address, 1000000000000n); // 1M with 6 decimals
  console.log(`   ✅ Minted 1,000,000 Token C (stablecoin)`);

  // =========================================================================
  // Step 5: Verify Contracts (Optional)
  // =========================================================================
  console.log("\n\n🔍 Step 5: Contract Verification...");
  console.log("-".repeat(40));

  if (network.name === "sepolia") {
    console.log("   Waiting 30 seconds for Etherscan to index contracts...");
    await new Promise(resolve => setTimeout(resolve, 30000));

    try {
      console.log("   Verifying Token A...");
      await run("verify:verify", {
        address: deployed.contracts.tokenA,
        constructorArguments: ["Soul Test Token A", "SoulA", 18],
      });
      console.log("   ✅ Token A verified");
    } catch (e: any) {
      console.log(`   ⚠️  Token A verification: ${e.message}`);
    }

    try {
      console.log("   Verifying Exchange...");
      await run("verify:verify", {
        address: deployed.contracts.exchange,
        constructorArguments: [deployer.address],
      });
      console.log("   ✅ Exchange verified");
    } catch (e: any) {
      console.log(`   ⚠️  Exchange verification: ${e.message}`);
    }

    try {
      console.log("   Verifying Stealth Registry...");
      await run("verify:verify", {
        address: deployed.contracts.stealthRegistry,
        constructorArguments: [deployer.address],
      });
      console.log("   ✅ Stealth Registry verified");
    } catch (e: any) {
      console.log(`   ⚠️  Stealth Registry verification: ${e.message}`);
    }
  } else {
    console.log("   ⏭️  Skipping verification (not on mainnet/testnet)");
  }

  // =========================================================================
  // Save Deployment
  // =========================================================================
  const deploymentDir = path.join(__dirname, "../../deployments");
  fs.mkdirSync(deploymentDir, { recursive: true });
  
  const deploymentFile = path.join(deploymentDir, `${network.name}.json`);
  fs.writeFileSync(deploymentFile, JSON.stringify(deployed, null, 2));

  // =========================================================================
  // Summary
  // =========================================================================
  console.log("\n\n" + "=".repeat(60));
  console.log("📊 Deployment Summary");
  console.log("=".repeat(60));

  console.log("\n🏗️  Deployed Contracts:");
  console.log(`   Token A:            ${deployed.contracts.tokenA}`);
  console.log(`   Token B:            ${deployed.contracts.tokenB}`);
  console.log(`   Token C:            ${deployed.contracts.tokenC}`);
  console.log(`   Exchange:           ${deployed.contracts.exchange}`);
  console.log(`   Stealth Registry:   ${deployed.contracts.stealthRegistry}`);
  console.log(`   MPC Order Matcher:  ${deployed.contracts.mpcOrderMatcher}`);
  console.log(`   Batch Verifier:     ${deployed.contracts.gasOptimizedVerifier}`);

  console.log("\n🔗 Etherscan Links:");
  console.log(`   Exchange: https://sepolia.etherscan.io/address/${deployed.contracts.exchange}`);
  console.log(`   Stealth:  https://sepolia.etherscan.io/address/${deployed.contracts.stealthRegistry}`);

  console.log(`\n💾 Deployment saved to: ${deploymentFile}`);

  console.log("\n📝 Next Steps:");
  console.log("   1. Get testnet tokens from faucet or use minted tokens");
  console.log("   2. Approve exchange to spend tokens");
  console.log("   3. Make deposits and create orders");
  console.log("   4. Register stealth meta-address for private payments");

  console.log("\n" + "=".repeat(60));
  console.log("✅ Deployment Complete!");
  console.log("=".repeat(60) + "\n");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Deployment failed:");
    console.error(error);
    process.exit(1);
  });
