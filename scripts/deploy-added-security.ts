import hre from "hardhat";
import { formatEther, parseEther } from "viem";
import * as fs from "fs";
import * as path from "path";

/**
 * Deploy Security Contracts to Sepolia
 *
 * Deploys existing security modules:
 * 1. ZKFraudProof
 * 2. BridgeCircuitBreaker
 * 3. BridgeRateLimiter
 * 4. FlashLoanGuard
 * 5. MEVProtection
 * 6. GriefingProtection
 * 7. EnhancedKillSwitch
 *
 * Run: npx hardhat run scripts/deploy-added-security.ts --network sepolia
 */

interface DeploymentResult {
  name: string;
  address: string;
}

async function main() {
  console.log("\n" + "=".repeat(60));
  console.log("   Zaseon Security Modules Deployment");
  console.log("=".repeat(60) + "\n");

  const [deployer] = await hre.viem.getWalletClients();
  const publicClient = await hre.viem.getPublicClient();

  console.log("Deployer:", deployer.account.address);

  const balance = await publicClient.getBalance({
    address: deployer.account.address,
  });
  console.log("Balance:", formatEther(balance), "ETH");

  if (balance < parseEther("0.1")) {
    console.error(
      "Insufficient balance. Need at least 0.1 ETH for deployment."
    );
    process.exit(1);
  }

  const deployments: DeploymentResult[] = [];
  const chainId = await publicClient.getChainId();

  console.log("\nDeploying Security Contracts...\n");

  // 1. ZKFraudProof
  console.log("1/7 Deploying ZKFraudProof...");
  const zkFraud = await hre.viem.deployContract("ZKFraudProof");
  console.log("   ZKFraudProof:", zkFraud.address);
  deployments.push({ name: "ZKFraudProof", address: zkFraud.address });

  // 2. BridgeCircuitBreaker
  console.log("2/7 Deploying BridgeCircuitBreaker...");
  const circuitBreaker = await hre.viem.deployContract("BridgeCircuitBreaker");
  console.log("   BridgeCircuitBreaker:", circuitBreaker.address);
  deployments.push({
    name: "BridgeCircuitBreaker",
    address: circuitBreaker.address,
  });

  // 3. BridgeRateLimiter
  console.log("3/7 Deploying BridgeRateLimiter...");
  const rateLimiter = await hre.viem.deployContract("BridgeRateLimiter");
  console.log("   BridgeRateLimiter:", rateLimiter.address);
  deployments.push({
    name: "BridgeRateLimiter",
    address: rateLimiter.address,
  });

  // 4. FlashLoanGuard
  console.log("4/7 Deploying FlashLoanGuard...");
  const flashGuard = await hre.viem.deployContract("FlashLoanGuard");
  console.log("   FlashLoanGuard:", flashGuard.address);
  deployments.push({ name: "FlashLoanGuard", address: flashGuard.address });

  // 5. MEVProtection
  console.log("5/7 Deploying MEVProtection...");
  const mevProtection = await hre.viem.deployContract("MEVProtection");
  console.log("   MEVProtection:", mevProtection.address);
  deployments.push({ name: "MEVProtection", address: mevProtection.address });

  // 6. GriefingProtection
  console.log("6/7 Deploying GriefingProtection...");
  const griefingProtection =
    await hre.viem.deployContract("GriefingProtection");
  console.log("   GriefingProtection:", griefingProtection.address);
  deployments.push({
    name: "GriefingProtection",
    address: griefingProtection.address,
  });

  // 7. EnhancedKillSwitch
  console.log("7/7 Deploying EnhancedKillSwitch...");
  const killSwitch = await hre.viem.deployContract("EnhancedKillSwitch");
  console.log("   EnhancedKillSwitch:", killSwitch.address);
  deployments.push({
    name: "EnhancedKillSwitch",
    address: killSwitch.address,
  });

  // Save deployment info
  const deploymentFile = path.join(
    __dirname,
    `../deployments/security-${chainId}.json`
  );
  const deploymentData = {
    chainId,
    timestamp: new Date().toISOString(),
    deployer: deployer.account.address,
    contracts: deployments.reduce(
      (acc, d) => {
        acc[d.name] = d.address;
        return acc;
      },
      {} as Record<string, string>
    ),
  };

  const deploymentsDir = path.join(__dirname, "../deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  fs.writeFileSync(deploymentFile, JSON.stringify(deploymentData, null, 2));
  console.log(`\nDeployment saved to: ${deploymentFile}`);

  // Summary
  console.log("\n" + "=".repeat(60));
  console.log("   Deployment Summary");
  console.log("=".repeat(60) + "\n");

  console.log(
    "| Contract                      | Address                                    |"
  );
  console.log(
    "|-------------------------------|-------------------------------------------|"
  );
  for (const d of deployments) {
    console.log(`| ${d.name.padEnd(29)} | ${d.address} |`);
  }

  console.log("\nSecurity modules deployment complete!\n");

  const finalBalance = await publicClient.getBalance({
    address: deployer.account.address,
  });
  console.log("Gas spent:", formatEther(balance - finalBalance), "ETH");
  console.log("Remaining balance:", formatEther(finalBalance), "ETH");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
