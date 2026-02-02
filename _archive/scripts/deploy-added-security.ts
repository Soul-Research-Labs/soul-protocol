import hre from "hardhat";
import { formatEther, parseEther } from "viem";
import * as fs from "fs";
import * as path from "path";

/**
 * Deploy Added Security Contracts to Sepolia
 * 
 * Deploys all 6 added security modules:
 * 1. RuntimeSecurityMonitor
 * 2. FormalBugBounty
 * 3. CryptographicAttestation
 * 4. EmergencyResponseAutomation
 * 5. ZKFraudProof
 * 6. ThresholdSignature
 */

interface DeploymentResult {
  name: string;
  address: string;
  txHash: string;
}

async function main() {
  console.log("\n" + "=".repeat(60));
  console.log("   Soul Added Security Deployment");
  console.log("=".repeat(60) + "\n");

  const [deployer] = await hre.viem.getWalletClients();
  const publicClient = await hre.viem.getPublicClient();

  console.log("Deployer:", deployer.account.address);
  
  const balance = await publicClient.getBalance({ address: deployer.account.address });
  console.log("Balance:", formatEther(balance), "ETH");

  if (balance < parseEther("0.1")) {
    console.error("❌ Insufficient balance. Need at least 0.1 ETH for deployment.");
    process.exit(1);
  }

  const deployments: DeploymentResult[] = [];
  const chainId = await publicClient.getChainId();

  console.log("\n📦 Deploying Added Security Contracts...\n");

  // 1. RuntimeSecurityMonitor
  console.log("1/6 Deploying RuntimeSecurityMonitor...");
  const runtimeMonitor = await hre.viem.deployContract("RuntimeSecurityMonitor");
  console.log("   ✅ RuntimeSecurityMonitor:", runtimeMonitor.address);
  deployments.push({
    name: "RuntimeSecurityMonitor",
    address: runtimeMonitor.address,
    txHash: "" // Not available directly from viem deploy
  });

  // 2. FormalBugBounty (needs a reward token - deploy mock or use existing)
  console.log("2/6 Deploying MockERC20 for BugBounty rewards...");
  const bountyToken = await hre.viem.deployContract("MockERC20", ["Soul Bug Bounty Token", "SoulBB", 18n]);
  console.log("   ✅ BountyToken:", bountyToken.address);

  console.log("   Deploying FormalBugBounty...");
  const bugBounty = await hre.viem.deployContract("FormalBugBounty", [bountyToken.address]);
  console.log("   ✅ FormalBugBounty:", bugBounty.address);
  deployments.push({
    name: "BountyToken",
    address: bountyToken.address,
    txHash: ""
  });
  deployments.push({
    name: "FormalBugBounty",
    address: bugBounty.address,
    txHash: ""
  });

  // 3. CryptographicAttestation
  console.log("3/6 Deploying CryptographicAttestation...");
  const attestation = await hre.viem.deployContract("CryptographicAttestation");
  console.log("   ✅ CryptographicAttestation:", attestation.address);
  deployments.push({
    name: "CryptographicAttestation",
    address: attestation.address,
    txHash: ""
  });

  // 4. EmergencyResponseAutomation
  console.log("4/6 Deploying EmergencyResponseAutomation...");
  const emergency = await hre.viem.deployContract("EmergencyResponseAutomation");
  console.log("   ✅ EmergencyResponseAutomation:", emergency.address);
  deployments.push({
    name: "EmergencyResponseAutomation",
    address: emergency.address,
    txHash: ""
  });

  // 5. ZKFraudProof
  console.log("5/6 Deploying ZKFraudProof...");
  const zkFraud = await hre.viem.deployContract("ZKFraudProof");
  console.log("   ✅ ZKFraudProof:", zkFraud.address);
  deployments.push({
    name: "ZKFraudProof",
    address: zkFraud.address,
    txHash: ""
  });

  // 6. ThresholdSignature
  console.log("6/6 Deploying ThresholdSignature...");
  const threshold = await hre.viem.deployContract("ThresholdSignature");
  console.log("   ✅ ThresholdSignature:", threshold.address);
  deployments.push({
    name: "ThresholdSignature",
    address: threshold.address,
    txHash: ""
  });

  // Setup initial configuration
  console.log("\n⚙️  Setting up initial configuration...\n");

  // Fund bug bounty with tokens
  console.log("   Minting bounty tokens...");
  await bountyToken.write.mint([bugBounty.address, parseEther("1000000")]);
  console.log("   ✅ Minted 1,000,000 SoulBB to FormalBugBounty");

  // Deploy orchestrator
  console.log("\n7/7 Deploying AddedSecurityOrchestrator...");
  const orchestrator = await hre.viem.deployContract("AddedSecurityOrchestrator");
  console.log("   ✅ AddedSecurityOrchestrator:", orchestrator.address);
  deployments.push({
    name: "AddedSecurityOrchestrator",
    address: orchestrator.address,
    txHash: ""
  });

  // Configure orchestrator with module addresses
  console.log("   Configuring orchestrator modules...");
  await orchestrator.write.setRuntimeMonitor([runtimeMonitor.address]);
  await orchestrator.write.setEmergencyResponse([emergency.address]);
  await orchestrator.write.setZKFraudProof([zkFraud.address]);
  await orchestrator.write.setThresholdSignature([threshold.address]);
  await orchestrator.write.setCryptoAttestation([attestation.address]);
  await orchestrator.write.setBugBounty([bugBounty.address]);
  console.log("   ✅ All modules configured in orchestrator");

  // Save deployment info
  const deploymentFile = path.join(__dirname, `../deployments/added-security-${chainId}.json`);
  const deploymentData = {
    chainId,
    timestamp: new Date().toISOString(),
    deployer: deployer.account.address,
    contracts: deployments.reduce((acc, d) => {
      acc[d.name] = d.address;
      return acc;
    }, {} as Record<string, string>)
  };

  // Ensure deployments directory exists
  const deploymentsDir = path.join(__dirname, "../deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  fs.writeFileSync(deploymentFile, JSON.stringify(deploymentData, null, 2));
  console.log(`\n📄 Deployment saved to: ${deploymentFile}`);

  // Summary
  console.log("\n" + "=".repeat(60));
  console.log("   Deployment Summary");
  console.log("=".repeat(60) + "\n");

  console.log("| Contract                      | Address                                    |");
  console.log("|-------------------------------|-------------------------------------------|");
  for (const d of deployments) {
    console.log(`| ${d.name.padEnd(29)} | ${d.address} |`);
  }

  // Verification commands
  console.log("\n" + "=".repeat(60));
  console.log("   Etherscan Verification Commands");
  console.log("=".repeat(60) + "\n");

  console.log("Run these commands to verify contracts on Etherscan:\n");
  console.log(`npx hardhat verify --network sepolia ${runtimeMonitor.address}`);
  console.log(`npx hardhat verify --network sepolia ${bountyToken.address} "Soul Bug Bounty Token" "SoulBB" 18`);
  console.log(`npx hardhat verify --network sepolia ${bugBounty.address} ${bountyToken.address}`);
  console.log(`npx hardhat verify --network sepolia ${attestation.address}`);
  console.log(`npx hardhat verify --network sepolia ${emergency.address}`);
  console.log(`npx hardhat verify --network sepolia ${zkFraud.address}`);
  console.log(`npx hardhat verify --network sepolia ${threshold.address}`);

  console.log("\n✅ Added Security deployment complete!\n");

  const finalBalance = await publicClient.getBalance({ address: deployer.account.address });
  console.log("Gas spent:", formatEther(balance - finalBalance), "ETH");
  console.log("Remaining balance:", formatEther(finalBalance), "ETH");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
