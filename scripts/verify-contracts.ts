/**
 * Contract Verification Script for Etherscan
 * 
 * This script verifies all deployed Soul v2 contracts on Etherscan.
 * Run after deployment to testnet or mainnet.
 * 
 * Usage: npx hardhat run scripts/verify-contracts.ts --network sepolia
 * 
 * Note: For Hardhat v3, verification requires hardhat-verify plugin
 * Install: npm install --save-dev @nomicfoundation/hardhat-verify
 */

import * as fs from "fs";
import * as path from "path";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Interface for deployed contract info
interface DeployedContract {
  name: string;
  address: string;
  constructorArgs: any[];
}

// Load deployment info from file
function loadDeploymentInfo(network: string): DeployedContract[] {
  // Try multiple file patterns
  const patterns = [
    `${network}.json`,
    `${network}-*.json`,
  ];
  
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  
  if (!fs.existsSync(deploymentsDir)) {
    throw new Error(`Deployments directory not found: ${deploymentsDir}\nPlease deploy contracts first.`);
  }
  
  // Find the deployment file
  const files = fs.readdirSync(deploymentsDir);
  const deploymentFile = files.find(f => f.startsWith(network));
  
  if (!deploymentFile) {
    throw new Error(`No deployment file found for network: ${network}\nAvailable: ${files.join(", ")}`);
  }
  
  const deploymentPath = path.join(deploymentsDir, deploymentFile);
  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
  const contracts = deployment.contracts;
  
  return [
    // Verifier Primitives
    { name: "MockProofVerifier", address: contracts.verifier, constructorArgs: [] },
    { name: "Groth16VerifierBN254", address: contracts.groth16Verifier, constructorArgs: [] },
    
    // State Management
    { 
      name: "ConfidentialStateContainerV3", 
      address: contracts.stateContainer, 
      constructorArgs: [contracts.verifier] 
    },
    { name: "NullifierRegistryV3", address: contracts.nullifierRegistry, constructorArgs: [] },
    
    // Cross-Chain
    { 
      name: "CrossChainProofHubV3", 
      address: contracts.crossChainHub, 
      constructorArgs: [contracts.verifier] 
    },
    { name: "SoulAtomicSwapV2", address: contracts.atomicSwap, constructorArgs: [] },
    
    // Compliance
    { name: "SoulComplianceV2", address: contracts.compliance, constructorArgs: [] },
    
    // Core Soul v2 Components
    { 
      name: "PC3", 
      address: contracts.pc3, 
      constructorArgs: [contracts.verifier] 
    },
    { 
      name: "PBP", 
      address: contracts.pbp, 
      constructorArgs: [contracts.verifier] 
    },
    { 
      name: "EASC", 
      address: contracts.easc, 
      constructorArgs: [contracts.verifier] 
    },
    { 
      name: "CDNA", 
      address: contracts.cdna, 
      constructorArgs: [] 
    },
    
    // Emergency
    { 
      name: "EmergencyRecovery", 
      address: contracts.emergencyRecovery, 
      constructorArgs: [] 
    },
  ];
}

// Verify a single contract using hardhat verify command
async function verifyContract(contract: DeployedContract, network: string): Promise<boolean> {
  console.log(`\n📝 Verifying ${contract.name} at ${contract.address}...`);
  
  try {
    // Build the verify command
    let cmd = `npx hardhat verify --network ${network} ${contract.address}`;
    
    // Add constructor arguments if any
    if (contract.constructorArgs.length > 0) {
      cmd += ` ${contract.constructorArgs.join(" ")}`;
    }
    
    const { stdout, stderr } = await execAsync(cmd);
    
    if (stdout.includes("Already Verified") || stdout.includes("successfully verified")) {
      console.log(`✅ ${contract.name} verified successfully!`);
      return true;
    }
    
    if (stderr && !stderr.includes("Already Verified")) {
      console.log(`⚠️  ${contract.name}: ${stderr}`);
    }
    
    return true;
  } catch (error: any) {
    if (error.message.includes("Already Verified") || error.stdout?.includes("Already Verified")) {
      console.log(`✅ ${contract.name} is already verified.`);
      return true;
    } else if (error.message.includes("does not have bytecode")) {
      console.log(`⚠️  ${contract.name} not deployed at this address.`);
      return false;
    } else {
      console.log(`❌ Failed to verify ${contract.name}: ${error.message}`);
      return false;
    }
  }
}

// Main verification function
async function main() {
  // Get network from command line args or default to sepolia
  const args = process.argv.slice(2);
  let network = "sepolia";
  
  const networkArgIndex = args.indexOf("--network");
  if (networkArgIndex !== -1 && args[networkArgIndex + 1]) {
    network = args[networkArgIndex + 1];
  }
  
  console.log(`\n🔍 Contract Verification Script`);
  console.log(`================================`);
  console.log(`Network: ${network}`);
  
  // Check for API key
  const etherscanApiKey = process.env.ETHERSCAN_API_KEY;
  if (!etherscanApiKey) {
    console.error("\n❌ Error: ETHERSCAN_API_KEY not set in environment");
    console.log("Please set ETHERSCAN_API_KEY in your .env file");
    process.exit(1);
  }
  
  // Load deployment info
  let contracts: DeployedContract[];
  try {
    contracts = loadDeploymentInfo(network);
  } catch (error: any) {
    console.error(`\n❌ ${error.message}`);
    process.exit(1);
  }
  
  console.log(`\nFound ${contracts.length} contracts to verify...`);
  
  // Verify all contracts
  let verified = 0;
  let failed = 0;
  
  for (const contract of contracts) {
    if (!contract.address || contract.address === "0x" || contract.address === undefined) {
      console.log(`\n⚠️  Skipping ${contract.name}: no address found`);
      continue;
    }
    
    const success = await verifyContract(contract, network);
    if (success) {
      verified++;
    } else {
      failed++;
    }
    
    // Rate limiting - Etherscan has API limits
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  // Summary
  console.log(`\n================================`);
  console.log(`Verification Summary:`);
  console.log(`  ✅ Verified: ${verified}`);
  console.log(`  ❌ Failed: ${failed}`);
  console.log(`================================\n`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
