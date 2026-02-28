/**
 * Etherscan Manual Verification Helper
 * 
 * This script provides utilities for manual Etherscan verification
 * when the Hardhat plugin doesn't work.
 * 
 * Usage: 
 *   npx ts-node scripts/verify-manual.ts <network> <contract-address> <contract-name>
 */

import * as fs from "fs";
import * as path from "path";

interface VerificationRequest {
  apikey: string;
  module: string;
  action: string;
  contractaddress: string;
  sourceCode: string;
  codeformat: string;
  contractname: string;
  compilerversion: string;
  optimizationUsed: string;
  runs: string;
  constructorArguements?: string;
  evmversion?: string;
  licenseType?: string;
}

// Etherscan API URLs by network
const ETHERSCAN_APIS: Record<string, string> = {
  mainnet: "https://api.etherscan.io/api",
  sepolia: "https://api-sepolia.etherscan.io/api",
  polygon: "https://api.polygonscan.com/api",
  arbitrum: "https://api.arbiscan.io/api",
  base: "https://api.basescan.org/api",
  optimism: "https://api-optimistic.etherscan.io/api",
};

// API keys by network
const API_KEYS: Record<string, string> = {
  mainnet: process.env.ETHERSCAN_API_KEY || "",
  sepolia: process.env.ETHERSCAN_API_KEY || "",
  polygon: process.env.POLYGONSCAN_API_KEY || "",
  arbitrum: process.env.ARBISCAN_API_KEY || "",
  base: process.env.BASESCAN_API_KEY || "",
  optimism: process.env.OPTIMISM_API_KEY || "",
};

/**
 * Get flattened contract source
 * Run: npx hardhat flatten contracts/YourContract.sol > flattened.sol
 */
function getFlattenedSource(contractPath: string): string {
  const flattenedPath = path.join(__dirname, "..", "flattened", `${contractPath}.sol`);
  
  if (fs.existsSync(flattenedPath)) {
    return fs.readFileSync(flattenedPath, "utf-8");
  }
  
  throw new Error(`Flattened source not found: ${flattenedPath}\nRun: npx hardhat flatten ${contractPath} > flattened/${path.basename(contractPath)}.sol`);
}

/**
 * Encode constructor arguments
 */
function encodeConstructorArgs(args: any[]): string {
  // This is simplified - for complex types, use ethers.js ABI encoder
  return args.map(arg => {
    if (typeof arg === "string" && arg.startsWith("0x")) {
      return arg.slice(2).padStart(64, "0");
    }
    return arg.toString(16).padStart(64, "0");
  }).join("");
}

/**
 * Submit verification request to Etherscan
 */
async function submitVerification(
  network: string,
  contractAddress: string,
  contractName: string,
  sourceCode: string,
  constructorArgs?: string
): Promise<string> {
  const apiUrl = ETHERSCAN_APIS[network];
  const apiKey = API_KEYS[network];
  
  if (!apiUrl) {
    throw new Error(`Unsupported network: ${network}`);
  }
  
  if (!apiKey) {
    throw new Error(`API key not set for ${network}`);
  }
  
  const params: VerificationRequest = {
    apikey: apiKey,
    module: "contract",
    action: "verifysourcecode",
    contractaddress: contractAddress,
    sourceCode: sourceCode,
    codeformat: "solidity-single-file",
    contractname: contractName,
    compilerversion: "v0.8.20+commit.a1b79de6",
    optimizationUsed: "1",
    runs: "200",
    evmversion: "paris",
    licenseType: "3", // MIT
  };
  
  if (constructorArgs) {
    params.constructorArguements = constructorArgs;
  }
  
  console.log(`\nSubmitting verification for ${contractName}...`);
  console.log(`Network: ${network}`);
  console.log(`Address: ${contractAddress}`);
  
  const response = await fetch(apiUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params as any).toString(),
  });
  
  const result = await response.json();
  
  if (result.status === "1") {
    console.log(`✅ Verification submitted! GUID: ${result.result}`);
    return result.result;
  } else {
    throw new Error(`Verification failed: ${result.result}`);
  }
}

/**
 * Check verification status
 */
async function checkVerificationStatus(network: string, guid: string): Promise<boolean> {
  const apiUrl = ETHERSCAN_APIS[network];
  const apiKey = API_KEYS[network];
  
  const params = new URLSearchParams({
    apikey: apiKey,
    module: "contract",
    action: "checkverifystatus",
    guid: guid,
  });
  
  const response = await fetch(`${apiUrl}?${params}`);
  const result = await response.json();
  
  if (result.result === "Pending in queue") {
    console.log("⏳ Verification pending...");
    return false;
  } else if (result.result === "Pass - Verified") {
    console.log("✅ Verification successful!");
    return true;
  } else if (result.result === "Fail - Unable to verify") {
    console.log("❌ Verification failed");
    return true;
  } else {
    console.log(`Status: ${result.result}`);
    return false;
  }
}

/**
 * Main function
 */
async function main() {
  console.log("\n🔍 Etherscan Manual Verification Helper");
  console.log("==========================================\n");
  
  const args = process.argv.slice(2);
  
  if (args.length < 3) {
    console.log("Usage: npx ts-node scripts/verify-manual.ts <network> <address> <contractName>");
    console.log("\nExample:");
    console.log("  npx ts-node scripts/verify-manual.ts sepolia 0x123... PC3");
    console.log("\nSupported networks:", Object.keys(ETHERSCAN_APIS).join(", "));
    
    console.log("\n📋 Instructions:");
    console.log("1. First, flatten your contract:");
    console.log("   npx hardhat flatten contracts/Zaseon/PC3.sol > flattened/PC3.sol");
    console.log("2. Then run this script");
    
    process.exit(0);
  }
  
  const [network, address, contractName] = args;
  
  console.log(`Network: ${network}`);
  console.log(`Address: ${address}`);
  console.log(`Contract: ${contractName}`);
  
  // For now, just provide instructions
  console.log("\n📋 Manual Verification Steps:");
  console.log("1. Go to the appropriate block explorer:");
  console.log(`   ${ETHERSCAN_APIS[network]?.replace("/api", "")}address/${address}#code`);
  console.log("2. Click 'Verify and Publish'");
  console.log("3. Select:");
  console.log("   - Compiler Type: Solidity (Standard JSON Input)");
  console.log("   - Compiler Version: v0.8.20+commit.a1b79de6");
  console.log("   - License: MIT");
  console.log("4. Upload the standard JSON input from:");
  console.log("   artifacts/build-info/<latest>.json");
  console.log("5. Add constructor arguments if needed");
  
  console.log("\n✅ Done!");
}

main().catch(console.error);
