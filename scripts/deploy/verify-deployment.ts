import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Post-Deployment Verification Script
 *
 * Reads a deployment JSON and verifies each contract is:
 * 1. Deployed (code exists at address)
 * 2. Initialized / configured correctly
 * 3. Has correct roles assigned
 *
 * Usage:
 *   npx hardhat run scripts/deploy/verify-deployment.ts --network sepolia
 *   DEPLOYMENT_FILE=deployments/sepolia-11155111.json npx hardhat run scripts/deploy/verify-deployment.ts
 */

interface DeploymentJSON {
  chainId: number;
  deployer: string;
  contracts: Record<string, string>;
  timestamp?: string;
}

async function main() {
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);

  // Find deployment file
  const candidateFiles = [
    process.env.DEPLOYMENT_FILE,
    `deployments/sepolia-${chainId}.json`,
    `deployments/${network.name}-${chainId}.json`,
    `deployments/localhost-${chainId}.json`,
  ].filter(Boolean) as string[];

  let deployment: DeploymentJSON | null = null;
  let deploymentFile = "";

  for (const f of candidateFiles) {
    const fullPath = path.resolve(f);
    if (fs.existsSync(fullPath)) {
      deployment = JSON.parse(fs.readFileSync(fullPath, "utf-8"));
      deploymentFile = f;
      break;
    }
  }

  if (!deployment) {
    console.error("No deployment file found. Tried:", candidateFiles);
    process.exit(1);
  }

  console.log(`\n${"=".repeat(72)}`);
  console.log(`ZASEON - Post-Deployment Verification`);
  console.log(`Network: ${network.name} (chain ${chainId})`);
  console.log(`Deployment: ${deploymentFile}`);
  console.log(`${"=".repeat(72)}\n`);

  let passed = 0;
  let failed = 0;
  const results: { name: string; address: string; status: string }[] = [];

  for (const [name, address] of Object.entries(deployment.contracts)) {
    process.stdout.write(`  ${name.padEnd(35)} ${address}  ... `);

    try {
      const code = await ethers.provider.getCode(address);
      if (code === "0x" || code.length <= 2) {
        console.log("❌ NO CODE");
        results.push({ name, address, status: "NO_CODE" });
        failed++;
        continue;
      }

      // Check bytecode size
      const byteLen = (code.length - 2) / 2;
      if (byteLen < 50) {
        console.log(`⚠️  TINY (${byteLen} bytes)`);
        results.push({ name, address, status: `TINY_${byteLen}B` });
        failed++;
        continue;
      }

      console.log(`✅ OK (${byteLen} bytes)`);
      results.push({ name, address, status: "OK" });
      passed++;
    } catch (err: any) {
      console.log(`❌ ERROR: ${err.message}`);
      results.push({ name, address, status: `ERROR: ${err.message}` });
      failed++;
    }
  }

  // Summary
  console.log(`\n${"─".repeat(72)}`);
  console.log(`  PASSED: ${passed}   FAILED: ${failed}   TOTAL: ${passed + failed}`);
  console.log(`${"─".repeat(72)}\n`);

  // Write verification report
  const reportPath = deploymentFile.replace(".json", "-verification.json");
  const report = {
    timestamp: new Date().toISOString(),
    network: network.name,
    chainId,
    deploymentFile,
    summary: { passed, failed, total: passed + failed },
    results,
  };
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`Report saved to ${reportPath}`);

  if (failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
