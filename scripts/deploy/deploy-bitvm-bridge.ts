import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  console.log(`Deploying BitVM Bridge on ${network.name} (${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  // Phase 1: Deploy BitVMBridge
  console.log("\n--- Phase 1: Deploy BitVMBridge ---");
  const BitVMBridge = await ethers.getContractFactory("BitVMBridge");
  const bridge = await BitVMBridge.deploy(deployer.address);
  await bridge.waitForDeployment();
  const bridgeAddress = await bridge.getAddress();
  console.log(`BitVMBridge deployed: ${bridgeAddress}`);

  // Phase 2: Configure
  console.log("\n--- Phase 2: Configure ---");
  const bitVMVerifier = process.env.BITVM_VERIFIER;
  const bitcoinBridge = process.env.BITCOIN_BRIDGE;
  if (bitVMVerifier && bitcoinBridge) {
    await (await bridge.configure(bitVMVerifier, bitcoinBridge)).wait();
    console.log(`Configured: verifier=${bitVMVerifier}, btcBridge=${bitcoinBridge}`);
  }
  const treasury = process.env.TREASURY_ADDRESS;
  if (treasury) {
    await (await bridge.setTreasury(treasury)).wait();
    console.log(`Treasury set to ${treasury}`);
  }

  // Phase 3: Role assignment
  console.log("\n--- Phase 3: Role Assignment ---");
  const guardian = process.env.GUARDIAN_ADDRESS;
  if (guardian) {
    const GUARDIAN_ROLE = await bridge.GUARDIAN_ROLE();
    await (await bridge.grantRole(GUARDIAN_ROLE, guardian)).wait();
    console.log(`GUARDIAN_ROLE granted to ${guardian}`);
  }

  // Phase 4: Save deployment
  const deployment = {
    network: network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    contracts: { BitVMBridge: bridgeAddress },
    timestamp: new Date().toISOString(),
  };
  const filename = `deployments/bitvm-bridge-${network.name}-${network.chainId}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${filename}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
