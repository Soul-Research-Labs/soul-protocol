import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  console.log(`Deploying Bitcoin Bridge Adapter on ${network.name} (${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  // Phase 1: Deploy BitcoinBridgeAdapter
  console.log("\n--- Phase 1: Deploy BitcoinBridgeAdapter ---");
  const BitcoinBridgeAdapter = await ethers.getContractFactory("BitcoinBridgeAdapter");
  const bridge = await BitcoinBridgeAdapter.deploy(deployer.address);
  await bridge.waitForDeployment();
  const bridgeAddress = await bridge.getAddress();
  console.log(`BitcoinBridgeAdapter deployed: ${bridgeAddress}`);

  // Phase 2: Configure SPV verifier and Wrapped BTC
  console.log("\n--- Phase 2: Configure Bridge ---");
  const spvVerifier = process.env.BTC_SPV_VERIFIER;
  const wrappedBTC = process.env.WRAPPED_BTC;
  if (spvVerifier && wrappedBTC) {
    await (await bridge.configure(spvVerifier, wrappedBTC)).wait();
    console.log(`Configured: SPV=${spvVerifier}, wBTC=${wrappedBTC}`);
  } else {
    console.log("Skipping config (set BTC_SPV_VERIFIER, WRAPPED_BTC)");
  }

  // Phase 3: Role assignment
  console.log("\n--- Phase 3: Role Assignment ---");
  const relayer = process.env.RELAYER_ADDRESS;
  const guardian = process.env.GUARDIAN_ADDRESS;
  const treasury = process.env.TREASURY_ADDRESS;
  if (relayer) {
    const RELAYER_ROLE = await bridge.RELAYER_ROLE();
    await (await bridge.grantRole(RELAYER_ROLE, relayer)).wait();
    console.log(`RELAYER_ROLE granted to ${relayer}`);
  }
  if (guardian) {
    const GUARDIAN_ROLE = await bridge.GUARDIAN_ROLE();
    await (await bridge.grantRole(GUARDIAN_ROLE, guardian)).wait();
    console.log(`GUARDIAN_ROLE granted to ${guardian}`);
  }
  if (treasury) {
    await (await bridge.setTreasury(treasury)).wait();
    console.log(`Treasury set to ${treasury}`);
  }

  // Phase 4: Save deployment
  const deployment = {
    network: network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    contracts: { BitcoinBridgeAdapter: bridgeAddress },
    timestamp: new Date().toISOString(),
  };
  const filename = `deployments/bitcoin-bridge-${network.name}-${network.chainId}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${filename}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
