import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  console.log(`Deploying Starknet Bridge Adapter on ${network.name} (${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  // Phase 1: Deploy StarknetBridgeAdapter
  console.log("\n--- Phase 1: Deploy StarknetBridgeAdapter ---");
  const StarknetBridgeAdapter = await ethers.getContractFactory("StarknetBridgeAdapter");
  const bridge = await StarknetBridgeAdapter.deploy(deployer.address);
  await bridge.waitForDeployment();
  const bridgeAddress = await bridge.getAddress();
  console.log(`StarknetBridgeAdapter deployed: ${bridgeAddress}`);

  // Phase 2: Configure Starknet contracts
  console.log("\n--- Phase 2: Configure Starknet ---");
  const starknetCore = process.env.STARKNET_CORE;
  const starknetMessaging = process.env.STARKNET_MESSAGING;
  const l2Bridge = process.env.STARKNET_L2_BRIDGE;
  if (starknetCore && starknetMessaging && l2Bridge) {
    await (await bridge.configure(starknetCore, starknetMessaging, BigInt(l2Bridge))).wait();
    console.log("Starknet contracts configured");
  } else {
    console.log("Skipping config (set STARKNET_CORE, STARKNET_MESSAGING, STARKNET_L2_BRIDGE)");
  }

  // Phase 3: Roles
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
    contracts: { StarknetBridgeAdapter: bridgeAddress },
    timestamp: new Date().toISOString(),
  };
  const filename = `deployments/starknet-bridge-${network.name}-${network.chainId}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${filename}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
