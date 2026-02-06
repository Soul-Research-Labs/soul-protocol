import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  console.log(`Deploying Arbitrum Bridge Adapter on ${network.name} (${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  // Phase 1: Deploy ArbitrumBridgeAdapter
  console.log("\n--- Phase 1: Deploy ArbitrumBridgeAdapter ---");
  const ArbitrumBridgeAdapter = await ethers.getContractFactory("ArbitrumBridgeAdapter");
  const bridge = await ArbitrumBridgeAdapter.deploy(deployer.address);
  await bridge.waitForDeployment();
  const bridgeAddress = await bridge.getAddress();
  console.log(`ArbitrumBridgeAdapter deployed: ${bridgeAddress}`);

  // Phase 2: Configure rollup (Arbitrum One)
  console.log("\n--- Phase 2: Configure Rollup ---");
  const inbox = process.env.ARB_INBOX || ethers.ZeroAddress;
  const outbox = process.env.ARB_OUTBOX || ethers.ZeroAddress;
  const arbBridge = process.env.ARB_BRIDGE || ethers.ZeroAddress;
  const rollup = process.env.ARB_ROLLUP || ethers.ZeroAddress;
  if (inbox !== ethers.ZeroAddress) {
    const tx = await bridge.configureRollup(42161, inbox, outbox, arbBridge, rollup, 0);
    await tx.wait();
    console.log("Arbitrum One rollup configured");
  } else {
    console.log("Skipping rollup config (set ARB_INBOX, ARB_OUTBOX, ARB_BRIDGE, ARB_ROLLUP)");
  }

  // Phase 3: Configure roles
  console.log("\n--- Phase 3: Role Assignment ---");
  const relayer = process.env.RELAYER_ADDRESS;
  const guardian = process.env.GUARDIAN_ADDRESS;
  const treasury = process.env.TREASURY_ADDRESS;
  if (relayer) {
    const EXECUTOR_ROLE = await bridge.EXECUTOR_ROLE();
    await (await bridge.grantRole(EXECUTOR_ROLE, relayer)).wait();
    console.log(`EXECUTOR_ROLE granted to ${relayer}`);
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
    contracts: { ArbitrumBridgeAdapter: bridgeAddress },
    timestamp: new Date().toISOString(),
  };
  const filename = `deployments/arbitrum-bridge-${network.name}-${network.chainId}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${filename}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
