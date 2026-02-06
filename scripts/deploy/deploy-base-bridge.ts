import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  console.log(`Deploying Base (OP Stack) Bridge Adapter on ${network.name} (${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  // Phase 1: Deploy BaseBridgeAdapter
  console.log("\n--- Phase 1: Deploy BaseBridgeAdapter ---");
  const l1Messenger = process.env.BASE_L1_MESSENGER || ethers.ZeroAddress;
  const l2Messenger = process.env.BASE_L2_MESSENGER || ethers.ZeroAddress;
  const basePortal = process.env.BASE_PORTAL || ethers.ZeroAddress;
  const isL1 = process.env.BASE_IS_L1 === "true";

  const BaseBridgeAdapter = await ethers.getContractFactory("BaseBridgeAdapter");
  const bridge = await BaseBridgeAdapter.deploy(deployer.address, l1Messenger, l2Messenger, basePortal, isL1);
  await bridge.waitForDeployment();
  const bridgeAddress = await bridge.getAddress();
  console.log(`BaseBridgeAdapter deployed: ${bridgeAddress}`);

  // Phase 2: Configure CCTP
  console.log("\n--- Phase 2: Configure CCTP ---");
  const cctpMessenger = process.env.CCTP_TOKEN_MESSENGER;
  const usdc = process.env.USDC_TOKEN;
  if (cctpMessenger && usdc) {
    await (await bridge.configureCCTP(cctpMessenger, usdc)).wait();
    console.log(`CCTP configured: messenger=${cctpMessenger}, usdc=${usdc}`);
  }

  // Phase 3: Configure roles
  console.log("\n--- Phase 3: Role Assignment ---");
  const relayer = process.env.RELAYER_ADDRESS;
  const guardian = process.env.GUARDIAN_ADDRESS;
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

  // Phase 4: Save deployment
  const deployment = {
    network: network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    contracts: { BaseBridgeAdapter: bridgeAddress },
    config: { isL1, l1Messenger, l2Messenger, basePortal },
    timestamp: new Date().toISOString(),
  };
  const filename = `deployments/base-bridge-${network.name}-${network.chainId}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${filename}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
