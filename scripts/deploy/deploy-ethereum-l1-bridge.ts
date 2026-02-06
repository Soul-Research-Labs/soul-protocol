import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  console.log(`Deploying Ethereum L1 Bridge on ${network.name} (${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  // Phase 1: Deploy EthereumL1Bridge
  console.log("\n--- Phase 1: Deploy EthereumL1Bridge ---");
  const EthereumL1Bridge = await ethers.getContractFactory("EthereumL1Bridge");
  const bridge = await EthereumL1Bridge.deploy();
  await bridge.waitForDeployment();
  const bridgeAddress = await bridge.getAddress();
  console.log(`EthereumL1Bridge deployed: ${bridgeAddress}`);

  // Phase 2: Configure roles
  console.log("\n--- Phase 2: Role Assignment ---");
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

  // Phase 3: Configure rate limits
  console.log("\n--- Phase 3: Configure Rate Limits ---");
  const maxCommitments = process.env.MAX_COMMITMENTS_PER_HOUR || "10";
  await (await bridge.setMaxCommitmentsPerHour(BigInt(maxCommitments))).wait();
  console.log(`Max commitments per hour: ${maxCommitments}`);

  // Phase 4: Save deployment
  const deployment = {
    network: network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    contracts: { EthereumL1Bridge: bridgeAddress },
    timestamp: new Date().toISOString(),
  };
  const filename = `deployments/ethereum-l1-bridge-${network.name}-${network.chainId}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${filename}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
