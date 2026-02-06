import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  console.log(`Deploying LayerZero Bridge Adapter on ${network.name} (${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  // Phase 1: Deploy LayerZeroBridgeAdapter
  console.log("\n--- Phase 1: Deploy LayerZeroBridgeAdapter ---");
  const LayerZeroBridgeAdapter = await ethers.getContractFactory("LayerZeroBridgeAdapter");
  const bridge = await LayerZeroBridgeAdapter.deploy();
  await bridge.waitForDeployment();
  const bridgeAddress = await bridge.getAddress();
  console.log(`LayerZeroBridgeAdapter deployed: ${bridgeAddress}`);

  // Phase 2: Configure endpoint
  console.log("\n--- Phase 2: Configure Endpoint ---");
  const endpoint = process.env.LZ_ENDPOINT;
  const localEid = process.env.LZ_LOCAL_EID;
  if (endpoint && localEid) {
    await (await bridge.setEndpoint(endpoint, parseInt(localEid))).wait();
    console.log(`Endpoint set: ${endpoint} (eid: ${localEid})`);
  }

  // Phase 3: Configure peers
  console.log("\n--- Phase 3: Configure Peers ---");
  const peers = process.env.LZ_PEERS; // JSON: [{"eid":30110,"address":"0x...","chainType":0}]
  if (peers) {
    const peerList = JSON.parse(peers);
    for (const peer of peerList) {
      await (await bridge.setPeer(peer.eid, peer.address, peer.chainType, 100000, 0)).wait();
      console.log(`Peer set: eid=${peer.eid}`);
    }
  }

  // Phase 4: Role assignment
  console.log("\n--- Phase 4: Role Assignment ---");
  const guardian = process.env.GUARDIAN_ADDRESS;
  if (guardian) {
    const GUARDIAN_ROLE = await bridge.GUARDIAN_ROLE();
    await (await bridge.grantRole(GUARDIAN_ROLE, guardian)).wait();
    console.log(`GUARDIAN_ROLE granted to ${guardian}`);
  }

  // Phase 5: Save deployment
  const deployment = {
    network: network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    contracts: { LayerZeroBridgeAdapter: bridgeAddress },
    timestamp: new Date().toISOString(),
  };
  const filename = `deployments/layerzero-bridge-${network.name}-${network.chainId}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${filename}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
