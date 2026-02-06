import { ethers } from "hardhat";
import * as fs from "fs";

/**
 * Deploy all L2 bridge adapters (Scroll, Linea, zkSync, Polygon zkEVM)
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  console.log(`Deploying L2 Bridge Adapters on ${network.name} (${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  const contracts: Record<string, string> = {};

  // Scroll
  console.log("\n--- Deploy ScrollBridgeAdapter ---");
  const scrollMessenger = process.env.SCROLL_MESSENGER || ethers.ZeroAddress;
  const scrollGateway = process.env.SCROLL_GATEWAY || ethers.ZeroAddress;
  const scrollRollup = process.env.SCROLL_ROLLUP || ethers.ZeroAddress;
  const Scroll = await ethers.getContractFactory("ScrollBridgeAdapter");
  const scroll = await Scroll.deploy(scrollMessenger, scrollGateway, scrollRollup, deployer.address);
  await scroll.waitForDeployment();
  contracts.ScrollBridgeAdapter = await scroll.getAddress();
  console.log(`ScrollBridgeAdapter: ${contracts.ScrollBridgeAdapter}`);

  // Linea
  console.log("\n--- Deploy LineaBridgeAdapter ---");
  const lineaMessageService = process.env.LINEA_MESSAGE_SERVICE || ethers.ZeroAddress;
  const lineaTokenBridge = process.env.LINEA_TOKEN_BRIDGE || ethers.ZeroAddress;
  const lineaRollup = process.env.LINEA_ROLLUP || ethers.ZeroAddress;
  const Linea = await ethers.getContractFactory("LineaBridgeAdapter");
  const linea = await Linea.deploy(lineaMessageService, lineaTokenBridge, lineaRollup, deployer.address);
  await linea.waitForDeployment();
  contracts.LineaBridgeAdapter = await linea.getAddress();
  console.log(`LineaBridgeAdapter: ${contracts.LineaBridgeAdapter}`);

  // zkSync
  console.log("\n--- Deploy zkSyncBridgeAdapter ---");
  const zkSyncDiamond = process.env.ZKSYNC_DIAMOND || ethers.ZeroAddress;
  const ZkSync = await ethers.getContractFactory("zkSyncBridgeAdapter");
  const zksync = await ZkSync.deploy(deployer.address, zkSyncDiamond);
  await zksync.waitForDeployment();
  contracts.zkSyncBridgeAdapter = await zksync.getAddress();
  console.log(`zkSyncBridgeAdapter: ${contracts.zkSyncBridgeAdapter}`);

  // Polygon zkEVM
  console.log("\n--- Deploy PolygonZkEVMBridgeAdapter ---");
  const polygonBridge = process.env.POLYGON_BRIDGE || ethers.ZeroAddress;
  const globalExitRoot = process.env.POLYGON_GLOBAL_EXIT_ROOT || ethers.ZeroAddress;
  const polygonZkEVM = process.env.POLYGON_ZKEVM || ethers.ZeroAddress;
  const networkId = parseInt(process.env.POLYGON_NETWORK_ID || "1");
  const Polygon = await ethers.getContractFactory("PolygonZkEVMBridgeAdapter");
  const polygon = await Polygon.deploy(polygonBridge, globalExitRoot, polygonZkEVM, networkId, deployer.address);
  await polygon.waitForDeployment();
  contracts.PolygonZkEVMBridgeAdapter = await polygon.getAddress();
  console.log(`PolygonZkEVMBridgeAdapter: ${contracts.PolygonZkEVMBridgeAdapter}`);

  // Save deployment
  const deployment = {
    network: network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    contracts,
    timestamp: new Date().toISOString(),
  };
  const filename = `deployments/l2-bridges-${network.name}-${network.chainId}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${filename}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
