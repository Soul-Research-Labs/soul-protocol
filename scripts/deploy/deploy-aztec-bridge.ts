import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  console.log(`Deploying Aztec Bridge Adapter on ${network.name} (${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  // Phase 1: Deploy AztecBridgeAdapter
  console.log("\n--- Phase 1: Deploy AztecBridgeAdapter ---");
  const AztecBridgeAdapter = await ethers.getContractFactory("AztecBridgeAdapter");
  const bridge = await AztecBridgeAdapter.deploy(deployer.address);
  await bridge.waitForDeployment();
  const bridgeAddress = await bridge.getAddress();
  console.log(`AztecBridgeAdapter deployed: ${bridgeAddress}`);

  // Phase 2: Configure Aztec contracts
  console.log("\n--- Phase 2: Configure Aztec ---");
  const rollup = process.env.AZTEC_ROLLUP;
  const inbox = process.env.AZTEC_INBOX;
  const outbox = process.env.AZTEC_OUTBOX;
  if (rollup && inbox && outbox) {
    await (await bridge.configureAztecContracts(rollup, inbox, outbox)).wait();
    console.log("Aztec contracts configured");
  }

  // Phase 3: Configure Soul contracts
  console.log("\n--- Phase 3: Configure Soul Contracts ---");
  const nullifierRegistry = process.env.NULLIFIER_REGISTRY;
  const stateContainer = process.env.STATE_CONTAINER;
  if (nullifierRegistry && stateContainer) {
    await (await bridge.configureSoulContracts(nullifierRegistry, stateContainer)).wait();
    console.log("Soul contracts configured");
  }

  // Phase 4: Configure verifiers
  console.log("\n--- Phase 4: Configure Verifiers ---");
  const soulVerifier = process.env.SOUL_VERIFIER;
  const plonkVerifier = process.env.PLONK_VERIFIER;
  const crossChainVerifier = process.env.CROSS_CHAIN_VERIFIER;
  if (soulVerifier && plonkVerifier && crossChainVerifier) {
    await (await bridge.configureVerifiers(soulVerifier, plonkVerifier, crossChainVerifier)).wait();
    console.log("Verifiers configured");
  }

  // Phase 5: Role assignment
  console.log("\n--- Phase 5: Role Assignment ---");
  const guardian = process.env.GUARDIAN_ADDRESS;
  const treasury = process.env.TREASURY_ADDRESS;
  if (guardian) {
    const GUARDIAN_ROLE = await bridge.GUARDIAN_ROLE();
    await (await bridge.grantRole(GUARDIAN_ROLE, guardian)).wait();
    console.log(`GUARDIAN_ROLE granted to ${guardian}`);
  }
  if (treasury) {
    await (await bridge.setTreasury(treasury)).wait();
    console.log(`Treasury set to ${treasury}`);
  }

  // Phase 6: Save deployment
  const deployment = {
    network: network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    contracts: { AztecBridgeAdapter: bridgeAddress },
    timestamp: new Date().toISOString(),
  };
  const filename = `deployments/aztec-bridge-${network.name}-${network.chainId}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${filename}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
