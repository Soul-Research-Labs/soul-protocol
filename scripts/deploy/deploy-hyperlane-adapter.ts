import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  console.log(`Deploying Hyperlane Adapter on ${network.name} (${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);

  // Phase 1: Deploy HyperlaneAdapter
  console.log("\n--- Phase 1: Deploy HyperlaneAdapter ---");
  const mailbox = process.env.HYPERLANE_MAILBOX || ethers.ZeroAddress;
  const localDomain = process.env.HYPERLANE_LOCAL_DOMAIN || "1";

  const HyperlaneAdapter = await ethers.getContractFactory("HyperlaneAdapter");
  const adapter = await HyperlaneAdapter.deploy(mailbox, parseInt(localDomain), deployer.address);
  await adapter.waitForDeployment();
  const adapterAddress = await adapter.getAddress();
  console.log(`HyperlaneAdapter deployed: ${adapterAddress}`);

  // Phase 2: Configure ISMs
  console.log("\n--- Phase 2: Configure ISMs ---");
  const validators = process.env.HYPERLANE_VALIDATORS;
  if (validators) {
    const validatorList = JSON.parse(validators);
    for (const v of validatorList) {
      await (await adapter.addValidator(v)).wait();
      console.log(`Validator added: ${v}`);
    }
  }

  // Phase 3: Role assignment
  console.log("\n--- Phase 3: Role Assignment ---");
  const guardian = process.env.GUARDIAN_ADDRESS;
  if (guardian) {
    const GUARDIAN_ROLE = await adapter.GUARDIAN_ROLE();
    await (await adapter.grantRole(GUARDIAN_ROLE, guardian)).wait();
    console.log(`GUARDIAN_ROLE granted to ${guardian}`);
  }

  // Phase 4: Save deployment
  const deployment = {
    network: network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    contracts: { HyperlaneAdapter: adapterAddress },
    config: { mailbox, localDomain },
    timestamp: new Date().toISOString(),
  };
  const filename = `deployments/hyperlane-adapter-${network.name}-${network.chainId}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
  console.log(`\nDeployment saved to ${filename}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
