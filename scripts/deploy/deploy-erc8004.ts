/**
 * @title ERC-8004 Trustless Agents - Deployment Script
 * @dev Deploys Identity, Reputation, and Validation Registries
 */
import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying ERC-8004 Trustless Agents with:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

  // ──────── Deploy Identity Registry ────────
  console.log("\n[1/3] Deploying ERC8004IdentityRegistry...");
  const IdentityFactory = await ethers.getContractFactory("ERC8004IdentityRegistry");
  const identity = await IdentityFactory.deploy();
  await identity.waitForDeployment();
  const identityAddr = await identity.getAddress();
  console.log("  IdentityRegistry:", identityAddr);

  // ──────── Deploy Reputation Registry ────────
  console.log("\n[2/3] Deploying ERC8004ReputationRegistry...");
  const ReputationFactory = await ethers.getContractFactory("ERC8004ReputationRegistry");
  const reputation = await ReputationFactory.deploy();
  await reputation.waitForDeployment();
  const reputationAddr = await reputation.getAddress();
  console.log("  ReputationRegistry:", reputationAddr);

  // Initialize Reputation with Identity reference
  const repTx = await reputation.initialize(identityAddr);
  await repTx.wait();
  console.log("  ReputationRegistry initialized with IdentityRegistry");

  // ──────── Deploy Validation Registry ────────
  console.log("\n[3/3] Deploying ERC8004ValidationRegistry...");
  const ValidationFactory = await ethers.getContractFactory("ERC8004ValidationRegistry");
  const validation = await ValidationFactory.deploy();
  await validation.waitForDeployment();
  const validationAddr = await validation.getAddress();
  console.log("  ValidationRegistry:", validationAddr);

  // Initialize Validation with Identity reference
  const valTx = await validation.initialize(identityAddr);
  await valTx.wait();
  console.log("  ValidationRegistry initialized with IdentityRegistry");

  // ──────── Summary ────────
  console.log("\n════════════════════════════════════════════");
  console.log("   ERC-8004 Trustless Agents Deployment");
  console.log("════════════════════════════════════════════");
  console.log(`  IdentityRegistry:    ${identityAddr}`);
  console.log(`  ReputationRegistry:  ${reputationAddr}`);
  console.log(`  ValidationRegistry:  ${validationAddr}`);
  console.log("════════════════════════════════════════════");

  // ──────── Verify Setup ────────
  const repIdentity = await reputation.identityRegistry();
  const valIdentity = await validation.identityRegistry();
  console.log("\nVerification:");
  console.log(`  Reputation → Identity: ${repIdentity === identityAddr ? "✓" : "✗"}`);
  console.log(`  Validation → Identity: ${valIdentity === identityAddr ? "✓" : "✗"}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
