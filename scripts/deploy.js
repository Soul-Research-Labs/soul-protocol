const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying PIL V3 contracts with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  // Track deployed addresses
  const deployed = {};

  // 1. Deploy Groth16VerifierBLS12381V2
  console.log("\n1. Deploying Groth16VerifierBLS12381V2...");
  const Verifier = await ethers.getContractFactory("Groth16VerifierBLS12381V2");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  deployed.verifier = await verifier.getAddress();
  console.log("   Groth16VerifierBLS12381V2 deployed to:", deployed.verifier);

  // 2. Deploy ConfidentialStateContainerV3
  console.log("\n2. Deploying ConfidentialStateContainerV3...");
  const StateContainer = await ethers.getContractFactory("ConfidentialStateContainerV3");
  const stateContainer = await StateContainer.deploy(deployed.verifier);
  await stateContainer.waitForDeployment();
  deployed.stateContainer = await stateContainer.getAddress();
  console.log("   ConfidentialStateContainerV3 deployed to:", deployed.stateContainer);

  // 3. Deploy NullifierRegistryV3
  console.log("\n3. Deploying NullifierRegistryV3...");
  const NullifierRegistry = await ethers.getContractFactory("NullifierRegistryV3");
  const nullifierRegistry = await NullifierRegistry.deploy();
  await nullifierRegistry.waitForDeployment();
  deployed.nullifierRegistry = await nullifierRegistry.getAddress();
  console.log("   NullifierRegistryV3 deployed to:", deployed.nullifierRegistry);

  // 4. Deploy CrossChainProofHubV3
  console.log("\n4. Deploying CrossChainProofHubV3...");
  const minimumStake = ethers.parseEther("10"); // 10 ETH minimum stake
  const challengePeriod = 3600; // 1 hour challenge period
  const ProofHub = await ethers.getContractFactory("CrossChainProofHubV3");
  const proofHub = await ProofHub.deploy(deployed.verifier, minimumStake, challengePeriod);
  await proofHub.waitForDeployment();
  deployed.proofHub = await proofHub.getAddress();
  console.log("   CrossChainProofHubV3 deployed to:", deployed.proofHub);

  // 5. Deploy PILAtomicSwapV2
  console.log("\n5. Deploying PILAtomicSwapV2...");
  const AtomicSwap = await ethers.getContractFactory("PILAtomicSwapV2");
  const atomicSwap = await AtomicSwap.deploy(deployer.address); // Deployer as fee collector
  await atomicSwap.waitForDeployment();
  deployed.atomicSwap = await atomicSwap.getAddress();
  console.log("   PILAtomicSwapV2 deployed to:", deployed.atomicSwap);

  // 6. Deploy PILComplianceV2
  console.log("\n6. Deploying PILComplianceV2...");
  const Compliance = await ethers.getContractFactory("PILComplianceV2");
  const compliance = await Compliance.deploy();
  await compliance.waitForDeployment();
  deployed.compliance = await compliance.getAddress();
  console.log("   PILComplianceV2 deployed to:", deployed.compliance);

  // ========== PIL v2 PRIMITIVES ==========

  // 7. Deploy ProofCarryingContainer (PC³)
  console.log("\n7. Deploying ProofCarryingContainer (PC³)...");
  const ProofCarryingContainer = await ethers.getContractFactory("ProofCarryingContainer");
  const proofCarryingContainer = await ProofCarryingContainer.deploy(deployed.verifier);
  await proofCarryingContainer.waitForDeployment();
  deployed.proofCarryingContainer = await proofCarryingContainer.getAddress();
  console.log("   ProofCarryingContainer deployed to:", deployed.proofCarryingContainer);

  // 8. Deploy PolicyBoundProofs (PBP)
  console.log("\n8. Deploying PolicyBoundProofs (PBP)...");
  const PolicyBoundProofs = await ethers.getContractFactory("PolicyBoundProofs");
  const policyBoundProofs = await PolicyBoundProofs.deploy(deployed.verifier);
  await policyBoundProofs.waitForDeployment();
  deployed.policyBoundProofs = await policyBoundProofs.getAddress();
  console.log("   PolicyBoundProofs deployed to:", deployed.policyBoundProofs);

  // 9. Deploy ExecutionAgnosticStateCommitments (EASC)
  console.log("\n9. Deploying ExecutionAgnosticStateCommitments (EASC)...");
  const ExecutionAgnosticStateCommitments = await ethers.getContractFactory("ExecutionAgnosticStateCommitments");
  const executionAgnosticStateCommitments = await ExecutionAgnosticStateCommitments.deploy();
  await executionAgnosticStateCommitments.waitForDeployment();
  deployed.executionAgnosticStateCommitments = await executionAgnosticStateCommitments.getAddress();
  console.log("   ExecutionAgnosticStateCommitments deployed to:", deployed.executionAgnosticStateCommitments);

  // 10. Deploy CrossDomainNullifierAlgebra (CDNA)
  console.log("\n10. Deploying CrossDomainNullifierAlgebra (CDNA)...");
  const CrossDomainNullifierAlgebra = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
  const crossDomainNullifierAlgebra = await CrossDomainNullifierAlgebra.deploy(deployed.verifier);
  await crossDomainNullifierAlgebra.waitForDeployment();
  deployed.crossDomainNullifierAlgebra = await crossDomainNullifierAlgebra.getAddress();
  console.log("   CrossDomainNullifierAlgebra deployed to:", deployed.crossDomainNullifierAlgebra);

  // 11. Deploy PILv2Orchestrator (Integrator)
  console.log("\n11. Deploying PILv2Orchestrator...");
  const PILv2Orchestrator = await ethers.getContractFactory("PILv2Orchestrator");
  const pilv2Orchestrator = await PILv2Orchestrator.deploy(
    deployed.proofCarryingContainer,
    deployed.policyBoundProofs,
    deployed.executionAgnosticStateCommitments,
    deployed.crossDomainNullifierAlgebra
  );
  await pilv2Orchestrator.waitForDeployment();
  deployed.pilv2Orchestrator = await pilv2Orchestrator.getAddress();
  console.log("   PILv2Orchestrator deployed to:", deployed.pilv2Orchestrator);

  // Summary
  console.log("\n" + "=".repeat(60));
  console.log("PIL V3 DEPLOYMENT SUMMARY");
  console.log("=".repeat(60));
  console.log(JSON.stringify(deployed, null, 2));
  console.log("=".repeat(60));

  // Write to file for later reference
  const fs = require("fs");
  const networkName = (await ethers.provider.getNetwork()).name;
  const deploymentFile = `deployments/${networkName}_${Date.now()}.json`;
  
  // Ensure deployments directory exists
  if (!fs.existsSync("deployments")) {
    fs.mkdirSync("deployments");
  }
  
  fs.writeFileSync(
    deploymentFile,
    JSON.stringify({
      network: networkName,
      deployer: deployer.address,
      timestamp: new Date().toISOString(),
      version: "v3",
      contracts: deployed
    }, null, 2)
  );
  console.log(`\nDeployment info saved to: ${deploymentFile}`);

  return deployed;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
