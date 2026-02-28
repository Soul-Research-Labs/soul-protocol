const { ethers, upgrades } = require("hardhat");

/**
 * Zaseon v2 Upgrade Script
 * 
 * Upgrades deployed UUPS proxies to new implementations
 * 
 * Usage:
 *   npx hardhat run scripts/upgrade-contracts.js --network sepolia
 */

async function main() {
    console.log("\n" + "=".repeat(60));
    console.log("Zaseon v2 CONTRACT UPGRADE");
    console.log("=".repeat(60) + "\n");

    const [deployer] = await ethers.getSigners();
    console.log("🔑 Upgrader:", deployer.address);

    // Load existing deployment
    const fs = require("fs");
    const path = require("path");
    const network = require("hardhat").network;
    
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const deploymentFile = path.join(
        "./deployments",
        `${network.name}-upgradeable-${chainId}.json`
    );

    if (!fs.existsSync(deploymentFile)) {
        console.error("❌ Deployment file not found:", deploymentFile);
        console.log("   Run deploy-upgradeable.js first");
        process.exit(1);
    }

    const deployment = JSON.parse(fs.readFileSync(deploymentFile, "utf-8"));
    console.log("📂 Loaded deployment from:", deploymentFile);
    console.log("");

    // ============================================
    // UPGRADE PC³
    // ============================================
    console.log("🔄 Upgrading ProofCarryingContainerUpgradeable...\n");

    const PC3UpgradeableV2 = await ethers.getContractFactory("ProofCarryingContainerUpgradeable");
    
    // Get current version before upgrade
    const pc3Proxy = await ethers.getContractAt(
        "ProofCarryingContainerUpgradeable",
        deployment.contracts.proofCarryingContainer
    );
    const oldVersion = await pc3Proxy.contractVersion();
    console.log("   Current version:", oldVersion.toString());

    // Prepare upgrade (validates upgrade compatibility)
    console.log("   Validating upgrade...");
    await upgrades.validateUpgrade(
        deployment.contracts.proofCarryingContainer,
        PC3UpgradeableV2,
        { kind: 'uups' }
    );
    console.log("   ✅ Upgrade validation passed");

    // Perform upgrade
    console.log("   Performing upgrade...");
    const upgradedPC3 = await upgrades.upgradeProxy(
        deployment.contracts.proofCarryingContainer,
        PC3UpgradeableV2,
        { kind: 'uups' }
    );
    await upgradedPC3.waitForDeployment();

    const newImplementation = await upgrades.erc1967.getImplementationAddress(
        deployment.contracts.proofCarryingContainer
    );
    const newVersion = await upgradedPC3.contractVersion();

    console.log("   ✅ Upgrade complete!");
    console.log("   New implementation:", newImplementation);
    console.log("   New version:", newVersion.toString());

    // ============================================
    // UPGRADE ORCHESTRATOR
    // ============================================
    console.log("\n🔄 Upgrading Zaseonv2OrchestratorUpgradeable...\n");

    const OrchestratorV2 = await ethers.getContractFactory("Zaseonv2OrchestratorUpgradeable");

    const orchestratorProxy = await ethers.getContractAt(
        "Zaseonv2OrchestratorUpgradeable",
        deployment.contracts.zaseonv2Orchestrator
    );
    const oldOrchestratorVersion = await orchestratorProxy.contractVersion();
    console.log("   Current version:", oldOrchestratorVersion.toString());

    console.log("   Validating upgrade...");
    await upgrades.validateUpgrade(
        deployment.contracts.zaseonv2Orchestrator,
        OrchestratorV2,
        { kind: 'uups' }
    );
    console.log("   ✅ Upgrade validation passed");

    console.log("   Performing upgrade...");
    const upgradedOrchestrator = await upgrades.upgradeProxy(
        deployment.contracts.zaseonv2Orchestrator,
        OrchestratorV2,
        { kind: 'uups' }
    );
    await upgradedOrchestrator.waitForDeployment();

    const newOrchestratorImpl = await upgrades.erc1967.getImplementationAddress(
        deployment.contracts.zaseonv2Orchestrator
    );
    const newOrchestratorVersion = await upgradedOrchestrator.contractVersion();

    console.log("   ✅ Upgrade complete!");
    console.log("   New implementation:", newOrchestratorImpl);
    console.log("   New version:", newOrchestratorVersion.toString());

    // ============================================
    // UPDATE DEPLOYMENT FILE
    // ============================================
    deployment.implementations.proofCarryingContainer = newImplementation;
    deployment.implementations.zaseonv2Orchestrator = newOrchestratorImpl;
    deployment.lastUpgrade = new Date().toISOString();
    
    fs.writeFileSync(deploymentFile, JSON.stringify(deployment, null, 2));
    console.log("\n💾 Deployment file updated");

    console.log("\n" + "=".repeat(60));
    console.log("UPGRADE COMPLETE");
    console.log("=".repeat(60));
    console.log("\n✅ All upgrades successful!");
    console.log("\nProxy addresses remain the same:");
    console.log(`  PC³: ${deployment.contracts.proofCarryingContainer}`);
    console.log(`  Orchestrator: ${deployment.contracts.zaseonv2Orchestrator}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("❌ Upgrade failed:", error);
        process.exit(1);
    });
