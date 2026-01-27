const { ethers, upgrades, network, run } = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * Soul v2 Upgradeable Contracts Deployment Script
 * 
 * Deploys UUPS upgradeable proxies for Soul v2 contracts:
 * - ProofCarryingContainerUpgradeable
 * - Soulv2OrchestratorUpgradeable
 */

const DEPLOYMENT_LOG_DIR = "./deployments";

async function main() {
    console.log("\n" + "=".repeat(80));
    console.log("Soul v2 UPGRADEABLE CONTRACTS DEPLOYMENT");
    console.log("=".repeat(80) + "\n");

    const [deployer] = await ethers.getSigners();
    console.log("🔑 Deployer:", deployer.address);
    console.log("💰 Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");
    console.log("🌐 Network:", network.name);
    console.log("⛓️  Chain ID:", (await ethers.provider.getNetwork()).chainId.toString());
    console.log("");

    const deployed = {
        network: network.name,
        chainId: Number((await ethers.provider.getNetwork()).chainId),
        deployer: deployer.address,
        timestamp: new Date().toISOString(),
        contracts: {},
        implementations: {}
    };

    try {
        // ============================================
        // PHASE 1: Deploy Non-Upgradeable Dependencies
        // ============================================
        console.log("📦 PHASE 1: Dependencies\n");

        // Deploy VerifierRegistry (non-upgradeable for simplicity)
        console.log("1️⃣  Deploying VerifierRegistry...");
        const VerifierRegistry = await ethers.getContractFactory("VerifierRegistry");
        const verifierRegistry = await VerifierRegistry.deploy();
        await verifierRegistry.waitForDeployment();
        deployed.contracts.verifierRegistry = await verifierRegistry.getAddress();
        console.log("   ✅ VerifierRegistry:", deployed.contracts.verifierRegistry);

        // ============================================
        // PHASE 2: Deploy Upgradeable Primitives
        // ============================================
        console.log("\n📦 PHASE 2: Upgradeable Primitives\n");

        // Deploy ProofCarryingContainerUpgradeable
        console.log("2️⃣  Deploying ProofCarryingContainerUpgradeable (UUPS Proxy)...");
        const PC3Upgradeable = await ethers.getContractFactory("ProofCarryingContainerUpgradeable");
        const pc3Proxy = await upgrades.deployProxy(
            PC3Upgradeable,
            [deployer.address], // initialize(admin)
            { 
                kind: 'uups',
                initializer: 'initialize'
            }
        );
        await pc3Proxy.waitForDeployment();
        deployed.contracts.proofCarryingContainer = await pc3Proxy.getAddress();
        deployed.implementations.proofCarryingContainer = await upgrades.erc1967.getImplementationAddress(
            await pc3Proxy.getAddress()
        );
        console.log("   ✅ PC³ Proxy:", deployed.contracts.proofCarryingContainer);
        console.log("   📋 Implementation:", deployed.implementations.proofCarryingContainer);

        // Deploy non-upgradeable PBP, EASC, CDNA for orchestrator
        console.log("\n3️⃣  Deploying PolicyBoundProofs...");
        const PBP = await ethers.getContractFactory("PolicyBoundProofs");
        const pbp = await PBP.deploy(deployed.contracts.verifierRegistry);
        await pbp.waitForDeployment();
        deployed.contracts.policyBoundProofs = await pbp.getAddress();
        console.log("   ✅ PolicyBoundProofs:", deployed.contracts.policyBoundProofs);

        console.log("\n4️⃣  Deploying ExecutionAgnosticStateCommitments...");
        const EASC = await ethers.getContractFactory("ExecutionAgnosticStateCommitments");
        const easc = await EASC.deploy();
        await easc.waitForDeployment();
        deployed.contracts.executionAgnosticStateCommitments = await easc.getAddress();
        console.log("   ✅ EASC:", deployed.contracts.executionAgnosticStateCommitments);

        console.log("\n5️⃣  Deploying CrossDomainNullifierAlgebra...");
        const CDNA = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
        const cdna = await CDNA.deploy(deployed.contracts.verifierRegistry);
        await cdna.waitForDeployment();
        deployed.contracts.crossDomainNullifierAlgebra = await cdna.getAddress();
        console.log("   ✅ CDNA:", deployed.contracts.crossDomainNullifierAlgebra);

        // ============================================
        // PHASE 3: Deploy Upgradeable Orchestrator
        // ============================================
        console.log("\n📦 PHASE 3: Upgradeable Orchestrator\n");

        console.log("6️⃣  Deploying Soulv2OrchestratorUpgradeable (UUPS Proxy)...");
        const OrchestratorUpgradeable = await ethers.getContractFactory("Soulv2OrchestratorUpgradeable");
        const orchestratorProxy = await upgrades.deployProxy(
            OrchestratorUpgradeable,
            [
                deployer.address,
                deployed.contracts.proofCarryingContainer,
                deployed.contracts.policyBoundProofs,
                deployed.contracts.executionAgnosticStateCommitments,
                deployed.contracts.crossDomainNullifierAlgebra
            ],
            {
                kind: 'uups',
                initializer: 'initialize'
            }
        );
        await orchestratorProxy.waitForDeployment();
        deployed.contracts.pilv2Orchestrator = await orchestratorProxy.getAddress();
        deployed.implementations.pilv2Orchestrator = await upgrades.erc1967.getImplementationAddress(
            await orchestratorProxy.getAddress()
        );
        console.log("   ✅ Orchestrator Proxy:", deployed.contracts.pilv2Orchestrator);
        console.log("   📋 Implementation:", deployed.implementations.pilv2Orchestrator);

        // ============================================
        // PHASE 4: Configuration
        // ============================================
        console.log("\n📦 PHASE 4: Configuration\n");

        // Configure PC³
        console.log("🔧 Configuring PC³...");
        await pc3Proxy.setVerifierRegistry(deployed.contracts.verifierRegistry);
        await pc3Proxy.addPolicy(ethers.ZeroHash);
        const VERIFIER_ROLE = await pc3Proxy.VERIFIER_ROLE();
        await pc3Proxy.grantRole(VERIFIER_ROLE, deployed.contracts.pilv2Orchestrator);
        console.log("   ✅ PC³ configured");

        // ============================================
        // PHASE 5: Save Deployment
        // ============================================
        console.log("\n📦 PHASE 5: Save Deployment\n");

        if (!fs.existsSync(DEPLOYMENT_LOG_DIR)) {
            fs.mkdirSync(DEPLOYMENT_LOG_DIR, { recursive: true });
        }

        const deploymentFile = path.join(DEPLOYMENT_LOG_DIR, `${network.name}-upgradeable-${deployed.chainId}.json`);
        fs.writeFileSync(deploymentFile, JSON.stringify(deployed, null, 2));
        console.log("💾 Deployment saved to:", deploymentFile);

        // Print summary
        console.log("\n" + "=".repeat(80));
        console.log("DEPLOYMENT SUMMARY");
        console.log("=".repeat(80));
        console.log("\nProxies (interact with these):");
        console.log(`  ProofCarryingContainer: ${deployed.contracts.proofCarryingContainer}`);
        console.log(`  Soulv2Orchestrator: ${deployed.contracts.pilv2Orchestrator}`);
        console.log("\nImplementations (for verification):");
        console.log(`  PC³ Implementation: ${deployed.implementations.proofCarryingContainer}`);
        console.log(`  Orchestrator Implementation: ${deployed.implementations.pilv2Orchestrator}`);
        console.log("\n🎉 Upgradeable deployment completed successfully!");

    } catch (error) {
        console.error("\n❌ Deployment failed:", error);
        process.exit(1);
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
