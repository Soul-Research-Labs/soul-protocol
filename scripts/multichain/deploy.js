const { ethers, network, run } = require("hardhat");
const fs = require("fs");
const path = require("path");
const { getChainConfig, saveDeployment, loadDeployment } = require("./chain-config");

/**
 * Zaseon v2 Multi-Chain Deployment Script
 * 
 * Unified deployment script that adapts to each chain's requirements.
 * 
 * Usage:
 *   npx hardhat run scripts/multichain/deploy.js --network arbitrum-sepolia
 *   npx hardhat run scripts/multichain/deploy.js --network optimism
 *   npx hardhat run scripts/multichain/deploy.js --network base
 *   npx hardhat run scripts/multichain/deploy.js --network polygon
 */

async function main() {
    console.log("\n" + "=".repeat(80));
    console.log("Zaseon v2 MULTI-CHAIN DEPLOYMENT");
    console.log("=".repeat(80) + "\n");

    // Get chain info
    const chainId = Number((await ethers.provider.getNetwork()).chainId);
    const chainConfig = getChainConfig(chainId);
    
    // Get deployer
    const [deployer, proposer, executor] = await ethers.getSigners();
    const balance = await ethers.provider.getBalance(deployer.address);
    
    console.log(`🌐 Chain: ${chainConfig.name} (${chainId})`);
    console.log(`🔑 Deployer: ${deployer.address}`);
    console.log(`💰 Balance: ${ethers.formatEther(balance)} ${chainConfig.nativeToken}`);
    console.log(`📝 Confirmations: ${chainConfig.confirmations}`);
    console.log(`⏰ Timelock Delay: ${chainConfig.timelockDelay / 3600} hours`);
    console.log(`🧪 Testnet: ${chainConfig.isTestnet ? "Yes" : "No"}`);
    console.log("");

    // Check for existing deployment
    const existingDeployment = loadDeployment(chainId);
    if (existingDeployment) {
        console.log("⚠️  Existing deployment found:");
        console.log(`   Deployed: ${existingDeployment.timestamp}`);
        console.log(`   Contracts: ${Object.keys(existingDeployment.contracts).length}`);
        console.log("");
        
        const readline = require("readline");
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        const answer = await new Promise(resolve => {
            rl.question("Continue with fresh deployment? (y/N): ", resolve);
        });
        rl.close();
        
        if (answer.toLowerCase() !== "y") {
            console.log("Deployment cancelled.");
            process.exit(0);
        }
    }

    // Track deployed addresses
    const deployed = {
        network: chainConfig.name,
        chainId: chainId,
        deployer: deployer.address,
        timestamp: new Date().toISOString(),
        isTestnet: chainConfig.isTestnet,
        contracts: {},
        txHashes: {},
        verified: {},
    };

    // Gas configuration for this chain
    const gasOverrides = chainConfig.gasConfig.maxFeePerGas ? {
        maxPriorityFeePerGas: chainConfig.gasConfig.maxPriorityFeePerGas,
        maxFeePerGas: chainConfig.gasConfig.maxFeePerGas,
    } : {};

    try {
        // ============================================
        // PHASE 1: Core Infrastructure
        // ============================================
        console.log("📦 PHASE 1: Core Infrastructure\n");

        // 1. Deploy VerifierRegistry
        console.log("1️⃣  Deploying VerifierRegistry...");
        const VerifierRegistry = await ethers.getContractFactory("VerifierRegistry");
        const verifierRegistry = await VerifierRegistry.deploy(gasOverrides);
        await verifierRegistry.waitForDeployment();
        const verifierRegistryTx = verifierRegistry.deploymentTransaction();
        await verifierRegistryTx.wait(chainConfig.confirmations);
        deployed.contracts.verifierRegistry = await verifierRegistry.getAddress();
        deployed.txHashes.verifierRegistry = verifierRegistryTx.hash;
        console.log(`   ✅ VerifierRegistry: ${deployed.contracts.verifierRegistry}`);

        // 2. Deploy ZK Verifiers
        console.log("\n2️⃣  Deploying ZK Verifiers...");
        
        // Groth16
        const Groth16VerifierBN254 = await ethers.getContractFactory("contracts/verifiers/Groth16VerifierBN254.sol:Groth16VerifierBN254");
        const groth16Verifier = await Groth16VerifierBN254.deploy(gasOverrides);
        await groth16Verifier.waitForDeployment();
        await groth16Verifier.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.groth16VerifierBN254 = await groth16Verifier.getAddress();
        deployed.txHashes.groth16VerifierBN254 = groth16Verifier.deploymentTransaction().hash;
        console.log(`   ✅ Groth16VerifierBN254: ${deployed.contracts.groth16VerifierBN254}`);

        // PLONK
        const PLONKVerifier = await ethers.getContractFactory("PLONKVerifier");
        const plonkVerifier = await PLONKVerifier.deploy(gasOverrides);
        await plonkVerifier.waitForDeployment();
        await plonkVerifier.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.plonkVerifier = await plonkVerifier.getAddress();
        deployed.txHashes.plonkVerifier = plonkVerifier.deploymentTransaction().hash;
        console.log(`   ✅ PLONKVerifier: ${deployed.contracts.plonkVerifier}`);

        // FRI
        const FRIVerifier = await ethers.getContractFactory("FRIVerifier");
        const friVerifier = await FRIVerifier.deploy(gasOverrides);
        await friVerifier.waitForDeployment();
        await friVerifier.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.friVerifier = await friVerifier.getAddress();
        deployed.txHashes.friVerifier = friVerifier.deploymentTransaction().hash;
        console.log(`   ✅ FRIVerifier: ${deployed.contracts.friVerifier}`);

        // 3. Deploy TEE Attestation
        console.log("\n3️⃣  Deploying TEEAttestation...");
        const TEEAttestation = await ethers.getContractFactory("TEEAttestation");
        const teeAttestation = await TEEAttestation.deploy(gasOverrides);
        await teeAttestation.waitForDeployment();
        await teeAttestation.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.teeAttestation = await teeAttestation.getAddress();
        deployed.txHashes.teeAttestation = teeAttestation.deploymentTransaction().hash;
        console.log(`   ✅ TEEAttestation: ${deployed.contracts.teeAttestation}`);

        // ============================================
        // PHASE 2: Zaseon v2 Primitives
        // ============================================
        console.log("\n📦 PHASE 2: Zaseon v2 Primitives\n");

        // 4. Deploy ProofCarryingContainer (PC³)
        console.log("4️⃣  Deploying ProofCarryingContainer (PC³)...");
        const ProofCarryingContainer = await ethers.getContractFactory("ProofCarryingContainer");
        const pc3 = await ProofCarryingContainer.deploy(gasOverrides);
        await pc3.waitForDeployment();
        await pc3.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.pc3 = await pc3.getAddress();
        deployed.txHashes.pc3 = pc3.deploymentTransaction().hash;
        console.log(`   ✅ ProofCarryingContainer: ${deployed.contracts.pc3}`);

        // 5. Deploy PolicyBoundProofs (PBP)
        console.log("\n5️⃣  Deploying PolicyBoundProofs (PBP)...");
        const PolicyBoundProofs = await ethers.getContractFactory("PolicyBoundProofs");
        const pbp = await PolicyBoundProofs.deploy(gasOverrides);
        await pbp.waitForDeployment();
        await pbp.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.pbp = await pbp.getAddress();
        deployed.txHashes.pbp = pbp.deploymentTransaction().hash;
        console.log(`   ✅ PolicyBoundProofs: ${deployed.contracts.pbp}`);

        // 6. Deploy ExecutionAgnosticStateCommitments (EASC)
        console.log("\n6️⃣  Deploying ExecutionAgnosticStateCommitments (EASC)...");
        const ExecutionAgnosticStateCommitments = await ethers.getContractFactory("ExecutionAgnosticStateCommitments");
        const easc = await ExecutionAgnosticStateCommitments.deploy(gasOverrides);
        await easc.waitForDeployment();
        await easc.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.easc = await easc.getAddress();
        deployed.txHashes.easc = easc.deploymentTransaction().hash;
        console.log(`   ✅ ExecutionAgnosticStateCommitments: ${deployed.contracts.easc}`);

        // 7. Deploy CrossDomainNullifierAlgebra (CDNA)
        console.log("\n7️⃣  Deploying CrossDomainNullifierAlgebra (CDNA)...");
        const CrossDomainNullifierAlgebra = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
        const cdna = await CrossDomainNullifierAlgebra.deploy(gasOverrides);
        await cdna.waitForDeployment();
        await cdna.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.cdna = await cdna.getAddress();
        deployed.txHashes.cdna = cdna.deploymentTransaction().hash;
        console.log(`   ✅ CrossDomainNullifierAlgebra: ${deployed.contracts.cdna}`);

        // ============================================
        // PHASE 3: Integration Layer
        // ============================================
        console.log("\n📦 PHASE 3: Integration Layer\n");

        // 8. Deploy Zaseonv2Orchestrator
        console.log("8️⃣  Deploying Zaseonv2Orchestrator...");
        const Zaseonv2Orchestrator = await ethers.getContractFactory("Zaseonv2Orchestrator");
        const orchestrator = await Zaseonv2Orchestrator.deploy(
            deployed.contracts.pc3,
            deployed.contracts.pbp,
            deployed.contracts.easc,
            deployed.contracts.cdna,
            gasOverrides
        );
        await orchestrator.waitForDeployment();
        await orchestrator.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.orchestrator = await orchestrator.getAddress();
        deployed.txHashes.orchestrator = orchestrator.deploymentTransaction().hash;
        console.log(`   ✅ Zaseonv2Orchestrator: ${deployed.contracts.orchestrator}`);

        // ============================================
        // PHASE 4: Security Layer
        // ============================================
        console.log("\n📦 PHASE 4: Security Layer\n");

        // 9. Deploy ZaseonTimelock
        console.log("9️⃣  Deploying ZaseonTimelock...");
        const ZaseonTimelock = await ethers.getContractFactory("ZaseonTimelock");
        const timelock = await ZaseonTimelock.deploy(
            chainConfig.timelockDelay,
            [proposer?.address || deployer.address],
            [executor?.address || deployer.address],
            deployer.address,
            gasOverrides
        );
        await timelock.waitForDeployment();
        await timelock.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.timelock = await timelock.getAddress();
        deployed.txHashes.timelock = timelock.deploymentTransaction().hash;
        console.log(`   ✅ ZaseonTimelock: ${deployed.contracts.timelock}`);

        // 10. Deploy TimelockAdmin
        console.log("\n🔟 Deploying TimelockAdmin...");
        const TimelockAdmin = await ethers.getContractFactory("TimelockAdmin");
        const timelockAdmin = await TimelockAdmin.deploy(
            deployed.contracts.timelock,
            gasOverrides
        );
        await timelockAdmin.waitForDeployment();
        await timelockAdmin.deploymentTransaction().wait(chainConfig.confirmations);
        deployed.contracts.timelockAdmin = await timelockAdmin.getAddress();
        deployed.txHashes.timelockAdmin = timelockAdmin.deploymentTransaction().hash;
        console.log(`   ✅ TimelockAdmin: ${deployed.contracts.timelockAdmin}`);

        // ============================================
        // PHASE 5: Configuration
        // ============================================
        console.log("\n⚙️  PHASE 5: Configuration\n");

        // Register verifiers in registry
        console.log("📝 Registering verifiers in VerifierRegistry...");
        await verifierRegistry.registerVerifier(
            ethers.id("groth16-bn254"),
            deployed.contracts.groth16VerifierBN254,
            "Groth16 BN254 Verifier",
            gasOverrides
        );
        await verifierRegistry.registerVerifier(
            ethers.id("plonk"),
            deployed.contracts.plonkVerifier,
            "PLONK Verifier",
            gasOverrides
        );
        await verifierRegistry.registerVerifier(
            ethers.id("fri-stark"),
            deployed.contracts.friVerifier,
            "FRI STARK Verifier",
            gasOverrides
        );
        console.log("   ✅ Verifiers registered");

        // Save deployment
        saveDeployment(chainId, deployed);

        // ============================================
        // Summary
        // ============================================
        console.log("\n" + "=".repeat(80));
        console.log("DEPLOYMENT COMPLETE");
        console.log("=".repeat(80));
        console.log(`\n🌐 Chain: ${chainConfig.name} (${chainId})`);
        console.log(`📦 Contracts Deployed: ${Object.keys(deployed.contracts).length}`);
        console.log(`🔗 Explorer: ${chainConfig.explorerUrl || "N/A"}`);
        console.log("\n📋 Contract Addresses:");
        
        for (const [name, address] of Object.entries(deployed.contracts)) {
            const explorerLink = chainConfig.explorerUrl 
                ? `${chainConfig.explorerUrl}/address/${address}`
                : address;
            console.log(`   ${name}: ${explorerLink}`);
        }

        // Verification reminder
        if (chainConfig.explorerApiUrl && chainConfig.explorerApiKey) {
            console.log("\n🔍 To verify contracts, run:");
            console.log(`   npx hardhat run scripts/multichain/verify.js --network ${network.name}`);
        }

        return deployed;

    } catch (error) {
        console.error("\n❌ Deployment failed:", error.message);
        
        // Save partial deployment
        if (Object.keys(deployed.contracts).length > 0) {
            deployed.error = error.message;
            deployed.partial = true;
            saveDeployment(chainId, deployed);
            console.log("📄 Partial deployment saved for recovery");
        }
        
        throw error;
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
