const { ethers, network, run } = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * Soul v2 Testnet Deployment Script
 * 
 * Deploys all Soul v2 contracts to testnet with proper configuration:
 * - VerifierRegistry (Central verifier management)
 * - Groth16VerifierBN254 (Production ZK verifier)
 * - ProofCarryingContainer (PC³)
 * - PolicyBoundProofs (PBP)
 * - ExecutionAgnosticStateCommitments (EASC)
 * - CrossDomainNullifierAlgebra (CDNA)
 * - Soulv2Orchestrator (Integration layer)
 * - SoulTimelock (Time-locked admin)
 * - TimelockAdmin (Admin wrapper)
 */

const DEPLOYMENT_LOG_DIR = "./deployments";
const TIMELOCK_MIN_DELAY = 48 * 3600; // 48 hours
const TIMELOCK_EMERGENCY_DELAY = 6 * 3600; // 6 hours

async function main() {
    console.log("\n" + "=".repeat(80));
    console.log("Soul v2 TESTNET DEPLOYMENT");
    console.log("=".repeat(80) + "\n");

    // Get deployer
    const [deployer, proposer, executor] = await ethers.getSigners();
    console.log("🔑 Deployer:", deployer.address);
    console.log("💰 Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");
    console.log("🌐 Network:", network.name);
    console.log("⛓️  Chain ID:", (await ethers.provider.getNetwork()).chainId.toString());
    console.log("");

    // Track deployed addresses
    const deployed = {
        network: network.name,
        chainId: Number((await ethers.provider.getNetwork()).chainId),
        deployer: deployer.address,
        timestamp: new Date().toISOString(),
        contracts: {}
    };

    try {
        // ============================================
        // PHASE 1: Core Infrastructure
        // ============================================
        console.log("📦 PHASE 1: Core Infrastructure\n");

        // 1. Deploy VerifierRegistry
        console.log("1️⃣  Deploying VerifierRegistry...");
        const VerifierRegistry = await ethers.getContractFactory("VerifierRegistry");
        const verifierRegistry = await VerifierRegistry.deploy();
        await verifierRegistry.waitForDeployment();
        deployed.contracts.verifierRegistry = await verifierRegistry.getAddress();
        console.log("   ✅ VerifierRegistry:", deployed.contracts.verifierRegistry);

        // 2. Deploy Groth16VerifierBN254
        console.log("\n2️⃣  Deploying Groth16VerifierBN254...");
        const Groth16VerifierBN254 = await ethers.getContractFactory("contracts/verifiers/Groth16VerifierBN254.sol:Groth16VerifierBN254");
        const groth16Verifier = await Groth16VerifierBN254.deploy();
        await groth16Verifier.waitForDeployment();
        deployed.contracts.groth16VerifierBN254 = await groth16Verifier.getAddress();
        console.log("   ✅ Groth16VerifierBN254:", deployed.contracts.groth16VerifierBN254);

        // 2b. Deploy PLONKVerifier
        console.log("\n2️⃣b Deploying PLONKVerifier...");
        const PLONKVerifier = await ethers.getContractFactory("PLONKVerifier");
        const plonkVerifier = await PLONKVerifier.deploy();
        await plonkVerifier.waitForDeployment();
        deployed.contracts.plonkVerifier = await plonkVerifier.getAddress();
        console.log("   ✅ PLONKVerifier:", deployed.contracts.plonkVerifier);

        // 2c. Deploy FRIVerifier
        console.log("\n2️⃣c Deploying FRIVerifier...");
        const FRIVerifier = await ethers.getContractFactory("FRIVerifier");
        const friVerifier = await FRIVerifier.deploy();
        await friVerifier.waitForDeployment();
        deployed.contracts.friVerifier = await friVerifier.getAddress();
        console.log("   ✅ FRIVerifier:", deployed.contracts.friVerifier);

        // 2d. Deploy TEEAttestation
        console.log("\n2️⃣d Deploying TEEAttestation...");
        const TEEAttestation = await ethers.getContractFactory("TEEAttestation");
        const teeAttestation = await TEEAttestation.deploy();
        await teeAttestation.waitForDeployment();
        deployed.contracts.teeAttestation = await teeAttestation.getAddress();
        console.log("   ✅ TEEAttestation:", deployed.contracts.teeAttestation);

        // ============================================
        // PHASE 2: Soul v2 Primitives
        // ============================================
        console.log("\n📦 PHASE 2: Soul v2 Primitives\n");

        // 3. Deploy ProofCarryingContainer (PC³)
        console.log("3️⃣  Deploying ProofCarryingContainer (PC³)...");
        const ProofCarryingContainer = await ethers.getContractFactory("ProofCarryingContainer");
        const pc3 = await ProofCarryingContainer.deploy();
        await pc3.waitForDeployment();
        deployed.contracts.proofCarryingContainer = await pc3.getAddress();
        console.log("   ✅ ProofCarryingContainer:", deployed.contracts.proofCarryingContainer);

        // 4. Deploy PolicyBoundProofs (PBP)
        console.log("\n4️⃣  Deploying PolicyBoundProofs (PBP)...");
        const PolicyBoundProofs = await ethers.getContractFactory("PolicyBoundProofs");
        const pbp = await PolicyBoundProofs.deploy();
        await pbp.waitForDeployment();
        deployed.contracts.policyBoundProofs = await pbp.getAddress();
        console.log("   ✅ PolicyBoundProofs:", deployed.contracts.policyBoundProofs);

        // 5. Deploy ExecutionAgnosticStateCommitments (EASC)
        console.log("\n5️⃣  Deploying ExecutionAgnosticStateCommitments (EASC)...");
        const EASC = await ethers.getContractFactory("ExecutionAgnosticStateCommitments");
        const easc = await EASC.deploy();
        await easc.waitForDeployment();
        deployed.contracts.executionAgnosticStateCommitments = await easc.getAddress();
        console.log("   ✅ ExecutionAgnosticStateCommitments:", deployed.contracts.executionAgnosticStateCommitments);

        // 6. Deploy CrossDomainNullifierAlgebra (CDNA)
        console.log("\n6️⃣  Deploying CrossDomainNullifierAlgebra (CDNA)...");
        const CDNA = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
        const cdna = await CDNA.deploy();
        await cdna.waitForDeployment();
        deployed.contracts.crossDomainNullifierAlgebra = await cdna.getAddress();
        console.log("   ✅ CrossDomainNullifierAlgebra:", deployed.contracts.crossDomainNullifierAlgebra);

        // ============================================
        // PHASE 3: Orchestrator
        // ============================================
        console.log("\n📦 PHASE 3: Orchestrator\n");

        // 7. Deploy Soulv2Orchestrator
        console.log("7️⃣  Deploying Soulv2Orchestrator...");
        const Soulv2Orchestrator = await ethers.getContractFactory("Soulv2Orchestrator");
        const orchestrator = await Soulv2Orchestrator.deploy(
            deployed.contracts.proofCarryingContainer,
            deployed.contracts.policyBoundProofs,
            deployed.contracts.executionAgnosticStateCommitments,
            deployed.contracts.crossDomainNullifierAlgebra
        );
        await orchestrator.waitForDeployment();
        deployed.contracts.soulv2Orchestrator = await orchestrator.getAddress();
        console.log("   ✅ Soulv2Orchestrator:", deployed.contracts.soulv2Orchestrator);

        // ============================================
        // PHASE 4: Security (Timelock)
        // ============================================
        console.log("\n📦 PHASE 4: Security (Timelock)\n");

        // Get proposer/executor addresses (use deployer for testnet)
        const proposerAddr = proposer ? proposer.address : deployer.address;
        const executorAddr = executor ? executor.address : deployer.address;

        // 8. Deploy SoulTimelock
        console.log("8️⃣  Deploying SoulTimelock...");
        const SoulTimelock = await ethers.getContractFactory("SoulTimelock");
        const timelock = await SoulTimelock.deploy(
            TIMELOCK_MIN_DELAY,        // minDelay
            TIMELOCK_EMERGENCY_DELAY,  // emergencyDelay
            1,                         // requiredConfirmations (1 for testnet)
            [proposerAddr],            // proposers
            [executorAddr],            // executors
            deployer.address           // admin
        );
        await timelock.waitForDeployment();
        deployed.contracts.pilTimelock = await timelock.getAddress();
        console.log("   ✅ SoulTimelock:", deployed.contracts.pilTimelock);
        console.log("      Min Delay:", TIMELOCK_MIN_DELAY / 3600, "hours");

        // 9. Deploy TimelockAdmin
        console.log("\n9️⃣  Deploying TimelockAdmin...");
        const TimelockAdmin = await ethers.getContractFactory("TimelockAdmin");
        const timelockAdmin = await TimelockAdmin.deploy(
            deployed.contracts.pilTimelock,
            deployed.contracts.proofCarryingContainer,
            deployed.contracts.policyBoundProofs,
            deployed.contracts.executionAgnosticStateCommitments,
            deployed.contracts.crossDomainNullifierAlgebra
        );
        await timelockAdmin.waitForDeployment();
        deployed.contracts.timelockAdmin = await timelockAdmin.getAddress();
        console.log("   ✅ TimelockAdmin:", deployed.contracts.timelockAdmin);

        // ============================================
        // PHASE 5: Configuration
        // ============================================
        console.log("\n📦 PHASE 5: Configuration\n");

        // Configure VerifierRegistry - register the BN254 verifier
        console.log("🔧 Configuring VerifierRegistry...");
        const VALIDITY_PROOF = ethers.keccak256(ethers.toUtf8Bytes("VALIDITY_PROOF"));
        const POLICY_PROOF = ethers.keccak256(ethers.toUtf8Bytes("POLICY_PROOF"));
        const NULLIFIER_PROOF = ethers.keccak256(ethers.toUtf8Bytes("NULLIFIER_PROOF"));

        // Note: The verifier needs to be initialized with verification keys first in production
        // For testnet, we skip this step as we don't have real verification keys

        // Configure PC³ with verifier registry
        console.log("🔧 Configuring ProofCarryingContainer...");
        await pc3.setVerifierRegistry(deployed.contracts.verifierRegistry);
        console.log("   ✅ VerifierRegistry set on PC³");

        // Add default policy (null policy - allows all)
        await pc3.addPolicy(ethers.ZeroHash);
        console.log("   ✅ Default policy added");

        // Grant VERIFIER_ROLE to orchestrator
        const VERIFIER_ROLE = await pc3.VERIFIER_ROLE();
        await pc3.grantRole(VERIFIER_ROLE, deployed.contracts.soulv2Orchestrator);
        console.log("   ✅ Orchestrator granted VERIFIER_ROLE");

        // ============================================
        // PHASE 6: Verification
        // ============================================
        console.log("\n📦 PHASE 6: Contract Verification\n");

        if (network.name !== "hardhat" && network.name !== "localhost") {
            console.log("⏳ Waiting for block confirmations before verification...");
            await new Promise(resolve => setTimeout(resolve, 30000)); // Wait 30 seconds

            const contractsToVerify = [
                { address: deployed.contracts.verifierRegistry, name: "VerifierRegistry", args: [] },
                { address: deployed.contracts.groth16VerifierBN254, name: "Groth16VerifierBN254", args: [] },
                { address: deployed.contracts.proofCarryingContainer, name: "ProofCarryingContainer", args: [] },
                { address: deployed.contracts.policyBoundProofs, name: "PolicyBoundProofs", args: [deployed.contracts.groth16VerifierBN254] },
                { address: deployed.contracts.executionAgnosticStateCommitments, name: "ExecutionAgnosticStateCommitments", args: [] },
                { address: deployed.contracts.crossDomainNullifierAlgebra, name: "CrossDomainNullifierAlgebra", args: [deployed.contracts.groth16VerifierBN254] },
                {
                    address: deployed.contracts.soulv2Orchestrator,
                    name: "Soulv2Orchestrator",
                    args: [
                        deployed.contracts.proofCarryingContainer,
                        deployed.contracts.policyBoundProofs,
                        deployed.contracts.executionAgnosticStateCommitments,
                        deployed.contracts.crossDomainNullifierAlgebra
                    ]
                },
                {
                    address: deployed.contracts.pilTimelock,
                    name: "SoulTimelock",
                    args: [TIMELOCK_MIN_DELAY, [proposerAddr], [executorAddr], deployer.address]
                },
                {
                    address: deployed.contracts.timelockAdmin,
                    name: "TimelockAdmin",
                    args: [
                        deployed.contracts.pilTimelock,
                        deployed.contracts.proofCarryingContainer,
                        deployed.contracts.policyBoundProofs,
                        deployed.contracts.executionAgnosticStateCommitments,
                        deployed.contracts.crossDomainNullifierAlgebra,
                        deployed.contracts.soulv2Orchestrator
                    ]
                }
            ];

            for (const contract of contractsToVerify) {
                try {
                    console.log(`🔍 Verifying ${contract.name}...`);
                    await run("verify:verify", {
                        address: contract.address,
                        constructorArguments: contract.args
                    });
                    console.log(`   ✅ ${contract.name} verified`);
                } catch (error) {
                    if (error.message.includes("Already Verified")) {
                        console.log(`   ⏭️  ${contract.name} already verified`);
                    } else {
                        console.log(`   ❌ Failed to verify ${contract.name}:`, error.message);
                    }
                }
            }
        } else {
            console.log("⏭️  Skipping verification on local network");
        }

        // ============================================
        // PHASE 7: Save Deployment
        // ============================================
        console.log("\n📦 PHASE 7: Save Deployment\n");

        // Ensure deployments directory exists
        if (!fs.existsSync(DEPLOYMENT_LOG_DIR)) {
            fs.mkdirSync(DEPLOYMENT_LOG_DIR, { recursive: true });
        }

        // Save deployment to file
        const deploymentFile = path.join(DEPLOYMENT_LOG_DIR, `${network.name}-${deployed.chainId}.json`);
        fs.writeFileSync(deploymentFile, JSON.stringify(deployed, null, 2));
        console.log("💾 Deployment saved to:", deploymentFile);

        // Print summary
        console.log("\n" + "=".repeat(80));
        console.log("DEPLOYMENT SUMMARY");
        console.log("=".repeat(80));
        console.log("");
        console.log("Network:", network.name);
        console.log("Chain ID:", deployed.chainId);
        console.log("Deployer:", deployer.address);
        console.log("");
        console.log("Contracts Deployed:");
        for (const [name, address] of Object.entries(deployed.contracts)) {
            console.log(`  ${name}: ${address}`);
        }
        console.log("");
        console.log("🎉 Deployment completed successfully!");

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
