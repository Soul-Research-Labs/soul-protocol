import hre from "hardhat";
import fs from "fs";
import path from "path";
import { formatEther, parseEther } from "viem";

/**
 * Soul v3 Deployment Script for Hardhat v3 (viem)
 * 
 * Deploys all Soul contracts with proper configuration
 */

const DEPLOYMENT_LOG_DIR = "./deployments";

async function main() {
    console.log("\n" + "=".repeat(80));
    console.log("Soul v3 DEPLOYMENT (Hardhat v3 / Viem)");
    console.log("=".repeat(80) + "\n");

    const { viem } = await hre.network.connect();
    const publicClient = await viem.getPublicClient();
    const [deployer] = await viem.getWalletClients();
    
    const balance = await publicClient.getBalance({ address: deployer.account.address });
    const chainId = await publicClient.getChainId();
    
    console.log("🔑 Deployer:", deployer.account.address);
    console.log("💰 Balance:", formatEther(balance), "ETH");
    console.log("🌐 Network:", hre.network.name);
    console.log("⛓️  Chain ID:", chainId);
    console.log("");

    // Check balance
    if (balance < parseEther("0.01")) {
        console.error("❌ Insufficient balance. Need at least 0.01 ETH for deployment.");
        process.exit(1);
    }

    // Track deployed addresses
    const deployed: {
        network: string;
        chainId: number;
        deployer: string;
        timestamp: string;
        contracts: Record<string, string>;
    } = {
        network: hre.network.name,
        chainId: chainId,
        deployer: deployer.account.address,
        timestamp: new Date().toISOString(),
        contracts: {}
    };

    try {
        // ============================================
        // PHASE 1: Core Verifiers
        // ============================================
        console.log("📦 PHASE 1: Core Verifiers\n");

        // 1. Deploy MockProofVerifier (for testnet) or real verifier
        console.log("1️⃣  Deploying MockProofVerifier...");
        const mockVerifier = await viem.deployContract("MockProofVerifier");
        await mockVerifier.write.setVerificationResult([true]);
        deployed.contracts.verifier = mockVerifier.address;
        console.log("   ✅ MockProofVerifier:", deployed.contracts.verifier);

        // 2. Deploy Groth16VerifierBLS12381
        console.log("\n2️⃣  Deploying Groth16VerifierBLS12381...");
        const groth16Verifier = await viem.deployContract("Groth16VerifierBLS12381");
        deployed.contracts.groth16Verifier = groth16Verifier.address;
        console.log("   ✅ Groth16VerifierBLS12381:", deployed.contracts.groth16Verifier);

        // 3. Deploy PLONKVerifier
        console.log("\n3️⃣  Deploying PLONKVerifier...");
        const plonkVerifier = await viem.deployContract("PLONKVerifier");
        deployed.contracts.plonkVerifier = plonkVerifier.address;
        console.log("   ✅ PLONKVerifier:", deployed.contracts.plonkVerifier);

        // 4. Deploy FRIVerifier
        console.log("\n4️⃣  Deploying FRIVerifier...");
        const friVerifier = await viem.deployContract("FRIVerifier");
        deployed.contracts.friVerifier = friVerifier.address;
        console.log("   ✅ FRIVerifier:", deployed.contracts.friVerifier);

        // ============================================
        // PHASE 2: Core Infrastructure
        // ============================================
        console.log("\n📦 PHASE 2: Core Infrastructure\n");

        // 5. Deploy ConfidentialStateContainerV3
        console.log("5️⃣  Deploying ConfidentialStateContainerV3...");
        const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
        deployed.contracts.stateContainer = stateContainer.address;
        console.log("   ✅ ConfidentialStateContainerV3:", deployed.contracts.stateContainer);

        // 6. Deploy NullifierRegistryV3
        console.log("\n6️⃣  Deploying NullifierRegistryV3...");
        const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
        deployed.contracts.nullifierRegistry = nullifierRegistry.address;
        console.log("   ✅ NullifierRegistryV3:", deployed.contracts.nullifierRegistry);

        // 7. Deploy CrossChainProofHubV3
        console.log("\n7️⃣  Deploying CrossChainProofHubV3...");
        const proofHub = await viem.deployContract("CrossChainProofHubV3");
        deployed.contracts.proofHub = proofHub.address;
        console.log("   ✅ CrossChainProofHubV3:", deployed.contracts.proofHub);

        // ============================================
        // PHASE 3: Application Layer
        // ============================================
        console.log("\n📦 PHASE 3: Application Layer\n");

        // 8. Deploy SoulAtomicSwapV2
        console.log("8️⃣  Deploying SoulAtomicSwapV2...");
        const atomicSwap = await viem.deployContract("SoulAtomicSwapV2", [deployer.account.address]);
        deployed.contracts.atomicSwap = atomicSwap.address;
        console.log("   ✅ SoulAtomicSwapV2:", deployed.contracts.atomicSwap);

        // 9. Deploy SoulComplianceV2
        console.log("\n9️⃣  Deploying SoulComplianceV2...");
        const compliance = await viem.deployContract("SoulComplianceV2");
        deployed.contracts.compliance = compliance.address;
        console.log("   ✅ SoulComplianceV2:", deployed.contracts.compliance);

        // ============================================
        // PHASE 4: Soul v2 Primitives
        // ============================================
        console.log("\n📦 PHASE 4: Soul v2 Primitives\n");

        // 10. Deploy ProofCarryingContainer (PC³)
        console.log("🔟 Deploying ProofCarryingContainer (PC³)...");
        const pc3 = await viem.deployContract("ProofCarryingContainer");
        deployed.contracts.proofCarryingContainer = pc3.address;
        console.log("   ✅ ProofCarryingContainer:", deployed.contracts.proofCarryingContainer);

        // 11. Deploy PolicyBoundProofs (PBP)
        console.log("\n1️⃣1️⃣ Deploying PolicyBoundProofs (PBP)...");
        const pbp = await viem.deployContract("PolicyBoundProofs");
        deployed.contracts.policyBoundProofs = pbp.address;
        console.log("   ✅ PolicyBoundProofs:", deployed.contracts.policyBoundProofs);

        // 12. Deploy ExecutionAgnosticStateCommitments (EASC)
        console.log("\n1️⃣2️⃣ Deploying ExecutionAgnosticStateCommitments (EASC)...");
        const easc = await viem.deployContract("ExecutionAgnosticStateCommitments");
        deployed.contracts.easc = easc.address;
        console.log("   ✅ ExecutionAgnosticStateCommitments:", deployed.contracts.easc);

        // 13. Deploy CrossDomainNullifierAlgebra (CDNA)
        console.log("\n1️⃣3️⃣ Deploying CrossDomainNullifierAlgebra (CDNA)...");
        const cdna = await viem.deployContract("CrossDomainNullifierAlgebra");
        deployed.contracts.cdna = cdna.address;
        console.log("   ✅ CrossDomainNullifierAlgebra:", deployed.contracts.cdna);

        // ============================================
        // PHASE 5: TEE Attestation
        // ============================================
        console.log("\n📦 PHASE 5: TEE Attestation\n");

        // 14. Deploy TEEAttestation
        console.log("1️⃣4️⃣ Deploying TEEAttestation...");
        const teeAttestation = await viem.deployContract("TEEAttestation");
        deployed.contracts.teeAttestation = teeAttestation.address;
        console.log("   ✅ TEEAttestation:", deployed.contracts.teeAttestation);

        // ============================================
        // PHASE 6: Security Infrastructure
        // ============================================
        console.log("\n📦 PHASE 6: Security Infrastructure\n");

        // 15. Deploy EmergencyRecovery
        console.log("1️⃣5️⃣ Deploying EmergencyRecovery...");
        const emergencyRecovery = await viem.deployContract("EmergencyRecovery");
        deployed.contracts.emergencyRecovery = emergencyRecovery.address;
        console.log("   ✅ EmergencyRecovery:", deployed.contracts.emergencyRecovery);

        // ============================================
        // PHASE 7: ZK-Bound State Locks (ZK-SLocks)
        // ============================================
        console.log("\n📦 PHASE 7: ZK-Bound State Locks\n");

        // 16. Deploy ZKBoundStateLocks
        console.log("1️⃣6️⃣ Deploying ZKBoundStateLocks...");
        const zkSlocks = await viem.deployContract("ZKBoundStateLocks", [mockVerifier.address]);
        deployed.contracts.zkBoundStateLocks = zkSlocks.address;
        console.log("   ✅ ZKBoundStateLocks:", deployed.contracts.zkBoundStateLocks);

        // 17. Deploy ZKSLockIntegration
        console.log("\n1️⃣7️⃣ Deploying ZKSLockIntegration...");
        const zkSLockIntegration = await viem.deployContract("ZKSLockIntegration", [
            zkSlocks.address,
            pc3.address,
            cdna.address
        ]);
        deployed.contracts.zkSLockIntegration = zkSLockIntegration.address;
        console.log("   ✅ ZKSLockIntegration:", deployed.contracts.zkSLockIntegration);

        // ============================================
        // Save Deployment
        // ============================================
        console.log("\n" + "=".repeat(80));
        console.log("DEPLOYMENT COMPLETE");
        console.log("=".repeat(80) + "\n");

        // Ensure directory exists
        if (!fs.existsSync(DEPLOYMENT_LOG_DIR)) {
            fs.mkdirSync(DEPLOYMENT_LOG_DIR, { recursive: true });
        }

        // Save deployment info
        const filename = `${hre.network.name}-${chainId}.json`;
        const filepath = path.join(DEPLOYMENT_LOG_DIR, filename);
        fs.writeFileSync(filepath, JSON.stringify(deployed, null, 2));
        console.log(`📝 Deployment saved to: ${filepath}`);

        // Summary
        console.log("\n📋 Deployed Contracts:");
        console.log("-".repeat(60));
        for (const [name, address] of Object.entries(deployed.contracts)) {
            console.log(`  ${name.padEnd(30)} ${address}`);
        }
        console.log("-".repeat(60));
        console.log(`\n✅ Total contracts deployed: ${Object.keys(deployed.contracts).length}`);

    } catch (error) {
        console.error("\n❌ Deployment failed:", error);
        process.exit(1);
    }
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
