const { ethers, network, run } = require("hardhat");
const fs = require("fs");
const path = require("path");
const { getChainConfig, loadDeployment } = require("./chain-config");

/**
 * Zaseon v2 Contract Verification Script
 * 
 * Automatically verifies all deployed contracts on block explorers.
 * 
 * Usage:
 *   npx hardhat run scripts/multichain/verify.js --network arbitrum-sepolia
 *   npx hardhat run scripts/multichain/verify.js --network optimism
 */

// Contract source paths for verification
const CONTRACT_PATHS = {
    verifierRegistry: "contracts/VerifierRegistry.sol:VerifierRegistry",
    groth16VerifierBN254: "contracts/verifiers/Groth16VerifierBN254.sol:Groth16VerifierBN254",
    plonkVerifier: "contracts/verifiers/PLONKVerifier.sol:PLONKVerifier",
    friVerifier: "contracts/verifiers/FRIVerifier.sol:FRIVerifier",
    teeAttestation: "contracts/tee/TEEAttestation.sol:TEEAttestation",
    pc3: "contracts/primitives/ProofCarryingContainer.sol:ProofCarryingContainer",
    pbp: "contracts/primitives/PolicyBoundProofs.sol:PolicyBoundProofs",
    easc: "contracts/primitives/ExecutionAgnosticStateCommitments.sol:ExecutionAgnosticStateCommitments",
    cdna: "contracts/primitives/CrossDomainNullifierAlgebra.sol:CrossDomainNullifierAlgebra",
    orchestrator: "contracts/Zaseonv2Orchestrator.sol:Zaseonv2Orchestrator",
    timelock: "contracts/governance/ZaseonTimelock.sol:ZaseonTimelock",
    timelockAdmin: "contracts/governance/TimelockAdmin.sol:TimelockAdmin",
};

async function verifyContract(address, constructorArgs, contractPath) {
    try {
        console.log(`   Verifying ${contractPath} at ${address}...`);
        
        await run("verify:verify", {
            address: address,
            constructorArguments: constructorArgs,
            contract: contractPath,
        });
        
        console.log(`   ✅ Verified: ${address}`);
        return { success: true, address };
    } catch (error) {
        if (error.message.includes("Already Verified")) {
            console.log(`   ⚠️  Already verified: ${address}`);
            return { success: true, address, alreadyVerified: true };
        }
        console.log(`   ❌ Failed: ${error.message}`);
        return { success: false, address, error: error.message };
    }
}

async function main() {
    console.log("\n" + "=".repeat(80));
    console.log("Zaseon v2 CONTRACT VERIFICATION");
    console.log("=".repeat(80) + "\n");

    // Get chain info
    const chainId = Number((await ethers.provider.getNetwork()).chainId);
    const chainConfig = getChainConfig(chainId);

    console.log(`🌐 Chain: ${chainConfig.name} (${chainId})`);
    console.log(`🔗 Explorer: ${chainConfig.explorerUrl}`);
    console.log("");

    // Check for API key
    if (!chainConfig.explorerApiKey) {
        console.error("❌ No explorer API key configured for this chain");
        console.log("   Please set the appropriate environment variable:");
        console.log("   - ETHERSCAN_API_KEY for Ethereum networks");
        console.log("   - ARBISCAN_API_KEY for Arbitrum networks");
        console.log("   - OPTIMISM_API_KEY for Optimism networks");
        console.log("   - BASESCAN_API_KEY for Base networks");
        console.log("   - POLYGONSCAN_API_KEY for Polygon networks");
        process.exit(1);
    }

    // Load deployment
    const deployment = loadDeployment(chainId);
    if (!deployment) {
        console.error("❌ No deployment found for this chain");
        console.log("   Please deploy first: npx hardhat run scripts/multichain/deploy.js");
        process.exit(1);
    }

    console.log(`📦 Found deployment from: ${deployment.timestamp}`);
    console.log(`   Contracts: ${Object.keys(deployment.contracts).length}`);
    console.log("");

    const results = {
        verified: [],
        alreadyVerified: [],
        failed: [],
    };

    // Get deployer for constructor args
    const [deployer, proposer, executor] = await ethers.getSigners();

    // Verify each contract
    console.log("🔍 Verifying contracts...\n");

    // 1. VerifierRegistry - no constructor args
    if (deployment.contracts.verifierRegistry) {
        const result = await verifyContract(
            deployment.contracts.verifierRegistry,
            [],
            CONTRACT_PATHS.verifierRegistry
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 2. Groth16VerifierBN254 - no constructor args
    if (deployment.contracts.groth16VerifierBN254) {
        const result = await verifyContract(
            deployment.contracts.groth16VerifierBN254,
            [],
            CONTRACT_PATHS.groth16VerifierBN254
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 3. PLONKVerifier - no constructor args
    if (deployment.contracts.plonkVerifier) {
        const result = await verifyContract(
            deployment.contracts.plonkVerifier,
            [],
            CONTRACT_PATHS.plonkVerifier
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 4. FRIVerifier - no constructor args
    if (deployment.contracts.friVerifier) {
        const result = await verifyContract(
            deployment.contracts.friVerifier,
            [],
            CONTRACT_PATHS.friVerifier
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 5. TEEAttestation - no constructor args
    if (deployment.contracts.teeAttestation) {
        const result = await verifyContract(
            deployment.contracts.teeAttestation,
            [],
            CONTRACT_PATHS.teeAttestation
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 6. ProofCarryingContainer - no constructor args
    if (deployment.contracts.pc3) {
        const result = await verifyContract(
            deployment.contracts.pc3,
            [],
            CONTRACT_PATHS.pc3
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 7. PolicyBoundProofs - no constructor args
    if (deployment.contracts.pbp) {
        const result = await verifyContract(
            deployment.contracts.pbp,
            [],
            CONTRACT_PATHS.pbp
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 8. ExecutionAgnosticStateCommitments - no constructor args
    if (deployment.contracts.easc) {
        const result = await verifyContract(
            deployment.contracts.easc,
            [],
            CONTRACT_PATHS.easc
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 9. CrossDomainNullifierAlgebra - no constructor args
    if (deployment.contracts.cdna) {
        const result = await verifyContract(
            deployment.contracts.cdna,
            [],
            CONTRACT_PATHS.cdna
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 10. Zaseonv2Orchestrator - has constructor args
    if (deployment.contracts.orchestrator) {
        const result = await verifyContract(
            deployment.contracts.orchestrator,
            [
                deployment.contracts.pc3,
                deployment.contracts.pbp,
                deployment.contracts.easc,
                deployment.contracts.cdna,
            ],
            CONTRACT_PATHS.orchestrator
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 11. ZaseonTimelock - has constructor args
    if (deployment.contracts.timelock) {
        const result = await verifyContract(
            deployment.contracts.timelock,
            [
                chainConfig.timelockDelay,
                [proposer?.address || deployer.address],
                [executor?.address || deployer.address],
                deployer.address,
            ],
            CONTRACT_PATHS.timelock
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // 12. TimelockAdmin - has constructor args
    if (deployment.contracts.timelockAdmin) {
        const result = await verifyContract(
            deployment.contracts.timelockAdmin,
            [deployment.contracts.timelock],
            CONTRACT_PATHS.timelockAdmin
        );
        (result.alreadyVerified ? results.alreadyVerified : result.success ? results.verified : results.failed).push(result);
    }

    // Summary
    console.log("\n" + "=".repeat(80));
    console.log("VERIFICATION SUMMARY");
    console.log("=".repeat(80));
    console.log(`\n✅ Newly Verified: ${results.verified.length}`);
    console.log(`⚠️  Already Verified: ${results.alreadyVerified.length}`);
    console.log(`❌ Failed: ${results.failed.length}`);

    if (results.failed.length > 0) {
        console.log("\n❌ Failed verifications:");
        for (const result of results.failed) {
            console.log(`   ${result.address}: ${result.error}`);
        }
    }

    // Update deployment with verification status
    deployment.verified = {
        timestamp: new Date().toISOString(),
        results: {
            verified: results.verified.map(r => r.address),
            alreadyVerified: results.alreadyVerified.map(r => r.address),
            failed: results.failed.map(r => ({ address: r.address, error: r.error })),
        },
    };

    // Save updated deployment
    const { saveDeployment } = require("./chain-config");
    saveDeployment(chainId, deployment);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
