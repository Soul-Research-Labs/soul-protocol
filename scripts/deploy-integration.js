// SPDX-License-Identifier: MIT
const { ethers } = require("hardhat");
const fs = require("fs");

/**
 * ZASEON Integration Deployment Script
 * 
 * Deploys and wires up all ZASEON components:
 * - ZaseonProtocolHub (Central registry)
 * - Verifiers (Groth16, Universal, MultiProver, Registry)
 * - Security Modules (Proof Validator, Watchtower, Circuit Breaker)
 * - Core Primitives (PC³, PBP, CDNA)
 */

async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying ZASEON Integration with account:", deployer.address);
    console.log("Account balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

    // =========================================================================
    // STEP 1: Deploy ZaseonProtocolHub
    // =========================================================================
    console.log("\n[1/6] Deploying ZaseonProtocolHub...");
    
    const ZaseonProtocolHub = await ethers.getContractFactory("ZaseonProtocolHub");
    const hub = await ZaseonProtocolHub.deploy();
    await hub.waitForDeployment();
    console.log("ZaseonProtocolHub deployed to:", await hub.getAddress());

    // =========================================================================
    // STEP 2: Deploy Verifiers
    // =========================================================================
    console.log("\n[2/6] Deploying Verifiers...");

    const Groth16VerifierBN254 = await ethers.getContractFactory("Groth16VerifierBN254");
    const groth16Verifier = await Groth16VerifierBN254.deploy();
    await groth16Verifier.waitForDeployment();
    console.log("Groth16VerifierBN254 deployed to:", await groth16Verifier.getAddress());

    const ZaseonUniversalVerifier = await ethers.getContractFactory("ZaseonUniversalVerifier");
    const universalVerifier = await ZaseonUniversalVerifier.deploy();
    await universalVerifier.waitForDeployment();
    console.log("ZaseonUniversalVerifier deployed to:", await universalVerifier.getAddress());

    const ZaseonMultiProver = await ethers.getContractFactory("ZaseonMultiProver");
    const multiProver = await ZaseonMultiProver.deploy();
    await multiProver.waitForDeployment();
    console.log("ZaseonMultiProver deployed to:", await multiProver.getAddress());

    const VerifierRegistry = await ethers.getContractFactory("VerifierRegistry");
    const verifierRegistry = await VerifierRegistry.deploy();
    await verifierRegistry.waitForDeployment();
    console.log("VerifierRegistry deployed to:", await verifierRegistry.getAddress());

    // =========================================================================
    // STEP 3: Register Verifiers with Hub
    // =========================================================================
    console.log("\n[3/6] Registering Verifiers...");

    const GROTH16_VERIFIER = ethers.keccak256(ethers.toUtf8Bytes("GROTH16"));

    await hub.setUniversalVerifier(await universalVerifier.getAddress());
    await hub.setMultiProver(await multiProver.getAddress());
    await hub.setVerifierRegistry(await verifierRegistry.getAddress());
    await hub.registerVerifier(GROTH16_VERIFIER, await groth16Verifier.getAddress(), 300000);
    console.log("Verifiers registered with ZaseonProtocolHub");

    // =========================================================================
    // STEP 4: Deploy Security Modules
    // =========================================================================
    console.log("\n[4/6] Deploying Security Modules...");

    const BridgeProofValidator = await ethers.getContractFactory("BridgeProofValidator");
    const bridgeProofValidator = await BridgeProofValidator.deploy();
    await bridgeProofValidator.waitForDeployment();
    console.log("BridgeProofValidator deployed to:", await bridgeProofValidator.getAddress());

    const BridgeWatchtower = await ethers.getContractFactory("BridgeWatchtower");
    const bridgeWatchtower = await BridgeWatchtower.deploy();
    await bridgeWatchtower.waitForDeployment();
    console.log("BridgeWatchtower deployed to:", await bridgeWatchtower.getAddress());

    const BridgeCircuitBreaker = await ethers.getContractFactory("BridgeCircuitBreaker");
    const bridgeCircuitBreaker = await BridgeCircuitBreaker.deploy();
    await bridgeCircuitBreaker.waitForDeployment();
    console.log("BridgeCircuitBreaker deployed to:", await bridgeCircuitBreaker.getAddress());

    await hub.setBridgeProofValidator(await bridgeProofValidator.getAddress());
    await hub.setBridgeWatchtower(await bridgeWatchtower.getAddress());
    await hub.setBridgeCircuitBreaker(await bridgeCircuitBreaker.getAddress());
    console.log("Security modules registered with ZaseonProtocolHub");

    // =========================================================================
    // STEP 5: Deploy Core Primitives
    // =========================================================================
    console.log("\n[5/6] Deploying Core Primitives...");

    const ProofCarryingContainer = await ethers.getContractFactory("ProofCarryingContainer");
    const pc3 = await ProofCarryingContainer.deploy();
    await pc3.waitForDeployment();
    console.log("ProofCarryingContainer deployed to:", await pc3.getAddress());

    const PolicyBoundProofs = await ethers.getContractFactory("PolicyBoundProofs");
    const pbp = await PolicyBoundProofs.deploy();
    await pbp.waitForDeployment();
    console.log("PolicyBoundProofs deployed to:", await pbp.getAddress());

    const CrossDomainNullifierAlgebra = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
    const cdna = await CrossDomainNullifierAlgebra.deploy();
    await cdna.waitForDeployment();
    console.log("CrossDomainNullifierAlgebra deployed to:", await cdna.getAddress());

    await hub.setProofCarryingContainer(await pc3.getAddress());
    await hub.setPolicyBoundProofs(await pbp.getAddress());
    await hub.setCrossDomainNullifierAlgebra(await cdna.getAddress());
    console.log("Core primitives registered with ZaseonProtocolHub");

    // =========================================================================
    // STEP 6: Deployment Summary
    // =========================================================================
    console.log("\n" + "=".repeat(80));
    console.log("ZASEON PROTOCOL INTEGRATION DEPLOYMENT COMPLETE");
    console.log("=".repeat(80));
    
    const deploymentInfo = {
        network: (await ethers.provider.getNetwork()).name,
        chainId: (await ethers.provider.getNetwork()).chainId.toString(),
        deployer: deployer.address,
        hub: await hub.getAddress(),
        verifiers: {
            groth16: await groth16Verifier.getAddress(),
            universal: await universalVerifier.getAddress(),
            multiProver: await multiProver.getAddress(),
            registry: await verifierRegistry.getAddress()
        },
        security: {
            bridgeProofValidator: await bridgeProofValidator.getAddress(),
            bridgeWatchtower: await bridgeWatchtower.getAddress(),
            bridgeCircuitBreaker: await bridgeCircuitBreaker.getAddress()
        },
        primitives: {
            proofCarryingContainer: await pc3.getAddress(),
            policyBoundProofs: await pbp.getAddress(),
            crossDomainNullifierAlgebra: await cdna.getAddress()
        }
    };

    console.log(JSON.stringify(deploymentInfo, null, 2));

    const filename = `deployments/integration-${deploymentInfo.chainId}.json`;
    fs.writeFileSync(filename, JSON.stringify(deploymentInfo, null, 2));
    console.log(`\nDeployment info saved to ${filename}`);

    return deploymentInfo;
}

main()
    .then(() => {
        console.log("\nDeployment successful!");
        process.exit(0);
    })
    .catch((error) => {
        console.error("Deployment failed:", error);
        process.exit(1);
    });
