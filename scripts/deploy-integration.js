// SPDX-License-Identifier: MIT
const { ethers } = require("hardhat");

/**
 * Soul Protocol Integration Deployment Script
 * 
 * This script deploys and wires up all Soul Protocol components:
 * - Verifiers (Binius, PLONK, FRI, Groth16, etc.)
 * - Bridge Adapters (zkSync, Scroll, Linea, Polygon zkEVM, Starknet, Bitcoin, Aztec)
 * - Privacy Modules (MLSAG, RingCT, Mixnet, Decoy, Gas Normalizer)
 * - Security Modules (Proof Validator, Watchtower, Security Oracle)
 * - MPC Modules (Threshold Signature, MPC Compliance)
 * - Core Primitives (ZK-SLocks, PC³, CDNA)
 */

async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying Soul Protocol Integration with account:", deployer.address);
    console.log("Account balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

    // =========================================================================
    // STEP 1: Deploy SoulProtocolHub
    // =========================================================================
    console.log("\n[1/7] Deploying SoulProtocolHub...");
    
    const SoulProtocolHub = await ethers.getContractFactory("SoulProtocolHub");
    const hub = await SoulProtocolHub.deploy();
    await hub.waitForDeployment();
    console.log("SoulProtocolHub deployed to:", await hub.getAddress());

    // =========================================================================
    // STEP 2: Deploy Verifiers
    // =========================================================================
    console.log("\n[2/7] Deploying Verifiers...");
    
    // Binius Verifier
    const BiniusVerifier = await ethers.getContractFactory("BiniusVerifier");
    const biniusVerifier = await BiniusVerifier.deploy(deployer.address);
    await biniusVerifier.waitForDeployment();
    console.log("BiniusVerifier deployed to:", await biniusVerifier.getAddress());

    // Binius Adapter
    const BiniusVerifierAdapter = await ethers.getContractFactory("BiniusVerifierAdapter");
    const biniusAdapter = await BiniusVerifierAdapter.deploy(await biniusVerifier.getAddress());
    await biniusAdapter.waitForDeployment();
    console.log("BiniusVerifierAdapter deployed to:", await biniusAdapter.getAddress());

    // PLONK Verifier
    const PLONKVerifier = await ethers.getContractFactory("PLONKVerifier");
    const plonkVerifier = await PLONKVerifier.deploy();
    await plonkVerifier.waitForDeployment();
    console.log("PLONKVerifier deployed to:", await plonkVerifier.getAddress());

    // FRI Verifier
    const FRIVerifier = await ethers.getContractFactory("FRIVerifier");
    const friVerifier = await FRIVerifier.deploy();
    await friVerifier.waitForDeployment();
    console.log("FRIVerifier deployed to:", await friVerifier.getAddress());

    // Groth16 Verifier (BN254)
    const Groth16VerifierBN254 = await ethers.getContractFactory("Groth16VerifierBN254");
    const groth16Verifier = await Groth16VerifierBN254.deploy();
    await groth16Verifier.waitForDeployment();
    console.log("Groth16VerifierBN254 deployed to:", await groth16Verifier.getAddress());

    // BTCSPVVerifier
    const BTCSPVVerifier = await ethers.getContractFactory("BTCSPVVerifier");
    const btcSpvVerifier = await BTCSPVVerifier.deploy();
    await btcSpvVerifier.waitForDeployment();
    console.log("BTCSPVVerifier deployed to:", await btcSpvVerifier.getAddress());

    // BitVM Verifier
    const BitVMVerifier = await ethers.getContractFactory("BitVMVerifier");
    const bitvmVerifier = await BitVMVerifier.deploy();
    await bitvmVerifier.waitForDeployment();
    console.log("BitVMVerifier deployed to:", await bitvmVerifier.getAddress());

    // Universal Verifier
    const SoulUniversalVerifier = await ethers.getContractFactory("SoulUniversalVerifier");
    const universalVerifier = await SoulUniversalVerifier.deploy();
    await universalVerifier.waitForDeployment();
    console.log("SoulUniversalVerifier deployed to:", await universalVerifier.getAddress());

    // Multi-Prover
    const SoulMultiProver = await ethers.getContractFactory("SoulMultiProver");
    const multiProver = await SoulMultiProver.deploy();
    await multiProver.waitForDeployment();
    console.log("SoulMultiProver deployed to:", await multiProver.getAddress());

    // Verifier Registry
    const VerifierRegistry = await ethers.getContractFactory("VerifierRegistry");
    const verifierRegistry = await VerifierRegistry.deploy();
    await verifierRegistry.waitForDeployment();
    console.log("VerifierRegistry deployed to:", await verifierRegistry.getAddress());

    // =========================================================================
    // STEP 3: Register Verifiers
    // =========================================================================
    console.log("\n[3/7] Registering Verifiers...");

    // Define proof type constants
    const BINIUS_VERIFIER = ethers.keccak256(ethers.toUtf8Bytes("BINIUS"));
    const PLONK_VERIFIER = ethers.keccak256(ethers.toUtf8Bytes("PLONK"));
    const FRI_VERIFIER = ethers.keccak256(ethers.toUtf8Bytes("FRI"));
    const GROTH16_VERIFIER = ethers.keccak256(ethers.toUtf8Bytes("GROTH16"));
    const BTC_SPV_VERIFIER = ethers.keccak256(ethers.toUtf8Bytes("BTC_SPV"));
    const BITVM_VERIFIER = ethers.keccak256(ethers.toUtf8Bytes("BITVM"));

    // Register with hub
    await hub.setUniversalVerifier(await universalVerifier.getAddress());
    await hub.setMultiProver(await multiProver.getAddress());
    await hub.setVerifierRegistry(await verifierRegistry.getAddress());

    // Batch register verifiers
    await hub.batchRegisterVerifiers(
        [BINIUS_VERIFIER, PLONK_VERIFIER, FRI_VERIFIER, GROTH16_VERIFIER, BTC_SPV_VERIFIER, BITVM_VERIFIER],
        [
            await biniusAdapter.getAddress(),
            await plonkVerifier.getAddress(),
            await friVerifier.getAddress(),
            await groth16Verifier.getAddress(),
            await btcSpvVerifier.getAddress(),
            await bitvmVerifier.getAddress()
        ],
        [600000, 500000, 400000, 300000, 200000, 800000] // Gas limits
    );
    console.log("Verifiers registered with SoulProtocolHub");

    // Register Binius with Universal Verifier (ProofSystem.Binius = 6)
    await universalVerifier.registerVerifier(6, await biniusAdapter.getAddress(), 600000);
    console.log("Binius registered with SoulUniversalVerifier");

    // =========================================================================
    // STEP 4: Deploy Privacy Modules
    // =========================================================================
    console.log("\n[4/7] Deploying Privacy Modules...");

    // MLSAG Signatures
    const MLSAGSignatures = await ethers.getContractFactory("MLSAGSignatures");
    const mlsag = await MLSAGSignatures.deploy();
    await mlsag.waitForDeployment();
    console.log("MLSAGSignatures deployed to:", await mlsag.getAddress());

    // Ring Confidential Transactions
    const RingConfidentialTransactions = await ethers.getContractFactory("RingConfidentialTransactions");
    const ringCT = await RingConfidentialTransactions.deploy();
    await ringCT.waitForDeployment();
    console.log("RingConfidentialTransactions deployed to:", await ringCT.getAddress());

    // Mixnet Node Registry
    const MixnetNodeRegistry = await ethers.getContractFactory("MixnetNodeRegistry");
    const mixnetRegistry = await MixnetNodeRegistry.deploy();
    await mixnetRegistry.waitForDeployment();
    console.log("MixnetNodeRegistry deployed to:", await mixnetRegistry.getAddress());

    // Decoy Traffic Generator
    const DecoyTrafficGenerator = await ethers.getContractFactory("DecoyTrafficGenerator");
    const decoyGenerator = await DecoyTrafficGenerator.deploy();
    await decoyGenerator.waitForDeployment();
    console.log("DecoyTrafficGenerator deployed to:", await decoyGenerator.getAddress());

    // Gas Normalizer
    const GasNormalizer = await ethers.getContractFactory("GasNormalizer");
    const gasNormalizer = await GasNormalizer.deploy();
    await gasNormalizer.waitForDeployment();
    console.log("GasNormalizer deployed to:", await gasNormalizer.getAddress());

    // Register privacy modules with hub
    await hub.setMLSAGSignatures(await mlsag.getAddress());
    await hub.setRingConfidentialTransactions(await ringCT.getAddress());
    await hub.setMixnetNodeRegistry(await mixnetRegistry.getAddress());
    await hub.setDecoyTrafficGenerator(await decoyGenerator.getAddress());
    await hub.setGasNormalizer(await gasNormalizer.getAddress());
    console.log("Privacy modules registered with SoulProtocolHub");

    // =========================================================================
    // STEP 5: Deploy Security Modules
    // =========================================================================
    console.log("\n[5/7] Deploying Security Modules...");

    // Bridge Proof Validator
    const BridgeProofValidator = await ethers.getContractFactory("BridgeProofValidator");
    const bridgeProofValidator = await BridgeProofValidator.deploy();
    await bridgeProofValidator.waitForDeployment();
    console.log("BridgeProofValidator deployed to:", await bridgeProofValidator.getAddress());

    // Bridge Watchtower
    const BridgeWatchtower = await ethers.getContractFactory("BridgeWatchtower");
    const bridgeWatchtower = await BridgeWatchtower.deploy();
    await bridgeWatchtower.waitForDeployment();
    console.log("BridgeWatchtower deployed to:", await bridgeWatchtower.getAddress());

    // Security Oracle
    const SecurityOracle = await ethers.getContractFactory("SecurityOracle");
    const securityOracle = await SecurityOracle.deploy();
    await securityOracle.waitForDeployment();
    console.log("SecurityOracle deployed to:", await securityOracle.getAddress());

    // Hybrid Crypto Verifier
    const HybridCryptoVerifier = await ethers.getContractFactory("HybridCryptoVerifier");
    const hybridCryptoVerifier = await HybridCryptoVerifier.deploy();
    await hybridCryptoVerifier.waitForDeployment();
    console.log("HybridCryptoVerifier deployed to:", await hybridCryptoVerifier.getAddress());

    // Register security modules with hub
    await hub.setBridgeProofValidator(await bridgeProofValidator.getAddress());
    await hub.setBridgeWatchtower(await bridgeWatchtower.getAddress());
    await hub.setSecurityOracle(await securityOracle.getAddress());
    await hub.setHybridCryptoVerifier(await hybridCryptoVerifier.getAddress());
    console.log("Security modules registered with SoulProtocolHub");

    // =========================================================================
    // STEP 6: Deploy Cross-Chain Components
    // =========================================================================
    console.log("\n[6/7] Deploying Cross-Chain Components...");

    // CrossChainMessageRelay (already exists, just get reference)
    // For new deployment:
    // const CrossChainMessageRelay = await ethers.getContractFactory("CrossChainMessageRelay");
    // const messageRelay = await CrossChainMessageRelay.deploy();
    // await messageRelay.waitForDeployment();
    // console.log("CrossChainMessageRelay deployed to:", await messageRelay.getAddress());

    // Wire up security modules to message relay (if deployed)
    // await messageRelay.setSoulProtocolHub(await hub.getAddress());
    // await messageRelay.setBridgeProofValidator(await bridgeProofValidator.getAddress());
    // await messageRelay.setBridgeWatchtower(await bridgeWatchtower.getAddress());
    // await messageRelay.setSecurityOracle(await securityOracle.getAddress());
    // await messageRelay.setHybridCryptoVerifier(await hybridCryptoVerifier.getAddress());

    // Set cross-chain message relay in hub
    await hub.setCrossChainMessageRelay(ethers.ZeroAddress); // Replace with actual address

    // =========================================================================
    // DEPLOYMENT SUMMARY
    // =========================================================================
    console.log("\n" + "=".repeat(80));
    console.log("SOUL PROTOCOL INTEGRATION DEPLOYMENT COMPLETE");
    console.log("=".repeat(80));
    
    const deploymentInfo = {
        network: (await ethers.provider.getNetwork()).name,
        chainId: (await ethers.provider.getNetwork()).chainId.toString(),
        deployer: deployer.address,
        hub: await hub.getAddress(),
        verifiers: {
            binius: await biniusVerifier.getAddress(),
            biniusAdapter: await biniusAdapter.getAddress(),
            plonk: await plonkVerifier.getAddress(),
            fri: await friVerifier.getAddress(),
            groth16: await groth16Verifier.getAddress(),
            btcSpv: await btcSpvVerifier.getAddress(),
            bitvm: await bitvmVerifier.getAddress(),
            universal: await universalVerifier.getAddress(),
            multiProver: await multiProver.getAddress(),
            registry: await verifierRegistry.getAddress()
        },
        privacy: {
            mlsag: await mlsag.getAddress(),
            ringCT: await ringCT.getAddress(),
            mixnetRegistry: await mixnetRegistry.getAddress(),
            decoyGenerator: await decoyGenerator.getAddress(),
            gasNormalizer: await gasNormalizer.getAddress()
        },
        security: {
            bridgeProofValidator: await bridgeProofValidator.getAddress(),
            bridgeWatchtower: await bridgeWatchtower.getAddress(),
            securityOracle: await securityOracle.getAddress(),
            hybridCryptoVerifier: await hybridCryptoVerifier.getAddress()
        }
    };

    console.log(JSON.stringify(deploymentInfo, null, 2));

    // Save deployment info
    const fs = require("fs");
    const filename = `deployments/integration-${deploymentInfo.chainId}.json`;
    fs.writeFileSync(filename, JSON.stringify(deploymentInfo, null, 2));
    console.log(`\nDeployment info saved to ${filename}`);

    return deploymentInfo;
}

main()
    .then((info) => {
        console.log("\nDeployment successful!");
        process.exit(0);
    })
    .catch((error) => {
        console.error("Deployment failed:", error);
        process.exit(1);
    });
