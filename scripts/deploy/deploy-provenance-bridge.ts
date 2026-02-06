/**
 * Soul Protocol - Provenance Bridge Deployment Script
 *
 * Deploys the complete Provenance bridge infrastructure:
 * 1. MockWrappedHASH (wHASH) ERC-20 token (9 decimals)
 * 2. MockTendermintValidatorOracle (Tendermint validator mock)
 * 3. ProvenanceBridgeAdapter
 * 4. Configure bridge parameters
 * 5. Grant roles (RELAYER, GUARDIAN, TREASURY)
 * 6. Verify deployment
 *
 * Provenance-specific:
 * - Chain ID: 505 (pio-mainnet-1 EVM mapping)
 * - 1 HASH = 1e9 nhash (9 decimals)
 * - 5 active validators (test), 4/5 supermajority
 * - 10 block confirmations (~60s BFT finality)
 * - 0.10% bridge fee
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-provenance-bridge.ts --network <network>
 */

import hre from "hardhat";
import fs from "fs";
import path from "path";

async function main() {
    const [deployer] = await hre.viem.getWalletClients();
    const publicClient = await hre.viem.getPublicClient();

    const deployerAddress = deployer.account.address;
    console.log(
        "Deploying Provenance bridge with account:",
        deployerAddress
    );

    const chainId = await publicClient.getChainId();
    console.log("Chain ID:", chainId);

    // =========================================================================
    // Phase 1: Deploy MockWrappedHASH
    // =========================================================================
    console.log("\n📦 Phase 1: Deploying MockWrappedHASH (9 decimals)...");

    const wHASH = await hre.viem.deployContract("MockWrappedHASH", []);
    console.log("  wHASH deployed at:", wHASH.address);

    // =========================================================================
    // Phase 2: Deploy MockTendermintValidatorOracle
    // =========================================================================
    console.log("\n📦 Phase 2: Deploying MockTendermintValidatorOracle...");

    const oracle = await hre.viem.deployContract(
        "MockTendermintValidatorOracle",
        []
    );
    console.log("  ValidatorOracle deployed at:", oracle.address);

    // Register 5 Tendermint validator addresses
    const validatorAddresses = [
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
        "0x4444444444444444444444444444444444444444",
        "0x5555555555555555555555555555555555555555",
    ] as `0x${string}`[];

    for (const addr of validatorAddresses) {
        await oracle.write.addValidator([addr]);
    }
    console.log("  Registered 5 Tendermint validators");

    // =========================================================================
    // Phase 3: Deploy ProvenanceBridgeAdapter
    // =========================================================================
    console.log("\n📦 Phase 3: Deploying ProvenanceBridgeAdapter...");

    const bridge = await hre.viem.deployContract("ProvenanceBridgeAdapter", [
        deployerAddress,
    ]);
    console.log("  ProvenanceBridgeAdapter deployed at:", bridge.address);

    // =========================================================================
    // Phase 4: Configure Bridge
    // =========================================================================
    console.log("\n⚙️  Phase 4: Configuring bridge...");

    // Provenance-side bridge contract address (placeholder for production)
    const provBridgeContract =
        "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" as `0x${string}`;

    await bridge.write.configure([
        provBridgeContract,
        wHASH.address,
        oracle.address,
        BigInt(4), // minValidatorSignatures (4 of 5 = supermajority)
        BigInt(10), // requiredBlockConfirmations (~60s BFT finality)
    ]);
    console.log("  Bridge configured");
    console.log("    Provenance bridge contract:", provBridgeContract);
    console.log("    Min validator signatures: 4 (of 5)");
    console.log("    Required block confirmations: 10 (~60s)");

    // =========================================================================
    // Phase 5: Grant Roles
    // =========================================================================
    console.log("\n🔐 Phase 5: Granting roles...");

    // In production, these would be separate addresses
    const relayerAddress = deployerAddress;
    const guardianAddress = deployerAddress;
    const treasuryAddress = deployerAddress;

    const RELAYER_ROLE = await bridge.read.RELAYER_ROLE();
    const GUARDIAN_ROLE = await bridge.read.GUARDIAN_ROLE();
    const TREASURY_ROLE = await bridge.read.TREASURY_ROLE();

    await bridge.write.grantRole([RELAYER_ROLE, relayerAddress]);
    console.log("  Granted RELAYER_ROLE to:", relayerAddress);

    await bridge.write.grantRole([GUARDIAN_ROLE, guardianAddress]);
    console.log("  Granted GUARDIAN_ROLE to:", guardianAddress);

    await bridge.write.grantRole([TREASURY_ROLE, treasuryAddress]);
    console.log("  Granted TREASURY_ROLE to:", treasuryAddress);

    // =========================================================================
    // Phase 6: Verify Deployment
    // =========================================================================
    console.log("\n✅ Phase 6: Verifying deployment...");

    const config = await bridge.read.bridgeConfig();
    console.log("  Bridge active:", config[5]); // .active field
    console.log("  wHASH address matches:", config[1] === wHASH.address);
    console.log(
        "  Oracle address matches:",
        config[2] === oracle.address
    );

    // =========================================================================
    // Save Deployment Artifact
    // =========================================================================
    const deployment = {
        network: chainId.toString(),
        deployer: deployerAddress,
        timestamp: new Date().toISOString(),
        contracts: {
            MockWrappedHASH: wHASH.address,
            MockTendermintValidatorOracle: oracle.address,
            ProvenanceBridgeAdapter: bridge.address,
        },
        configuration: {
            provBridgeContract,
            minValidatorSignatures: 4,
            requiredBlockConfirmations: 10,
            validatorCount: validatorAddresses.length,
            bridgeFeeBps: 10,
            provenanceChainId: 505,
            nhashPerHash: "1000000000",
        },
        roles: {
            relayer: relayerAddress,
            guardian: guardianAddress,
            treasury: treasuryAddress,
        },
    };

    const deploymentsDir = path.join(__dirname, "../../deployments");
    if (!fs.existsSync(deploymentsDir)) {
        fs.mkdirSync(deploymentsDir, { recursive: true });
    }

    const artifactPath = path.join(
        deploymentsDir,
        `provenance-bridge-${chainId}.json`
    );
    fs.writeFileSync(artifactPath, JSON.stringify(deployment, null, 2));
    console.log("\n💾 Deployment artifact saved to:", artifactPath);

    // =========================================================================
    // Summary
    // =========================================================================
    console.log("\n" + "=".repeat(60));
    console.log("  PROVENANCE BRIDGE DEPLOYMENT COMPLETE");
    console.log("=".repeat(60));
    console.log("  wHASH (9 dec):       ", wHASH.address);
    console.log("  ValidatorOracle:     ", oracle.address);
    console.log("  ProvenanceBridge:    ", bridge.address);
    console.log("  Min Validators:       4/5 (BFT supermajority)");
    console.log("  Block Confirmations:  10 (~60s)");
    console.log("  Bridge Fee:           0.10%");
    console.log("  HASH Precision:       9 decimals (1e9 nhash)");
    console.log("  Chain ID:             505 (pio-mainnet-1)");
    console.log("=".repeat(60));
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
