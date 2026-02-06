/**
 * Soul Protocol - Solana Bridge Deployment Script
 *
 * Deploys the complete Solana bridge infrastructure:
 * 1. MockWrappedSOL (wSOL) ERC-20 token
 * 2. MockSolanaGuardianOracle (Wormhole Guardian mock)
 * 3. SolanaBridgeAdapter
 * 4. Configure bridge parameters
 * 5. Grant roles (RELAYER, GUARDIAN, TREASURY)
 * 6. Grant MINTER_ROLE to bridge on wSOL token
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-solana-bridge.ts --network <network>
 */

import hre from "hardhat";
import fs from "fs";
import path from "path";

async function main() {
    const [deployer] = await hre.viem.getWalletClients();
    const publicClient = await hre.viem.getPublicClient();

    const deployerAddress = deployer.account.address;
    console.log("Deploying Solana bridge with account:", deployerAddress);

    const chainId = await publicClient.getChainId();
    console.log("Chain ID:", chainId);

    // =========================================================================
    // Phase 1: Deploy MockWrappedSOL
    // =========================================================================
    console.log("\n📦 Phase 1: Deploying MockWrappedSOL...");

    const wSOL = await hre.viem.deployContract("MockWrappedSOL", [
        deployerAddress,
    ]);
    console.log("  wSOL deployed at:", wSOL.address);

    // =========================================================================
    // Phase 2: Deploy MockSolanaGuardianOracle
    // =========================================================================
    console.log("\n📦 Phase 2: Deploying MockSolanaGuardianOracle...");

    const oracle = await hre.viem.deployContract("MockSolanaGuardianOracle", [
        deployerAddress,
    ]);
    console.log("  GuardianOracle deployed at:", oracle.address);

    // Register 5 Guardian keys (simulating Wormhole Guardian set)
    const guardianKeys = [
        "0x" + "01".padEnd(64, "0"),
        "0x" + "02".padEnd(64, "0"),
        "0x" + "03".padEnd(64, "0"),
        "0x" + "04".padEnd(64, "0"),
        "0x" + "05".padEnd(64, "0"),
    ] as `0x${string}`[];

    for (const key of guardianKeys) {
        await oracle.write.registerGuardian([key]);
    }
    console.log("  Registered 5 Guardians");

    // =========================================================================
    // Phase 3: Deploy SolanaBridgeAdapter
    // =========================================================================
    console.log("\n📦 Phase 3: Deploying SolanaBridgeAdapter...");

    const bridge = await hre.viem.deployContract("SolanaBridgeAdapter", [
        deployerAddress,
    ]);
    console.log("  SolanaBridgeAdapter deployed at:", bridge.address);

    // =========================================================================
    // Phase 4: Configure Bridge
    // =========================================================================
    console.log("\n⚙️  Phase 4: Configuring bridge...");

    // Solana bridge program address (32 bytes — placeholder for production)
    const solanaBridgeProgram =
        "0x" +
        Buffer.from("SoulBridgeProgram11111111111111")
            .toString("hex")
            .padEnd(64, "0");

    await bridge.write.configure([
        solanaBridgeProgram as `0x${string}`,
        wSOL.address,
        oracle.address,
        BigInt(3), // minGuardianSignatures (3 of 5)
        BigInt(32), // requiredSlotConfirmations
    ]);
    console.log("  Bridge configured");
    console.log("    Solana bridge program:", solanaBridgeProgram);
    console.log("    Min Guardian signatures: 3");
    console.log("    Required slot confirmations: 32");

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
    // Phase 6: Grant MINTER_ROLE to bridge on wSOL
    // =========================================================================
    console.log("\n🪙 Phase 6: Granting MINTER_ROLE to bridge...");

    await wSOL.write.grantMinter([bridge.address]);
    console.log("  Granted MINTER_ROLE on wSOL to bridge");

    // =========================================================================
    // Save Deployment Artifact
    // =========================================================================
    const deployment = {
        network: chainId.toString(),
        deployer: deployerAddress,
        timestamp: new Date().toISOString(),
        contracts: {
            MockWrappedSOL: wSOL.address,
            MockSolanaGuardianOracle: oracle.address,
            SolanaBridgeAdapter: bridge.address,
        },
        configuration: {
            solanaBridgeProgram,
            minGuardianSignatures: 3,
            requiredSlotConfirmations: 32,
            guardianKeys: guardianKeys.length,
            bridgeFeeBps: 25,
            lamportsPerSol: "1000000000",
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
        `solana-bridge-${chainId}.json`
    );
    fs.writeFileSync(artifactPath, JSON.stringify(deployment, null, 2));
    console.log("\n💾 Deployment artifact saved to:", artifactPath);

    // =========================================================================
    // Summary
    // =========================================================================
    console.log("\n" + "=".repeat(60));
    console.log("  SOLANA BRIDGE DEPLOYMENT COMPLETE");
    console.log("=".repeat(60));
    console.log("  wSOL:              ", wSOL.address);
    console.log("  GuardianOracle:    ", oracle.address);
    console.log("  SolanaBridgeAdapter:", bridge.address);
    console.log("  Min Guardians:      3/5");
    console.log("  Slot Confirmations: 32");
    console.log("  Bridge Fee:         0.25%");
    console.log("=".repeat(60));
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
