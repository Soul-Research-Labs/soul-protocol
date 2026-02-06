/**
 * Soul Protocol - Plasma Bridge Deployment Script
 *
 * Deploys the complete Plasma bridge infrastructure:
 * 1. MockWrappedPLASMA (wPLASMA) ERC-20 token (8 decimals)
 * 2. MockPlasmaOperatorOracle (operator verification mock)
 * 3. PlasmaBridgeAdapter
 * 4. Configure bridge parameters
 * 5. Grant roles (RELAYER, GUARDIAN, TREASURY)
 * 6. Verify deployment
 *
 * Plasma-specific:
 * - Chain ID: 515 (plasma-mainnet-1 EVM mapping)
 * - 1 PLASMA = 1e8 satoplasma (8 decimals, UTXO-inspired)
 * - 3 operators (test), 2 min confirmations
 * - 12 L1 commitment confirmations (Ethereum finality)
 * - 0.08% bridge fee (8 BPS)
 * - 7-day challenge period for exits
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-plasma-bridge.ts --network <network>
 */

import hre from "hardhat";
import fs from "fs";
import path from "path";

async function main() {
    const [deployer] = await hre.viem.getWalletClients();
    const publicClient = await hre.viem.getPublicClient();

    const deployerAddress = deployer.account.address;
    console.log(
        "Deploying Plasma bridge with account:",
        deployerAddress
    );

    const chainId = await publicClient.getChainId();
    console.log("Chain ID:", chainId);

    // =========================================================================
    // Phase 1: Deploy MockWrappedPLASMA
    // =========================================================================
    console.log("\n📦 Phase 1: Deploying MockWrappedPLASMA (8 decimals)...");

    const wPLASMA = await hre.viem.deployContract("MockWrappedPLASMA", []);
    console.log("  wPLASMA deployed at:", wPLASMA.address);

    // =========================================================================
    // Phase 2: Deploy MockPlasmaOperatorOracle
    // =========================================================================
    console.log("\n📦 Phase 2: Deploying MockPlasmaOperatorOracle...");

    const oracle = await hre.viem.deployContract(
        "MockPlasmaOperatorOracle",
        []
    );
    console.log("  OperatorOracle deployed at:", oracle.address);

    // Register 3 Plasma operator addresses
    const operatorAddresses = [
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
    ] as `0x${string}`[];

    for (const addr of operatorAddresses) {
        await oracle.write.addOperator([addr]);
    }
    console.log("  Registered 3 Plasma operators");

    // =========================================================================
    // Phase 3: Deploy PlasmaBridgeAdapter
    // =========================================================================
    console.log("\n📦 Phase 3: Deploying PlasmaBridgeAdapter...");

    const bridge = await hre.viem.deployContract("PlasmaBridgeAdapter", [
        deployerAddress,
    ]);
    console.log("  PlasmaBridgeAdapter deployed at:", bridge.address);

    // =========================================================================
    // Phase 4: Configure Bridge
    // =========================================================================
    console.log("\n⚙️  Phase 4: Configuring bridge...");

    // Plasma-side bridge contract address (placeholder for production)
    const plasmaBridgeContract =
        "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" as `0x${string}`;

    await bridge.write.configure([
        plasmaBridgeContract,
        wPLASMA.address,
        oracle.address,
        BigInt(2), // minOperatorConfirmations (2 of 3)
        BigInt(12), // requiredL1Confirmations (Ethereum finality)
    ]);
    console.log("  Bridge configured");
    console.log("    Plasma bridge contract:", plasmaBridgeContract);
    console.log("    Min operator confirmations: 2 (of 3)");
    console.log("    Required L1 confirmations: 12 (Ethereum finality)");

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
    console.log("  wPLASMA address matches:", config[1] === wPLASMA.address);
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
            MockWrappedPLASMA: wPLASMA.address,
            MockPlasmaOperatorOracle: oracle.address,
            PlasmaBridgeAdapter: bridge.address,
        },
        configuration: {
            plasmaBridgeContract,
            minOperatorConfirmations: 2,
            requiredL1Confirmations: 12,
            operatorCount: operatorAddresses.length,
            bridgeFeeBps: 8,
            plasmaChainId: 515,
            satoplasmaPerPlasma: "100000000",
            challengePeriodDays: 7,
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
        `plasma-bridge-${chainId}.json`
    );
    fs.writeFileSync(artifactPath, JSON.stringify(deployment, null, 2));
    console.log("\n💾 Deployment artifact saved to:", artifactPath);

    // =========================================================================
    // Summary
    // =========================================================================
    console.log("\n" + "=".repeat(60));
    console.log("  PLASMA BRIDGE DEPLOYMENT COMPLETE");
    console.log("=".repeat(60));
    console.log("  wPLASMA (8 dec):      ", wPLASMA.address);
    console.log("  OperatorOracle:       ", oracle.address);
    console.log("  PlasmaBridge:         ", bridge.address);
    console.log("  Min Operators:         2/3");
    console.log("  L1 Confirmations:      12 (Ethereum finality)");
    console.log("  Challenge Period:      7 days");
    console.log("  Bridge Fee:            0.08%");
    console.log("  PLASMA Precision:      8 decimals (1e8 satoplasma)");
    console.log("  Chain ID:              515 (plasma-mainnet-1)");
    console.log("=".repeat(60));
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
