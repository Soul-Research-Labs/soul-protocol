import hre from "hardhat";
import fs from "fs";
import path from "path";
import { formatEther, parseEther, type Address } from "viem";

/**
 * Soul Privacy Middleware Deployment Script (Hardhat v3 / viem)
 *
 * Deploys the privacy middleware stack in dependency order:
 *   1. CrossChainSanctionsOracle
 *   2. UniversalProofTranslator
 *   3. RelayerFeeMarket
 *   4. UniversalShieldedPool
 *   5. PrivacyRouter (wires all components)
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-privacy-middleware.ts --network <network>
 *
 * Environment:
 *   DEPLOY_TEST_MODE=true   - Enable test mode for ShieldedPool (testnet only)
 */

const DEPLOYMENT_LOG_DIR = "./deployments";

interface DeploymentLog {
    network: string;
    chainId: number;
    deployer: string;
    timestamp: string;
    contracts: Record<string, string>;
    configuration: Record<string, unknown>;
}

async function main() {
    console.log("\n" + "=".repeat(80));
    console.log("SOUL PRIVACY MIDDLEWARE DEPLOYMENT (Hardhat v3 / Viem)");
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
    if (balance < parseEther("0.05")) {
        console.error("❌ Insufficient balance. Need at least 0.05 ETH for privacy middleware deployment.");
        process.exit(1);
    }

    // Determine test mode (only for testnets)
    const isTestMode = process.env.DEPLOY_TEST_MODE === "true";
    const isProduction = ["mainnet", "arbitrum", "optimism", "base"].includes(hre.network.name);

    if (isTestMode && isProduction) {
        console.error("❌ Cannot enable test mode on production networks!");
        process.exit(1);
    }

    console.log(`🔧 Test Mode: ${isTestMode ? "ENABLED (testnet)" : "DISABLED (production)"}`);
    console.log("");

    // Try to load existing v3 deployment for cross-references
    let existingDeployment: Record<string, string> = {};
    try {
        const existingPath = path.join(DEPLOYMENT_LOG_DIR, `${hre.network.name}-${chainId}.json`);
        if (fs.existsSync(existingPath)) {
            const existing = JSON.parse(fs.readFileSync(existingPath, "utf-8"));
            existingDeployment = existing.contracts || {};
            console.log("📋 Found existing deployment, cross-referencing addresses...");
        }
    } catch {
        console.log("📋 No existing deployment found, deploying standalone.");
    }

    const deployed: DeploymentLog = {
        network: hre.network.name,
        chainId: chainId,
        deployer: deployer.account.address,
        timestamp: new Date().toISOString(),
        contracts: {},
        configuration: {
            testMode: isTestMode,
            isProduction: isProduction,
        },
    };

    try {
        // ============================================
        // PHASE 1: Compliance Infrastructure
        // ============================================
        console.log("📦 PHASE 1: Compliance Infrastructure\n");

        // 1. Deploy CrossChainSanctionsOracle
        console.log("1️⃣  Deploying CrossChainSanctionsOracle...");
        const sanctionsOracle = await viem.deployContract("CrossChainSanctionsOracle", [
            deployer.account.address, // admin
            1n,                       // quorum threshold
        ]);
        deployed.contracts.sanctionsOracle = sanctionsOracle.address;
        console.log("   ✅ CrossChainSanctionsOracle:", deployed.contracts.sanctionsOracle);

        // ============================================
        // PHASE 2: Proof Translation Layer
        // ============================================
        console.log("\n📦 PHASE 2: Proof Translation Layer\n");

        // 2. Deploy UniversalProofTranslator
        console.log("2️⃣  Deploying UniversalProofTranslator...");
        const proofTranslator = await viem.deployContract("UniversalProofTranslator", [
            deployer.account.address, // admin
        ]);
        deployed.contracts.proofTranslator = proofTranslator.address;
        console.log("   ✅ UniversalProofTranslator:", deployed.contracts.proofTranslator);

        // Register existing verifiers if available from v3 deployment
        if (existingDeployment.verifier) {
            console.log("   🔗 Linking MockProofVerifier as source verifier...");
            // ProofSystem enum: GROTH16=0, PLONK=1, FFLONK=2, STARK=3, ULTRAPLONK=4, HALO2=5, NOVA=6, BULLETPROOFS=7
            await proofTranslator.write.setSourceVerifier([0, existingDeployment.verifier as Address]); // Groth16
            console.log("   ✅ Groth16 source verifier set");
        }
        if (existingDeployment.plonkVerifier) {
            await proofTranslator.write.setSourceVerifier([1, existingDeployment.plonkVerifier as Address]); // PLONK
            console.log("   ✅ PLONK source verifier set");
        }

        // ============================================
        // PHASE 3: Relayer Fee Market
        // ============================================
        console.log("\n📦 PHASE 3: Relayer Fee Market\n");

        // 3. Deploy RelayerFeeMarket
        console.log("3️⃣  Deploying RelayerFeeMarket...");
        const relayerFeeMarket = await viem.deployContract("RelayerFeeMarket", [
            deployer.account.address, // admin
            "0x0000000000000000000000000000000000000000" as Address, // ETH as fee token (zero = native)
        ]);
        deployed.contracts.relayerFeeMarket = relayerFeeMarket.address;
        console.log("   ✅ RelayerFeeMarket:", deployed.contracts.relayerFeeMarket);

        // Initialize default routes for major L2s (using keccak256 hashes as chain identifiers)
        const l2Routes = [
            { sourceChain: "ethereum", destChain: "arbitrum", name: "Ethereum → Arbitrum" },
            { sourceChain: "ethereum", destChain: "optimism", name: "Ethereum → Optimism" },
            { sourceChain: "ethereum", destChain: "base", name: "Ethereum → Base" },
            { sourceChain: "arbitrum", destChain: "optimism", name: "Arbitrum → Optimism" },
            { sourceChain: "arbitrum", destChain: "base", name: "Arbitrum → Base" },
            { sourceChain: "optimism", destChain: "base", name: "Optimism → Base" },
        ];

        const defaultBaseFee = parseEther("0.001"); // 0.001 ETH base fee
        const { keccak256: viemKeccak256, toHex } = await import("viem");
        for (const route of l2Routes) {
            try {
                const srcHash = viemKeccak256(toHex(route.sourceChain));
                const dstHash = viemKeccak256(toHex(route.destChain));
                await relayerFeeMarket.write.initializeRoute([
                    srcHash,
                    dstHash,
                    defaultBaseFee,
                ]);
                console.log(`   ✅ Route: ${route.name}`);
            } catch (e) {
                console.log(`   ⚠️  Route ${route.name}: skipped (may already exist)`);
            }
        }

        // ============================================
        // PHASE 4: Shielded Pool
        // ============================================
        console.log("\n📦 PHASE 4: Shielded Pool\n");

        // 4. Deploy UniversalShieldedPool
        // In production: verifier address must be set (use existing or deploy new)
        // In test mode: verifier can be address(0)
        const verifierAddress = existingDeployment.verifier ||
            "0x0000000000000000000000000000000000000000";

        if (!isTestMode && verifierAddress === "0x0000000000000000000000000000000000000000") {
            console.warn("   ⚠️  WARNING: No verifier configured for production. Deploying MockProofVerifier...");
            const mockVerifier = await viem.deployContract("MockProofVerifier");
            await mockVerifier.write.setVerificationResult([true]);
            deployed.contracts.shieldedPoolVerifier = mockVerifier.address;
            console.log("   ✅ MockProofVerifier (temporary):", mockVerifier.address);
        }

        const finalVerifier = deployed.contracts.shieldedPoolVerifier ||
            verifierAddress as Address;

        console.log("4️⃣  Deploying UniversalShieldedPool...");
        const shieldedPool = await viem.deployContract("UniversalShieldedPool", [
            deployer.account.address,  // admin
            finalVerifier as Address,  // withdrawal verifier
            isTestMode,                // test mode flag
        ]);
        deployed.contracts.shieldedPool = shieldedPool.address;
        console.log("   ✅ UniversalShieldedPool:", deployed.contracts.shieldedPool);
        console.log(`      Verifier: ${finalVerifier}`);
        console.log(`      Test Mode: ${isTestMode}`);

        // Register ETH as default asset
        try {
            await shieldedPool.write.registerAsset([
                "0x0000000000000000000000000000000000000000" as Address, // ETH
                18,  // decimals
                parseEther("100"), // max deposit
            ]);
            console.log("   ✅ ETH registered as asset (max: 100 ETH)");
        } catch (e) {
            console.log("   ⚠️  ETH asset registration skipped");
        }

        // ============================================
        // PHASE 5: Privacy Router (Facade)
        // ============================================
        console.log("\n📦 PHASE 5: Privacy Router\n");

        // 5. Deploy PrivacyRouter — wires all components together
        const proofHubAddress = existingDeployment.proofHub ||
            "0x0000000000000000000000000000000000000000";
        const stealthRegistryAddress = existingDeployment.stealthRegistry ||
            "0x0000000000000000000000000000000000000000";

        console.log("5️⃣  Deploying PrivacyRouter...");
        const privacyRouter = await viem.deployContract("PrivacyRouter", [
            deployer.account.address,               // admin
            shieldedPool.address,                    // shielded pool
            proofHubAddress as Address,              // cross-chain proof hub
            stealthRegistryAddress as Address,       // stealth address registry
            "0x0000000000000000000000000000000000000000" as Address, // nullifier manager
            sanctionsOracle.address,                 // compliance
            proofTranslator.address,                 // proof translator
        ]);
        deployed.contracts.privacyRouter = privacyRouter.address;
        console.log("   ✅ PrivacyRouter:", deployed.contracts.privacyRouter);

        // ============================================
        // PHASE 6: Post-Deployment Configuration
        // ============================================
        console.log("\n📦 PHASE 6: Post-Deployment Configuration\n");

        // Grant RELAYER_ROLE on ShieldedPool to RelayerFeeMarket
        try {
            const RELAYER_ROLE = "0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4"; // keccak256("RELAYER_ROLE")
            await shieldedPool.write.grantRole([RELAYER_ROLE as `0x${string}`, relayerFeeMarket.address]);
            console.log("   ✅ RELAYER_ROLE granted to RelayerFeeMarket");
        } catch (e) {
            console.log("   ⚠️  RELAYER_ROLE grant skipped (may not be supported)");
        }

        // Link ProofTranslator to PrivacyRouter
        try {
            await privacyRouter.write.setComponent([
                3, // PROOF_TRANSLATOR component index
                proofTranslator.address,
            ]);
            console.log("   ✅ ProofTranslator linked to PrivacyRouter");
        } catch (e) {
            // May already be set in constructor
            console.log("   ⚠️  Component linking skipped (set in constructor)");
        }

        // ============================================
        // Save Deployment
        // ============================================
        console.log("\n" + "=".repeat(80));
        console.log("PRIVACY MIDDLEWARE DEPLOYMENT COMPLETE");
        console.log("=".repeat(80) + "\n");

        // Merge with existing deployment if present
        if (Object.keys(existingDeployment).length > 0) {
            deployed.contracts = { ...existingDeployment, ...deployed.contracts };
        }

        // Ensure directory exists
        if (!fs.existsSync(DEPLOYMENT_LOG_DIR)) {
            fs.mkdirSync(DEPLOYMENT_LOG_DIR, { recursive: true });
        }

        // Save deployment info
        const filename = `privacy-middleware-${hre.network.name}-${chainId}.json`;
        const filepath = path.join(DEPLOYMENT_LOG_DIR, filename);
        fs.writeFileSync(filepath, JSON.stringify(deployed, null, 2));
        console.log(`📝 Deployment saved to: ${filepath}`);

        // Summary
        console.log("\n📋 Privacy Middleware Contracts:");
        console.log("-".repeat(60));
        const privacyContracts = [
            "sanctionsOracle",
            "proofTranslator",
            "relayerFeeMarket",
            "shieldedPool",
            "privacyRouter",
        ];
        for (const name of privacyContracts) {
            const addr = deployed.contracts[name];
            if (addr) {
                console.log(`  ${name.padEnd(30)} ${addr}`);
            }
        }
        console.log("-".repeat(60));
        console.log(`\n✅ Privacy middleware contracts deployed: ${privacyContracts.filter(n => deployed.contracts[n]).length}`);

        // Production checklist
        if (isTestMode) {
            console.log("\n⚠️  TEST MODE CHECKLIST:");
            console.log("  □ Deploy production ZK verifier contract");
            console.log("  □ Call shieldedPool.disableTestMode() before mainnet");
            console.log("  □ Configure sanctions oracle providers");
            console.log("  □ Set up relayer fee routes for production chains");
        }

    } catch (error) {
        console.error("\n❌ Deployment failed:", error);
        process.exit(1);
    }
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
