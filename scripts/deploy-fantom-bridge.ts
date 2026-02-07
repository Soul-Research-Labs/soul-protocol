import hre from "hardhat";
import fs from "fs";
import path from "path";
import { formatEther, parseEther } from "viem";

/**
 * Soul Protocol - Fantom Bridge Adapter Deployment (Hardhat v3 / Viem)
 *
 * Deploys: MockWrappedFTM, MockLachesisVerifier, FantomBridgeAdapter
 */

const DEPLOYMENT_LOG_DIR = "./deployments";

async function main() {
    console.log("\n" + "=".repeat(70));
    console.log("  FANTOM BRIDGE ADAPTER DEPLOYMENT (Hardhat v3 / Viem)");
    console.log("=".repeat(70) + "\n");

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

    if (balance < parseEther("0.01")) {
        console.error("❌ Insufficient balance. Need at least 0.01 ETH.");
        process.exit(1);
    }

    const deployed: {
        network: string; chainId: number; deployer: string;
        timestamp: string; contracts: Record<string, string>;
    } = {
        network: hre.network.name, chainId, deployer: deployer.account.address,
        timestamp: new Date().toISOString(), contracts: {}
    };

    try {
        // 1. Deploy MockWrappedFTM
        console.log("1️⃣  Deploying MockWrappedFTM...");
        const wrappedFTM = await viem.deployContract("MockWrappedFTM");
        deployed.contracts.wrappedFTM = wrappedFTM.address;
        console.log("   ✅ MockWrappedFTM:", wrappedFTM.address);

        // 2. Deploy MockLachesisVerifier
        console.log("\n2️⃣  Deploying MockLachesisVerifier...");
        const lachesisVerifier = await viem.deployContract("MockLachesisVerifier");
        deployed.contracts.lachesisVerifier = lachesisVerifier.address;
        console.log("   ✅ MockLachesisVerifier:", lachesisVerifier.address);

        // 3. Deploy FantomBridgeAdapter
        console.log("\n3️⃣  Deploying FantomBridgeAdapter...");
        const bridge = await viem.deployContract("FantomBridgeAdapter", [deployer.account.address]);
        deployed.contracts.fantomBridgeAdapter = bridge.address;
        console.log("   ✅ FantomBridgeAdapter:", bridge.address);

        // 4. Configure the bridge adapter
        console.log("\n4️⃣  Configuring FantomBridgeAdapter...");
        await bridge.write.configure([bridge.address, wrappedFTM.address, lachesisVerifier.address, 2n, 1n]);
        console.log("   ✅ Bridge configured (minValidators=2, confirmations=1)");

        // 5. Set treasury
        console.log("\n5️⃣  Setting treasury...");
        await bridge.write.setTreasury([deployer.account.address]);
        console.log("   ✅ Treasury set to deployer");

        // 6. Grant RELAYER_ROLE
        console.log("\n6️⃣  Granting RELAYER_ROLE...");
        const RELAYER_ROLE = await bridge.read.RELAYER_ROLE();
        await bridge.write.grantRole([RELAYER_ROLE, deployer.account.address]);
        console.log("   ✅ RELAYER_ROLE granted to deployer");

        // Save deployment
        console.log("\n" + "=".repeat(70));
        console.log("  FANTOM BRIDGE DEPLOYMENT COMPLETE");
        console.log("=".repeat(70) + "\n");

        if (!fs.existsSync(DEPLOYMENT_LOG_DIR)) {
            fs.mkdirSync(DEPLOYMENT_LOG_DIR, { recursive: true });
        }

        const filename = `fantom-bridge-${hre.network.name}-${chainId}.json`;
        const filepath = path.join(DEPLOYMENT_LOG_DIR, filename);
        fs.writeFileSync(filepath, JSON.stringify(deployed, null, 2));
        console.log(`📝 Deployment saved to: ${filepath}`);

        console.log("\n📋 Deployed Contracts:");
        console.log("-".repeat(55));
        for (const [name, address] of Object.entries(deployed.contracts)) {
            console.log(`  ${name.padEnd(28)} ${address}`);
        }
        console.log("-".repeat(55));
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
