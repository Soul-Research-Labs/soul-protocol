import hre from "hardhat";
import { formatEther } from "viem";

async function main() {
    const { viem } = await hre.network.connect();
    const publicClient = await viem.getPublicClient();
    const [deployer] = await viem.getWalletClients();
    
    const balance = await publicClient.getBalance({ address: deployer.account.address });
    const chainId = await publicClient.getChainId();
    
    console.log("\n=== Wallet Balance Check ===");
    console.log("Address:", deployer.account.address);
    console.log("Chain ID:", chainId);
    console.log("Balance:", formatEther(balance), "ETH\n");
    
    if (balance < BigInt(1e16)) { // Less than 0.01 ETH
        console.log("⚠️  Warning: Balance is low for deployment.");
        console.log("   Get testnet ETH from:");
        console.log("   - https://sepoliafaucet.com");
        console.log("   - https://www.alchemy.com/faucets/ethereum-sepolia");
        console.log("   - https://cloud.google.com/application/web3/faucet/ethereum/sepolia");
    }
}

main().catch(console.error);
