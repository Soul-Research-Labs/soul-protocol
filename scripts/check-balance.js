// Quick script to check deployer balance
const { ethers } = require("hardhat");

async function main() {
    const [signer] = await ethers.getSigners();
    const balance = await ethers.provider.getBalance(signer.address);
    
    console.log("Deployer:", signer.address);
    console.log("Balance:", ethers.formatEther(balance), "ETH");
    
    if (balance === 0n) {
        console.log("\n⚠️  No funds available!");
        console.log("Get Sepolia ETH from: https://sepoliafaucet.com");
    }
}

main().catch(console.error);
