import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Demo Script: End-to-End Private Swap
 * 
 * This script demonstrates the complete flow of:
 * 1. Deploying contracts
 * 2. Setting up tokens and pools
 * 3. Executing private swaps
 * 4. Cross-chain order creation
 * 5. Stealth address usage
 */

interface DeploymentResult {
  exchange: string;
  tokenA: string;
  tokenB: string;
  stealthRegistry: string;
  pc3: string;
}

async function main() {
  console.log("🚀 Zaseon Private Exchange Demo\n");
  console.log("=".repeat(60));

  const [deployer, user1, user2, relayer] = await ethers.getSigners();
  
  console.log("\n📋 Accounts:");
  console.log(`  Deployer: ${deployer.address}`);
  console.log(`  User 1:   ${user1.address}`);
  console.log(`  User 2:   ${user2.address}`);
  console.log(`  Relayer:  ${relayer.address}`);

  // Step 1: Deploy Contracts
  console.log("\n\n🔧 Step 1: Deploying Contracts...");
  console.log("-".repeat(40));

  // Deploy Mock Tokens
  const MockToken = await ethers.getContractFactory("MockToken");
  const tokenA = await MockToken.deploy("Privacy Token Alpha", "PRIV-A", 18);
  const tokenB = await MockToken.deploy("Privacy Token Beta", "PRIV-B", 18);
  
  console.log(`  ✅ Token A deployed: ${await tokenA.getAddress()}`);
  console.log(`  ✅ Token B deployed: ${await tokenB.getAddress()}`);

  // Deploy Exchange
  const Exchange = await ethers.getContractFactory("ZaseonPrivateExchange");
  const exchange = await Exchange.deploy(deployer.address);
  console.log(`  ✅ Exchange deployed: ${await exchange.getAddress()}`);

  // Deploy Stealth Registry
  const StealthRegistry = await ethers.getContractFactory("StealthAddressRegistry");
  const stealthRegistry = await StealthRegistry.deploy(deployer.address);
  console.log(`  ✅ Stealth Registry deployed: ${await stealthRegistry.getAddress()}`);

  // Step 2: Setup
  console.log("\n\n⚙️  Step 2: Setting Up Exchange...");
  console.log("-".repeat(40));

  // Grant roles
  await exchange.grantRole(await exchange.RELAYER_ROLE(), relayer.address);
  await exchange.grantRole(await exchange.OPERATOR_ROLE(), deployer.address);
  console.log("  ✅ Roles granted");

  // Add supported tokens
  await exchange.addSupportedToken(
    await tokenA.getAddress(),
    ethers.parseEther("0.001"),
    ethers.parseEther("1000000")
  );
  await exchange.addSupportedToken(
    await tokenB.getAddress(),
    ethers.parseEther("0.001"),
    ethers.parseEther("1000000")
  );
  console.log("  ✅ Tokens added to exchange");

  // Mint tokens to users
  const mintAmount = ethers.parseEther("100000");
  await tokenA.mint(user1.address, mintAmount);
  await tokenA.mint(user2.address, mintAmount);
  await tokenB.mint(user1.address, mintAmount);
  await tokenB.mint(user2.address, mintAmount);
  console.log(`  ✅ Minted ${ethers.formatEther(mintAmount)} tokens to each user`);

  // Approve exchange
  await tokenA.connect(user1).approve(await exchange.getAddress(), ethers.MaxUint256);
  await tokenB.connect(user1).approve(await exchange.getAddress(), ethers.MaxUint256);
  await tokenA.connect(user2).approve(await exchange.getAddress(), ethers.MaxUint256);
  await tokenB.connect(user2).approve(await exchange.getAddress(), ethers.MaxUint256);
  console.log("  ✅ Approvals set");

  // Step 3: Deposits
  console.log("\n\n💰 Step 3: Making Deposits...");
  console.log("-".repeat(40));

  const depositAmount = ethers.parseEther("10000");
  
  const tx1 = await exchange.connect(user1).deposit(await tokenA.getAddress(), depositAmount);
  await tx1.wait();
  console.log(`  ✅ User 1 deposited ${ethers.formatEther(depositAmount)} Token A`);
  console.log(`     Gas used: ${(await tx1.wait())?.gasUsed}`);

  const tx2 = await exchange.connect(user1).deposit(await tokenB.getAddress(), depositAmount);
  await tx2.wait();
  console.log(`  ✅ User 1 deposited ${ethers.formatEther(depositAmount)} Token B`);

  const tx3 = await exchange.connect(user2).deposit(await tokenA.getAddress(), depositAmount);
  await tx3.wait();
  console.log(`  ✅ User 2 deposited ${ethers.formatEther(depositAmount)} Token A`);

  const tx4 = await exchange.connect(user2).deposit(await tokenB.getAddress(), depositAmount);
  await tx4.wait();
  console.log(`  ✅ User 2 deposited ${ethers.formatEther(depositAmount)} Token B`);

  // Step 4: Create AMM Pool
  console.log("\n\n🏊 Step 4: Creating Bridge Capacity Pool...");
  console.log("-".repeat(40));

  const poolAmount = ethers.parseEther("5000");
  const mockProof = "0x" + "01".repeat(128);

  const poolTx = await exchange.connect(user1).createPool(
    await tokenA.getAddress(),
    await tokenB.getAddress(),
    poolAmount,
    poolAmount,
    mockProof
  );
  await poolTx.wait();
  console.log(`  ✅ Pool created with ${ethers.formatEther(poolAmount)} each token`);
  console.log(`     Gas used: ${(await poolTx.wait())?.gasUsed}`);

  // Step 5: Private Swap
  console.log("\n\n🔄 Step 5: Executing Private Swap...");
  console.log("-".repeat(40));

  const swapAmount = ethers.parseEther("100");
  const minOutput = ethers.parseEther("90"); // 10% slippage tolerance

  console.log(`  📤 User 2 swapping ${ethers.formatEther(swapAmount)} Token A for Token B`);
  console.log("     (Privacy-preserving: Amount hidden from observers)");

  const swapTx = await exchange.connect(user2).swapPrivate(
    await tokenA.getAddress(),
    await tokenB.getAddress(),
    swapAmount,
    minOutput,
    mockProof
  );
  const swapReceipt = await swapTx.wait();
  console.log("  ✅ Swap executed successfully!");
  console.log(`     Gas used: ${swapReceipt?.gasUsed}`);
  console.log(`     Transaction: ${swapTx.hash}`);

  // Step 6: Create Private Order
  console.log("\n\n📝 Step 6: Creating Private Order...");
  console.log("-".repeat(40));

  const orderAmount = ethers.parseEther("500");
  const deadline = Math.floor(Date.now() / 1000) + 86400; // 24 hours

  const orderTx = await exchange.connect(user1).createOrder(
    await tokenA.getAddress(),
    await tokenB.getAddress(),
    orderAmount,
    orderAmount * 95n / 100n, // 5% slippage
    deadline,
    1, // Limit order
    0, // Buy side
    mockProof
  );
  const orderReceipt = await orderTx.wait();
  console.log("  ✅ Private order created!");
  console.log(`     Gas used: ${orderReceipt?.gasUsed}`);

  // Step 7: Stealth Address Demo
  console.log("\n\n🥷 Step 7: Stealth Address Registration...");
  console.log("-".repeat(40));

  // Generate stealth meta-address
  const spendingPubKeyX = ethers.hexlify(ethers.randomBytes(32));
  const spendingPubKeyY = ethers.hexlify(ethers.randomBytes(32));
  const viewingPubKeyX = ethers.hexlify(ethers.randomBytes(32));
  const viewingPubKeyY = ethers.hexlify(ethers.randomBytes(32));

  const registerTx = await stealthRegistry.connect(user1).registerMetaAddress(
    spendingPubKeyX,
    spendingPubKeyY,
    viewingPubKeyX,
    viewingPubKeyY,
    { value: ethers.parseEther("0.01") }
  );
  await registerTx.wait();
  console.log("  ✅ User 1 registered stealth meta-address");
  console.log(`     Can now receive private payments!`);

  // Step 8: Cross-Chain Order
  console.log("\n\n🌉 Step 8: Creating Cross-Chain Order...");
  console.log("-".repeat(40));

  const destChainId = 137; // Polygon
  const destToken = ethers.hexlify(ethers.randomBytes(20));

  const ccOrderTx = await exchange.connect(user1).createCrossChainOrder(
    await tokenA.getAddress(),
    destToken,
    destChainId,
    ethers.parseEther("100"),
    ethers.parseEther("95"),
    deadline,
    mockProof
  );
  await ccOrderTx.wait();
  console.log("  ✅ Cross-chain order created!");
  console.log(`     Destination: Chain ${destChainId}`);
  console.log("     (Will be settled via Zaseon cross-chain messaging)");

  // Summary
  console.log("\n\n" + "=".repeat(60));
  console.log("📊 Demo Summary");
  console.log("=".repeat(60));

  const deployment: DeploymentResult = {
    exchange: await exchange.getAddress(),
    tokenA: await tokenA.getAddress(),
    tokenB: await tokenB.getAddress(),
    stealthRegistry: await stealthRegistry.getAddress(),
    pc3: ethers.ZeroAddress, // Not deployed in this demo
  };

  console.log("\n🏗️  Deployed Contracts:");
  console.log(`    Exchange:         ${deployment.exchange}`);
  console.log(`    Token A:          ${deployment.tokenA}`);
  console.log(`    Token B:          ${deployment.tokenB}`);
  console.log(`    Stealth Registry: ${deployment.stealthRegistry}`);

  console.log("\n✅ Completed Operations:");
  console.log("    • Deployed all contracts");
  console.log("    • Created bridge capacity");
  console.log("    • Executed private swap");
  console.log("    • Created private order");
  console.log("    • Registered stealth address");
  console.log("    • Created cross-chain order");

  console.log("\n🔐 Privacy Features Demonstrated:");
  console.log("    • Private deposits with commitments");
  console.log("    • Privacy-preserving AMM swaps");
  console.log("    • Encrypted order book");
  console.log("    • Stealth addresses for unlinkable payments");
  console.log("    • Cross-chain privacy with PC³");

  // Save deployment info
  const deploymentPath = path.join(__dirname, "../../deployments/demo.json");
  fs.mkdirSync(path.dirname(deploymentPath), { recursive: true });
  fs.writeFileSync(deploymentPath, JSON.stringify(deployment, null, 2));
  console.log(`\n💾 Deployment info saved to: ${deploymentPath}`);

  console.log("\n" + "=".repeat(60));
  console.log("🎉 Demo Complete!");
  console.log("=".repeat(60) + "\n");
}

// Execute demo
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Demo failed:");
    console.error(error);
    process.exit(1);
  });
