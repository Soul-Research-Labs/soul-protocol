import { ethers } from "hardhat";

/**
 * Deploy script for ZilliqaBridgeAdapter
 *
 * Deploys:
 * 1. MockWrappedZIL (wZIL ERC-20, 12 decimals)
 * 2. MockZilliqaDSCommitteeOracle (DS committee attestation oracle)
 * 3. ZilliqaBridgeAdapter (main bridge contract)
 *
 * Configuration:
 * - 4 DS committee members with voting power 100 each
 * - 3 minimum DS signatures required (2/3+1 of committee)
 * - 30 TX block confirmations for finality
 * - Initial wZIL supply: 10M ZIL (in Qa)
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying Zilliqa Bridge with account:", deployer.address);

  // 1. Deploy MockWrappedZIL
  const MockWrappedZIL = await ethers.getContractFactory("MockWrappedZIL");
  const wZIL = await MockWrappedZIL.deploy();
  await wZIL.waitForDeployment();
  const wZILAddress = await wZIL.getAddress();
  console.log("MockWrappedZIL deployed to:", wZILAddress);

  // 2. Deploy MockZilliqaDSCommitteeOracle
  const MockOracle = await ethers.getContractFactory("MockZilliqaDSCommitteeOracle");
  const dsOracle = await MockOracle.deploy();
  await dsOracle.waitForDeployment();
  const dsOracleAddress = await dsOracle.getAddress();
  console.log("MockZilliqaDSCommitteeOracle deployed to:", dsOracleAddress);

  // 3. Deploy ZilliqaBridgeAdapter
  const ZilliqaBridge = await ethers.getContractFactory("ZilliqaBridgeAdapter");
  const bridge = await ZilliqaBridge.deploy(deployer.address);
  await bridge.waitForDeployment();
  const bridgeAddress = await bridge.getAddress();
  console.log("ZilliqaBridgeAdapter deployed to:", bridgeAddress);

  // 4. Setup DS committee members
  const dsMembers = [
    { address: "0x0000000000000000000000000000000000003001", votingPower: 100 },
    { address: "0x0000000000000000000000000000000000003002", votingPower: 100 },
    { address: "0x0000000000000000000000000000000000003003", votingPower: 100 },
    { address: "0x0000000000000000000000000000000000003004", votingPower: 100 },
  ];

  for (const member of dsMembers) {
    const tx = await dsOracle.addDSMember(member.address, member.votingPower);
    await tx.wait();
    console.log(`Added DS member ${member.address} with voting power ${member.votingPower}`);
  }

  // 5. Configure bridge
  const MIN_DS_SIGNATURES = 3;
  const REQUIRED_TX_BLOCK_CONFIRMATIONS = 30;

  const configureTx = await bridge.configure(
    "0x0000000000000000000000000000000000000001", // Placeholder Zilliqa bridge contract
    wZILAddress,
    dsOracleAddress,
    MIN_DS_SIGNATURES,
    REQUIRED_TX_BLOCK_CONFIRMATIONS
  );
  await configureTx.wait();
  console.log("Bridge configured");

  // 6. Set treasury
  const treasuryTx = await bridge.setTreasury(deployer.address);
  await treasuryTx.wait();
  console.log("Treasury set to deployer");

  // 7. Mint initial wZIL supply to bridge (10M ZIL in Qa)
  const QA_PER_ZIL = 1_000_000_000_000n;
  const INITIAL_SUPPLY = 10_000_000n * QA_PER_ZIL;
  const mintTx = await wZIL.mint(bridgeAddress, INITIAL_SUPPLY);
  await mintTx.wait();
  console.log(`Minted ${INITIAL_SUPPLY} Qa (10M ZIL) to bridge`);

  console.log("\n=== Zilliqa Bridge Deployment Summary ===");
  console.log(`wZIL Token:        ${wZILAddress}`);
  console.log(`DS Committee Oracle: ${dsOracleAddress}`);
  console.log(`Bridge Adapter:    ${bridgeAddress}`);
  console.log(`DS Members:        ${dsMembers.length}`);
  console.log(`Min DS Signatures: ${MIN_DS_SIGNATURES}`);
  console.log(`TX Block Confirms: ${REQUIRED_TX_BLOCK_CONFIRMATIONS}`);
  console.log("==========================================");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
