import { ethers } from "hardhat";

async function main() {
  const registryAddress = "0x..."; // Soul Registry Address
  const Registry = await ethers.getContractAt("VerifierRegistry", registryAddress);

  // Take parameters from environment or defaults
  const proofTypeName = process.env.PROOF_TYPE || "STATE_TRANSITION_PROOF";
  const version = parseInt(process.env.VERSION || "1");

  const proofType = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(proofTypeName));

  console.log(`Switching ${proofTypeName} to version ${version}...`);
  
  const tx = await Registry.switchVersion(proofType, version);
  await tx.wait();

  console.log(`Action complete. ${proofTypeName} is now at version ${version}.`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
