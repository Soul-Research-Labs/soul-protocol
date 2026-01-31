import hre from "hardhat";
const { ethers } = hre as any;

async function main() {
  console.log("Starting Gas Profiling for Noir Migration...");

  // In a real run, these would be the deployed addresses
  const universalVerifierAddress = process.env.UNIVERSAL_VERIFIER || "0x...";
  const UniversalVerifier = await ethers.getContractAt("SoulUniversalVerifier", universalVerifierAddress);

  const proofTypes = [
    { name: "State Transfer", system: 1, typeHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("STATE_TRANSITION_PROOF")) },
    { name: "Commitment", system: 1, typeHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("COMMITMENT_PROOF")) },
    { name: "Cross Chain", system: 1, typeHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("CROSS_CHAIN_PROOF")) }
  ];

  console.log("Profiling results (Gas Units):");
  console.log("--------------------------------------------------");
  console.log("| Circuit          | Gas Used | Event Gas | Status |");
  console.log("--------------------------------------------------");

  for (const p of proofTypes) {
    try {
      // Mock data - would be replaced with actual proof/inputs from Noir
      const mockProof = "0x..."; 
      const mockInputs = "0x..."; 

      // Trigger verification
      // Note: This is an estimation/dry-run. For real profiling, one would send a tx.
      const tx = await (UniversalVerifier as any).verify({
        system: p.system,
        vkeyOrCircuitHash: p.typeHash,
        publicInputsHash: (ethers.utils as any).keccak256(mockInputs),
        proof: mockProof
      }, mockInputs);

      const receipt = await (tx as any).wait();
      
      // Extract GasUsed from event
      const event = (receipt.events as any[])?.find(e => e.event === "ProofVerified");
      const gasFromEvent = event?.args?.gasUsed || 0;

      console.log(`| ${p.name.padEnd(16)} | ${receipt.gasUsed.toString().padEnd(8)} | ${gasFromEvent.toString().padEnd(9)} | OK     |`);
    } catch (err: any) {
      console.log(`| ${p.name.padEnd(16)} | N/A      | N/A       | FAIL   |`);
    }
  }

  console.log("--------------------------------------------------");
  console.log("Note: Event Gas is the internal measurement; Gas Used is the total TX gas.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
