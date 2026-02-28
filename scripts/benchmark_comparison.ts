import hre from "hardhat";
import { expect } from "chai";
import { keccak256, toBytes, toHex, zeroAddress } from "viem";

/**
 * @title Noir Gas Benchmark Comparison
 * @notice Compares legacy Groth16 verifiers vs new Noir Adapters
 */
async function main() {
    console.log("=== ZASEON: Gas Benchmark Comparison ===");
    
    // 1. Setup Infrastructure
    const { viem } = hre as any;
    const [deployer] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    console.log("Deploying testing infrastructure...");
    
    // Deploy Universal Verifier
    const universalVerifier = await viem.deployContract("ZaseonUniversalVerifier");
    
    // Deploy Mocks
    const mockGroth16 = await viem.deployContract("MockNoirVerifier"); // Reuse mock as it has simple verify()
    const mockNoir = await viem.deployContract("MockNoirVerifier");
    
    // Deploy Adapter
    const stateTransferAdapter = await viem.deployContract("StateTransferAdapter", [mockNoir.address]);
    
    // 2. Benchmarking Legacy (Simulated via Adapter for fair comparison)
    // We want to measure the adapter's overhead + verifier call
    console.log("\n--- Benchmarking State Transfer ---");
    
    const signals = [1n, 123n, 456n, 789n, 1011n, 1213n, 1415n]; // 7 signals
    const lenHex = "0000000000000000000000000000000000000000000000000000000000000007";
    const publicInputs = "0x" + lenHex + signals.map(s => s.toString(16).padStart(64, '0')).join("");
    const proof = "0x" + "00".repeat(256); // Dummy proof

    // Noir Check
    const noirStart = Date.now();
    const txNoir = await stateTransferAdapter.write.verify([zeroAddress, proof, publicInputs]);
    const receiptNoir = await publicClient.waitForTransactionReceipt({ hash: txNoir });
    const noirEnd = Date.now();

    console.log(`Noir Adapter Gas Used: ${receiptNoir.gasUsed.toString()}`);
    console.log(`Execution Time: ${noirEnd - noirStart}ms`);

    // 3. Comparison with legacy method
    // If we had a real Groth16 verifier, we'd call verifyProof(uint[2], ...)
    // But here we measure the adapter's conversion cost
    
    console.log("\n--- Benchmarking Batch Call Compatibility ---");
    const txBatch = await universalVerifier.write.verify([
        {
            system: 2, // Noir
            vkeyOrCircuitHash: zeroAddress,
            publicInputsHash: keccak256(publicInputs),
            proof: proof
        },
        publicInputs
    ]);
    const receiptBatch = await publicClient.waitForTransactionReceipt({ hash: txBatch });
    console.log(`Universal Verifier (Noir) Gas: ${receiptBatch.gasUsed.toString()}`);

    console.log("\n=== Benchmarking complete ===");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
