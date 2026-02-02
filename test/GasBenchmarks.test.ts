import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, toHex, zeroHash, hexToBigInt } from "viem";

/**
 * Gas Benchmark Tests for Hardhat v3 (viem)
 */
describe("Gas Benchmarks (viem)", function () {
  this.timeout(180000);

  describe("State Registration Gas", function () {
    it("Should measure single state registration gas", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();

      const txHash = await stateContainer.write.registerState([
        toHex(toBytes("gas_test_state")),
        keccak256(toBytes("gas_commit")),
        keccak256(toBytes("gas_null")),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      console.log(`    State registration gas: ${receipt.gasUsed}`);
      expect(Number(receipt.gasUsed)).to.be.lessThan(500000);
    });

    it("Should measure gas scaling with state size", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();

      const sizes = [32, 64, 128, 256, 512];
      const gasResults: { size: number; gas: bigint }[] = [];

      for (let i = 0; i < sizes.length; i++) {
        const size = sizes[i];
        const state = toHex(new Uint8Array(size).fill(0x42));

        const txHash = await stateContainer.write.registerState([
          state,
          keccak256(toBytes(`size_commit_${i}`)),
          keccak256(toBytes(`size_null_${i}`)),
          toHex(toBytes("proof")),
          zeroHash
        ], { account: user1.account });

        const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
        gasResults.push({ size, gas: receipt.gasUsed });
      }

      console.log("    Gas by state size:");
      for (const { size, gas } of gasResults) {
        console.log(`      ${size} bytes: ${gas} gas`);
      }

      // Gas should scale roughly linearly
      const ratio = Number(gasResults[gasResults.length - 1].gas) / Number(gasResults[0].gas);
      expect(ratio).to.be.lessThan(5);
    });
  });

  describe("Nullifier Registration Gas", function () {
    it("Should measure single nullifier registration gas", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();

      const txHash = await nullifierRegistry.write.registerNullifier([
        keccak256(toBytes("gas_null")),
        zeroHash
      ], { account: owner.account });

      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      console.log(`    Nullifier registration gas: ${receipt.gasUsed}`);
      // First registration includes Merkle tree initialization which uses more gas
      expect(Number(receipt.gasUsed)).to.be.lessThan(1500000);
    });

    it("Should measure batch nullifier registration gas", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();

      const batchSizes = [1, 5, 10, 15, 20];

      for (const batchSize of batchSizes) {
        // Deploy fresh registry for each test
        const registry = await viem.deployContract("NullifierRegistryV3");

        const nullifiers: `0x${string}`[] = [];
        const commitments: `0x${string}`[] = [];

        for (let i = 0; i < batchSize; i++) {
          nullifiers.push(keccak256(toBytes(`batch_${batchSize}_null_${i}`)));
          commitments.push(keccak256(toBytes(`batch_${batchSize}_commit_${i}`)));
        }

        const txHash = await registry.write.batchRegisterNullifiers([nullifiers, commitments], { account: owner.account });
        const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });

        console.log(`    Batch ${batchSize} nullifiers: ${receipt.gasUsed} gas (${Number(receipt.gasUsed) / batchSize} per item)`);
      }
    });
  });

  describe("Cross-Chain Proof Gas", function () {
    it("Should measure proof submission gas", async function () {
      const { viem } = await hre.network.connect();
      
      const proofHub = await viem.deployContract("CrossChainProofHubV3");
      const [owner, relayer] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();

      // Setup
      await proofHub.write.addSupportedChain([1n], { account: owner.account });
      await proofHub.write.addSupportedChain([137n], { account: owner.account });

      const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
      await proofHub.write.grantRole([RELAYER_ROLE, relayer.account.address], { account: owner.account });
      await proofHub.write.confirmRoleSeparation({ account: owner.account });
      await proofHub.write.depositStake({ account: relayer.account, value: BigInt(1e18) });

      const txHash = await proofHub.write.submitProof([
        toHex(toBytes("proof_data")),
        toHex(toBytes("public_inputs")),
        keccak256(toBytes("gas_commitment")),
        1n,
        137n,
      ], { account: relayer.account, value: BigInt(1e15) });

      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      console.log(`    Proof submission gas: ${receipt.gasUsed}`);
      expect(Number(receipt.gasUsed)).to.be.lessThan(500000);
    });
  });

  describe("Read Operations Gas", function () {
    it("Should verify view functions are efficient", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      // Register a state
      const commitment = keccak256(toBytes("view_test_commit"));
      await stateContainer.write.registerState([
        toHex(toBytes("view_test_state")),
        commitment,
        keccak256(toBytes("view_test_null")),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      // View functions should be fast
      const startTime = Date.now();
      for (let i = 0; i < 100; i++) {
        await stateContainer.read.isStateActive([commitment]);
        await stateContainer.read.totalStates();
      }
      const endTime = Date.now();

      console.log(`    100 view calls: ${endTime - startTime}ms`);
      expect(endTime - startTime).to.be.lessThan(5000);
    });
  });
});
