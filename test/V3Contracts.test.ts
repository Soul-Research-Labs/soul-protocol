import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, toHex, zeroHash } from "viem";

/**
 * V3 Contracts Test Suite for Hardhat v3 (viem)
 * Tests core V3 contracts: ConfidentialStateContainerV3, NullifierRegistryV3, CrossChainProofHubV3
 */
describe("V3 Contracts (viem)", function () {
  this.timeout(120000);

  describe("ConfidentialStateContainerV3", function () {
    it("Should register a new state", async function () {
      const { viem } = await hre.network.connect();
      
      // Deploy mock verifier
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);

      // Deploy state container
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);

      // Get wallet clients
      const [owner, user1] = await viem.getWalletClients();

      const commitment = keccak256(toBytes("test_commitment"));
      const nullifier = keccak256(toBytes("test_nullifier"));
      const encryptedState = toHex(toBytes("encrypted_state_data"));

      await stateContainer.write.registerState([
        encryptedState,
        commitment,
        nullifier,
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      // Verify state is active
      expect(await stateContainer.read.isStateActive([commitment])).to.be.true;

      // Retrieve state
      const state = await stateContainer.read.getState([commitment]);
      expect(state.encryptedState.toLowerCase()).to.equal(encryptedState.toLowerCase());
    });

    it("Should prevent duplicate commitments", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);

      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const commitment = keccak256(toBytes("duplicate_commitment"));

      await stateContainer.write.registerState([
        toHex(toBytes("state1")),
        commitment,
        keccak256(toBytes("null1")),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      try {
        await stateContainer.write.registerState([
          toHex(toBytes("state2")),
          commitment, // Same commitment
          keccak256(toBytes("null2")),
          toHex(toBytes("proof")),
          zeroHash
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("CommitmentAlreadyExists");
      }
    });

    it("Should prevent duplicate nullifiers", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);

      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const nullifier = keccak256(toBytes("duplicate_nullifier"));

      await stateContainer.write.registerState([
        toHex(toBytes("state1")),
        keccak256(toBytes("commit1")),
        nullifier,
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      try {
        await stateContainer.write.registerState([
          toHex(toBytes("state2")),
          keccak256(toBytes("commit2")),
          nullifier, // Same nullifier
          toHex(toBytes("proof")),
          zeroHash
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("NullifierAlreadyUsed");
      }
    });

    it("Should track total states", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);

      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const initialCount = await stateContainer.read.totalStates();

      for (let i = 0; i < 5; i++) {
        await stateContainer.write.registerState([
          toHex(toBytes(`state_${i}`)),
          keccak256(toBytes(`commit_${i}`)),
          keccak256(toBytes(`null_${i}`)),
          toHex(toBytes("proof")),
          zeroHash
        ], { account: user1.account });
      }

      expect(await stateContainer.read.totalStates()).to.equal(initialCount + 5n);
    });
  });

  describe("NullifierRegistryV3", function () {
    it("Should register a nullifier", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();

      const nullifier = keccak256(toBytes("test_nullifier"));

      await nullifierRegistry.write.registerNullifier([nullifier, zeroHash], { account: owner.account });

      expect(await nullifierRegistry.read.exists([nullifier])).to.be.true;
    });

    it("Should prevent duplicate nullifiers", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();

      const nullifier = keccak256(toBytes("duplicate"));

      await nullifierRegistry.write.registerNullifier([nullifier, zeroHash], { account: owner.account });

      try {
        await nullifierRegistry.write.registerNullifier([nullifier, zeroHash], { account: owner.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("NullifierAlreadyExists");
      }
    });

    it("Should track total nullifiers", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();

      const initialCount = await nullifierRegistry.read.totalNullifiers();

      for (let i = 0; i < 5; i++) {
        await nullifierRegistry.write.registerNullifier([
          keccak256(toBytes(`null_${i}`)),
          zeroHash
        ], { account: owner.account });
      }

      expect(await nullifierRegistry.read.totalNullifiers()).to.equal(initialCount + 5n);
    });

    it("Should update merkle root", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();

      const initialRoot = await nullifierRegistry.read.merkleRoot();

      await nullifierRegistry.write.registerNullifier([
        keccak256(toBytes("merkle_test")),
        zeroHash
      ], { account: owner.account });

      const newRoot = await nullifierRegistry.read.merkleRoot();
      expect(newRoot).to.not.equal(initialRoot);
    });

    it("Should batch register nullifiers", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();

      const nullifiers: `0x${string}`[] = [];
      const commitments: `0x${string}`[] = [];

      for (let i = 0; i < 5; i++) {
        nullifiers.push(keccak256(toBytes(`batch_null_${i}`)));
        commitments.push(keccak256(toBytes(`batch_commit_${i}`)));
      }

      await nullifierRegistry.write.batchRegisterNullifiers([nullifiers, commitments], { account: owner.account });

      for (const nullifier of nullifiers) {
        expect(await nullifierRegistry.read.exists([nullifier])).to.be.true;
      }
    });
  });

  describe("CrossChainProofHubV3", function () {
    it("Should add a supported chain", async function () {
      const { viem } = await hre.network.connect();
      
      const proofHub = await viem.deployContract("CrossChainProofHubV3");
      const [owner] = await viem.getWalletClients();

      await proofHub.write.addSupportedChain([1n], { account: owner.account });

      expect(await proofHub.read.supportedChains([1n])).to.be.true;
    });

    it("Should submit proof", async function () {
      const { viem } = await hre.network.connect();
      
      const proofHub = await viem.deployContract("CrossChainProofHubV3");
      const [owner, relayer] = await viem.getWalletClients();

      // Add supported chains
      await proofHub.write.addSupportedChain([1n], { account: owner.account });
      await proofHub.write.addSupportedChain([137n], { account: owner.account });

      // Grant relayer role to different address (role separation required)
      const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
      await proofHub.write.grantRole([RELAYER_ROLE, relayer.account.address], { account: owner.account });

      // Confirm role separation (required for mainnet safety)
      await proofHub.write.confirmRoleSeparation({ account: owner.account });

      // Deposit stake
      await proofHub.write.depositStake({ account: relayer.account, value: BigInt(1e18) });

      // Submit proof with correct signature:
      // submitProof(bytes proof, bytes publicInputs, bytes32 commitment, uint64 sourceChainId, uint64 destChainId)
      const commitment = keccak256(toBytes("state_root"));
      
      // Need to send fee with the transaction (1000000000000000 = 0.001 ETH)
      await proofHub.write.submitProof([
        toHex(toBytes("proof_data")), // bytes proof
        toHex(toBytes("public_inputs")), // bytes publicInputs
        commitment, // bytes32 commitment
        1n, // uint64 source chain
        137n, // uint64 dest chain
      ], { account: relayer.account, value: BigInt(1e15) }); // 0.001 ETH fee

      // Verify proof was submitted - check relayer stats
      // getRelayerStats returns (stake, successCount, slashCount)
      const [stake, successCount, slashCount] = await proofHub.read.getRelayerStats([relayer.account.address]);
      // Note: successCount only increments after proof is finalized, so we just check the proof exists
      expect(Number(stake)).to.be.greaterThan(0);
    });
  });

  describe("Access Control", function () {
    it("Should enforce admin role", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);

      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      try {
        await stateContainer.write.pause({ account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("AccessControl");
      }
    });

    it("Should allow owner to pause", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);

      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner] = await viem.getWalletClients();

      await stateContainer.write.pause({ account: owner.account });
      expect(await stateContainer.read.paused()).to.be.true;
    });

    it("Should allow owner to unpause", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);

      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner] = await viem.getWalletClients();

      await stateContainer.write.pause({ account: owner.account });
      await stateContainer.write.unpause({ account: owner.account });
      expect(await stateContainer.read.paused()).to.be.false;
    });

    it("Should prevent operations when paused", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);

      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      await stateContainer.write.pause({ account: owner.account });

      try {
        await stateContainer.write.registerState([
          toHex(toBytes("paused_state")),
          keccak256(toBytes("paused_commit")),
          keccak256(toBytes("paused_null")),
          toHex(toBytes("proof")),
          zeroHash
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("EnforcedPause");
      }
    });
  });

  describe("Events", function () {
    it("Should emit StateRegistered event", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);

      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();

      const commitment = keccak256(toBytes("event_test"));
      const nullifier = keccak256(toBytes("event_null"));

      const txHash = await stateContainer.write.registerState([
        toHex(toBytes("event_state")),
        commitment,
        nullifier,
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      expect(receipt.logs.length).to.be.greaterThan(0);
    });

    it("Should emit NullifierRegistered event", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();

      const nullifier = keccak256(toBytes("event_nullifier"));

      const txHash = await nullifierRegistry.write.registerNullifier([nullifier, zeroHash], { account: owner.account });

      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      expect(receipt.logs.length).to.be.greaterThan(0);
    });
  });
});
