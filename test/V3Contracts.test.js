const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

describe("V3 Core Contracts", function () {
  // Mock verifier that always returns true
  async function deployMockVerifier() {
    const MockVerifier = await ethers.getContractFactory("MockProofVerifier");
    return await MockVerifier.deploy();
  }

  // Deploy V3 contracts fixture
  async function deployV3Fixture() {
    const [owner, operator, user1, user2, relayer, challenger] = await ethers.getSigners();

    const mockVerifier = await deployMockVerifier();

    const ConfidentialStateContainerV3 = await ethers.getContractFactory("ConfidentialStateContainerV3");
    const stateContainer = await ConfidentialStateContainerV3.deploy(await mockVerifier.getAddress());

    const NullifierRegistryV3 = await ethers.getContractFactory("NullifierRegistryV3");
    const nullifierRegistry = await NullifierRegistryV3.deploy();

    const CrossChainProofHubV3 = await ethers.getContractFactory("CrossChainProofHubV3");
    const proofHub = await CrossChainProofHubV3.deploy();

    return {
      stateContainer,
      nullifierRegistry,
      proofHub,
      mockVerifier,
      owner,
      operator,
      user1,
      user2,
      relayer,
      challenger
    };
  }

  describe("ConfidentialStateContainerV3", function () {
    it("Should deploy with correct roles", async function () {
      const { stateContainer, owner } = await loadFixture(deployV3Fixture);

      const DEFAULT_ADMIN_ROLE = await stateContainer.DEFAULT_ADMIN_ROLE();
      const OPERATOR_ROLE = await stateContainer.OPERATOR_ROLE();
      const EMERGENCY_ROLE = await stateContainer.EMERGENCY_ROLE();

      expect(await stateContainer.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be.true;
      expect(await stateContainer.hasRole(OPERATOR_ROLE, owner.address)).to.be.true;
      expect(await stateContainer.hasRole(EMERGENCY_ROLE, owner.address)).to.be.true;
    });

    it("Should register state successfully", async function () {
      const { stateContainer, user1 } = await loadFixture(deployV3Fixture);

      const encryptedState = ethers.toUtf8Bytes("encrypted_data_123");
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment1"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier1"));
      const proof = ethers.toUtf8Bytes("proof_data");
      const publicInputs = ethers.toUtf8Bytes("public_inputs");
      const metadata = ethers.ZeroHash;

      await expect(stateContainer.connect(user1).registerState(
        encryptedState,
        commitment,
        nullifier,
        proof,
        publicInputs,
        metadata
      )).to.emit(stateContainer, "StateRegistered");
      
      // Verify state was registered
      expect(await stateContainer.totalStates()).to.equal(1);
      expect(await stateContainer.nullifiers(nullifier)).to.be.true;
    });

    it("Should prevent duplicate nullifiers", async function () {
      const { stateContainer, user1 } = await loadFixture(deployV3Fixture);

      const encryptedState = ethers.toUtf8Bytes("encrypted_data");
      const commitment1 = ethers.keccak256(ethers.toUtf8Bytes("commitment1"));
      const commitment2 = ethers.keccak256(ethers.toUtf8Bytes("commitment2"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier"));
      const proof = ethers.toUtf8Bytes("proof");
      const publicInputs = ethers.toUtf8Bytes("inputs");

      await stateContainer.connect(user1).registerState(
        encryptedState, commitment1, nullifier, proof, publicInputs, ethers.ZeroHash
      );

      await expect(stateContainer.connect(user1).registerState(
        encryptedState, commitment2, nullifier, proof, publicInputs, ethers.ZeroHash
      )).to.be.revertedWithCustomError(stateContainer, "NullifierAlreadyUsed");
    });

    it("Should transfer state correctly", async function () {
      const { stateContainer, user1, user2 } = await loadFixture(deployV3Fixture);

      const encryptedState = ethers.toUtf8Bytes("state_v1");
      const commitment1 = ethers.keccak256(ethers.toUtf8Bytes("commitment1"));
      const nullifier1 = ethers.keccak256(ethers.toUtf8Bytes("nullifier1"));
      const proof = ethers.toUtf8Bytes("proof");
      const publicInputs = ethers.toUtf8Bytes("inputs");

      await stateContainer.connect(user1).registerState(
        encryptedState, commitment1, nullifier1, proof, publicInputs, ethers.ZeroHash
      );

      const newEncryptedState = ethers.toUtf8Bytes("state_v2");
      const commitment2 = ethers.keccak256(ethers.toUtf8Bytes("commitment2"));
      const nullifier2 = ethers.keccak256(ethers.toUtf8Bytes("nullifier2"));

      await expect(stateContainer.connect(user1).transferState(
        commitment1,
        newEncryptedState,
        commitment2,
        nullifier2,
        proof,
        publicInputs,
        user2.address
      )).to.emit(stateContainer, "StateTransferred")
        .withArgs(commitment1, commitment2, user2.address, 2);

      // Old state should be retired
      const oldState = await stateContainer.getState(commitment1);
      expect(oldState.status).to.equal(3); // Retired

      // New state should be active
      const newState = await stateContainer.getState(commitment2);
      expect(newState.status).to.equal(0); // Active
      expect(newState.owner).to.equal(user2.address);
    });

    it("Should lock and unlock state", async function () {
      const { stateContainer, owner, user1 } = await loadFixture(deployV3Fixture);

      const encryptedState = ethers.toUtf8Bytes("state");
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier"));
      const proof = ethers.toUtf8Bytes("proof");
      const publicInputs = ethers.toUtf8Bytes("inputs");

      await stateContainer.connect(user1).registerState(
        encryptedState, commitment, nullifier, proof, publicInputs, ethers.ZeroHash
      );

      // Lock the state
      await stateContainer.connect(owner).lockState(commitment);
      let state = await stateContainer.getState(commitment);
      expect(state.status).to.equal(1); // Locked

      // Unlock the state
      await stateContainer.connect(owner).unlockState(commitment);
      state = await stateContainer.getState(commitment);
      expect(state.status).to.equal(0); // Active
    });

    it("Should pause and unpause", async function () {
      const { stateContainer, owner, user1 } = await loadFixture(deployV3Fixture);

      await stateContainer.connect(owner).pause();
      
      const encryptedState = ethers.toUtf8Bytes("state");
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier"));
      const proof = ethers.toUtf8Bytes("proof");
      const publicInputs = ethers.toUtf8Bytes("inputs");

      await expect(stateContainer.connect(user1).registerState(
        encryptedState, commitment, nullifier, proof, publicInputs, ethers.ZeroHash
      )).to.be.revertedWithCustomError(stateContainer, "EnforcedPause");

      await stateContainer.connect(owner).unpause();

      await expect(stateContainer.connect(user1).registerState(
        encryptedState, commitment, nullifier, proof, publicInputs, ethers.ZeroHash
      )).to.not.be.reverted;
    });
  });

  describe("NullifierRegistryV3", function () {
    it("Should initialize with correct merkle root", async function () {
      const { nullifierRegistry } = await loadFixture(deployV3Fixture);

      const merkleRoot = await nullifierRegistry.merkleRoot();
      expect(merkleRoot).to.not.equal(ethers.ZeroHash);
    });

    it("Should register nullifier and update merkle root", async function () {
      const { nullifierRegistry, owner } = await loadFixture(deployV3Fixture);

      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier1"));
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment1"));

      const oldRoot = await nullifierRegistry.merkleRoot();

      await expect(nullifierRegistry.registerNullifier(nullifier, commitment))
        .to.emit(nullifierRegistry, "NullifierRegistered")
        .to.emit(nullifierRegistry, "MerkleRootUpdated");

      const newRoot = await nullifierRegistry.merkleRoot();
      expect(newRoot).to.not.equal(oldRoot);
      expect(await nullifierRegistry.isNullifierUsed(nullifier)).to.be.true;
    });

    it("Should batch register nullifiers", async function () {
      const { nullifierRegistry } = await loadFixture(deployV3Fixture);

      const nullifiers = [
        ethers.keccak256(ethers.toUtf8Bytes("n1")),
        ethers.keccak256(ethers.toUtf8Bytes("n2")),
        ethers.keccak256(ethers.toUtf8Bytes("n3"))
      ];
      const commitments = [
        ethers.keccak256(ethers.toUtf8Bytes("c1")),
        ethers.keccak256(ethers.toUtf8Bytes("c2")),
        ethers.keccak256(ethers.toUtf8Bytes("c3"))
      ];

      await expect(nullifierRegistry.batchRegisterNullifiers(nullifiers, commitments))
        .to.emit(nullifierRegistry, "NullifierBatchRegistered")
        .withArgs(nullifiers, 0, 3);

      expect(await nullifierRegistry.totalNullifiers()).to.equal(3);

      // All should be registered
      for (const n of nullifiers) {
        expect(await nullifierRegistry.isNullifierUsed(n)).to.be.true;
      }
    });

    it("Should batch check nullifier existence", async function () {
      const { nullifierRegistry } = await loadFixture(deployV3Fixture);

      const registered = ethers.keccak256(ethers.toUtf8Bytes("registered"));
      const notRegistered = ethers.keccak256(ethers.toUtf8Bytes("not_registered"));

      await nullifierRegistry.registerNullifier(registered, ethers.ZeroHash);

      const results = await nullifierRegistry.batchExists([registered, notRegistered]);
      expect(results[0]).to.be.true;
      expect(results[1]).to.be.false;
    });

    it("Should validate historical merkle roots", async function () {
      const { nullifierRegistry } = await loadFixture(deployV3Fixture);

      const initialRoot = await nullifierRegistry.merkleRoot();

      // Register some nullifiers
      for (let i = 0; i < 5; i++) {
        const nullifier = ethers.keccak256(ethers.toUtf8Bytes(`n${i}`));
        await nullifierRegistry.registerNullifier(nullifier, ethers.ZeroHash);
      }

      // Initial root should still be valid (in history)
      expect(await nullifierRegistry.isValidRoot(initialRoot)).to.be.true;

      // Current root should also be valid
      const currentRoot = await nullifierRegistry.merkleRoot();
      expect(await nullifierRegistry.isValidRoot(currentRoot)).to.be.true;
    });

    it("Should get nullifier data", async function () {
      const { nullifierRegistry, owner } = await loadFixture(deployV3Fixture);

      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("test_nullifier"));
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("test_commitment"));

      await nullifierRegistry.registerNullifier(nullifier, commitment);

      const data = await nullifierRegistry.getNullifierData(nullifier);
      expect(data.commitment).to.equal(commitment);
      expect(data.registrar).to.equal(owner.address);
      expect(data.index).to.equal(0);
    });
  });

  describe("CrossChainProofHubV3", function () {
    it("Should allow relayer to deposit stake", async function () {
      const { proofHub, relayer } = await loadFixture(deployV3Fixture);

      const stakeAmount = ethers.parseEther("1");
      
      await expect(proofHub.connect(relayer).depositStake({ value: stakeAmount }))
        .to.emit(proofHub, "RelayerStakeDeposited")
        .withArgs(relayer.address, stakeAmount);

      expect(await proofHub.relayerStakes(relayer.address)).to.equal(stakeAmount);
    });

    it("Should submit proof with sufficient stake", async function () {
      const { proofHub, mockVerifier, owner, relayer } = await loadFixture(deployV3Fixture);

      // Set verifier
      const DEFAULT_PROOF_TYPE = await proofHub.DEFAULT_PROOF_TYPE();
      await proofHub.setVerifier(DEFAULT_PROOF_TYPE, await mockVerifier.getAddress());

      // Add source chain as supported
      await proofHub.addSupportedChain(1);

      // Deposit stake
      const stakeAmount = ethers.parseEther("1");
      await proofHub.connect(relayer).depositStake({ value: stakeAmount });

      // Submit proof
      const proof = ethers.toUtf8Bytes("proof_data");
      const publicInputs = ethers.toUtf8Bytes("public_inputs");
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const sourceChainId = 1n;
      const destChainId = 31337n; // Local chain

      const fee = await proofHub.proofSubmissionFee();

      await expect(proofHub.connect(relayer).submitProof(
        proof,
        publicInputs,
        commitment,
        sourceChainId,
        destChainId,
        { value: fee }
      )).to.emit(proofHub, "ProofSubmitted");

      expect(await proofHub.totalProofs()).to.equal(1);
    });

    it("Should reject proof submission with insufficient stake", async function () {
      const { proofHub, relayer } = await loadFixture(deployV3Fixture);

      const proof = ethers.toUtf8Bytes("proof");
      const publicInputs = ethers.toUtf8Bytes("inputs");
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const fee = await proofHub.proofSubmissionFee();

      await expect(proofHub.connect(relayer).submitProof(
        proof,
        publicInputs,
        commitment,
        1n,
        31337n,
        { value: fee }
      )).to.be.revertedWithCustomError(proofHub, "InsufficientStake");
    });

    it("Should allow challenge during challenge period", async function () {
      const { proofHub, mockVerifier, owner, relayer, challenger } = await loadFixture(deployV3Fixture);

      // Setup
      const DEFAULT_PROOF_TYPE = await proofHub.DEFAULT_PROOF_TYPE();
      await proofHub.setVerifier(DEFAULT_PROOF_TYPE, await mockVerifier.getAddress());
      await proofHub.addSupportedChain(1); // Add source chain
      await proofHub.connect(relayer).depositStake({ value: ethers.parseEther("1") });

      // Submit proof
      const proof = ethers.toUtf8Bytes("proof_data");
      const publicInputs = ethers.toUtf8Bytes("public_inputs");
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const fee = await proofHub.proofSubmissionFee();

      const tx = await proofHub.connect(relayer).submitProof(
        proof, publicInputs, commitment, 1n, 31337n, { value: fee }
      );
      const receipt = await tx.wait();
      
      // Get proofId from event
      const event = receipt.logs.find(log => {
        try {
          return proofHub.interface.parseLog(log)?.name === "ProofSubmitted";
        } catch { return false; }
      });
      const proofId = proofHub.interface.parseLog(event).args[0];

      // Challenge
      const challengeStake = await proofHub.minChallengerStake();
      
      await expect(proofHub.connect(challenger).challengeProof(
        proofId,
        "Invalid proof data",
        { value: challengeStake }
      )).to.emit(proofHub, "ChallengeCreated")
        .withArgs(proofId, challenger.address, "Invalid proof data");
    });

    it("Should finalize proof after challenge period", async function () {
      const { proofHub, mockVerifier, relayer } = await loadFixture(deployV3Fixture);

      // Setup
      const DEFAULT_PROOF_TYPE = await proofHub.DEFAULT_PROOF_TYPE();
      await proofHub.setVerifier(DEFAULT_PROOF_TYPE, await mockVerifier.getAddress());
      await proofHub.addSupportedChain(1); // Add source chain
      await proofHub.connect(relayer).depositStake({ value: ethers.parseEther("1") });

      // Set shorter challenge period for testing
      await proofHub.setChallengePeriod(1); // 1 second

      // Submit proof
      const proof = ethers.toUtf8Bytes("proof");
      const publicInputs = ethers.toUtf8Bytes("inputs");
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const fee = await proofHub.proofSubmissionFee();

      const tx = await proofHub.connect(relayer).submitProof(
        proof, publicInputs, commitment, 1n, 31337n, { value: fee }
      );
      const receipt = await tx.wait();
      
      const event = receipt.logs.find(log => {
        try {
          return proofHub.interface.parseLog(log)?.name === "ProofSubmitted";
        } catch { return false; }
      });
      const proofId = proofHub.interface.parseLog(event).args[0];

      // Wait for challenge period
      await ethers.provider.send("evm_increaseTime", [2]);
      await ethers.provider.send("evm_mine");

      // Finalize
      await expect(proofHub.finalizeProof(proofId))
        .to.emit(proofHub, "ProofVerified")
        .to.emit(proofHub, "ProofFinalized");

      expect(await proofHub.isProofFinalized(proofId)).to.be.true;
    });

    it("Should add and remove supported chains", async function () {
      const { proofHub, owner } = await loadFixture(deployV3Fixture);

      const newChainId = 137n; // Polygon

      await expect(proofHub.addSupportedChain(newChainId))
        .to.emit(proofHub, "ChainAdded")
        .withArgs(newChainId);

      expect(await proofHub.supportedChains(newChainId)).to.be.true;

      await expect(proofHub.removeSupportedChain(newChainId))
        .to.emit(proofHub, "ChainRemoved")
        .withArgs(newChainId);

      expect(await proofHub.supportedChains(newChainId)).to.be.false;
    });
  });
});

// Helper to get block timestamp
async function getBlockTimestamp() {
  const block = await ethers.provider.getBlock("latest");
  return block.timestamp;
}
