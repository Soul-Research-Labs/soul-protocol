const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture, time } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

/**
 * PIL v2 End-to-End Integration Tests
 * 
 * Complete workflow tests that exercise the full PIL v2 stack:
 * 1. Full Private Transfer Flow with PC³
 * 2. Cross-Domain Nullifier with CDNA
 * 3. Policy Compliance with PBP
 * 4. State Commitments with EASC
 * 5. Orchestrator Coordination
 */

describe("PIL v2 E2E Integration", function () {
  
  // ============================================
  // TEST FIXTURES
  // ============================================
  
  async function deployFullStackFixture() {
    const [admin, operator, user1, user2, relayer] = await ethers.getSigners();
    
    // Deploy PC³
    const PC3 = await ethers.getContractFactory("ProofCarryingContainer");
    const pc3 = await PC3.deploy();
    
    // Deploy PBP
    const PBP = await ethers.getContractFactory("PolicyBoundProofs");
    const pbp = await PBP.deploy();
    
    // Deploy EASC
    const EASC = await ethers.getContractFactory("ExecutionAgnosticStateCommitments");
    const easc = await EASC.deploy();
    
    // Deploy CDNA
    const CDNA = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
    const cdna = await CDNA.deploy();
    
    // Deploy Orchestrator
    const Orchestrator = await ethers.getContractFactory("PILv2Orchestrator");
    const orchestrator = await Orchestrator.deploy(
      await pc3.getAddress(),
      await pbp.getAddress(),
      await easc.getAddress(),
      await cdna.getAddress()
    );
    
    // Configure roles
    const VERIFIER_ROLE = await pc3.VERIFIER_ROLE();
    const ORCHESTRATOR_ROLE = await orchestrator.ORCHESTRATOR_ROLE();
    const POLICY_ADMIN_ROLE = await pbp.POLICY_ADMIN_ROLE();
    const REGISTRAR_ROLE = await easc.COMMITMENT_REGISTRAR_ROLE();
    const BACKEND_ADMIN = await easc.BACKEND_ADMIN_ROLE();
    const NULLIFIER_REGISTRAR = await cdna.NULLIFIER_REGISTRAR_ROLE();
    
    // Grant orchestrator permissions
    await pc3.grantRole(VERIFIER_ROLE, await orchestrator.getAddress());
    await orchestrator.grantRole(ORCHESTRATOR_ROLE, operator.address);
    await pbp.grantRole(POLICY_ADMIN_ROLE, operator.address);
    await easc.grantRole(REGISTRAR_ROLE, await orchestrator.getAddress());
    await easc.grantRole(REGISTRAR_ROLE, operator.address);
    await easc.grantRole(BACKEND_ADMIN, admin.address);
    await cdna.grantRole(NULLIFIER_REGISTRAR, await orchestrator.getAddress());
    await cdna.grantRole(NULLIFIER_REGISTRAR, operator.address);
    
    // Add default policy to PC³
    const defaultPolicyHash = ethers.ZeroHash;
    await pc3.addPolicy(defaultPolicyHash);
    
    // Add test policy 
    const testPolicyHash = ethers.keccak256(ethers.toUtf8Bytes("test-policy"));
    await pc3.addPolicy(testPolicyHash);
    
    // Register backend for EASC
    await easc.registerBackend(
      0, // ZkVM
      "SP1 zkVM Backend",
      ethers.keccak256(ethers.toUtf8Bytes("sp1-verifier-key")),
      ethers.keccak256(ethers.toUtf8Bytes("sp1-config"))
    );
    const backendIds = await easc.getActiveBackends();
    
    // Register domains for CDNA
    const ethDomainTx = await cdna.registerDomain(
      1, // Ethereum
      ethers.keccak256(ethers.toUtf8Bytes("pil-app")),
      0 // MerkleTree type
    );
    const ethDomainReceipt = await ethDomainTx.wait();
    const ethDomainEvent = ethDomainReceipt.logs.find(log => {
      try { return cdna.interface.parseLog(log)?.name === "DomainRegistered"; }
      catch { return false; }
    });
    const ethDomainId = cdna.interface.parseLog(ethDomainEvent).args[0];
    
    return {
      pc3,
      pbp,
      easc,
      cdna,
      orchestrator,
      admin,
      operator,
      user1,
      user2,
      relayer,
      defaultPolicyHash,
      testPolicyHash,
      backendIds,
      ethDomainId
    };
  }
  
  // Helper functions
  async function createProofBundle() {
    const validityProof = "0x" + "01".repeat(256);
    const policyProof = "0x" + "02".repeat(256);
    const nullifierProof = "0x" + "03".repeat(256);
    const proofHash = ethers.keccak256(
      ethers.concat([validityProof, policyProof, nullifierProof])
    );
    // Use blockchain time to handle time manipulation in other tests
    const blockNumber = await ethers.provider.getBlockNumber();
    const block = await ethers.provider.getBlock(blockNumber);
    const now = Number(block.timestamp);
    
    return {
      validityProof,
      policyProof,
      nullifierProof,
      proofHash,
      proofTimestamp: now,
      proofExpiry: now + 3600 // 1 hour
    };
  }
  
  function createContainerData() {
    return {
      encryptedPayload: "0xdeadbeef",
      stateCommitment: ethers.keccak256(ethers.randomBytes(32)),
      nullifier: ethers.keccak256(ethers.randomBytes(32))
    };
  }
  
  // ============================================
  // E2E TEST SUITE 1: FULL PRIVATE TRANSFER FLOW
  // ============================================
  
  describe("E2E: Full Private Transfer Flow", function () {
    
    it("should complete full transfer: create → verify → consume", async function () {
      const { pc3, user1, defaultPolicyHash } = await loadFixture(deployFullStackFixture);
      
      const container = createContainerData();
      const proofs = await createProofBundle();
      
      // Step 1: Create container
      const createTx = await pc3.connect(user1).createContainer(
        container.encryptedPayload,
        container.stateCommitment,
        container.nullifier,
        proofs,
        defaultPolicyHash
      );
      
      const createReceipt = await createTx.wait();
      const createEvent = createReceipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(createEvent).args[0];
      
      expect(containerId).to.not.equal(ethers.ZeroHash);
      
      // Step 2: Verify container
      const verifyResult = await pc3.verifyContainer(containerId);
      expect(verifyResult.validityValid).to.be.true;
      expect(verifyResult.notExpired).to.be.true;
      expect(verifyResult.notConsumed).to.be.true;
      
      // Step 3: Consume container (requires VERIFIER_ROLE)
      const VERIFIER_ROLE = await pc3.VERIFIER_ROLE();
      await pc3.grantRole(VERIFIER_ROLE, user1.address);
      
      const consumeTx = await pc3.connect(user1).consumeContainer(containerId);
      await consumeTx.wait();
      
      // Verify container is consumed
      const storedContainer = await pc3.containers(containerId);
      expect(storedContainer.isConsumed).to.be.true;
      
      // Verify nullifier is marked
      expect(await pc3.consumedNullifiers(container.nullifier)).to.be.true;
    });
    
    it("should prevent double-consumption of container", async function () {
      const { pc3, user1, defaultPolicyHash } = await loadFixture(deployFullStackFixture);
      
      const container = createContainerData();
      const proofs = await createProofBundle();
      
      // Create container
      const createTx = await pc3.connect(user1).createContainer(
        container.encryptedPayload,
        container.stateCommitment,
        container.nullifier,
        proofs,
        defaultPolicyHash
      );
      const receipt = await createTx.wait();
      const event = receipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(event).args[0];
      
      // Grant role and consume
      const VERIFIER_ROLE = await pc3.VERIFIER_ROLE();
      await pc3.grantRole(VERIFIER_ROLE, user1.address);
      await pc3.connect(user1).consumeContainer(containerId);
      
      // Try to consume again
      await expect(
        pc3.connect(user1).consumeContainer(containerId)
      ).to.be.revertedWithCustomError(pc3, "ContainerAlreadyConsumed");
    });
    
    it("should batch verify multiple containers", async function () {
      const { pc3, user1, defaultPolicyHash } = await loadFixture(deployFullStackFixture);
      
      const containerIds = [];
      
      // Create 3 containers
      for (let i = 0; i < 3; i++) {
        const container = createContainerData();
        const proofs = await createProofBundle();
        
        const tx = await pc3.connect(user1).createContainer(
          container.encryptedPayload,
          container.stateCommitment,
          container.nullifier,
          proofs,
          defaultPolicyHash
        );
        const receipt = await tx.wait();
        const event = receipt.logs.find(log => {
          try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
          catch { return false; }
        });
        containerIds.push(pc3.interface.parseLog(event).args[0]);
      }
      
      // Batch verify
      const results = await pc3.batchVerifyContainers(containerIds);
      
      // All should be valid
      for (let i = 0; i < results.length; i++) {
        expect(results[i].validityValid).to.be.true;
      }
    });
  });
  
  // ============================================
  // E2E TEST SUITE 2: CROSS-DOMAIN NULLIFIER FLOW
  // ============================================
  
  describe("E2E: Cross-Domain Nullifier Flow", function () {
    
    it("should register and consume nullifier", async function () {
      const { cdna, operator, ethDomainId } = await loadFixture(deployFullStackFixture);
      
      const nullifierValue = ethers.keccak256(ethers.randomBytes(32));
      const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const transitionId = ethers.keccak256(ethers.toUtf8Bytes("transition"));
      
      // Register nullifier
      const registerTx = await cdna.connect(operator).registerNullifier(
        ethDomainId,
        nullifierValue,
        commitmentHash,
        transitionId
      );
      const receipt = await registerTx.wait();
      
      // Get the computed nullifier from event
      const event = receipt.logs.find(log => {
        try { return cdna.interface.parseLog(log)?.name === "NullifierRegistered"; }
        catch { return false; }
      });
      const nullifier = cdna.interface.parseLog(event).args[0];
      
      // Nullifier should exist but not be consumed
      expect(await cdna.nullifierExists(nullifier)).to.be.true;
      const nullifierData = await cdna.nullifiers(nullifier);
      expect(nullifierData.isConsumed).to.be.false;
      
      // Consume nullifier
      await cdna.connect(operator).consumeNullifier(nullifier);
      
      // Verify consumed
      const consumedData = await cdna.nullifiers(nullifier);
      expect(consumedData.isConsumed).to.be.true;
    });
    
    it("should prevent double-consumption of nullifier", async function () {
      const { cdna, operator, ethDomainId } = await loadFixture(deployFullStackFixture);
      
      const nullifierValue = ethers.keccak256(ethers.randomBytes(32));
      const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const transitionId = ethers.keccak256(ethers.toUtf8Bytes("transition"));
      
      // Register nullifier
      const registerTx = await cdna.connect(operator).registerNullifier(
        ethDomainId,
        nullifierValue,
        commitmentHash,
        transitionId
      );
      const receipt = await registerTx.wait();
      const event = receipt.logs.find(log => {
        try { return cdna.interface.parseLog(log)?.name === "NullifierRegistered"; }
        catch { return false; }
      });
      const nullifier = cdna.interface.parseLog(event).args[0];
      
      // Consume once
      await cdna.connect(operator).consumeNullifier(nullifier);
      
      // Try again - should fail
      await expect(
        cdna.connect(operator).consumeNullifier(nullifier)
      ).to.be.revertedWithCustomError(cdna, "NullifierAlreadyConsumed");
    });
  });
  
  // ============================================
  // E2E TEST SUITE 3: POLICY COMPLIANCE FLOW
  // ============================================
  
  describe("E2E: Policy Compliance Flow", function () {
    
    it("should register and verify policy", async function () {
      const { pbp, operator } = await loadFixture(deployFullStackFixture);
      
      // Create policy struct
      const policy = {
        policyId: ethers.ZeroHash,
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("kyc-policy-v1")),
        name: "KYC Policy V1",
        description: "Standard KYC compliance policy",
        requiresIdentity: true,
        requiresJurisdiction: true,
        requiresAmount: false,
        requiresCounterparty: false,
        minAmount: 0n,
        maxAmount: ethers.MaxUint256,
        allowedAssets: [],
        blockedCountries: [],
        createdAt: 0n,
        expiresAt: BigInt(Math.floor(Date.now() / 1000) + 86400 * 30),
        isActive: true
      };
      
      // Register policy
      const tx = await pbp.connect(operator).registerPolicy(policy);
      const receipt = await tx.wait();
      
      // Get policy ID from event
      const event = receipt.logs.find(log => {
        try { return pbp.interface.parseLog(log)?.name === "PolicyRegistered"; }
        catch { return false; }
      });
      const policyId = pbp.interface.parseLog(event).args[0];
      
      // Verify policy exists and is active
      const storedPolicy = await pbp.policies(policyId);
      expect(storedPolicy.isActive).to.be.true;
      expect(storedPolicy.name).to.equal("KYC Policy V1");
    });
    
    it("should deactivate policy", async function () {
      const { pbp, operator } = await loadFixture(deployFullStackFixture);
      
      const policy = {
        policyId: ethers.ZeroHash,
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("temp-policy")),
        name: "Temporary Policy",
        description: "A temporary policy",
        requiresIdentity: false,
        requiresJurisdiction: false,
        requiresAmount: false,
        requiresCounterparty: false,
        minAmount: 0n,
        maxAmount: ethers.MaxUint256,
        allowedAssets: [],
        blockedCountries: [],
        createdAt: 0n,
        expiresAt: BigInt(Math.floor(Date.now() / 1000) + 3600),
        isActive: true
      };
      
      const tx = await pbp.connect(operator).registerPolicy(policy);
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => {
        try { return pbp.interface.parseLog(log)?.name === "PolicyRegistered"; }
        catch { return false; }
      });
      const policyId = pbp.interface.parseLog(event).args[0];
      
      // Deactivate
      await pbp.connect(operator).deactivatePolicy(policyId);
      
      const deactivated = await pbp.policies(policyId);
      expect(deactivated.isActive).to.be.false;
    });
  });
  
  // ============================================
  // E2E TEST SUITE 4: STATE COMMITMENT FLOW
  // ============================================
  
  describe("E2E: State Commitment Flow", function () {
    
    it("should create state commitment", async function () {
      const { easc, operator } = await loadFixture(deployFullStackFixture);
      
      const stateHash = ethers.keccak256(ethers.toUtf8Bytes("merkle-state-root"));
      const transitionHash = ethers.keccak256(ethers.toUtf8Bytes("transition-hash"));
      const nullifier = ethers.keccak256(ethers.randomBytes(32));
      
      const tx = await easc.connect(operator).createCommitment(
        stateHash,
        transitionHash,
        nullifier
      );
      
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => {
        try { return easc.interface.parseLog(log)?.name === "CommitmentCreated"; }
        catch { return false; }
      });
      
      expect(event).to.not.be.undefined;
      const commitmentId = easc.interface.parseLog(event).args[0];
      expect(commitmentId).to.not.equal(ethers.ZeroHash);
    });
    
    it("should create multiple commitments with unique nullifiers", async function () {
      const { easc, operator } = await loadFixture(deployFullStackFixture);
      
      // Create multiple commitments with different nullifiers
      for (let i = 0; i < 3; i++) {
        const stateHash = ethers.keccak256(ethers.toUtf8Bytes(`state-${i}`));
        const transitionHash = ethers.keccak256(ethers.toUtf8Bytes(`transition-${i}`));
        const nullifier = ethers.keccak256(ethers.randomBytes(32));
        
        const tx = await easc.connect(operator).createCommitment(stateHash, transitionHash, nullifier);
        await tx.wait();
      }
      
      // Verify total
      const total = await easc.totalCommitments();
      expect(total).to.equal(3n);
    });
  });
  
  // ============================================
  // E2E TEST SUITE 5: ORCHESTRATOR COORDINATION
  // ============================================
  
  describe("E2E: Orchestrator Coordination", function () {
    
    it("should verify all primitive connections", async function () {
      const { orchestrator, pc3, pbp, easc, cdna } = await loadFixture(deployFullStackFixture);
      
      expect(await orchestrator.pc3()).to.equal(await pc3.getAddress());
      expect(await orchestrator.pbp()).to.equal(await pbp.getAddress());
      expect(await orchestrator.easc()).to.equal(await easc.getAddress());
      expect(await orchestrator.cdna()).to.equal(await cdna.getAddress());
    });
    
    it("should handle primitive pause/unpause", async function () {
      const { orchestrator, admin } = await loadFixture(deployFullStackFixture);
      
      // Pause
      await orchestrator.connect(admin).pause();
      expect(await orchestrator.paused()).to.be.true;
      
      // Unpause
      await orchestrator.connect(admin).unpause();
      expect(await orchestrator.paused()).to.be.false;
    });
    
    it("should have correct primitive references", async function () {
      const { orchestrator, pc3, pbp, easc, cdna } = await loadFixture(deployFullStackFixture);
      
      // Verify primitive addresses match
      expect(await orchestrator.pc3()).to.equal(await pc3.getAddress());
      expect(await orchestrator.pbp()).to.equal(await pbp.getAddress());
    });
  });
  
  // ============================================
  // E2E TEST SUITE 6: GAS BENCHMARKS
  // ============================================
  
  describe("E2E: Gas Benchmarks", function () {
    
    it("should measure container creation gas", async function () {
      const { pc3, user1, defaultPolicyHash } = await loadFixture(deployFullStackFixture);
      
      const container = createContainerData();
      const proofs = await createProofBundle();
      
      const tx = await pc3.connect(user1).createContainer(
        container.encryptedPayload,
        container.stateCommitment,
        container.nullifier,
        proofs,
        defaultPolicyHash
      );
      
      const receipt = await tx.wait();
      console.log(`    Container creation gas: ${receipt.gasUsed.toString()}`);
      
      expect(receipt.gasUsed).to.be.lessThan(1000000n);
    });
    
    it("should measure nullifier registration gas", async function () {
      const { cdna, operator, ethDomainId } = await loadFixture(deployFullStackFixture);
      
      const nullifierValue = ethers.keccak256(ethers.randomBytes(32));
      const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const transitionId = ethers.keccak256(ethers.toUtf8Bytes("transition"));
      
      const tx = await cdna.connect(operator).registerNullifier(
        ethDomainId,
        nullifierValue,
        commitmentHash,
        transitionId
      );
      const receipt = await tx.wait();
      
      console.log(`    Nullifier registration gas: ${receipt.gasUsed.toString()}`);
      expect(receipt.gasUsed).to.be.lessThan(350000n);
    });
    
    it("should measure policy registration gas", async function () {
      const { pbp, operator } = await loadFixture(deployFullStackFixture);
      
      const policy = {
        policyId: ethers.ZeroHash,
        policyHash: ethers.keccak256(ethers.randomBytes(32)),
        name: "Gas Test Policy",
        description: "For gas measurement",
        requiresIdentity: true,
        requiresJurisdiction: false,
        requiresAmount: false,
        requiresCounterparty: false,
        minAmount: 0n,
        maxAmount: ethers.MaxUint256,
        allowedAssets: [],
        blockedCountries: [],
        createdAt: 0n,
        expiresAt: BigInt(Math.floor(Date.now() / 1000) + 86400),
        isActive: true
      };
      
      const tx = await pbp.connect(operator).registerPolicy(policy);
      const receipt = await tx.wait();
      
      console.log(`    Policy registration gas: ${receipt.gasUsed.toString()}`);
      expect(receipt.gasUsed).to.be.lessThan(300000n);
    });
  });
  
  // ============================================
  // E2E TEST SUITE 7: ERROR HANDLING
  // ============================================
  
  describe("E2E: Error Handling", function () {
    
    it("should reject container with unsupported policy", async function () {
      const { pc3, user1 } = await loadFixture(deployFullStackFixture);
      
      const container = createContainerData();
      const proofs = await createProofBundle();
      const unsupportedPolicy = ethers.keccak256(ethers.toUtf8Bytes("unsupported"));
      
      await expect(
        pc3.connect(user1).createContainer(
          container.encryptedPayload,
          container.stateCommitment,
          container.nullifier,
          proofs,
          unsupportedPolicy
        )
      ).to.be.revertedWithCustomError(pc3, "UnsupportedPolicy");
    });
    
    it("should reject verification of expired proofs", async function () {
      const { pc3, user1, defaultPolicyHash } = await loadFixture(deployFullStackFixture);
      
      const container = createContainerData();
      const proofs = await createProofBundle();
      // Use blockchain time for consistency
      const blockNumber = await ethers.provider.getBlockNumber();
      const block = await ethers.provider.getBlock(blockNumber);
      proofs.proofExpiry = Number(block.timestamp) - 3600; // Already expired
      // Recalculate proof hash
      proofs.proofHash = ethers.keccak256(
        ethers.concat([proofs.validityProof, proofs.policyProof, proofs.nullifierProof])
      );
      
      // Container creation should succeed (expiry checked at verification)
      const tx = await pc3.connect(user1).createContainer(
        container.encryptedPayload,
        container.stateCommitment,
        container.nullifier,
        proofs,
        defaultPolicyHash
      );
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(event).args[0];
      
      // Verification should fail due to expired proof
      const result = await pc3.verifyContainer(containerId);
      expect(result.notExpired).to.be.false;
    });
    
    it("should reject duplicate container IDs", async function () {
      const { pc3, user1, defaultPolicyHash } = await loadFixture(deployFullStackFixture);
      
      const container = createContainerData();
      const proofs = await createProofBundle();
      
      // Create first container
      await pc3.connect(user1).createContainer(
        container.encryptedPayload,
        container.stateCommitment,
        container.nullifier,
        proofs,
        defaultPolicyHash
      );
      
      // Try to create container with same stateCommitment and nullifier (same container ID)
      const newProofs = await createProofBundle();
      
      await expect(
        pc3.connect(user1).createContainer(
          "0xbeefdead",
          container.stateCommitment, // Same state commitment
          container.nullifier, // Same nullifier = same container ID
          newProofs,
          defaultPolicyHash
        )
      ).to.be.revertedWithCustomError(pc3, "ContainerAlreadyExists");
    });
    
    it("should prevent consuming with used nullifier", async function () {
      const { pc3, user1, admin, defaultPolicyHash } = await loadFixture(deployFullStackFixture);
      
      const container = createContainerData();
      const proofs = await createProofBundle();
      
      // Create container
      const tx = await pc3.connect(user1).createContainer(
        container.encryptedPayload,
        container.stateCommitment,
        container.nullifier,
        proofs,
        defaultPolicyHash
      );
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(event).args[0];
      
      // Grant role and consume
      const VERIFIER_ROLE = await pc3.VERIFIER_ROLE();
      await pc3.grantRole(VERIFIER_ROLE, user1.address);
      await pc3.connect(user1).consumeContainer(containerId);
      
      // Now the nullifier is consumed, creating new container with same nullifier should fail
      const newContainer = createContainerData();
      newContainer.nullifier = container.nullifier; // Use same nullifier
      const newProofs = await createProofBundle();
      
      await expect(
        pc3.connect(user1).createContainer(
          newContainer.encryptedPayload,
          newContainer.stateCommitment,
          newContainer.nullifier,
          newProofs,
          defaultPolicyHash
        )
      ).to.be.revertedWithCustomError(pc3, "NullifierAlreadyConsumed");
    });
  });
});
