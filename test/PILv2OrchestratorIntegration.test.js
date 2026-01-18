const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

/**
 * PILv2Orchestrator Integration Tests
 * 
 * End-to-end tests for coordinated workflows across all PIL v2 primitives:
 * - PC³ ↔ CDNA: Cross-chain container nullifiers
 * - EASC ↔ PBP: Policy-bound state commitments
 * - Full Flow: PC³ → EASC → CDNA → PBP
 */

describe("PILv2Orchestrator Integration", function () {
  
  // Deploy all primitives and orchestrator
  async function deployFullStackFixture() {
    const [admin, orchestrator, user, backend1, backend2] = await ethers.getSigners();
    
    // Deploy PC³
    const PC3Factory = await ethers.getContractFactory("ProofCarryingContainer");
    const pc3 = await PC3Factory.connect(admin).deploy();
    
    // Deploy PBP
    const PBPFactory = await ethers.getContractFactory("PolicyBoundProofs");
    const pbp = await PBPFactory.connect(admin).deploy();
    
    // Deploy EASC
    const EASCFactory = await ethers.getContractFactory("ExecutionAgnosticStateCommitments");
    const easc = await EASCFactory.connect(admin).deploy();
    
    // Deploy CDNA
    const CDNAFactory = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
    const cdna = await CDNAFactory.connect(admin).deploy();
    
    // Deploy Orchestrator
    const OrchestratorFactory = await ethers.getContractFactory("PILv2Orchestrator");
    const orch = await OrchestratorFactory.connect(admin).deploy(
      await pc3.getAddress(),
      await pbp.getAddress(),
      await easc.getAddress(),
      await cdna.getAddress()
    );
    
    // Grant roles
    const ORCHESTRATOR_ROLE = await orch.ORCHESTRATOR_ROLE();
    await orch.connect(admin).grantRole(ORCHESTRATOR_ROLE, orchestrator.address);
    
    // Setup PC³
    const VERIFIER_ROLE = await pc3.VERIFIER_ROLE();
    await pc3.connect(admin).grantRole(VERIFIER_ROLE, await orch.getAddress());
    const policyHash = ethers.keccak256(ethers.toUtf8Bytes("test-policy"));
    await pc3.connect(admin).addPolicy(policyHash);
    
    // Setup PBP
    const POLICY_ADMIN_ROLE = await pbp.POLICY_ADMIN_ROLE();
    await pbp.connect(admin).grantRole(POLICY_ADMIN_ROLE, orchestrator.address);
    
    // Setup EASC
    const REGISTRAR_ROLE = await easc.COMMITMENT_REGISTRAR_ROLE();
    const BACKEND_ADMIN = await easc.BACKEND_ADMIN_ROLE();
    await easc.connect(admin).grantRole(REGISTRAR_ROLE, await orch.getAddress());
    await easc.connect(admin).grantRole(BACKEND_ADMIN, admin.address);
    
    // Register backends
    await easc.connect(admin).registerBackend(
      0, // ZkVM
      "SP1 zkVM",
      ethers.keccak256(ethers.toUtf8Bytes("sp1-key")),
      ethers.keccak256(ethers.toUtf8Bytes("sp1-config"))
    );
    const backendIds = await easc.getActiveBackends();
    
    // Setup CDNA
    const NULLIFIER_REGISTRAR = await cdna.NULLIFIER_REGISTRAR_ROLE();
    await cdna.connect(admin).grantRole(NULLIFIER_REGISTRAR, await orch.getAddress());
    
    // Register domains
    const ethDomainTx = await cdna.connect(admin).registerDomain(
      1, // Ethereum
      ethers.keccak256(ethers.toUtf8Bytes("soul-app")),
      0
    );
    const ethDomainReceipt = await ethDomainTx.wait();
    const ethDomainEvent = ethDomainReceipt.logs.find(log => {
      try { return cdna.interface.parseLog(log)?.name === "DomainRegistered"; }
      catch { return false; }
    });
    const ethDomainId = cdna.interface.parseLog(ethDomainEvent).args[0];
    
    const polyDomainTx = await cdna.connect(admin).registerDomain(
      137, // Polygon
      ethers.keccak256(ethers.toUtf8Bytes("soul-app")),
      0
    );
    const polyDomainReceipt = await polyDomainTx.wait();
    const polyDomainEvent = polyDomainReceipt.logs.find(log => {
      try { return cdna.interface.parseLog(log)?.name === "DomainRegistered"; }
      catch { return false; }
    });
    const polyDomainId = cdna.interface.parseLog(polyDomainEvent).args[0];
    
    return { 
      pc3, pbp, easc, cdna, orch,
      admin, orchestrator, user,
      policyHash, backendIds, ethDomainId, polyDomainId
    };
  }
  
  // Helper: Create valid proof bundle
  function createValidProofBundle() {
    const validityProof = "0x" + "01".repeat(256);
    const policyProof = "0x" + "02".repeat(256);
    const nullifierProof = "0x" + "03".repeat(256);
    const proofHash = ethers.keccak256(
      ethers.concat([validityProof, policyProof, nullifierProof])
    );
    const now = Math.floor(Date.now() / 1000);
    
    return {
      validityProof,
      policyProof,
      nullifierProof,
      proofHash,
      proofTimestamp: now,
      proofExpiry: now + 86400
    };
  }

  describe("Connection Verification", function () {
    it("Should verify all primitive connections", async function () {
      const { orch } = await loadFixture(deployFullStackFixture);
      
      const [pc3Connected, pbpConnected, eascConnected, cdnaConnected] = 
        await orch.checkConnections();
      
      expect(pc3Connected).to.be.true;
      expect(pbpConnected).to.be.true;
      expect(eascConnected).to.be.true;
      expect(cdnaConnected).to.be.true;
    });

    it("Should have correct contract references", async function () {
      const { orch, pc3, pbp, easc, cdna } = await loadFixture(deployFullStackFixture);
      
      expect(await orch.pc3()).to.equal(await pc3.getAddress());
      expect(await orch.pbp()).to.equal(await pbp.getAddress());
      expect(await orch.easc()).to.equal(await easc.getAddress());
      expect(await orch.cdna()).to.equal(await cdna.getAddress());
    });
  });

  describe("PC³ ↔ CDNA Integration", function () {
    it("Should register container nullifier in domain", async function () {
      const { pc3, cdna, orch, orchestrator, user, policyHash, ethDomainId } = 
        await loadFixture(deployFullStackFixture);
      
      // Create a container first
      const encryptedPayload = "0xdeadbeef";
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("state-cdna"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier-cdna"));
      const proofBundle = createValidProofBundle();
      
      const tx = await pc3.connect(user).createContainer(
        encryptedPayload,
        stateCommitment,
        nullifier,
        proofBundle,
        policyHash
      );
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(event).args[0];
      
      // Register container in domain via orchestrator (use staticCall to get return value)
      const domainNullifier = await orch.connect(orchestrator).registerContainerInDomain.staticCall(
        containerId,
        nullifier,
        stateCommitment,
        ethDomainId
      );
      
      // Execute the actual transaction
      await orch.connect(orchestrator).registerContainerInDomain(
        containerId,
        nullifier,
        stateCommitment,
        ethDomainId
      );
      
      // Verify mapping was created
      const storedDomain = await orch.getContainerDomain(containerId);
      expect(storedDomain).to.equal(ethDomainId);
      
      // Verify nullifier exists in CDNA
      expect(await cdna.nullifierExists(domainNullifier)).to.be.true;
    });
  });

  describe("EASC ↔ PBP Integration", function () {
    it("Should create policy-bound commitment", async function () {
      const { pbp, orch, orchestrator, admin } = await loadFixture(deployFullStackFixture);
      
      // Register a policy first
      const policy = {
        policyId: ethers.ZeroHash,
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("compliance-policy")),
        name: "Compliance Policy",
        description: "KYC/AML compliant",
        requiresIdentity: true,
        requiresJurisdiction: true,
        requiresAmount: false,
        requiresCounterparty: false,
        minAmount: 0n,
        maxAmount: ethers.MaxUint256,
        allowedAssets: [],
        blockedCountries: [],
        createdAt: 0n,
        expiresAt: 0n,
        isActive: true
      };
      
      const policyTx = await pbp.connect(orchestrator).registerPolicy(policy);
      const policyReceipt = await policyTx.wait();
      const policyEvent = policyReceipt.logs.find(log => {
        try { return pbp.interface.parseLog(log)?.name === "PolicyRegistered"; }
        catch { return false; }
      });
      const policyId = pbp.interface.parseLog(policyEvent).args[0];
      
      // Create policy-bound commitment
      const stateHash = ethers.keccak256(ethers.toUtf8Bytes("policy-state"));
      const transitionHash = ethers.keccak256(ethers.toUtf8Bytes("policy-transition"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("policy-nullifier"));
      
      const commitmentId = await orch.connect(orchestrator).createPolicyBoundCommitment.staticCall(
        stateHash, transitionHash, nullifier, policyId
      );
      
      await orch.connect(orchestrator).createPolicyBoundCommitment(
        stateHash, transitionHash, nullifier, policyId
      );
      
      expect(commitmentId).to.not.equal(ethers.ZeroHash);
    });

    it("Should reject commitment with invalid policy", async function () {
      const { orch, orchestrator } = await loadFixture(deployFullStackFixture);
      
      const stateHash = ethers.keccak256(ethers.toUtf8Bytes("invalid-state"));
      const transitionHash = ethers.keccak256(ethers.toUtf8Bytes("invalid-transition"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("invalid-nullifier"));
      const fakePolicyId = ethers.keccak256(ethers.toUtf8Bytes("fake-policy"));
      
      await expect(
        orch.connect(orchestrator).createPolicyBoundCommitment(
          stateHash, transitionHash, nullifier, fakePolicyId
        )
      ).to.be.revertedWithCustomError(orch, "InvalidPolicyId");
    });
  });

  describe("Full Coordinated Flow", function () {
    it("Should create coordinated transition", async function () {
      const { pc3, pbp, easc, cdna, orch, orchestrator, user, admin, policyHash, backendIds, ethDomainId } = 
        await loadFixture(deployFullStackFixture);
      
      // 1. Create container
      const encryptedPayload = "0xdeadbeef";
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("coord-state"));
      const containerNullifier = ethers.keccak256(ethers.toUtf8Bytes("coord-nullifier"));
      const proofBundle = createValidProofBundle();
      
      const containerTx = await pc3.connect(user).createContainer(
        encryptedPayload,
        stateCommitment,
        containerNullifier,
        proofBundle,
        policyHash
      );
      const containerReceipt = await containerTx.wait();
      const containerEvent = containerReceipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(containerEvent).args[0];
      
      // 2. Register policy
      const policy = {
        policyId: ethers.ZeroHash,
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("coord-policy")),
        name: "Coordinated Policy",
        description: "For coordinated transitions",
        requiresIdentity: true,
        requiresJurisdiction: false,
        requiresAmount: false,
        requiresCounterparty: false,
        minAmount: 0n,
        maxAmount: ethers.MaxUint256,
        allowedAssets: [],
        blockedCountries: [],
        createdAt: 0n,
        expiresAt: 0n,
        isActive: true
      };
      
      const policyTx = await pbp.connect(orchestrator).registerPolicy(policy);
      const policyReceipt = await policyTx.wait();
      const policyEvent = policyReceipt.logs.find(log => {
        try { return pbp.interface.parseLog(log)?.name === "PolicyRegistered"; }
        catch { return false; }
      });
      const policyId = pbp.interface.parseLog(policyEvent).args[0];
      
      // 3. Create coordinated transition (get transitionId from event)
      const newStateHash = ethers.keccak256(ethers.toUtf8Bytes("new-coord-state"));
      const transitionHash = ethers.keccak256(ethers.toUtf8Bytes("coord-transition"));
      
      const coordTx = await orch.connect(orchestrator).createCoordinatedTransition(
        containerId,
        containerNullifier,
        newStateHash,
        transitionHash,
        ethDomainId,
        policyId
      );
      const coordReceipt = await coordTx.wait();
      const coordEvent = coordReceipt.logs.find(log => {
        try { return orch.interface.parseLog(log)?.name === "CoordinatedTransitionCreated"; }
        catch { return false; }
      });
      const transitionId = orch.interface.parseLog(coordEvent).args[0];
      
      // 4. Verify transition was created
      const transition = await orch.getTransition(transitionId);
      expect(transition.containerId).to.equal(containerId);
      expect(transition.domainId).to.equal(ethDomainId);
      expect(transition.policyId).to.equal(policyId);
      expect(transition.isComplete).to.be.false;
      
      // 5. Verify mappings
      expect(await orch.getContainerDomain(containerId)).to.equal(ethDomainId);
      expect(await orch.getContainerCommitment(containerId)).to.not.equal(ethers.ZeroHash);
      
      // 6. Verify total transitions
      expect(await orch.totalTransitions()).to.equal(1n);
    });

    it("Should complete coordinated transition", async function () {
      const { pc3, pbp, easc, cdna, orch, orchestrator, user, admin, policyHash, backendIds, ethDomainId } = 
        await loadFixture(deployFullStackFixture);
      
      // Setup: Create container and transition
      const encryptedPayload = "0xdeadbeef";
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("complete-state"));
      const containerNullifier = ethers.keccak256(ethers.toUtf8Bytes("complete-nullifier"));
      const proofBundle = createValidProofBundle();
      
      const containerTx = await pc3.connect(user).createContainer(
        encryptedPayload,
        stateCommitment,
        containerNullifier,
        proofBundle,
        policyHash
      );
      const containerReceipt = await containerTx.wait();
      const containerEvent = containerReceipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(containerEvent).args[0];
      
      // Register policy
      const policy = {
        policyId: ethers.ZeroHash,
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("complete-policy")),
        name: "Complete Policy",
        description: "For completion test",
        requiresIdentity: false,
        requiresJurisdiction: false,
        requiresAmount: false,
        requiresCounterparty: false,
        minAmount: 0n,
        maxAmount: ethers.MaxUint256,
        allowedAssets: [],
        blockedCountries: [],
        createdAt: 0n,
        expiresAt: 0n,
        isActive: true
      };
      
      const policyTx = await pbp.connect(orchestrator).registerPolicy(policy);
      const policyReceipt = await policyTx.wait();
      const policyEvent = policyReceipt.logs.find(log => {
        try { return pbp.interface.parseLog(log)?.name === "PolicyRegistered"; }
        catch { return false; }
      });
      const policyId = pbp.interface.parseLog(policyEvent).args[0];
      
      // Create transition (get transitionId from event)
      const coordTx = await orch.connect(orchestrator).createCoordinatedTransition(
        containerId,
        containerNullifier,
        ethers.keccak256(ethers.toUtf8Bytes("new-complete-state")),
        ethers.keccak256(ethers.toUtf8Bytes("complete-transition")),
        ethDomainId,
        policyId
      );
      const coordReceipt = await coordTx.wait();
      const coordEvent = coordReceipt.logs.find(log => {
        try { return orch.interface.parseLog(log)?.name === "CoordinatedTransitionCreated"; }
        catch { return false; }
      });
      const transitionId = orch.interface.parseLog(coordEvent).args[0];
      
      // Complete transition
      const attestationProof = ethers.zeroPadValue("0x", 64);
      const executionHash = ethers.keccak256(ethers.toUtf8Bytes("execution"));
      
      await orch.connect(orchestrator).completeCoordinatedTransition(
        transitionId,
        backendIds[0],
        attestationProof,
        executionHash
      );
      
      // Verify completion
      const transition = await orch.getTransition(transitionId);
      expect(transition.isComplete).to.be.true;
      
      // Verify container was consumed
      const container = await pc3.getContainer(containerId);
      expect(container.isConsumed).to.be.true;
    });

    it("Should prevent double completion", async function () {
      const { pc3, pbp, orch, orchestrator, user, policyHash, backendIds, ethDomainId } = 
        await loadFixture(deployFullStackFixture);
      
      // Setup
      const proofBundle = createValidProofBundle();
      const containerTx = await pc3.connect(user).createContainer(
        "0xdeadbeef",
        ethers.keccak256(ethers.toUtf8Bytes("double-state")),
        ethers.keccak256(ethers.toUtf8Bytes("double-nullifier")),
        proofBundle,
        policyHash
      );
      const containerReceipt = await containerTx.wait();
      const containerEvent = containerReceipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(containerEvent).args[0];
      
      const policy = {
        policyId: ethers.ZeroHash,
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("double-policy")),
        name: "Double Policy",
        description: "Test",
        requiresIdentity: false,
        requiresJurisdiction: false,
        requiresAmount: false,
        requiresCounterparty: false,
        minAmount: 0n,
        maxAmount: ethers.MaxUint256,
        allowedAssets: [],
        blockedCountries: [],
        createdAt: 0n,
        expiresAt: 0n,
        isActive: true
      };
      
      const policyTx = await pbp.connect(orchestrator).registerPolicy(policy);
      const policyReceipt = await policyTx.wait();
      const policyEvent = policyReceipt.logs.find(log => {
        try { return pbp.interface.parseLog(log)?.name === "PolicyRegistered"; }
        catch { return false; }
      });
      const policyId = pbp.interface.parseLog(policyEvent).args[0];
      
      // Create transition (get transitionId from event)
      const coordTx = await orch.connect(orchestrator).createCoordinatedTransition(
        containerId,
        ethers.keccak256(ethers.toUtf8Bytes("double-nullifier")),
        ethers.keccak256(ethers.toUtf8Bytes("new-double-state")),
        ethers.keccak256(ethers.toUtf8Bytes("double-transition")),
        ethDomainId,
        policyId
      );
      const coordReceipt = await coordTx.wait();
      const coordEvent = coordReceipt.logs.find(log => {
        try { return orch.interface.parseLog(log)?.name === "CoordinatedTransitionCreated"; }
        catch { return false; }
      });
      const transitionId = orch.interface.parseLog(coordEvent).args[0];
      
      // Complete once
      await orch.connect(orchestrator).completeCoordinatedTransition(
        transitionId,
        backendIds[0],
        ethers.zeroPadValue("0x", 64),
        ethers.keccak256(ethers.toUtf8Bytes("exec"))
      );
      
      // Try to complete again
      await expect(
        orch.connect(orchestrator).completeCoordinatedTransition(
          transitionId,
          backendIds[0],
          ethers.zeroPadValue("0x", 64),
          ethers.keccak256(ethers.toUtf8Bytes("exec2"))
        )
      ).to.be.revertedWithCustomError(orch, "TransitionAlreadyComplete");
    });
  });

  describe("Access Control", function () {
    it("Should reject non-orchestrator calls", async function () {
      const { orch, user, ethDomainId } = await loadFixture(deployFullStackFixture);
      
      await expect(
        orch.connect(user).registerContainerInDomain(
          ethers.keccak256(ethers.toUtf8Bytes("fake")),
          ethers.keccak256(ethers.toUtf8Bytes("fake")),
          ethers.keccak256(ethers.toUtf8Bytes("fake")),
          ethDomainId
        )
      ).to.be.reverted;
    });

    it("Should allow admin to pause", async function () {
      const { orch, admin } = await loadFixture(deployFullStackFixture);
      
      await orch.connect(admin).pause();
      expect(await orch.paused()).to.be.true;
      
      await orch.connect(admin).unpause();
      expect(await orch.paused()).to.be.false;
    });
  });
});
