const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

/**
 * PIL v2 Primitives Integration Tests
 * 
 * Tests for the four MVP-ready cryptographic primitives:
 * - PC³ (Proof-Carrying Confidential Containers)
 * - PBP (Policy-Bound Proofs)
 * - EASC (Execution-Agnostic State Commitments)
 * - CDNA (Cross-Domain Nullifier Algebra)
 */

describe("PIL v2 Primitives", function () {
  
  // Fixture for PC³
  async function deployPC3Fixture() {
    const [admin, verifier, user] = await ethers.getSigners();
    
    const PC3Factory = await ethers.getContractFactory("ProofCarryingContainer");
    const pc3 = await PC3Factory.connect(admin).deploy();
    
    const VERIFIER_ROLE = await pc3.VERIFIER_ROLE();
    await pc3.connect(admin).grantRole(VERIFIER_ROLE, verifier.address);
    
    const policyHash = ethers.keccak256(ethers.toUtf8Bytes("test-policy"));
    await pc3.connect(admin).addPolicy(policyHash);
    
    return { pc3, admin, verifier, user, policyHash };
  }
  
  // Fixture for PBP
  async function deployPBPFixture() {
    const [admin, verifier, user] = await ethers.getSigners();
    
    const PBPFactory = await ethers.getContractFactory("PolicyBoundProofs");
    const pbp = await PBPFactory.connect(admin).deploy();
    
    const VERIFIER_ROLE = await pbp.VERIFIER_ROLE();
    await pbp.connect(admin).grantRole(VERIFIER_ROLE, verifier.address);
    
    return { pbp, admin, verifier, user };
  }
  
  // Fixture for EASC
  async function deployEASCFixture() {
    const [admin, registrar, user] = await ethers.getSigners();
    
    const EASCFactory = await ethers.getContractFactory("ExecutionAgnosticStateCommitments");
    const easc = await EASCFactory.connect(admin).deploy();
    
    const REGISTRAR_ROLE = await easc.COMMITMENT_REGISTRAR_ROLE();
    await easc.connect(admin).grantRole(REGISTRAR_ROLE, registrar.address);
    
    // Register backends
    const zkVmTx = await easc.connect(admin).registerBackend(
      0, // ZkVM
      "SP1 zkVM",
      ethers.keccak256(ethers.toUtf8Bytes("sp1-key")),
      ethers.keccak256(ethers.toUtf8Bytes("sp1-config"))
    );
    await zkVmTx.wait();
    
    const teeTx = await easc.connect(admin).registerBackend(
      1, // TEE
      "Intel SGX",
      ethers.keccak256(ethers.toUtf8Bytes("sgx-key")),
      ethers.keccak256(ethers.toUtf8Bytes("sgx-config"))
    );
    await teeTx.wait();
    
    return { easc, admin, registrar, user };
  }
  
  // Fixture for CDNA
  async function deployCDNAFixture() {
    const [admin, registrar, bridge, user] = await ethers.getSigners();
    
    const CDNAFactory = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
    const cdna = await CDNAFactory.connect(admin).deploy();
    
    const REGISTRAR_ROLE = await cdna.NULLIFIER_REGISTRAR_ROLE();
    const BRIDGE_ROLE = await cdna.BRIDGE_ROLE();
    await cdna.connect(admin).grantRole(REGISTRAR_ROLE, registrar.address);
    await cdna.connect(admin).grantRole(BRIDGE_ROLE, bridge.address);
    
    // Register domains
    await cdna.connect(admin).registerDomain(
      1, // Ethereum mainnet
      ethers.keccak256(ethers.toUtf8Bytes("soul-stablecoin")),
      0
    );
    
    await cdna.connect(admin).registerDomain(
      137, // Polygon
      ethers.keccak256(ethers.toUtf8Bytes("soul-stablecoin")),
      0
    );
    
    return { cdna, admin, registrar, bridge, user };
  }
  
  // Helper functions
  async function createValidProofBundle() {
    // Create 256-byte proofs (512 hex chars)
    const validityProof = "0x" + "01".repeat(256);  // 256 bytes
    const policyProof = "0x" + "02".repeat(256);    // 256 bytes  
    const nullifierProof = "0x" + "03".repeat(256); // 256 bytes
    
    // Compute proof hash the same way the contract does
    const proofHash = ethers.keccak256(
      ethers.concat([validityProof, policyProof, nullifierProof])
    );
    // Use blockchain time, not wall time, to handle time manipulation in other tests
    const blockNumber = await ethers.provider.getBlockNumber();
    const block = await ethers.provider.getBlock(blockNumber);
    const now = Number(block.timestamp);
    
    return {
      validityProof: validityProof,
      policyProof: policyProof,
      nullifierProof: nullifierProof,
      proofHash: proofHash,
      proofTimestamp: now,
      proofExpiry: now + 86400
    };
  }
  
  function createTestPolicy() {
    return {
      policyId: ethers.ZeroHash,
      policyHash: ethers.keccak256(ethers.toUtf8Bytes("test-policy")),
      name: "Test Policy",
      description: "A test disclosure policy",
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
  }

  describe("ProofCarryingContainer (PC³)", function () {
    it("Should create a container with embedded proofs", async function () {
      const { pc3, user, policyHash } = await loadFixture(deployPC3Fixture);
      
      const encryptedPayload = "0xdeadbeef";
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("state"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier"));
      
      const proofBundle = await createValidProofBundle();
      
      const tx = await pc3.connect(user).createContainer(
        encryptedPayload,
        stateCommitment,
        nullifier,
        proofBundle,
        policyHash
      );
      await tx.wait();
      
      const totalContainers = await pc3.totalContainers();
      expect(totalContainers).to.equal(1n);
    });

    it("Should verify container proofs", async function () {
      const { pc3, user, policyHash } = await loadFixture(deployPC3Fixture);
      
      const encryptedPayload = "0xdeadbeef";
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("state-verify"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier-verify"));
      const proofBundle = await createValidProofBundle();
      
      const tx = await pc3.connect(user).createContainer(
        encryptedPayload,
        stateCommitment,
        nullifier,
        proofBundle,
        policyHash
      );
      const receipt = await tx.wait();
      
      // Get container ID from event
      const event = receipt.logs.find(log => {
        try {
          return pc3.interface.parseLog(log)?.name === "ContainerCreated";
        } catch { return false; }
      });
      const parsedEvent = pc3.interface.parseLog(event);
      const containerId = parsedEvent.args[0];
      
      const result = await pc3.verifyContainer(containerId);
      
      expect(result.validityValid).to.be.true;
      expect(result.notExpired).to.be.true;
      expect(result.notConsumed).to.be.true;
    });

    it("Should consume container and mark nullifier as used", async function () {
      const { pc3, verifier, user, policyHash } = await loadFixture(deployPC3Fixture);
      
      const encryptedPayload = "0xdeadbeef";
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("state-consume"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier-consume"));
      const proofBundle = await createValidProofBundle();
      
      const tx = await pc3.connect(user).createContainer(
        encryptedPayload,
        stateCommitment,
        nullifier,
        proofBundle,
        policyHash
      );
      const receipt = await tx.wait();
      
      const event = receipt.logs.find(log => {
        try {
          return pc3.interface.parseLog(log)?.name === "ContainerCreated";
        } catch { return false; }
      });
      const parsedEvent = pc3.interface.parseLog(event);
      const containerId = parsedEvent.args[0];
      
      await pc3.connect(verifier).consumeContainer(containerId);
      
      const container = await pc3.getContainer(containerId);
      expect(container.isConsumed).to.be.true;
      expect(await pc3.isNullifierConsumed(container.nullifier)).to.be.true;
    });

    it("Should export container for cross-chain transfer", async function () {
      const { pc3, user, policyHash } = await loadFixture(deployPC3Fixture);
      
      const encryptedPayload = "0xdeadbeef";
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("state-export"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier-export"));
      const proofBundle = await createValidProofBundle();
      
      const tx = await pc3.connect(user).createContainer(
        encryptedPayload,
        stateCommitment,
        nullifier,
        proofBundle,
        policyHash
      );
      const receipt = await tx.wait();
      
      const event = receipt.logs.find(log => {
        try {
          return pc3.interface.parseLog(log)?.name === "ContainerCreated";
        } catch { return false; }
      });
      const parsedEvent = pc3.interface.parseLog(event);
      const containerId = parsedEvent.args[0];
      
      const exportedData = await pc3.exportContainer(containerId);
      
      expect(exportedData.length).to.be.greaterThan(0);
    });

    it("Should prevent double-consumption of container", async function () {
      const { pc3, verifier, user, policyHash } = await loadFixture(deployPC3Fixture);
      
      const encryptedPayload = "0xdeadbeef";
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("state-double"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier-double"));
      const proofBundle = await createValidProofBundle();
      
      const tx = await pc3.connect(user).createContainer(
        encryptedPayload,
        stateCommitment,
        nullifier,
        proofBundle,
        policyHash
      );
      const receipt = await tx.wait();
      
      const event = receipt.logs.find(log => {
        try {
          return pc3.interface.parseLog(log)?.name === "ContainerCreated";
        } catch { return false; }
      });
      const parsedEvent = pc3.interface.parseLog(event);
      const containerId = parsedEvent.args[0];
      
      await pc3.connect(verifier).consumeContainer(containerId);
      
      await expect(
        pc3.connect(verifier).consumeContainer(containerId)
      ).to.be.reverted;
    });
  });

  describe("PolicyBoundProofs (PBP)", function () {
    it("Should register a disclosure policy", async function () {
      const { pbp, admin } = await loadFixture(deployPBPFixture);
      
      const policy = createTestPolicy();
      
      const tx = await pbp.connect(admin).registerPolicy(policy);
      await tx.wait();
      
      const totalPolicies = await pbp.totalPolicies();
      expect(totalPolicies).to.equal(1n);
    });

    it("Should bind verification key to policy", async function () {
      const { pbp, admin } = await loadFixture(deployPBPFixture);
      
      const policy = createTestPolicy();
      await pbp.connect(admin).registerPolicy(policy);
      
      const vkHash = ethers.keccak256(ethers.toUtf8Bytes("verification-key"));
      
      const tx = await pbp.connect(admin).bindVerificationKey(vkHash, policy.policyHash);
      await tx.wait();
      
      const boundVk = await pbp.getVerificationKey(vkHash);
      expect(boundVk.policyHash).to.equal(policy.policyHash);
      expect(boundVk.domainSeparator).to.not.equal(ethers.ZeroHash);
    });

    it("Should verify bound proof within policy scope", async function () {
      const { pbp, admin } = await loadFixture(deployPBPFixture);
      
      const policy = createTestPolicy();
      await pbp.connect(admin).registerPolicy(policy);
      
      const vkHash = ethers.keccak256(ethers.toUtf8Bytes("verification-key"));
      const domainSeparator = await pbp.connect(admin).bindVerificationKey.staticCall(vkHash, policy.policyHash);
      await pbp.connect(admin).bindVerificationKey(vkHash, policy.policyHash);
      
      // Use blockchain time to handle time manipulation in other tests
      const blockNumber = await ethers.provider.getBlockNumber();
      const block = await ethers.provider.getBlock(blockNumber);
      const now = Number(block.timestamp);
      const boundProof = {
        proof: ethers.zeroPadValue("0x", 256),
        policyHash: policy.policyHash,
        domainSeparator: domainSeparator,
        publicInputs: [policy.policyHash],
        generatedAt: now,
        expiresAt: now + 86400
      };
      
      const result = await pbp.verifyBoundProof(boundProof, vkHash);
      
      expect(result.proofValid).to.be.true;
      expect(result.policyValid).to.be.true;
      expect(result.withinScope).to.be.true;
    });

    it("Should reject proof outside policy scope", async function () {
      const { pbp, admin } = await loadFixture(deployPBPFixture);
      
      const policy1 = createTestPolicy();
      policy1.policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy1"));
      await pbp.connect(admin).registerPolicy(policy1);
      
      const policy2 = createTestPolicy();
      policy2.policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy2"));
      policy2.name = "Policy 2";
      await pbp.connect(admin).registerPolicy(policy2);
      
      const vkHash = ethers.keccak256(ethers.toUtf8Bytes("verification-key"));
      const domainSeparator = await pbp.connect(admin).bindVerificationKey.staticCall(vkHash, policy1.policyHash);
      await pbp.connect(admin).bindVerificationKey(vkHash, policy1.policyHash);
      
      // Use blockchain time to handle time manipulation in other tests
      const blockNumber = await ethers.provider.getBlockNumber();
      const block = await ethers.provider.getBlock(blockNumber);
      const now = Number(block.timestamp);
      const boundProof = {
        proof: ethers.zeroPadValue("0x", 256),
        policyHash: policy2.policyHash, // Wrong policy!
        domainSeparator: domainSeparator,
        publicInputs: [policy2.policyHash],
        generatedAt: now,
        expiresAt: now + 86400
      };
      
      const result = await pbp.verifyBoundProof(boundProof, vkHash);
      
      expect(result.withinScope).to.be.false;
      expect(result.failureReason).to.equal("Proof out of policy scope");
    });
  });

  describe("ExecutionAgnosticStateCommitments (EASC)", function () {
    it("Should register execution backends", async function () {
      const { easc } = await loadFixture(deployEASCFixture);
      
      const totalBackends = await easc.totalBackends();
      expect(totalBackends).to.equal(2n);
    });

    it("Should create state commitment", async function () {
      const { easc, registrar } = await loadFixture(deployEASCFixture);
      
      const stateHash = ethers.keccak256(ethers.toUtf8Bytes("state-data"));
      const transitionHash = ethers.keccak256(ethers.toUtf8Bytes("transition"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier"));
      
      const tx = await easc.connect(registrar).createCommitment(stateHash, transitionHash, nullifier);
      await tx.wait();
      
      const totalCommitments = await easc.totalCommitments();
      expect(totalCommitments).to.equal(1n);
    });

    it("Should attest commitment and finalize", async function () {
      const { easc, registrar, admin } = await loadFixture(deployEASCFixture);
      
      const stateHash = ethers.keccak256(ethers.toUtf8Bytes("state-attest"));
      const transitionHash = ethers.keccak256(ethers.toUtf8Bytes("transition"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier-attest"));
      
      const commitmentId = await easc.connect(registrar).createCommitment.staticCall(
        stateHash, transitionHash, nullifier
      );
      await easc.connect(registrar).createCommitment(stateHash, transitionHash, nullifier);
      
      // Get zkVM backend ID
      const backendIds = await easc.getActiveBackends();
      const zkVmBackendId = backendIds[0];
      
      const attestationProof = ethers.zeroPadValue("0x", 64);
      const executionHash = ethers.keccak256(ethers.toUtf8Bytes("zkvm-execution"));
      
      await easc.connect(registrar).attestCommitment(
        commitmentId, zkVmBackendId, attestationProof, executionHash
      );
      
      const commitment = await easc.getCommitment(commitmentId);
      expect(commitment.isFinalized).to.be.true;
      expect(commitment.attestationCount).to.equal(1n);
    });

    it("Should require multiple attestations when configured", async function () {
      const { easc, registrar, admin } = await loadFixture(deployEASCFixture);
      
      await easc.connect(admin).setRequiredAttestations(2);
      
      const stateHash = ethers.keccak256(ethers.toUtf8Bytes("state-multi"));
      const transitionHash = ethers.keccak256(ethers.toUtf8Bytes("transition"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier-multi"));
      
      const commitmentId = await easc.connect(registrar).createCommitment.staticCall(
        stateHash, transitionHash, nullifier
      );
      await easc.connect(registrar).createCommitment(stateHash, transitionHash, nullifier);
      
      const backendIds = await easc.getActiveBackends();
      const attestationProof = ethers.zeroPadValue("0x", 64);
      
      // First attestation
      await easc.connect(registrar).attestCommitment(
        commitmentId, backendIds[0], attestationProof, ethers.keccak256(ethers.toUtf8Bytes("zkvm"))
      );
      
      let commitment = await easc.getCommitment(commitmentId);
      expect(commitment.isFinalized).to.be.false;
      
      // Second attestation
      await easc.connect(registrar).attestCommitment(
        commitmentId, backendIds[1], attestationProof, ethers.keccak256(ethers.toUtf8Bytes("tee"))
      );
      
      commitment = await easc.getCommitment(commitmentId);
      expect(commitment.isFinalized).to.be.true;
    });
  });

  describe("CrossDomainNullifierAlgebra (CDNA)", function () {
    it("Should register domains", async function () {
      const { cdna } = await loadFixture(deployCDNAFixture);
      
      const totalDomains = await cdna.totalDomains();
      expect(totalDomains).to.equal(2n);
    });

    it("Should register domain-bound nullifier", async function () {
      const { cdna, registrar, admin } = await loadFixture(deployCDNAFixture);
      
      const domainIds = await cdna.getActiveDomains();
      const ethereumDomainId = domainIds[0];
      
      const nullifierValue = ethers.keccak256(ethers.toUtf8Bytes("user-secret"));
      const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const transitionId = ethers.keccak256(ethers.toUtf8Bytes("transition-1"));
      
      const nullifier = await cdna.connect(registrar).registerNullifier.staticCall(
        ethereumDomainId, nullifierValue, commitmentHash, transitionId
      );
      await cdna.connect(registrar).registerNullifier(
        ethereumDomainId, nullifierValue, commitmentHash, transitionId
      );
      
      expect(nullifier).to.not.equal(ethers.ZeroHash);
      expect(await cdna.nullifierExists(nullifier)).to.be.true;
      expect(await cdna.isNullifierValid(nullifier)).to.be.true;
    });

    it("Should produce different nullifiers for different domains", async function () {
      const { cdna, registrar } = await loadFixture(deployCDNAFixture);
      
      const domainIds = await cdna.getActiveDomains();
      const ethereumDomainId = domainIds[0];
      const polygonDomainId = domainIds[1];
      
      const nullifierValue = ethers.keccak256(ethers.toUtf8Bytes("same-secret"));
      const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      const transitionId = ethers.keccak256(ethers.toUtf8Bytes("transition"));
      
      const ethNullifier = await cdna.connect(registrar).registerNullifier.staticCall(
        ethereumDomainId, nullifierValue, commitmentHash, transitionId
      );
      await cdna.connect(registrar).registerNullifier(
        ethereumDomainId, nullifierValue, commitmentHash, transitionId
      );
      
      const polyNullifier = await cdna.connect(registrar).registerNullifier.staticCall(
        polygonDomainId, nullifierValue, commitmentHash, transitionId
      );
      await cdna.connect(registrar).registerNullifier(
        polygonDomainId, nullifierValue, commitmentHash, transitionId
      );
      
      // Key CDNA property: same secret, different domains = different nullifiers
      expect(ethNullifier).to.not.equal(polyNullifier);
    });

    it("Should derive cross-domain nullifiers", async function () {
      const { cdna, registrar, bridge } = await loadFixture(deployCDNAFixture);
      
      const domainIds = await cdna.getActiveDomains();
      const ethereumDomainId = domainIds[0];
      const polygonDomainId = domainIds[1];
      
      // Register parent nullifier on Ethereum
      const parentNullifier = await cdna.connect(registrar).registerNullifier.staticCall(
        ethereumDomainId,
        ethers.keccak256(ethers.toUtf8Bytes("secret-derive")),
        ethers.keccak256(ethers.toUtf8Bytes("commitment")),
        ethers.keccak256(ethers.toUtf8Bytes("transition-1"))
      );
      await cdna.connect(registrar).registerNullifier(
        ethereumDomainId,
        ethers.keccak256(ethers.toUtf8Bytes("secret-derive")),
        ethers.keccak256(ethers.toUtf8Bytes("commitment")),
        ethers.keccak256(ethers.toUtf8Bytes("transition-1"))
      );
      
      // Derive child nullifier on Polygon
      const derivationProof = ethers.zeroPadValue("0x", 256);
      const newTransitionId = ethers.keccak256(ethers.toUtf8Bytes("transition-2"));
      
      const childNullifier = await cdna.connect(bridge).registerDerivedNullifier.staticCall(
        parentNullifier, polygonDomainId, newTransitionId, derivationProof
      );
      await cdna.connect(bridge).registerDerivedNullifier(
        parentNullifier, polygonDomainId, newTransitionId, derivationProof
      );
      
      expect(childNullifier).to.not.equal(ethers.ZeroHash);
      expect(childNullifier).to.not.equal(parentNullifier);
      
      // Verify linkage
      const children = await cdna.getChildNullifiers(parentNullifier);
      expect(children.length).to.equal(1);
      expect(children[0]).to.equal(childNullifier);
    });

    it("Should consume nullifier (prevent double-spend)", async function () {
      const { cdna, registrar } = await loadFixture(deployCDNAFixture);
      
      const domainIds = await cdna.getActiveDomains();
      const ethereumDomainId = domainIds[0];
      
      const nullifier = await cdna.connect(registrar).registerNullifier.staticCall(
        ethereumDomainId,
        ethers.keccak256(ethers.toUtf8Bytes("secret-consume")),
        ethers.keccak256(ethers.toUtf8Bytes("commitment")),
        ethers.keccak256(ethers.toUtf8Bytes("transition"))
      );
      await cdna.connect(registrar).registerNullifier(
        ethereumDomainId,
        ethers.keccak256(ethers.toUtf8Bytes("secret-consume")),
        ethers.keccak256(ethers.toUtf8Bytes("commitment")),
        ethers.keccak256(ethers.toUtf8Bytes("transition"))
      );
      
      expect(await cdna.isNullifierValid(nullifier)).to.be.true;
      
      await cdna.connect(registrar).consumeNullifier(nullifier);
      
      expect(await cdna.isNullifierValid(nullifier)).to.be.false;
      
      // Cannot consume again
      await expect(
        cdna.connect(registrar).consumeNullifier(nullifier)
      ).to.be.reverted;
    });

    it("Should manage epochs", async function () {
      const { cdna, registrar, admin } = await loadFixture(deployCDNAFixture);
      
      const domainIds = await cdna.getActiveDomains();
      const ethereumDomainId = domainIds[0];
      
      const initialEpoch = await cdna.currentEpochId();
      expect(initialEpoch).to.equal(1n);
      
      // Register nullifier
      await cdna.connect(registrar).registerNullifier(
        ethereumDomainId,
        ethers.keccak256(ethers.toUtf8Bytes("epoch-secret")),
        ethers.keccak256(ethers.toUtf8Bytes("commitment")),
        ethers.keccak256(ethers.toUtf8Bytes("transition"))
      );
      
      // Finalize epoch
      const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("epoch-1-root"));
      await cdna.connect(admin).finalizeEpoch(merkleRoot);
      
      const epoch = await cdna.getEpoch(1);
      expect(epoch.isFinalized).to.be.true;
      expect(epoch.merkleRoot).to.equal(merkleRoot);
      
      // New epoch started
      expect(await cdna.currentEpochId()).to.equal(2n);
    });

    it("Should verify cross-domain proof", async function () {
      const { cdna, registrar, bridge } = await loadFixture(deployCDNAFixture);
      
      const domainIds = await cdna.getActiveDomains();
      const ethereumDomainId = domainIds[0];
      const polygonDomainId = domainIds[1];
      
      // Setup parent nullifier
      const secret = ethers.keccak256(ethers.toUtf8Bytes("verify-secret"));
      const parentNullifier = await cdna.connect(registrar).registerNullifier.staticCall(
        ethereumDomainId, secret,
        ethers.keccak256(ethers.toUtf8Bytes("commitment")),
        ethers.keccak256(ethers.toUtf8Bytes("transition-1"))
      );
      await cdna.connect(registrar).registerNullifier(
        ethereumDomainId, secret,
        ethers.keccak256(ethers.toUtf8Bytes("commitment")),
        ethers.keccak256(ethers.toUtf8Bytes("transition-1"))
      );
      
      // Derive child
      const childNullifier = await cdna.connect(bridge).registerDerivedNullifier.staticCall(
        parentNullifier, polygonDomainId,
        ethers.keccak256(ethers.toUtf8Bytes("transition-2")),
        ethers.zeroPadValue("0x", 256)
      );
      await cdna.connect(bridge).registerDerivedNullifier(
        parentNullifier, polygonDomainId,
        ethers.keccak256(ethers.toUtf8Bytes("transition-2")),
        ethers.zeroPadValue("0x", 256)
      );
      
      // Verify cross-domain proof
      const proof = ethers.zeroPadValue("0x", 256);
      const crossProof = {
        sourceNullifier: parentNullifier,
        targetNullifier: childNullifier,
        sourceDomainId: ethereumDomainId,
        targetDomainId: polygonDomainId,
        proof: proof,
        proofHash: ethers.keccak256(proof)
      };
      
      const isValid = await cdna.verifyCrossDomainProof(crossProof);
      expect(isValid).to.be.true;
    });
  });

  describe("Batch Operations", function () {
    describe("PC³ Batch Operations", function () {
      it("Should batch verify multiple containers", async function () {
        const { pc3, user, policyHash } = await loadFixture(deployPC3Fixture);
        
        const containerIds = [];
        
        // Create 3 containers
        for (let i = 0; i < 3; i++) {
          const encryptedPayload = `0xdeadbeef${i.toString(16).padStart(2, "0")}`;
          const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes(`state-batch-${i}`));
          const nullifier = ethers.keccak256(ethers.toUtf8Bytes(`nullifier-batch-${i}`));
          const proofBundle = await createValidProofBundle();
          
          const tx = await pc3.connect(user).createContainer(
            encryptedPayload,
            stateCommitment,
            nullifier,
            proofBundle,
            policyHash
          );
          const receipt = await tx.wait();
          
          const event = receipt.logs.find(log => {
            try {
              return pc3.interface.parseLog(log)?.name === "ContainerCreated";
            } catch { return false; }
          });
          const parsedEvent = pc3.interface.parseLog(event);
          containerIds.push(parsedEvent.args[0]);
        }
        
        // Batch verify
        const results = await pc3.batchVerifyContainers(containerIds);
        
        expect(results).to.have.lengthOf(3);
        expect(results.every(r => r.validityValid)).to.be.true;
      });

      it("Should get paginated container IDs", async function () {
        const { pc3, user, policyHash } = await loadFixture(deployPC3Fixture);
        
        // Create 5 containers
        for (let i = 0; i < 5; i++) {
          const encryptedPayload = `0xdeadbeef${i.toString(16).padStart(2, "0")}`;
          const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes(`state-page-${i}`));
          const nullifier = ethers.keccak256(ethers.toUtf8Bytes(`nullifier-page-${i}`));
          const proofBundle = await createValidProofBundle();
          
          await pc3.connect(user).createContainer(
            encryptedPayload,
            stateCommitment,
            nullifier,
            proofBundle,
            policyHash
          );
        }
        
        // Get first 2
        const page1 = await pc3.getContainerIds(0, 2);
        expect(page1).to.have.lengthOf(2);
        
        // Get next 2
        const page2 = await pc3.getContainerIds(2, 2);
        expect(page2).to.have.lengthOf(2);
        
        // Get remaining
        const page3 = await pc3.getContainerIds(4, 2);
        expect(page3).to.have.lengthOf(1);
      });
    });

    describe("PBP Batch Operations", function () {
      it("Should batch check policy validity", async function () {
        const { pbp, admin } = await loadFixture(deployPBPFixture);
        
        const policyIds = [];
        
        // Register 3 policies using struct format
        for (let i = 0; i < 3; i++) {
          const policy = {
            policyId: ethers.ZeroHash,
            policyHash: ethers.keccak256(ethers.toUtf8Bytes(`batch-policy-${i}`)),
            name: `Batch Policy ${i}`,
            description: `Test policy ${i}`,
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
          
          const tx = await pbp.connect(admin).registerPolicy(policy);
          const receipt = await tx.wait();
          
          const event = receipt.logs.find(log => {
            try {
              return pbp.interface.parseLog(log)?.name === "PolicyRegistered";
            } catch { return false; }
          });
          const parsedEvent = pbp.interface.parseLog(event);
          // Collect policyId (args[0]), not policyHash (args[1])
          policyIds.push(parsedEvent.args[0]);
        }
        
        // Include a fake policy ID
        const fakeId = ethers.keccak256(ethers.toUtf8Bytes("fake-policy-id"));
        policyIds.push(fakeId);
        
        // Batch check
        const results = await pbp.batchCheckPolicies(policyIds);
        
        expect(results).to.have.lengthOf(4);
        expect(results[0]).to.be.true;
        expect(results[1]).to.be.true;
        expect(results[2]).to.be.true;
        expect(results[3]).to.be.false; // Fake policy
      });

      it("Should get paginated policy and VK hashes", async function () {
        const { pbp, admin } = await loadFixture(deployPBPFixture);
        
        // Register 3 policies using struct format
        for (let i = 0; i < 3; i++) {
          const policy = {
            policyId: ethers.ZeroHash,
            policyHash: ethers.keccak256(ethers.toUtf8Bytes(`page-policy-${i}`)),
            name: `Page Policy ${i}`,
            description: `Test policy ${i}`,
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
          await pbp.connect(admin).registerPolicy(policy);
        }
        
        const policyIds = await pbp.getPolicyIds(0, 10);
        expect(policyIds).to.have.lengthOf(3);
      });
    });

    describe("EASC Batch Operations", function () {
      it("Should batch check commitment finalization status", async function () {
        const { easc, registrar, user } = await loadFixture(deployEASCFixture);
        
        const commitmentIds = [];
        
        // Create 2 commitments (without requiredAttestations parameter)
        for (let i = 0; i < 2; i++) {
          const stateHash = ethers.keccak256(ethers.toUtf8Bytes(`batch-state-${i}`));
          const transitionHash = ethers.keccak256(ethers.toUtf8Bytes(`batch-transition-${i}`));
          const nullifier = ethers.keccak256(ethers.toUtf8Bytes(`batch-nullifier-${i}`));
          
          const commitmentId = await easc.connect(registrar).createCommitment.staticCall(
            stateHash, transitionHash, nullifier
          );
          await easc.connect(registrar).createCommitment(
            stateHash, transitionHash, nullifier
          );
          commitmentIds.push(commitmentId);
        }
        
        // Batch check (none finalized yet)
        let results = await easc.batchCheckCommitments(commitmentIds);
        expect(results[0]).to.be.false;
        expect(results[1]).to.be.false;
        
        // Attest and finalize first commitment
        const backends = await easc.getActiveBackends();
        await easc.connect(registrar).attestCommitment(
          commitmentIds[0],
          backends[0],
          ethers.zeroPadValue("0x", 64),
          ethers.keccak256(ethers.toUtf8Bytes("exec-hash-batch"))
        );
        
        // Check again
        results = await easc.batchCheckCommitments(commitmentIds);
        expect(results[0]).to.be.true;
        expect(results[1]).to.be.false;
      });

      it("Should get contract stats", async function () {
        const { easc, registrar } = await loadFixture(deployEASCFixture);
        
        // Create a commitment
        const stateHash = ethers.keccak256(ethers.toUtf8Bytes("stats-state"));
        const transitionHash = ethers.keccak256(ethers.toUtf8Bytes("stats-transition"));
        const nullifier = ethers.keccak256(ethers.toUtf8Bytes("stats-nullifier"));
        
        await easc.connect(registrar).createCommitment(
          stateHash, transitionHash, nullifier
        );
        
        const stats = await easc.getStats();
        
        expect(stats[0]).to.equal(1n); // totalCommitments
        expect(stats[2]).to.be.greaterThan(0n); // activeBackends (from fixture)
      });
    });

    describe("CDNA Batch Operations", function () {
      it("Should batch check nullifier existence", async function () {
        const { cdna, registrar, admin } = await loadFixture(deployCDNAFixture);
        
        // Get domains from fixture
        const domains = await cdna.getActiveDomains();
        const domainId = domains[0];
        
        const nullifiers = [];
        
        // Register 3 nullifiers (using 4 arguments)
        for (let i = 0; i < 3; i++) {
          const nullifierValue = ethers.keccak256(ethers.toUtf8Bytes(`batch-null-value-${i}`));
          const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes(`commit-${i}`));
          const transitionId = ethers.keccak256(ethers.toUtf8Bytes(`trans-${i}`));
          
          const nullifier = await cdna.connect(registrar).registerNullifier.staticCall(
            domainId, nullifierValue, commitmentHash, transitionId
          );
          await cdna.connect(registrar).registerNullifier(
            domainId, nullifierValue, commitmentHash, transitionId
          );
          nullifiers.push(nullifier);
        }
        
        // Add a fake nullifier
        const fakeNull = ethers.keccak256(ethers.toUtf8Bytes("fake-nullifier"));
        nullifiers.push(fakeNull);
        
        // Batch check
        const results = await cdna.batchCheckNullifiers(nullifiers);
        
        expect(results).to.have.lengthOf(4);
        expect(results[0]).to.be.true;
        expect(results[1]).to.be.true;
        expect(results[2]).to.be.true;
        expect(results[3]).to.be.false; // Fake nullifier
      });

      it("Should batch consume nullifiers", async function () {
        const { cdna, registrar, admin } = await loadFixture(deployCDNAFixture);
        
        const domains = await cdna.getActiveDomains();
        const domainId = domains[0];
        
        const nullifiers = [];
        
        // Register 2 nullifiers (using 4 arguments)
        for (let i = 0; i < 2; i++) {
          const nullifierValue = ethers.keccak256(ethers.toUtf8Bytes(`consume-batch-value-${i}`));
          const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes(`commit-consume-${i}`));
          const transitionId = ethers.keccak256(ethers.toUtf8Bytes(`trans-consume-${i}`));
          
          const nullifier = await cdna.connect(registrar).registerNullifier.staticCall(
            domainId, nullifierValue, commitmentHash, transitionId
          );
          await cdna.connect(registrar).registerNullifier(
            domainId, nullifierValue, commitmentHash, transitionId
          );
          nullifiers.push(nullifier);
        }
        
        // Batch consume
        await cdna.connect(registrar).batchConsumeNullifiers(nullifiers);
        
        // Verify all consumed
        for (const nullifier of nullifiers) {
          const data = await cdna.nullifiers(nullifier);
          expect(data.isConsumed).to.be.true;
        }
      });

      it("Should get nullifier stats", async function () {
        const { cdna, registrar } = await loadFixture(deployCDNAFixture);
        
        const domains = await cdna.getActiveDomains();
        const domainId = domains[0];
        
        // Register a nullifier (using 4 arguments)
        await cdna.connect(registrar).registerNullifier(
          domainId,
          ethers.keccak256(ethers.toUtf8Bytes("stats-nullifier-value")),
          ethers.keccak256(ethers.toUtf8Bytes("stats-commit")),
          ethers.keccak256(ethers.toUtf8Bytes("stats-trans"))
        );
        
        const stats = await cdna.getStats();
        
        expect(stats[0]).to.be.greaterThan(0n); // totalDomains
        expect(stats[1]).to.be.greaterThan(0n); // totalNullifiers
      });
    });
  });

  describe("Integration: End-to-End Flow", function () {
    it("Should deploy all PIL v2 primitives", async function () {
      const [admin] = await ethers.getSigners();
      
      const PC3 = await ethers.getContractFactory("ProofCarryingContainer");
      const pc3 = await PC3.deploy();
      
      const PBP = await ethers.getContractFactory("PolicyBoundProofs");
      const pbp = await PBP.deploy();
      
      const EASC = await ethers.getContractFactory("ExecutionAgnosticStateCommitments");
      const easc = await EASC.deploy();
      
      const CDNA = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
      const cdna = await CDNA.deploy();
      
      expect(await pc3.getAddress()).to.not.equal(ethers.ZeroAddress);
      expect(await pbp.getAddress()).to.not.equal(ethers.ZeroAddress);
      expect(await easc.getAddress()).to.not.equal(ethers.ZeroAddress);
      expect(await cdna.getAddress()).to.not.equal(ethers.ZeroAddress);
    });
  });
});
