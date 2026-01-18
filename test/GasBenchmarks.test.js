const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

/**
 * PIL v2 Gas Benchmarks
 * 
 * Comprehensive gas profiling for all primitive operations.
 * Results are logged in a structured format for analysis.
 */

describe("PIL v2 Gas Benchmarks", function () {
  
  // Track gas costs
  const gasReport = {
    pc3: {},
    pbp: {},
    easc: {},
    cdna: {},
    orchestrator: {}
  };
  
  // Helper to log gas cost
  async function measureGas(name, category, txPromise) {
    const tx = await txPromise;
    const receipt = await tx.wait();
    gasReport[category][name] = receipt.gasUsed;
    console.log(`  [${category.toUpperCase()}] ${name}: ${receipt.gasUsed.toLocaleString()} gas`);
    return { tx, receipt };
  }

  // Deploy all primitives
  async function deployBenchmarkFixture() {
    const [admin, user, verifier] = await ethers.getSigners();
    
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
    
    // Setup roles
    await pc3.connect(admin).grantRole(await pc3.VERIFIER_ROLE(), verifier.address);
    await pc3.connect(admin).grantRole(await pc3.VERIFIER_ROLE(), await orch.getAddress());
    await easc.connect(admin).grantRole(await easc.COMMITMENT_REGISTRAR_ROLE(), await orch.getAddress());
    await easc.connect(admin).grantRole(await easc.BACKEND_ADMIN_ROLE(), admin.address);
    await cdna.connect(admin).grantRole(await cdna.NULLIFIER_REGISTRAR_ROLE(), await orch.getAddress());
    await pbp.connect(admin).grantRole(await pbp.POLICY_ADMIN_ROLE(), admin.address);
    await orch.connect(admin).grantRole(await orch.ORCHESTRATOR_ROLE(), admin.address);
    
    // Setup baseline data
    const policyHash = ethers.keccak256(ethers.toUtf8Bytes("benchmark-policy"));
    await pc3.connect(admin).addPolicy(policyHash);
    
    // Register backend
    await easc.connect(admin).registerBackend(
      0,
      "Benchmark Backend",
      ethers.keccak256(ethers.toUtf8Bytes("backend-key")),
      ethers.keccak256(ethers.toUtf8Bytes("backend-config"))
    );
    const backendIds = await easc.getActiveBackends();
    
    // Register domain
    const domainTx = await cdna.connect(admin).registerDomain(
      1,
      ethers.keccak256(ethers.toUtf8Bytes("benchmark-app")),
      0
    );
    const domainReceipt = await domainTx.wait();
    const domainEvent = domainReceipt.logs.find(log => {
      try { return cdna.interface.parseLog(log)?.name === "DomainRegistered"; }
      catch { return false; }
    });
    const domainId = cdna.interface.parseLog(domainEvent).args[0];
    
    return { 
      pc3, pbp, easc, cdna, orch,
      admin, user, verifier,
      policyHash, backendIds, domainId
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

  describe("ProofCarryingContainer (PC³) Benchmarks", function () {
    it("createContainer - single container creation", async function () {
      const { pc3, user, policyHash } = await loadFixture(deployBenchmarkFixture);
      
      await measureGas("createContainer", "pc3",
        pc3.connect(user).createContainer(
          "0xdeadbeef",
          ethers.keccak256(ethers.toUtf8Bytes("state-1")),
          ethers.keccak256(ethers.toUtf8Bytes("nullifier-1")),
          createValidProofBundle(),
          policyHash
        )
      );
    });

    it("verifyContainer - container verification (view function)", async function () {
      const { pc3, user, verifier, policyHash } = await loadFixture(deployBenchmarkFixture);
      
      const tx = await pc3.connect(user).createContainer(
        "0xdeadbeef",
        ethers.keccak256(ethers.toUtf8Bytes("verify-state")),
        ethers.keccak256(ethers.toUtf8Bytes("verify-nullifier")),
        createValidProofBundle(),
        policyHash
      );
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(event).args[0];
      
      // verifyContainer is a view function, so we just verify it works
      const result = await pc3.connect(verifier).verifyContainer(containerId);
      console.log(`  [PC3] verifyContainer: view function, valid=${result.isValid}`);
    });

    it("consumeContainer - container consumption", async function () {
      const { pc3, user, verifier, policyHash } = await loadFixture(deployBenchmarkFixture);
      
      const tx = await pc3.connect(user).createContainer(
        "0xdeadbeef",
        ethers.keccak256(ethers.toUtf8Bytes("consume-state")),
        ethers.keccak256(ethers.toUtf8Bytes("consume-nullifier")),
        createValidProofBundle(),
        policyHash
      );
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(event).args[0];
      
      await measureGas("consumeContainer", "pc3",
        pc3.connect(verifier).consumeContainer(containerId)
      );
    });

    it("batchVerifyContainers - 5 containers (view function)", async function () {
      const { pc3, user, verifier, policyHash } = await loadFixture(deployBenchmarkFixture);
      
      const containerIds = [];
      for (let i = 0; i < 5; i++) {
        const tx = await pc3.connect(user).createContainer(
          "0xdeadbeef",
          ethers.keccak256(ethers.toUtf8Bytes(`batch-verify-state-${i}`)),
          ethers.keccak256(ethers.toUtf8Bytes(`batch-verify-nullifier-${i}`)),
          createValidProofBundle(),
          policyHash
        );
        const receipt = await tx.wait();
        const event = receipt.logs.find(log => {
          try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
          catch { return false; }
        });
        containerIds.push(pc3.interface.parseLog(event).args[0]);
      }
      
      // batchVerifyContainers is a view function
      const results = await pc3.batchVerifyContainers(containerIds);
      const validCount = results.filter(r => r.isValid).length;
      console.log(`  [PC3] batchVerifyContainers_5: view function, ${validCount}/5 valid`);
    });
  });

  describe("PolicyBoundProofs (PBP) Benchmarks", function () {
    it("registerPolicy - single policy registration", async function () {
      const { pbp, admin } = await loadFixture(deployBenchmarkFixture);
      
      const policy = {
        policyId: ethers.ZeroHash,
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("gas-policy")),
        name: "Gas Benchmark Policy",
        description: "Policy for gas measurement",
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
      
      await measureGas("registerPolicy", "pbp",
        pbp.connect(admin).registerPolicy(policy)
      );
    });

    it("batchCheckPolicies - check 5 policies", async function () {
      const { pbp, admin } = await loadFixture(deployBenchmarkFixture);
      
      const policyIds = [];
      for (let i = 0; i < 5; i++) {
        const policy = {
          policyId: ethers.ZeroHash,
          policyHash: ethers.keccak256(ethers.toUtf8Bytes(`batch-check-policy-${i}`)),
          name: `Batch Check Policy ${i}`,
          description: "Batch policy",
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
          try { return pbp.interface.parseLog(log)?.name === "PolicyRegistered"; }
          catch { return false; }
        });
        policyIds.push(pbp.interface.parseLog(event).args[0]);
      }
      
      // batchCheckPolicies is a view function, so we just test it works
      const results = await pbp.batchCheckPolicies(policyIds);
      console.log(`  [PBP] batchCheckPolicies_5: ${policyIds.length} policies checked, all valid: ${results.every(r => r)}`);
    });
  });

  describe("ExecutionAgnosticStateCommitments (EASC) Benchmarks", function () {
    it("createCommitment - single commitment", async function () {
      const { easc, orch, admin } = await loadFixture(deployBenchmarkFixture);
      
      // Grant registrar role to admin
      await easc.connect(admin).grantRole(await easc.COMMITMENT_REGISTRAR_ROLE(), admin.address);
      
      await measureGas("createCommitment", "easc",
        easc.connect(admin).createCommitment(
          ethers.keccak256(ethers.toUtf8Bytes("easc-state")),
          ethers.keccak256(ethers.toUtf8Bytes("easc-transition")),
          ethers.keccak256(ethers.toUtf8Bytes("easc-nullifier"))
        )
      );
    });

    it("attestCommitment - backend attestation", async function () {
      const { easc, admin, backendIds } = await loadFixture(deployBenchmarkFixture);
      
      await easc.connect(admin).grantRole(await easc.COMMITMENT_REGISTRAR_ROLE(), admin.address);
      
      const tx = await easc.connect(admin).createCommitment(
        ethers.keccak256(ethers.toUtf8Bytes("attest-state")),
        ethers.keccak256(ethers.toUtf8Bytes("attest-transition")),
        ethers.keccak256(ethers.toUtf8Bytes("attest-nullifier"))
      );
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => {
        try { return easc.interface.parseLog(log)?.name === "CommitmentCreated"; }
        catch { return false; }
      });
      const commitmentId = easc.interface.parseLog(event).args[0];
      
      await measureGas("attestCommitment", "easc",
        easc.connect(admin).attestCommitment(
          commitmentId,
          backendIds[0],
          ethers.zeroPadValue("0x", 64),
          ethers.keccak256(ethers.toUtf8Bytes("execution"))
        )
      );
    });

    it("batchCheckCommitments - check 5 commitments", async function () {
      const { easc, admin } = await loadFixture(deployBenchmarkFixture);
      
      await easc.connect(admin).grantRole(await easc.COMMITMENT_REGISTRAR_ROLE(), admin.address);
      
      const commitmentIds = [];
      for (let i = 0; i < 5; i++) {
        const tx = await easc.connect(admin).createCommitment(
          ethers.keccak256(ethers.toUtf8Bytes(`batch-check-state-${i}`)),
          ethers.keccak256(ethers.toUtf8Bytes(`batch-check-transition-${i}`)),
          ethers.keccak256(ethers.toUtf8Bytes(`batch-check-nullifier-${i}`))
        );
        const receipt = await tx.wait();
        const event = receipt.logs.find(log => {
          try { return easc.interface.parseLog(log)?.name === "CommitmentCreated"; }
          catch { return false; }
        });
        commitmentIds.push(easc.interface.parseLog(event).args[0]);
      }
      
      // batchCheckCommitments is a view function
      const results = await easc.batchCheckCommitments(commitmentIds);
      console.log(`  [EASC] batchCheckCommitments_5: ${commitmentIds.length} commitments checked, all exist: ${results.every(r => r)}`);
    });
  });

  describe("CrossDomainNullifierAlgebra (CDNA) Benchmarks", function () {
    it("registerDomain - domain registration", async function () {
      const { cdna, admin } = await loadFixture(deployBenchmarkFixture);
      
      await measureGas("registerDomain", "cdna",
        cdna.connect(admin).registerDomain(
          42161, // Arbitrum
          ethers.keccak256(ethers.toUtf8Bytes("arb-app")),
          0
        )
      );
    });

    it("registerNullifier - single nullifier", async function () {
      const { cdna, admin, domainId } = await loadFixture(deployBenchmarkFixture);
      
      await cdna.connect(admin).grantRole(await cdna.NULLIFIER_REGISTRAR_ROLE(), admin.address);
      
      await measureGas("registerNullifier", "cdna",
        cdna.connect(admin).registerNullifier(
          domainId,
          ethers.keccak256(ethers.toUtf8Bytes("cdna-nullifier")),
          ethers.keccak256(ethers.toUtf8Bytes("cdna-state")),
          ethers.keccak256(ethers.toUtf8Bytes("cdna-transition"))
        )
      );
    });

    it("batchConsumeNullifiers - 5 nullifiers", async function () {
      const { cdna, admin, domainId } = await loadFixture(deployBenchmarkFixture);
      
      await cdna.connect(admin).grantRole(await cdna.NULLIFIER_REGISTRAR_ROLE(), admin.address);
      
      const nullifiers = [];
      for (let i = 0; i < 5; i++) {
        const tx = await cdna.connect(admin).registerNullifier(
          domainId,
          ethers.keccak256(ethers.toUtf8Bytes(`batch-consume-null-${i}`)),
          ethers.keccak256(ethers.toUtf8Bytes(`batch-consume-state-${i}`)),
          ethers.keccak256(ethers.toUtf8Bytes(`batch-consume-trans-${i}`))
        );
        const receipt = await tx.wait();
        const event = receipt.logs.find(log => {
          try { return cdna.interface.parseLog(log)?.name === "NullifierRegistered"; }
          catch { return false; }
        });
        nullifiers.push(cdna.interface.parseLog(event).args[0]);
      }
      
      await measureGas("batchConsumeNullifiers_5", "cdna",
        cdna.connect(admin).batchConsumeNullifiers(nullifiers)
      );
    });
  });

  describe("PILv2Orchestrator Benchmarks", function () {
    it("registerContainerInDomain - cross-chain registration", async function () {
      const { pc3, orch, admin, user, policyHash, domainId } = await loadFixture(deployBenchmarkFixture);
      
      // Create container
      const tx = await pc3.connect(user).createContainer(
        "0xdeadbeef",
        ethers.keccak256(ethers.toUtf8Bytes("orch-state")),
        ethers.keccak256(ethers.toUtf8Bytes("orch-nullifier")),
        createValidProofBundle(),
        policyHash
      );
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => {
        try { return pc3.interface.parseLog(log)?.name === "ContainerCreated"; }
        catch { return false; }
      });
      const containerId = pc3.interface.parseLog(event).args[0];
      
      await measureGas("registerContainerInDomain", "orchestrator",
        orch.connect(admin).registerContainerInDomain(
          containerId,
          ethers.keccak256(ethers.toUtf8Bytes("orch-nullifier")),
          ethers.keccak256(ethers.toUtf8Bytes("orch-state")),
          domainId
        )
      );
    });

    it("createPolicyBoundCommitment - policy-bound commitment", async function () {
      const { pbp, orch, admin } = await loadFixture(deployBenchmarkFixture);
      
      // Register policy
      const policy = {
        policyId: ethers.ZeroHash,
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("orch-policy")),
        name: "Orchestrator Policy",
        description: "For benchmarks",
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
      
      const policyTx = await pbp.connect(admin).registerPolicy(policy);
      const policyReceipt = await policyTx.wait();
      const policyEvent = policyReceipt.logs.find(log => {
        try { return pbp.interface.parseLog(log)?.name === "PolicyRegistered"; }
        catch { return false; }
      });
      const policyId = pbp.interface.parseLog(policyEvent).args[0];
      
      await measureGas("createPolicyBoundCommitment", "orchestrator",
        orch.connect(admin).createPolicyBoundCommitment(
          ethers.keccak256(ethers.toUtf8Bytes("pbc-state")),
          ethers.keccak256(ethers.toUtf8Bytes("pbc-transition")),
          ethers.keccak256(ethers.toUtf8Bytes("pbc-nullifier")),
          policyId
        )
      );
    });

    it("createCoordinatedTransition - full coordinated flow", async function () {
      const { pc3, pbp, orch, admin, user, policyHash, domainId } = await loadFixture(deployBenchmarkFixture);
      
      // Create container
      const containerTx = await pc3.connect(user).createContainer(
        "0xdeadbeef",
        ethers.keccak256(ethers.toUtf8Bytes("coord-state")),
        ethers.keccak256(ethers.toUtf8Bytes("coord-nullifier")),
        createValidProofBundle(),
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
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("coord-policy")),
        name: "Coordinated Policy",
        description: "For benchmarks",
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
      
      const policyTx = await pbp.connect(admin).registerPolicy(policy);
      const policyReceipt = await policyTx.wait();
      const policyEvent = policyReceipt.logs.find(log => {
        try { return pbp.interface.parseLog(log)?.name === "PolicyRegistered"; }
        catch { return false; }
      });
      const policyId = pbp.interface.parseLog(policyEvent).args[0];
      
      await measureGas("createCoordinatedTransition", "orchestrator",
        orch.connect(admin).createCoordinatedTransition(
          containerId,
          ethers.keccak256(ethers.toUtf8Bytes("coord-nullifier")),
          ethers.keccak256(ethers.toUtf8Bytes("new-coord-state")),
          ethers.keccak256(ethers.toUtf8Bytes("coord-transition")),
          domainId,
          policyId
        )
      );
    });

    it("completeCoordinatedTransition - transition completion", async function () {
      const { pc3, pbp, orch, admin, user, policyHash, domainId, backendIds } = await loadFixture(deployBenchmarkFixture);
      
      // Create container
      const containerTx = await pc3.connect(user).createContainer(
        "0xdeadbeef",
        ethers.keccak256(ethers.toUtf8Bytes("complete-state")),
        ethers.keccak256(ethers.toUtf8Bytes("complete-nullifier")),
        createValidProofBundle(),
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
        description: "For benchmarks",
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
      
      const policyTx = await pbp.connect(admin).registerPolicy(policy);
      const policyReceipt = await policyTx.wait();
      const policyEvent = policyReceipt.logs.find(log => {
        try { return pbp.interface.parseLog(log)?.name === "PolicyRegistered"; }
        catch { return false; }
      });
      const policyId = pbp.interface.parseLog(policyEvent).args[0];
      
      // Create transition
      const transitionTx = await orch.connect(admin).createCoordinatedTransition(
        containerId,
        ethers.keccak256(ethers.toUtf8Bytes("complete-nullifier")),
        ethers.keccak256(ethers.toUtf8Bytes("new-complete-state")),
        ethers.keccak256(ethers.toUtf8Bytes("complete-transition")),
        domainId,
        policyId
      );
      const transitionReceipt = await transitionTx.wait();
      const transitionEvent = transitionReceipt.logs.find(log => {
        try { return orch.interface.parseLog(log)?.name === "CoordinatedTransitionCreated"; }
        catch { return false; }
      });
      const transitionId = orch.interface.parseLog(transitionEvent).args[0];
      
      await measureGas("completeCoordinatedTransition", "orchestrator",
        orch.connect(admin).completeCoordinatedTransition(
          transitionId,
          backendIds[0],
          ethers.zeroPadValue("0x", 64),
          ethers.keccak256(ethers.toUtf8Bytes("execution"))
        )
      );
    });
  });

  describe("Multiple Operations Efficiency", function () {
    it("Compare single vs multiple container creations", async function () {
      const { pc3, user, policyHash } = await loadFixture(deployBenchmarkFixture);
      
      // Measure gas for 10 single container creations
      console.log("\n  === Container Creation Gas Analysis ===");
      let singleTotal = 0n;
      
      for (let i = 0; i < 10; i++) {
        const tx = await pc3.connect(user).createContainer(
          "0xdeadbeef",
          ethers.keccak256(ethers.toUtf8Bytes(`single-state-${i}`)),
          ethers.keccak256(ethers.toUtf8Bytes(`single-nullifier-${i}`)),
          createValidProofBundle(),
          policyHash
        );
        const receipt = await tx.wait();
        singleTotal += receipt.gasUsed;
      }
      console.log(`  10 single createContainer: ${singleTotal.toLocaleString()} gas total`);
      console.log(`  Average per container: ${(Number(singleTotal) / 10).toFixed(0)} gas`);
      console.log(`  Note: Batch creation could reduce gas by ~15-25% per container`);
    });
  });

  // Print summary after all tests
  after(function () {
    console.log("\n" + "=".repeat(60));
    console.log("  PIL v2 GAS BENCHMARK SUMMARY");
    console.log("=".repeat(60));
    
    for (const [category, operations] of Object.entries(gasReport)) {
      if (Object.keys(operations).length > 0) {
        console.log(`\n  ${category.toUpperCase()}:`);
        for (const [op, gas] of Object.entries(operations)) {
          console.log(`    ${op}: ${gas.toLocaleString()} gas`);
        }
      }
    }
    
    console.log("\n" + "=".repeat(60));
  });
});
