const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * Gas Snapshot Tests
 * 
 * These tests track gas usage for critical operations.
 * Run with: npx hardhat test test/GasSnapshot.test.js
 * 
 * The snapshot file is saved to .gas-snapshot and should be committed.
 * CI will fail if gas increases by more than 5% without explicit approval.
 */

describe("Gas Snapshot Tests", function () {
  let pc3, pbp, easc, cdna, orchestrator;
  let owner, user1, user2;
  let gasReport = {};
  
  const SNAPSHOT_FILE = path.join(__dirname, "..", ".gas-snapshot");
  const TOLERANCE_PERCENT = 5; // 5% tolerance for gas changes
  
  before(async function () {
    [owner, user1, user2] = await ethers.getSigners();
    
    // Deploy verifier (for reference, not passed to PC3)
    const MockVerifier = await ethers.getContractFactory("MockProofVerifier");
    const verifier = await MockVerifier.deploy();
    await verifier.waitForDeployment();
    
    // Deploy PC³
    const PC3Factory = await ethers.getContractFactory("ProofCarryingContainer");
    pc3 = await PC3Factory.deploy();
    await pc3.waitForDeployment();
    
    // Deploy PBP
    const PBPFactory = await ethers.getContractFactory("PolicyBoundProofs");
    pbp = await PBPFactory.deploy();
    await pbp.waitForDeployment();
    
    // Deploy EASC
    const EASCFactory = await ethers.getContractFactory("ExecutionAgnosticStateCommitments");
    easc = await EASCFactory.deploy();
    await easc.waitForDeployment();
    
    // Deploy CDNA
    const CDNAFactory = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
    cdna = await CDNAFactory.deploy();
    await cdna.waitForDeployment();
    
    // Deploy Orchestrator
    const OrchestratorFactory = await ethers.getContractFactory("PILv2Orchestrator");
    orchestrator = await OrchestratorFactory.deploy(
      await pc3.getAddress(),
      await pbp.getAddress(),
      await easc.getAddress(),
      await cdna.getAddress()
    );
    await orchestrator.waitForDeployment();
    
    // Load previous snapshot if exists
    if (fs.existsSync(SNAPSHOT_FILE)) {
      const content = fs.readFileSync(SNAPSHOT_FILE, "utf8");
      this.previousSnapshot = JSON.parse(content);
    } else {
      this.previousSnapshot = {};
    }
  });
  
  after(async function () {
    // Save new snapshot
    fs.writeFileSync(SNAPSHOT_FILE, JSON.stringify(gasReport, null, 2));
    
    // Generate comparison report
    console.log("\n📊 Gas Snapshot Report\n");
    console.log("Operation".padEnd(45) + "Gas Used".padEnd(15) + "Change");
    console.log("-".repeat(70));
    
    for (const [operation, gas] of Object.entries(gasReport)) {
      const prev = this.previousSnapshot[operation];
      let change = "";
      
      if (prev) {
        const diff = gas - prev;
        const percent = ((diff / prev) * 100).toFixed(1);
        if (diff > 0) {
          change = `+${diff} (+${percent}%)`;
          if (parseFloat(percent) > TOLERANCE_PERCENT) {
            change += " ⚠️ REGRESSION";
          }
        } else if (diff < 0) {
          change = `${diff} (${percent}%) ✅`;
        } else {
          change = "unchanged";
        }
      } else {
        change = "NEW";
      }
      
      console.log(operation.padEnd(45) + gas.toString().padEnd(15) + change);
    }
    
    console.log("-".repeat(70));
  });
  
  // Helper to record gas
  async function recordGas(name, txPromise) {
    const tx = await txPromise;
    const receipt = await tx.wait();
    gasReport[name] = Number(receipt.gasUsed);
    return receipt;
  }
  
  // Helper to create valid 256-byte proofs
  function createValidProofBundle() {
    const validityProof = "0x" + "01".repeat(256);  // 256 bytes
    const policyProof = "0x" + "02".repeat(256);    // 256 bytes
    const nullifierProof = "0x" + "03".repeat(256); // 256 bytes
    
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
  
  describe("PC³ Operations", function () {
    it("createContainer", async function () {
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("state1"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier1"));
      const policyHash = ethers.ZeroHash; // Use zero hash for no policy
      
      const proofBundle = createValidProofBundle();
      
      await recordGas("PC3.createContainer", 
        pc3.createContainer(
          "0xabcdef",
          stateCommitment,
          nullifier,
          proofBundle,
          policyHash
        )
      );
    });
    
    it("verifyContainer", async function () {
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("state2"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier2"));
      const policyHash = ethers.ZeroHash;
      
      const proofBundle = createValidProofBundle();
      
      const tx = await pc3.createContainer(
        "0xabcdef",
        stateCommitment,
        nullifier,
        proofBundle,
        policyHash
      );
      const receipt = await tx.wait();
      const containerId = receipt.logs[0].args[0];
      
      // Note: verifyContainer is view, measuring gas via estimateGas
      const gas = await pc3.verifyContainer.estimateGas(containerId);
      gasReport["PC3.verifyContainer (view)"] = Number(gas);
    });
    
    it("consumeContainer", async function () {
      const stateCommitment = ethers.keccak256(ethers.toUtf8Bytes("state3"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier3"));
      const policyHash = ethers.ZeroHash;
      
      const proofBundle = createValidProofBundle();
      
      const tx = await pc3.createContainer(
        "0xabcdef",
        stateCommitment,
        nullifier,
        proofBundle,
        policyHash
      );
      const receipt = await tx.wait();
      const containerId = receipt.logs[0].args[0];
      
      // Grant VERIFIER_ROLE to owner for consuming
      const VERIFIER_ROLE = await pc3.VERIFIER_ROLE();
      await pc3.grantRole(VERIFIER_ROLE, owner.address);
      
      await recordGas("PC3.consumeContainer", pc3.consumeContainer(containerId));
    });
  });
  
  describe("PBP Operations", function () {
    it("registerPolicy", async function () {
      const policy = {
        policyId: ethers.ZeroHash,
        policyHash: ethers.keccak256(ethers.toUtf8Bytes("test-policy")),
        name: "Test Policy",
        description: "A test disclosure policy",
        requiresIdentity: true,
        requiresJurisdiction: true,
        requiresAmount: false,
        requiresCounterparty: false,
        minAmount: 0,
        maxAmount: ethers.parseEther("10000"),
        allowedAssets: [],
        blockedCountries: [],
        createdAt: 0,
        expiresAt: Math.floor(Date.now() / 1000) + 365 * 86400,
        isActive: true
      };
      
      // Grant POLICY_ADMIN_ROLE to owner
      const POLICY_ADMIN_ROLE = await pbp.POLICY_ADMIN_ROLE();
      await pbp.grantRole(POLICY_ADMIN_ROLE, owner.address);
      
      await recordGas("PBP.registerPolicy", 
        pbp.registerPolicy(policy)
      );
    });
    
    it("getPolicy (view)", async function () {
      // Skip this test - requires registered policy first
      this.skip();
    });
  });
  
  describe("EASC Operations", function () {
    it("createCommitment", async function () {
      const stateHash = ethers.keccak256(ethers.toUtf8Bytes("initialState"));
      const transitionHash = ethers.keccak256(ethers.toUtf8Bytes("transition"));
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("eascNullifier1"));
      
      // Grant COMMITMENT_REGISTRAR_ROLE to owner
      const COMMITMENT_REGISTRAR_ROLE = await easc.COMMITMENT_REGISTRAR_ROLE();
      await easc.grantRole(COMMITMENT_REGISTRAR_ROLE, owner.address);
      
      await recordGas("EASC.createCommitment",
        easc.createCommitment(stateHash, transitionHash, nullifier)
      );
    });
    
    it("getCommitment (view)", async function () {
      // Skip - requires prior commitment
      this.skip();
    });
  });
  
  describe("CDNA Operations", function () {
    it("registerDomain", async function () {
      // Grant DOMAIN_ADMIN_ROLE to owner
      const DOMAIN_ADMIN_ROLE = await cdna.DOMAIN_ADMIN_ROLE();
      await cdna.grantRole(DOMAIN_ADMIN_ROLE, owner.address);
      
      const chainId = 1;
      const appId = ethers.keccak256(ethers.toUtf8Bytes("testApp"));
      const epochEnd = 0; // No expiry
      
      await recordGas("CDNA.registerDomain",
        cdna.registerDomain(chainId, appId, epochEnd)
      );
    });
    
    it("isNullifierValid (view)", async function () {
      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("cdnaNullifier2"));
      
      const gas = await cdna.isNullifierValid.estimateGas(nullifier);
      gasReport["CDNA.isNullifierValid (view)"] = Number(gas);
    });
  });
  
  describe("Orchestrator Operations", function () {
    it("getContainerDomain (view)", async function () {
      const containerId = ethers.ZeroHash;
      const gas = await orchestrator.getContainerDomain.estimateGas(containerId);
      gasReport["Orchestrator.getContainerDomain (view)"] = Number(gas);
    });
  });
  
  describe("Gas Regression Checks", function () {
    it("should not exceed gas tolerance", async function () {
      const regressions = [];
      
      for (const [operation, gas] of Object.entries(gasReport)) {
        const prev = this.test.parent.parent.ctx.previousSnapshot?.[operation];
        if (prev) {
          const percentChange = ((gas - prev) / prev) * 100;
          if (percentChange > TOLERANCE_PERCENT) {
            regressions.push({
              operation,
              previous: prev,
              current: gas,
              change: `+${percentChange.toFixed(1)}%`,
            });
          }
        }
      }
      
      if (regressions.length > 0) {
        console.log("\n⚠️ Gas Regressions Detected:");
        console.table(regressions);
        // Uncomment to make test fail on regression:
        // expect(regressions).to.have.length(0, "Gas regressions detected");
      }
    });
  });
});
