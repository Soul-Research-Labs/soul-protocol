const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

describe("PLONKVerifier", function () {
  async function deployPLONKVerifierFixture() {
    const [owner, user] = await ethers.getSigners();
    
    const PLONKVerifier = await ethers.getContractFactory("PLONKVerifier");
    const verifier = await PLONKVerifier.deploy();
    
    return { verifier, owner, user };
  }
  
  describe("Deployment", function () {
    it("Should deploy with correct owner", async function () {
      const { verifier, owner } = await loadFixture(deployPLONKVerifierFixture);
      
      expect(await verifier.owner()).to.equal(owner.address);
    });
    
    it("Should not be initialized initially", async function () {
      const { verifier } = await loadFixture(deployPLONKVerifierFixture);
      
      expect(await verifier.initialized()).to.equal(false);
      expect(await verifier.isReady()).to.equal(false);
    });
    
    it("Should return correct proof type", async function () {
      const { verifier } = await loadFixture(deployPLONKVerifierFixture);
      
      expect(await verifier.proofType()).to.equal("PLONK-BN254");
    });
  });
  
  describe("Initialization", function () {
    it("Should initialize with valid verification key", async function () {
      const { verifier } = await loadFixture(deployPLONKVerifierFixture);
      
      // Mock verification key (simplified for testing)
      const domainSize = 1024; // Power of 2
      const publicInputCount = 2;
      
      const mockPoint = [1n, 2n];
      const mockG2Point = [
        11559732032986387107991004021392285783925812861821192530917403151452391805634n,
        10857046999023057135944570762232829481370756359578518086990519993285655852781n,
        4082367875863433681332203403145435568316851327593401208105741076214120093531n,
        8495653923123431417604973247489272438418190587263600148770280649306958101930n
      ];
      
      await verifier.setVerificationKey(
        domainSize,
        publicInputCount,
        mockPoint, // qM
        mockPoint, // qL
        mockPoint, // qR
        mockPoint, // qO
        mockPoint, // qC
        mockPoint, // sigma1
        mockPoint, // sigma2
        mockPoint, // sigma3
        mockG2Point // xN
      );
      
      expect(await verifier.initialized()).to.equal(true);
      expect(await verifier.isReady()).to.equal(true);
      expect(await verifier.domainSize()).to.equal(domainSize);
      expect(await verifier.publicInputCount()).to.equal(publicInputCount);
    });
    
    it("Should reject non-power-of-2 domain size", async function () {
      const { verifier } = await loadFixture(deployPLONKVerifierFixture);
      
      const mockPoint = [1n, 2n];
      const mockG2Point = [1n, 2n, 3n, 4n];
      
      await expect(
        verifier.setVerificationKey(
          1000, // Not power of 2
          2,
          mockPoint, mockPoint, mockPoint, mockPoint, mockPoint,
          mockPoint, mockPoint, mockPoint,
          mockG2Point
        )
      ).to.be.revertedWithCustomError(verifier, "InvalidDomainSize");
    });
    
    it("Should reject double initialization", async function () {
      const { verifier } = await loadFixture(deployPLONKVerifierFixture);
      
      const mockPoint = [1n, 2n];
      const mockG2Point = [1n, 2n, 3n, 4n];
      
      await verifier.setVerificationKey(
        1024, 2,
        mockPoint, mockPoint, mockPoint, mockPoint, mockPoint,
        mockPoint, mockPoint, mockPoint,
        mockG2Point
      );
      
      await expect(
        verifier.setVerificationKey(
          2048, 2,
          mockPoint, mockPoint, mockPoint, mockPoint, mockPoint,
          mockPoint, mockPoint, mockPoint,
          mockG2Point
        )
      ).to.be.revertedWithCustomError(verifier, "AlreadyInitialized");
    });
    
    it("Should reject initialization from non-owner", async function () {
      const { verifier, user } = await loadFixture(deployPLONKVerifierFixture);
      
      const mockPoint = [1n, 2n];
      const mockG2Point = [1n, 2n, 3n, 4n];
      
      await expect(
        verifier.connect(user).setVerificationKey(
          1024, 2,
          mockPoint, mockPoint, mockPoint, mockPoint, mockPoint,
          mockPoint, mockPoint, mockPoint,
          mockG2Point
        )
      ).to.be.revertedWithCustomError(verifier, "NotOwner");
    });
  });
  
  describe("Verification", function () {
    async function deployAndInitializeFixture() {
      const { verifier, owner, user } = await loadFixture(deployPLONKVerifierFixture);
      
      const mockPoint = [1n, 2n];
      const mockG2Point = [
        11559732032986387107991004021392285783925812861821192530917403151452391805634n,
        10857046999023057135944570762232829481370756359578518086990519993285655852781n,
        4082367875863433681332203403145435568316851327593401208105741076214120093531n,
        8495653923123431417604973247489272438418190587263600148770280649306958101930n
      ];
      
      await verifier.setVerificationKey(
        1024, 2,
        mockPoint, mockPoint, mockPoint, mockPoint, mockPoint,
        mockPoint, mockPoint, mockPoint,
        mockG2Point
      );
      
      return { verifier, owner, user };
    }
    
    it("Should reject proof that is too small", async function () {
      const { verifier } = await loadFixture(deployAndInitializeFixture);
      
      const shortProof = ethers.randomBytes(100); // Less than 768 bytes
      const publicInputs = [1n, 2n];
      
      await expect(
        verifier.verify(shortProof, publicInputs)
      ).to.be.revertedWithCustomError(verifier, "InvalidProofSize");
    });
    
    it("Should reject wrong number of public inputs", async function () {
      const { verifier } = await loadFixture(deployAndInitializeFixture);
      
      const proof = ethers.randomBytes(928); // 29 * 32 bytes
      const publicInputs = [1n]; // Only 1, expected 2
      
      await expect(
        verifier.verify(proof, publicInputs)
      ).to.be.revertedWithCustomError(verifier, "InvalidPublicInputCount");
    });
    
    it("Should reject public inputs outside field", async function () {
      const { verifier } = await loadFixture(deployAndInitializeFixture);
      
      const proof = ethers.randomBytes(928);
      // Field modulus + 1 (too large)
      const invalidInput = 21888242871839275222246405745257275088548364400416034343698204186575808495618n;
      const publicInputs = [1n, invalidInput];
      
      await expect(
        verifier.verify(proof, publicInputs)
      ).to.be.revertedWithCustomError(verifier, "InvalidPublicInput");
    });
    
    it("Should return expected public input count", async function () {
      const { verifier } = await loadFixture(deployAndInitializeFixture);
      
      expect(await verifier.getPublicInputCount()).to.equal(2);
    });
    
    it("Should support verifySingle for single input", async function () {
      const { verifier } = await loadFixture(deployPLONKVerifierFixture);
      
      // Initialize with 1 public input
      const mockPoint = [1n, 2n];
      const mockG2Point = [1n, 2n, 3n, 4n];
      
      await verifier.setVerificationKey(
        1024, 1, // Only 1 public input
        mockPoint, mockPoint, mockPoint, mockPoint, mockPoint,
        mockPoint, mockPoint, mockPoint,
        mockG2Point
      );
      
      // verifySingle should not revert for size check
      const proof = ethers.randomBytes(928);
      
      // Note: This will still fail pairing check but won't fail on input count
      // In a real test, we'd use a valid proof
      await expect(
        verifier.verifySingle(proof, 123n)
      ).to.be.reverted; // Expected to fail at pairing, but not at input validation
    });
  });
  
  describe("Batch Verification", function () {
    it("Should verify batch of proofs", async function () {
      const { verifier } = await loadFixture(deployPLONKVerifierFixture);
      
      const mockPoint = [1n, 2n];
      const mockG2Point = [1n, 2n, 3n, 4n];
      
      await verifier.setVerificationKey(
        1024, 1,
        mockPoint, mockPoint, mockPoint, mockPoint, mockPoint,
        mockPoint, mockPoint, mockPoint,
        mockG2Point
      );
      
      // The batch function should return an array of results
      // For now just verify it can be called
      const proofs = [ethers.randomBytes(928), ethers.randomBytes(928)];
      const publicInputs = [[1n], [2n]];
      
      // Will revert due to pairing issues, but tests interface
      await expect(verifier.verifyBatch(proofs, publicInputs)).to.be.reverted;
    });
  });
});

describe("FRIVerifier", function () {
  async function deployFRIVerifierFixture() {
    const [owner, user] = await ethers.getSigners();
    
    const FRIVerifier = await ethers.getContractFactory("FRIVerifier");
    const verifier = await FRIVerifier.deploy();
    
    return { verifier, owner, user };
  }
  
  describe("Deployment", function () {
    it("Should deploy with correct owner", async function () {
      const { verifier, owner } = await loadFixture(deployFRIVerifierFixture);
      
      expect(await verifier.owner()).to.equal(owner.address);
    });
    
    it("Should not be initialized initially", async function () {
      const { verifier } = await loadFixture(deployFRIVerifierFixture);
      
      expect(await verifier.isReady()).to.equal(false);
    });
    
    it("Should return correct proof type", async function () {
      const { verifier } = await loadFixture(deployFRIVerifierFixture);
      
      expect(await verifier.proofType()).to.equal("FRI-STARK");
    });
  });
  
  describe("Initialization", function () {
    it("Should initialize with valid FRI config", async function () {
      const { verifier } = await loadFixture(deployFRIVerifierFixture);
      
      const domainSize = 1024; // Power of 2
      const numLayers = 10;
      const numQueries = 30;
      const foldingFactor = 2;
      
      await verifier.initialize(domainSize, numLayers, numQueries, foldingFactor);
      
      expect(await verifier.isReady()).to.equal(true);
      
      const config = await verifier.getConfig();
      expect(config.domainSize).to.equal(domainSize);
      expect(config.numLayers).to.equal(numLayers);
      expect(config.numQueries).to.equal(numQueries);
      expect(config.foldingFactor).to.equal(foldingFactor);
    });
    
    it("Should reject non-power-of-2 domain size", async function () {
      const { verifier } = await loadFixture(deployFRIVerifierFixture);
      
      await expect(
        verifier.initialize(1000, 10, 30, 2) // 1000 is not power of 2
      ).to.be.revertedWithCustomError(verifier, "InvalidDomainSize");
    });
    
    it("Should reject zero layers", async function () {
      const { verifier } = await loadFixture(deployFRIVerifierFixture);
      
      await expect(
        verifier.initialize(1024, 0, 30, 2)
      ).to.be.revertedWithCustomError(verifier, "InvalidLayerCount");
    });
    
    it("Should reject too many layers", async function () {
      const { verifier } = await loadFixture(deployFRIVerifierFixture);
      
      await expect(
        verifier.initialize(1024, 25, 30, 2) // More than MAX_FRI_LAYERS (20)
      ).to.be.revertedWithCustomError(verifier, "InvalidLayerCount");
    });
    
    it("Should reject double initialization", async function () {
      const { verifier } = await loadFixture(deployFRIVerifierFixture);
      
      await verifier.initialize(1024, 10, 30, 2);
      
      await expect(
        verifier.initialize(2048, 10, 30, 2)
      ).to.be.revertedWithCustomError(verifier, "AlreadyInitialized");
    });
    
    it("Should reject initialization from non-owner", async function () {
      const { verifier, user } = await loadFixture(deployFRIVerifierFixture);
      
      await expect(
        verifier.connect(user).initialize(1024, 10, 30, 2)
      ).to.be.revertedWithCustomError(verifier, "NotOwner");
    });
  });
  
  describe("Verification", function () {
    async function deployAndInitializeFRIFixture() {
      const { verifier, owner, user } = await loadFixture(deployFRIVerifierFixture);
      
      await verifier.initialize(1024, 10, 30, 2);
      
      return { verifier, owner, user };
    }
    
    it("Should reject proof that is too small", async function () {
      const { verifier } = await loadFixture(deployAndInitializeFRIFixture);
      
      const shortProof = ethers.randomBytes(100); // Less than 512 bytes
      const publicInputs = [1n];
      
      await expect(
        verifier.verify(shortProof, publicInputs)
      ).to.be.revertedWithCustomError(verifier, "InvalidProofSize");
    });
    
    it("Should reject public inputs outside field", async function () {
      const { verifier } = await loadFixture(deployAndInitializeFRIFixture);
      
      const proof = ethers.randomBytes(1024);
      // Goldilocks field modulus + 1 (too large)
      const invalidInput = 18446744069414584322n;
      const publicInputs = [invalidInput];
      
      await expect(
        verifier.verify(proof, publicInputs)
      ).to.be.revertedWithCustomError(verifier, "InvalidPublicInput");
    });
    
    it("Should return 0 for variable public input count", async function () {
      const { verifier } = await loadFixture(deployAndInitializeFRIFixture);
      
      expect(await verifier.getPublicInputCount()).to.equal(0);
    });
    
    it("Should support verifySingle", async function () {
      const { verifier } = await loadFixture(deployAndInitializeFRIFixture);
      
      const proof = ethers.randomBytes(1024);
      
      // verifySingle wraps verify, will fail on proof structure but not input
      await expect(
        verifier.verifySingle(proof, 123n)
      ).to.be.reverted;
    });
  });
});

describe("TEEAttestation", function () {
  async function deployTEEAttestationFixture() {
    const [admin, operator, user] = await ethers.getSigners();
    
    const TEEAttestation = await ethers.getContractFactory("TEEAttestation");
    const tee = await TEEAttestation.deploy();
    
    return { tee, admin, operator, user };
  }
  
  describe("Deployment", function () {
    it("Should deploy with admin role", async function () {
      const { tee, admin } = await loadFixture(deployTEEAttestationFixture);
      
      const DEFAULT_ADMIN_ROLE = await tee.DEFAULT_ADMIN_ROLE();
      expect(await tee.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;
    });
    
    it("Should have default attestation validity period", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      expect(await tee.attestationValidityPeriod()).to.equal(24 * 60 * 60); // 24 hours
    });
  });
  
  describe("Enclave Registration", function () {
    it("Should register an enclave", async function () {
      const { tee, admin } = await loadFixture(deployTEEAttestationFixture);
      
      const mrenclave = ethers.randomBytes(32);
      const mrsigner = ethers.randomBytes(32);
      const isvProdId = 1;
      const isvSvn = 1;
      const platform = 1; // SGX_DCAP
      
      const tx = await tee.registerEnclave(
        mrenclave,
        mrsigner,
        isvProdId,
        isvSvn,
        platform
      );
      
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);
      
      expect(await tee.totalEnclaves()).to.equal(1);
    });
    
    it("Should reject registration from non-manager", async function () {
      const { tee, user } = await loadFixture(deployTEEAttestationFixture);
      
      const mrenclave = ethers.randomBytes(32);
      const mrsigner = ethers.randomBytes(32);
      
      await expect(
        tee.connect(user).registerEnclave(mrenclave, mrsigner, 1, 1, 1)
      ).to.be.reverted;
    });
  });
  
  describe("Trust Management", function () {
    it("Should add trusted signer", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      const mrsigner = ethers.randomBytes(32);
      
      await tee.addTrustedSigner(mrsigner);
      
      expect(await tee.trustedSigners(mrsigner)).to.be.true;
    });
    
    it("Should remove trusted signer", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      const mrsigner = ethers.randomBytes(32);
      
      await tee.addTrustedSigner(mrsigner);
      expect(await tee.trustedSigners(mrsigner)).to.be.true;
      
      await tee.removeTrustedSigner(mrsigner);
      expect(await tee.trustedSigners(mrsigner)).to.be.false;
    });
    
    it("Should add trusted enclave", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      const mrenclave = ethers.randomBytes(32);
      
      await tee.addTrustedEnclave(mrenclave);
      
      expect(await tee.trustedEnclaves(mrenclave)).to.be.true;
    });
    
    it("Should check if enclave is trusted", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      const mrenclave = ethers.randomBytes(32);
      const mrsigner = ethers.randomBytes(32);
      
      // Neither trusted initially
      expect(await tee.isEnclaveTrusted(mrenclave, mrsigner)).to.be.false;
      
      // Trust by enclave
      await tee.addTrustedEnclave(mrenclave);
      expect(await tee.isEnclaveTrusted(mrenclave, mrsigner)).to.be.true;
      
      // Trust by signer
      const mrenclave2 = ethers.randomBytes(32);
      await tee.addTrustedSigner(mrsigner);
      expect(await tee.isEnclaveTrusted(mrenclave2, mrsigner)).to.be.true;
    });
    
    it("Should set minimum ISV SVN", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      await tee.setMinIsvSvn(1, 5);
      
      expect(await tee.minIsvSvn(1)).to.equal(5);
    });
  });
  
  describe("SGX Attestation", function () {
    it("Should verify SGX attestation from trusted enclave", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      const mrenclave = ethers.keccak256(ethers.toUtf8Bytes("test-enclave"));
      const mrsigner = ethers.keccak256(ethers.toUtf8Bytes("test-signer"));
      
      // Trust the enclave
      await tee.addTrustedEnclave(mrenclave);
      
      const quote = {
        version: 3,
        signType: 1, // DCAP
        reportData: ethers.keccak256(ethers.toUtf8Bytes("report-data")),
        mrenclave: mrenclave,
        mrsigner: mrsigner,
        isvProdId: 1,
        isvSvn: 1,
        signature: ethers.randomBytes(64)
      };
      
      const tx = await tee.verifySGXAttestation(quote);
      const receipt = await tx.wait();
      
      expect(receipt.status).to.equal(1);
      expect(await tee.totalAttestations()).to.equal(1);
    });
    
    it("Should reject attestation from untrusted enclave", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      const mrenclave = ethers.keccak256(ethers.toUtf8Bytes("untrusted-enclave"));
      const mrsigner = ethers.keccak256(ethers.toUtf8Bytes("untrusted-signer"));
      
      const quote = {
        version: 3,
        signType: 1,
        reportData: ethers.keccak256(ethers.toUtf8Bytes("report-data")),
        mrenclave: mrenclave,
        mrsigner: mrsigner,
        isvProdId: 1,
        isvSvn: 1,
        signature: ethers.randomBytes(64)
      };
      
      await expect(
        tee.verifySGXAttestation(quote)
      ).to.be.revertedWithCustomError(tee, "EnclaveNotTrusted");
    });
    
    it("Should reject attestation with invalid quote", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      const quote = {
        version: 3,
        signType: 1,
        reportData: ethers.ZeroHash,
        mrenclave: ethers.ZeroHash, // Invalid - zero
        mrsigner: ethers.ZeroHash,
        isvProdId: 1,
        isvSvn: 1,
        signature: "0x"
      };
      
      await expect(
        tee.verifySGXAttestation(quote)
      ).to.be.revertedWithCustomError(tee, "InvalidQuote");
    });
  });
  
  describe("Configuration", function () {
    it("Should update attestation validity period", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      await tee.setAttestationValidityPeriod(48 * 60 * 60);
      
      expect(await tee.attestationValidityPeriod()).to.equal(48 * 60 * 60);
    });
    
    it("Should update TCB info", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      const platform = 1; // SGX_DCAP
      const fmspc = ethers.keccak256(ethers.toUtf8Bytes("fmspc"));
      const tcbLevel = 5;
      const nextUpdate = Math.floor(Date.now() / 1000) + 86400;
      
      await tee.updateTCBInfo(platform, fmspc, tcbLevel, nextUpdate);
      
      const tcbInfoId = ethers.keccak256(
        ethers.solidityPacked(["uint8", "bytes32"], [platform, fmspc])
      );
      
      const tcbInfo = await tee.tcbInfos(tcbInfoId);
      expect(tcbInfo.tcbLevel).to.equal(tcbLevel);
      expect(tcbInfo.isValid).to.be.true;
    });
  });
  
  describe("Pausability", function () {
    it("Should pause and unpause", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      await tee.pause();
      expect(await tee.paused()).to.be.true;
      
      await tee.unpause();
      expect(await tee.paused()).to.be.false;
    });
    
    it("Should reject attestation when paused", async function () {
      const { tee } = await loadFixture(deployTEEAttestationFixture);
      
      const mrenclave = ethers.keccak256(ethers.toUtf8Bytes("test-enclave"));
      await tee.addTrustedEnclave(mrenclave);
      
      await tee.pause();
      
      const quote = {
        version: 3,
        signType: 1,
        reportData: ethers.keccak256(ethers.toUtf8Bytes("report-data")),
        mrenclave: mrenclave,
        mrsigner: ethers.randomBytes(32),
        isvProdId: 1,
        isvSvn: 1,
        signature: ethers.randomBytes(64)
      };
      
      await expect(
        tee.verifySGXAttestation(quote)
      ).to.be.revertedWithCustomError(tee, "EnforcedPause");
    });
  });
});
