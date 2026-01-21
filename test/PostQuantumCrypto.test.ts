import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, toHex, zeroHash, Address, Hex } from "viem";

/**
 * Post-Quantum Cryptography Test Suite
 * Tests PQC contracts: PostQuantumSignatureVerifier, HybridCryptoVerifier, PQCKeyRegistry, PQCContainerExtension
 */
describe("Post-Quantum Cryptography (viem)", function () {
  this.timeout(120000);

  // Helper to generate mock key data
  function generateMockKey(size: number): Hex {
    const bytes = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return toHex(bytes);
  }

  // Helper to generate mock signature
  function generateMockSignature(size: number): Hex {
    const bytes = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return toHex(bytes);
  }

  describe("PQCKeyRegistry", function () {
    it("Should deploy PQCKeyRegistry", async function () {
      const { viem } = await hre.network.connect();
      
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      expect(keyRegistry.address).to.not.equal(zeroHash);
    });

    it("Should register a Dilithium2 key", async function () {
      const { viem } = await hre.network.connect();
      
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      const [admin, user1] = await viem.getWalletClients();

      const dilithiumPubKey = generateMockKey(1312); // Dilithium2 public key size
      const oneYear = BigInt(365 * 24 * 60 * 60);
      const now = BigInt(Math.floor(Date.now() / 1000));
      const expiresAt = now + oneYear;

      // Register key (DILITHIUM2 = 0)
      const hash = await keyRegistry.write.registerKey([0, dilithiumPubKey, expiresAt], {
        account: user1.account
      });

      // Verify transaction succeeded
      expect(hash).to.not.be.undefined;

      // Get key stats
      const [total, active, revoked] = await keyRegistry.read.getStats();
      expect(total).to.equal(1n);
      expect(active).to.equal(1n);
      expect(revoked).to.equal(0n);
    });

    it("Should get owner keys", async function () {
      const { viem } = await hre.network.connect();
      
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      const [admin, user1] = await viem.getWalletClients();

      const pubKey = generateMockKey(1312);
      const oneYear = BigInt(365 * 24 * 60 * 60);
      const now = BigInt(Math.floor(Date.now() / 1000));
      const expiresAt = now + oneYear;

      await keyRegistry.write.registerKey([0, pubKey, expiresAt], {
        account: user1.account
      });

      const keys = await keyRegistry.read.getOwnerKeys([user1.account.address]);
      expect(keys.length).to.equal(1);
    });

    it("Should track algorithm key counts", async function () {
      const { viem } = await hre.network.connect();
      
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      const [admin, user1, user2] = await viem.getWalletClients();

      const oneYear = BigInt(365 * 24 * 60 * 60);
      const now = BigInt(Math.floor(Date.now() / 1000));
      const expiresAt = now + oneYear;

      // Register Dilithium2 key
      await keyRegistry.write.registerKey([0, generateMockKey(1312), expiresAt], {
        account: user1.account
      });

      // Register another Dilithium2 key
      await keyRegistry.write.registerKey([0, generateMockKey(1312), expiresAt], {
        account: user2.account
      });

      // Register Dilithium3 key  
      await keyRegistry.write.registerKey([1, generateMockKey(1952), expiresAt], {
        account: user1.account
      });

      // Check stats
      const [total, active, revoked] = await keyRegistry.read.getStats();
      expect(total).to.equal(3n);
      expect(active).to.equal(3n);
    });
  });

  describe("PostQuantumSignatureVerifier", function () {
    it("Should deploy PostQuantumSignatureVerifier", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      expect(pqVerifier.address).to.not.equal(zeroHash);
    });

    it("Should support Dilithium algorithms", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");

      // Check supported algorithms (0 = DILITHIUM2, 1 = DILITHIUM3, 2 = DILITHIUM5)
      expect(await pqVerifier.read.supportedAlgorithms([0])).to.be.true;
      expect(await pqVerifier.read.supportedAlgorithms([1])).to.be.true;
      expect(await pqVerifier.read.supportedAlgorithms([2])).to.be.true;
    });

    it("Should support SPHINCS+ algorithms", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");

      // SPHINCS+ variants (3 = SPHINCS_SHA2_128F, 5 = SPHINCS_SHA2_256F)
      expect(await pqVerifier.read.supportedAlgorithms([3])).to.be.true;
      expect(await pqVerifier.read.supportedAlgorithms([5])).to.be.true;
    });

    it("Should support Falcon algorithms", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");

      // Falcon (7 = FALCON512, 8 = FALCON1024)
      expect(await pqVerifier.read.supportedAlgorithms([7])).to.be.true;
      expect(await pqVerifier.read.supportedAlgorithms([8])).to.be.true;
    });

    it("Should toggle algorithm support", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const [admin] = await viem.getWalletClients();

      // Disable Dilithium2 (algorithm 0)
      await pqVerifier.write.setAlgorithmSupport([0, false], {
        account: admin.account
      });

      expect(await pqVerifier.read.supportedAlgorithms([0])).to.be.false;

      // Re-enable it
      await pqVerifier.write.setAlgorithmSupport([0, true], {
        account: admin.account
      });

      expect(await pqVerifier.read.supportedAlgorithms([0])).to.be.true;
    });

    it("Should set challenge bond", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const [admin] = await viem.getWalletClients();

      // Set new challenge bond
      const newBond = 500000000000000000n; // 0.5 ETH
      await pqVerifier.write.setChallengeBond([newBond], {
        account: admin.account
      });

      expect(await pqVerifier.read.challengeBond()).to.equal(newBond);
    });
  });

  describe("HybridCryptoVerifier", function () {
    it("Should deploy HybridCryptoVerifier with PQ verifier", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);
      
      expect(hybridVerifier.address).to.not.equal(zeroHash);
      expect((await hybridVerifier.read.pqVerifier()).toLowerCase()).to.equal(pqVerifier.address.toLowerCase());
    });

    it("Should support default hybrid modes", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);

      // Check supported modes (0 = ECDSA_DILITHIUM2, 1 = ECDSA_DILITHIUM3, etc.)
      expect(await hybridVerifier.read.supportedModes([0])).to.be.true; // ECDSA_DILITHIUM2
      expect(await hybridVerifier.read.supportedModes([1])).to.be.true; // ECDSA_DILITHIUM3
      expect(await hybridVerifier.read.supportedModes([2])).to.be.true; // ECDSA_DILITHIUM5
    });

    it("Should derive hybrid key deterministically", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);

      const classicalSecret = keccak256(toBytes("classical secret"));
      const pqSecret = keccak256(toBytes("pq secret"));
      const context = keccak256(toBytes("key derivation context"));

      const derivedKey1 = await hybridVerifier.read.deriveHybridKey([classicalSecret, pqSecret, context]);
      const derivedKey2 = await hybridVerifier.read.deriveHybridKey([classicalSecret, pqSecret, context]);

      expect(derivedKey1).to.equal(derivedKey2);
    });

    it("Should derive different keys for different contexts", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);

      const classicalSecret = keccak256(toBytes("classical secret"));
      const pqSecret = keccak256(toBytes("pq secret"));
      const context1 = keccak256(toBytes("context 1"));
      const context2 = keccak256(toBytes("context 2"));

      const derivedKey1 = await hybridVerifier.read.deriveHybridKey([classicalSecret, pqSecret, context1]);
      const derivedKey2 = await hybridVerifier.read.deriveHybridKey([classicalSecret, pqSecret, context2]);

      expect(derivedKey1).to.not.equal(derivedKey2);
    });

    it("Should register hybrid key pair", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);
      const [admin, user1] = await viem.getWalletClients();

      const pqPubKey = generateMockKey(1312);
      const oneYear = BigInt(365 * 24 * 60 * 60);
      const now = BigInt(Math.floor(Date.now() / 1000));
      const expiresAt = now + oneYear;

      // Register hybrid key (ECDSA_DILITHIUM2 = 0)
      const hash = await hybridVerifier.write.registerHybridKey([
        user1.account.address,
        pqPubKey,
        0, // ECDSA_DILITHIUM2 mode
        expiresAt
      ], {
        account: user1.account
      });

      expect(hash).to.not.be.undefined;
    });

    it("Should get hybrid key hash for owner", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);
      const [admin, user1] = await viem.getWalletClients();

      const pqPubKey = generateMockKey(1312);
      const oneYear = BigInt(365 * 24 * 60 * 60);
      const now = BigInt(Math.floor(Date.now() / 1000));
      const expiresAt = now + oneYear;

      await hybridVerifier.write.registerHybridKey([
        user1.account.address,
        pqPubKey,
        0,
        expiresAt
      ], {
        account: user1.account
      });

      const keyHash = await hybridVerifier.read.getHybridKeyHash([user1.account.address]);
      expect(keyHash).to.not.equal(zeroHash);
    });
  });

  describe("PQCContainerExtension", function () {
    it("Should deploy PQCContainerExtension with linked contracts", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      
      const containerExtension = await viem.deployContract("PQCContainerExtension", [
        pqVerifier.address,
        hybridVerifier.address,
        keyRegistry.address
      ]);

      expect((await containerExtension.read.pqVerifier()).toLowerCase()).to.equal(pqVerifier.address.toLowerCase());
      expect((await containerExtension.read.hybridVerifier()).toLowerCase()).to.equal(hybridVerifier.address.toLowerCase());
      expect((await containerExtension.read.keyRegistry()).toLowerCase()).to.equal(keyRegistry.address.toLowerCase());
    });

    it("Should set minimum security level", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      const containerExtension = await viem.deployContract("PQCContainerExtension", [
        pqVerifier.address,
        hybridVerifier.address,
        keyRegistry.address
      ]);

      const [admin] = await viem.getWalletClients();

      await containerExtension.write.setMinSecurityLevel([3], {
        account: admin.account
      });

      expect(await containerExtension.read.minSecurityLevel()).to.equal(3);
    });

    it("Should set mandatory hybrid mode", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      const containerExtension = await viem.deployContract("PQCContainerExtension", [
        pqVerifier.address,
        hybridVerifier.address,
        keyRegistry.address
      ]);

      const [admin] = await viem.getWalletClients();

      await containerExtension.write.setMandatoryHybridMode([true], {
        account: admin.account
      });

      expect(await containerExtension.read.mandatoryHybridMode()).to.be.true;
    });

    it("Should return empty containers for unknown key", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      const containerExtension = await viem.deployContract("PQCContainerExtension", [
        pqVerifier.address,
        hybridVerifier.address,
        keyRegistry.address
      ]);

      const randomKeyHash = keccak256(toBytes("random key"));
      const containers = await containerExtension.read.getContainersByKey([randomKeyHash]);
      
      expect(containers.length).to.equal(0);
    });

    it("Should check if container has PQC extension", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      const containerExtension = await viem.deployContract("PQCContainerExtension", [
        pqVerifier.address,
        hybridVerifier.address,
        keyRegistry.address
      ]);

      const randomContainerId = keccak256(toBytes("random container"));
      const hasExtension = await containerExtension.read.hasPQCExtension([randomContainerId]);
      
      expect(hasExtension).to.be.false;
    });

    it("Should update verifiers", async function () {
      const { viem } = await hre.network.connect();
      
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      const containerExtension = await viem.deployContract("PQCContainerExtension", [
        pqVerifier.address,
        hybridVerifier.address,
        keyRegistry.address
      ]);

      const [admin] = await viem.getWalletClients();

      // Deploy new verifiers
      const newPqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const newHybridVerifier = await viem.deployContract("HybridCryptoVerifier", [newPqVerifier.address]);
      const newKeyRegistry = await viem.deployContract("PQCKeyRegistry");

      await containerExtension.write.updateVerifiers([
        newPqVerifier.address,
        newHybridVerifier.address,
        newKeyRegistry.address
      ], {
        account: admin.account
      });

      expect((await containerExtension.read.pqVerifier()).toLowerCase()).to.equal(newPqVerifier.address.toLowerCase());
      expect((await containerExtension.read.hybridVerifier()).toLowerCase()).to.equal(newHybridVerifier.address.toLowerCase());
      expect((await containerExtension.read.keyRegistry()).toLowerCase()).to.equal(newKeyRegistry.address.toLowerCase());
    });
  });

  describe("Integration", function () {
    it("Should deploy full PQC stack", async function () {
      const { viem } = await hre.network.connect();
      
      // Deploy all contracts
      const pqVerifier = await viem.deployContract("PostQuantumSignatureVerifier");
      const hybridVerifier = await viem.deployContract("HybridCryptoVerifier", [pqVerifier.address]);
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      const containerExtension = await viem.deployContract("PQCContainerExtension", [
        pqVerifier.address,
        hybridVerifier.address,
        keyRegistry.address
      ]);

      // Verify all deployed
      expect(pqVerifier.address).to.not.equal(zeroHash);
      expect(hybridVerifier.address).to.not.equal(zeroHash);
      expect(keyRegistry.address).to.not.equal(zeroHash);
      expect(containerExtension.address).to.not.equal(zeroHash);

      // Verify linkage (case-insensitive)
      expect((await containerExtension.read.pqVerifier()).toLowerCase()).to.equal(pqVerifier.address.toLowerCase());
      expect((await hybridVerifier.read.pqVerifier()).toLowerCase()).to.equal(pqVerifier.address.toLowerCase());
    });

    it("Should register PQC key and track statistics", async function () {
      const { viem } = await hre.network.connect();
      
      const keyRegistry = await viem.deployContract("PQCKeyRegistry");
      const [admin, user1, user2, user3] = await viem.getWalletClients();

      const oneYear = BigInt(365 * 24 * 60 * 60);
      const now = BigInt(Math.floor(Date.now() / 1000));
      const expiresAt = now + oneYear;

      // Register keys for different users with different algorithms
      await keyRegistry.write.registerKey([0, generateMockKey(1312), expiresAt], { account: user1.account }); // Dilithium2
      await keyRegistry.write.registerKey([1, generateMockKey(1952), expiresAt], { account: user2.account }); // Dilithium3
      await keyRegistry.write.registerKey([7, generateMockKey(897), expiresAt], { account: user3.account });  // Falcon512

      const [total, active, revoked] = await keyRegistry.read.getStats();
      expect(total).to.equal(3n);
      expect(active).to.equal(3n);
      expect(revoked).to.equal(0n);

      // Check algorithm-specific counts
      expect(await keyRegistry.read.algorithmKeyCount([0])).to.equal(1n); // Dilithium2
      expect(await keyRegistry.read.algorithmKeyCount([1])).to.equal(1n); // Dilithium3
      expect(await keyRegistry.read.algorithmKeyCount([7])).to.equal(1n); // Falcon512
    });
  });
});
