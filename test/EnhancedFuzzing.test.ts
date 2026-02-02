import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, toHex, zeroHash } from "viem";

/**
 * Enhanced Fuzzing Tests for Hardhat v3 (viem)
 */
describe("Enhanced Fuzzing (viem)", function () {
  this.timeout(180000);

  function randomBytes32(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return toHex(bytes);
  }

  function randomBytes(length: number): `0x${string}` {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return toHex(bytes);
  }

  describe("Random Input Fuzzing", function () {
    it("Should handle 50 random commitments", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      for (let i = 0; i < 50; i++) {
        const commitment = randomBytes32();
        const nullifier = randomBytes32();
        const state = randomBytes(64 + Math.floor(Math.random() * 192));

        await stateContainer.write.registerState([
          state,
          commitment,
          nullifier,
          toHex(toBytes("proof")),

          zeroHash
        ], { account: user1.account });

        expect(await stateContainer.read.isStateActive([commitment])).to.be.true;
      }

      expect(await stateContainer.read.totalStates()).to.equal(50n);
    });

    it("Should handle 50 random nullifiers", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();

      const usedNullifiers = new Set<string>();

      for (let i = 0; i < 50; i++) {
        const nullifier = randomBytes32();

        if (usedNullifiers.has(nullifier.toLowerCase())) {
          continue;
        }

        await nullifierRegistry.write.registerNullifier([nullifier, zeroHash], { account: owner.account });
        usedNullifiers.add(nullifier.toLowerCase());

        expect(await nullifierRegistry.read.exists([nullifier])).to.be.true;
      }

      expect(await nullifierRegistry.read.totalNullifiers()).to.be.greaterThan(40n);
    });

    it("Should reject duplicate random nullifiers", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();

      const nullifier = randomBytes32();
      await nullifierRegistry.write.registerNullifier([nullifier, zeroHash], { account: owner.account });

      try {
        await nullifierRegistry.write.registerNullifier([nullifier, zeroHash], { account: owner.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("NullifierAlreadyExists");
      }
    });
  });

  describe("Boundary Value Testing", function () {
    it("Should handle minimum state size", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const minState = "0x01" as `0x${string}`;
      const commitment = randomBytes32();

      await stateContainer.write.registerState([
        minState,
        commitment,
        randomBytes32(),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      const state = await stateContainer.read.getState([commitment]);
      expect(state.encryptedState.toLowerCase()).to.equal(minState.toLowerCase());
    });

    it("Should handle 1KB state", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const largeState = randomBytes(1024);
      const commitment = randomBytes32();

      await stateContainer.write.registerState([
        largeState,
        commitment,
        randomBytes32(),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      const state = await stateContainer.read.getState([commitment]);
      expect(state.encryptedState.toLowerCase()).to.equal(largeState.toLowerCase());
    });

    it("Should handle max bytes32 commitment", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const maxCommitment = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" as `0x${string}`;

      await stateContainer.write.registerState([
        toHex(toBytes("max_commit_test")),
        maxCommitment,
        randomBytes32(),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      expect(await stateContainer.read.isStateActive([maxCommitment])).to.be.true;
    });
  });

  describe("Property-Based Testing", function () {
    it("Property: Nullifier uniqueness", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const usedNullifiers = new Set<string>();

      for (let i = 0; i < 30; i++) {
        const nullifier = randomBytes32();

        if (usedNullifiers.has(nullifier.toLowerCase())) {
          // Should fail
          try {
            await stateContainer.write.registerState([
              toHex(toBytes(`state_${i}`)),
              randomBytes32(),
              nullifier,
              toHex(toBytes("proof")),
    
              zeroHash
            ], { account: user1.account });
            expect.fail("Should have reverted for duplicate");
          } catch (error: any) {
            expect(error.message).to.include("NullifierAlreadyUsed");
          }
        } else {
          // Should succeed
          await stateContainer.write.registerState([
            toHex(toBytes(`state_${i}`)),
            randomBytes32(),
            nullifier,
            toHex(toBytes("proof")),
  
            zeroHash
          ], { account: user1.account });
          usedNullifiers.add(nullifier.toLowerCase());
        }
      }
    });

    it("Property: State count monotonically increases", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      let previousCount = await stateContainer.read.totalStates();

      for (let i = 0; i < 20; i++) {
        await stateContainer.write.registerState([
          toHex(toBytes(`mono_state_${i}`)),
          randomBytes32(),
          randomBytes32(),
          toHex(toBytes("proof")),

          zeroHash
        ], { account: user1.account });

        const currentCount = await stateContainer.read.totalStates();
        expect(currentCount).to.be.greaterThan(previousCount);
        previousCount = currentCount;
      }
    });

    it("Property: Merkle root changes with each registration", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();

      const roots: string[] = [];
      roots.push(await nullifierRegistry.read.merkleRoot());

      for (let i = 0; i < 10; i++) {
        await nullifierRegistry.write.registerNullifier([randomBytes32(), zeroHash], { account: owner.account });

        const newRoot = await nullifierRegistry.read.merkleRoot();
        expect(roots).to.not.include(newRoot);
        roots.push(newRoot);
      }

      // All roots unique
      expect(new Set(roots).size).to.equal(roots.length);
    });
  });

  describe("Stress Testing", function () {
    it("Should handle rapid sequential operations", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const startTime = Date.now();
      const count = 50;

      for (let i = 0; i < count; i++) {
        await stateContainer.write.registerState([
          toHex(toBytes(`stress_${i}`)),
          randomBytes32(),
          randomBytes32(),
          toHex(toBytes("proof")),

          zeroHash
        ], { account: user1.account });
      }

      const endTime = Date.now();
      const totalTime = endTime - startTime;
      const tps = (count * 1000) / totalTime;

      console.log(`    ${count} operations in ${totalTime}ms (${tps.toFixed(2)} TPS)`);
      expect(tps).to.be.greaterThan(5);
    });
  });

  describe("Error Injection", function () {
    it("Should handle verification failures gracefully", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([false]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      try {
        await stateContainer.write.registerState([
          toHex(toBytes("fail_state")),
          randomBytes32(),
          randomBytes32(),
          toHex(toBytes("proof")),

          zeroHash
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("InvalidProof");
      }
    });

    it("Should reject empty state", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      try {
        await stateContainer.write.registerState([
          "0x",
          randomBytes32(),
          randomBytes32(),
          toHex(toBytes("proof")),

          zeroHash
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("EmptyEncryptedState");
      }
    });
  });

  describe("Concurrency Simulation", function () {
    it("Should handle multiple users", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1, user2, user3] = await viem.getWalletClients();

      // All users register states
      await stateContainer.write.registerState([
        toHex(toBytes("user1_state")),
        randomBytes32(),
        randomBytes32(),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      await stateContainer.write.registerState([
        toHex(toBytes("user2_state")),
        randomBytes32(),
        randomBytes32(),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user2.account });

      await stateContainer.write.registerState([
        toHex(toBytes("user3_state")),
        randomBytes32(),
        randomBytes32(),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user3.account });

      expect(await stateContainer.read.totalStates()).to.equal(3n);
    });

    it("Should handle race for same nullifier", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1, user2] = await viem.getWalletClients();

      const sharedNullifier = randomBytes32();

      // First user succeeds
      await stateContainer.write.registerState([
        toHex(toBytes("user1_state")),
        randomBytes32(),
        sharedNullifier,
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      // Second user fails
      try {
        await stateContainer.write.registerState([
          toHex(toBytes("user2_state")),
          randomBytes32(),
          sharedNullifier,
          toHex(toBytes("proof")),

          zeroHash
        ], { account: user2.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("NullifierAlreadyUsed");
      }
    });
  });
});
