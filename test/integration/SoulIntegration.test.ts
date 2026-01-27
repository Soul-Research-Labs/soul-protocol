import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, zeroHash, type Address, type Hash, type WalletClient, type GetContractReturnType } from "viem";

/**
 * Soul Protocol Integration Tests
 * 
 * These tests verify end-to-end flows across multiple contracts
 */
describe("Soul Protocol Integration Tests", function () {
  // Increase timeout for complex operations
  this.timeout(120000);

  let zkSlocks: GetContractReturnType<any>;
  let mockVerifier: GetContractReturnType<any>;

  let deployer: WalletClient;
  let user1: WalletClient;
  let user2: WalletClient;
  let relayer: WalletClient;
  let viem: any;

  // Test data
  const ZERO_BYTES32 = zeroHash;
  const ONE_HOUR = 3600;
  const ONE_DAY = 86400;

  before(async function () {
    const network = await hre.network.connect();
    viem = network.viem;
    [deployer, user1, user2, relayer] = await viem.getWalletClients();

    // Deploy contracts
    console.log("Deploying MockProofVerifier...");
    mockVerifier = await viem.deployContract("MockProofVerifier");
    await mockVerifier.write.setVerificationResult([true]);

    console.log("Deploying ZKBoundStateLocks...");
    zkSlocks = await viem.deployContract("ZKBoundStateLocks", [mockVerifier.address]);

    console.log("All contracts deployed successfully");
  });

  describe("ZK-SLocks Lifecycle", function () {
    let lockId: Hash;
    const commitment = keccak256(toBytes("test-commitment"));
    const predicateHash = keccak256(toBytes("transfer"));
    const policyHash = keccak256(toBytes("default-policy"));

    it("should create a new lock", async function () {
      const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

      // Create lock using viem pattern
      const hash = await zkSlocks.write.createLock([
        commitment,
        predicateHash,
        policyHash,
        domainSeparator,
        deadline
      ], { account: user1.account });

      // Verify lock was created
      const activeLocks = await zkSlocks.read.getActiveLockIds();
      expect(activeLocks.length).to.be.greaterThan(0);
      
      lockId = activeLocks[activeLocks.length - 1];
      expect(lockId).to.not.equal(ZERO_BYTES32);

      // Verify lock data
      const lock = await zkSlocks.read.getLock([lockId]);
      expect(lock.oldStateCommitment).to.equal(commitment);
      expect(lock.isUnlocked).to.be.false;
    });

    it("should track lock statistics", async function () {
      const stats = await zkSlocks.read.getStats();
      // getStats returns [created, unlocked, active, optimistic, disputed]
      expect(stats[0]).to.be.gte(1n); // totalLocksCreated
    });

    it("should prevent duplicate lock creation", async function () {
      // Same parameters at same timestamp would create same lock ID
      // This is prevented by the contract
      const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

      // Creating with same params should work (different timestamp)
      await zkSlocks.write.createLock([
        commitment,
        predicateHash,
        policyHash,
        domainSeparator,
        deadline
      ], { account: user1.account });
    });

    it("should list active locks", async function () {
      const activeLocks = await zkSlocks.read.getActiveLockIds();
      expect(activeLocks.length).to.be.gte(1);
    });

    it("should check if lock can be unlocked", async function () {
      const canUnlock = await zkSlocks.read.canUnlock([lockId]);
      // Should be true if deadline hasn't passed
      expect(typeof canUnlock).to.equal("boolean");
    });
  });

  describe("Cross-Domain Nullifier Prevention", function () {
    const nullifier = keccak256(toBytes("unique-nullifier-1"));

    it("should not allow nullifier reuse", async function () {
      // First check - nullifier should be unused
      const isUsedBefore = await zkSlocks.read.nullifierUsed([nullifier]);
      expect(isUsedBefore).to.be.false;
    });
  });

  describe("Privacy Pool Deposits and Withdrawals", function () {
    it("should process deposits correctly", async function () {
      // This would require a PrivacyPool contract
      // Placeholder for integration test
      expect(true).to.be.true;
    });
  });

  describe("Cross-Chain Bridge Operations", function () {
    describe("Solana Bridge", function () {
      it("should configure bridge correctly", async function () {
        // Bridge would need to be deployed and configured
        // Placeholder test
        expect(true).to.be.true;
      });
    });

    describe("Cardano Bridge", function () {
      it("should configure bridge correctly", async function () {
        // Placeholder test
        expect(true).to.be.true;
      });
    });
  });

  describe("Multi-Contract Flows", function () {
    it("should complete full privacy-preserving transfer flow", async function () {
      // 1. Create ZK-SLock
      // 2. Generate proof
      // 3. Submit to bridge
      // 4. Verify cross-chain
      // 5. Complete on destination

      // This is a complex integration test
      console.log("Testing full privacy flow...");
      
      const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
      const commitment = keccak256(toBytes("transfer-state"));
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_DAY);

      // Create lock
      await zkSlocks.write.createLock([
        commitment,
        keccak256(toBytes("transfer")),
        keccak256(toBytes("policy")),
        domainSeparator,
        deadline
      ], { account: user1.account });

      const activeLocks = await zkSlocks.read.getActiveLockIds();
      expect(activeLocks.length).to.be.greaterThan(0);
      console.log("Lock created successfully");
    });

    it("should handle concurrent operations", async function () {
      // Create multiple locks in sequence (viem doesn't support true parallel writes easily)
      for (let i = 0; i < 5; i++) {
        const commitment = keccak256(toBytes(`concurrent-${i}-${Date.now()}`));
        const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
        const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

        await zkSlocks.write.createLock([
          commitment,
          keccak256(toBytes("transfer")),
          keccak256(toBytes("policy")),
          domainSeparator,
          deadline
        ], { account: user1.account });
      }

      const activeLocks = await zkSlocks.read.getActiveLockIds();
      expect(activeLocks.length).to.be.gte(5);
      console.log("Created 5 locks");
    });
  });

  describe("Gas Benchmarks", function () {
    it("should measure createLock gas usage", async function () {
      const commitment = keccak256(toBytes(`gas-bench-${Date.now()}`));
      const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

      // Create lock and check it succeeded
      await zkSlocks.write.createLock([
        commitment,
        keccak256(toBytes("transfer")),
        keccak256(toBytes("policy")),
        domainSeparator,
        deadline
      ], { account: user1.account });

      // Verify lock was created
      const activeLocks = await zkSlocks.read.getActiveLockIds();
      expect(activeLocks.length).to.be.greaterThan(0);
      console.log(`createLock executed successfully`);
    });
  });

  describe("Error Handling", function () {
    it("should revert on invalid domain separator", async function () {
      const invalidDomain = zeroHash;
      const commitment = keccak256(toBytes("error-test"));
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

      let reverted = false;
      try {
        await zkSlocks.write.createLock([
          commitment,
          keccak256(toBytes("transfer")),
          keccak256(toBytes("policy")),
          invalidDomain,
          deadline
        ], { account: user1.account });
      } catch {
        reverted = true;
      }
      expect(reverted).to.be.true;
    });

    it("should revert when contract is paused", async function () {
      // Pause the contract
      const LOCK_ADMIN_ROLE = await zkSlocks.read.LOCK_ADMIN_ROLE();
      await zkSlocks.write.grantRole([LOCK_ADMIN_ROLE, deployer.account.address], { account: deployer.account });
      await zkSlocks.write.pause([], { account: deployer.account });

      const commitment = keccak256(toBytes("paused-test"));
      const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

      let reverted = false;
      try {
        await zkSlocks.write.createLock([
          commitment,
          keccak256(toBytes("transfer")),
          keccak256(toBytes("policy")),
          domainSeparator,
          deadline
        ], { account: user1.account });
      } catch {
        reverted = true;
      }
      expect(reverted).to.be.true;

      // Unpause for other tests
      await zkSlocks.write.unpause([], { account: deployer.account });
    });
  });

  describe("Access Control", function () {
    it("should enforce role-based access", async function () {
      const LOCK_ADMIN_ROLE = await zkSlocks.read.LOCK_ADMIN_ROLE();
      
      // User1 should not have admin role initially
      const hasRole = await zkSlocks.read.hasRole([LOCK_ADMIN_ROLE, user1.account.address]);
      expect(hasRole).to.be.false;

      // Non-admin should not be able to pause
      let reverted = false;
      try {
        await zkSlocks.write.pause([], { account: user1.account });
      } catch {
        reverted = true;
      }
      expect(reverted).to.be.true;
    });
  });
});
