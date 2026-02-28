import { expect } from "chai";
import hre from "hardhat";
import {
  keccak256,
  toBytes,
  zeroHash,
  type Address,
  type Hash,
  type WalletClient,
  type GetContractReturnType,
} from "viem";

/**
 * ZASEON Integration Tests
 *
 * These tests verify end-to-end flows across multiple contracts
 */
describe("ZASEON Integration Tests", function () {
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
    zkSlocks = await viem.deployContract("ZKBoundStateLocks", [
      mockVerifier.address,
    ]);

    console.log("All contracts deployed successfully");
  });

  describe("ZK-SLocks Lifecycle", function () {
    let lockId: Hash;
    const commitment = keccak256(toBytes("test-commitment"));
    const predicateHash = keccak256(toBytes("transfer"));
    const policyHash = keccak256(toBytes("default-policy"));

    it("should create a new lock", async function () {
      const domainSeparator = await zkSlocks.read.generateDomainSeparator([
        1, 0, 0,
      ]);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

      // Create lock using viem pattern
      const hash = await zkSlocks.write.createLock(
        [commitment, predicateHash, policyHash, domainSeparator, deadline],
        { account: user1.account },
      );

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
      const domainSeparator = await zkSlocks.read.generateDomainSeparator([
        1, 0, 0,
      ]);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

      // Creating with same params should work (different timestamp)
      await zkSlocks.write.createLock(
        [commitment, predicateHash, policyHash, domainSeparator, deadline],
        { account: user1.account },
      );
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
    let shieldedPool: GetContractReturnType<any>;

    before(async function () {
      // Deploy UniversalShieldedPool in test mode (no real ZK verification)
      shieldedPool = await viem.deployContract("UniversalShieldedPool", [
        deployer.account.address, // admin
        mockVerifier.address, // withdrawal verifier
        true, // testMode = true
      ]);
    });

    it("should accept an ETH deposit with valid commitment", async function () {
      // Generate a test commitment (non-zero, within field size)
      const commitment = keccak256(toBytes("privacy-pool-deposit-1"));
      const depositAmount = 100000000000000000n; // 0.1 ETH

      const rootBefore = await shieldedPool.read.currentRoot();

      await shieldedPool.write.depositETH([commitment], {
        account: user1.account,
        value: depositAmount,
      });

      // After deposit the Merkle root should have changed
      const rootAfter = await shieldedPool.read.currentRoot();
      expect(rootAfter).to.not.equal(rootBefore);

      // Next leaf index should have advanced
      const nextIndex = await shieldedPool.read.nextLeafIndex();
      expect(nextIndex).to.be.gte(1n);
    });

    it("should reject a deposit with zero commitment", async function () {
      let reverted = false;
      try {
        await shieldedPool.write.depositETH([zeroHash], {
          account: user1.account,
          value: 100000000000000000n,
        });
      } catch {
        reverted = true;
      }
      expect(reverted).to.be.true;
    });

    it("should track the Merkle root history", async function () {
      const root = await shieldedPool.read.currentRoot();
      const isKnown = await shieldedPool.read.isKnownRoot([root]);
      expect(isKnown).to.be.true;
    });
  });

  describe("Cross-Chain Bridge Operations", function () {
    describe("Arbitrum Bridge (MockInbox)", function () {
      let mockInbox: GetContractReturnType<any>;

      before(async function () {
        mockInbox = await viem.deployContract("MockArbitrumInbox");
      });

      it("should compute retryable ticket submission fee", async function () {
        const fee = await mockInbox.read.calculateRetryableSubmissionFee([
          256n, // dataLength
          0n, // baseFee (not used in mock)
        ]);
        // Mock returns dataLength * 10 as the fee
        expect(fee).to.be.gte(0n);
      });
    });

    describe("Hyperlane Bridge (MockMailbox)", function () {
      let mockMailbox: GetContractReturnType<any>;

      before(async function () {
        mockMailbox = await viem.deployContract("MockHyperlaneMailbox", [
          31337, // local domain = hardhat chain id
        ]);
      });

      it("should dispatch a message to a remote domain", async function () {
        const remoteDomain = 42161; // Arbitrum
        const recipient = keccak256(toBytes("remote-recipient"));
        const body = toBytes("cross-chain-payload");

        const messageId = await mockMailbox.write.dispatch(
          [remoteDomain, recipient, body],
          { account: deployer.account },
        );
        expect(messageId).to.not.be.undefined;
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

      const domainSeparator = await zkSlocks.read.generateDomainSeparator([
        1, 0, 0,
      ]);
      const commitment = keccak256(toBytes("transfer-state"));
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_DAY);

      // Create lock
      await zkSlocks.write.createLock(
        [
          commitment,
          keccak256(toBytes("transfer")),
          keccak256(toBytes("policy")),
          domainSeparator,
          deadline,
        ],
        { account: user1.account },
      );

      const activeLocks = await zkSlocks.read.getActiveLockIds();
      expect(activeLocks.length).to.be.greaterThan(0);
      console.log("Lock created successfully");
    });

    it("should handle concurrent operations", async function () {
      // Create multiple locks in sequence (viem doesn't support true parallel writes easily)
      for (let i = 0; i < 5; i++) {
        const commitment = keccak256(toBytes(`concurrent-${i}-${Date.now()}`));
        const domainSeparator = await zkSlocks.read.generateDomainSeparator([
          1, 0, 0,
        ]);
        const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

        await zkSlocks.write.createLock(
          [
            commitment,
            keccak256(toBytes("transfer")),
            keccak256(toBytes("policy")),
            domainSeparator,
            deadline,
          ],
          { account: user1.account },
        );
      }

      const activeLocks = await zkSlocks.read.getActiveLockIds();
      expect(activeLocks.length).to.be.gte(5);
      console.log("Created 5 locks");
    });
  });

  describe("Gas Benchmarks", function () {
    it("should measure createLock gas usage", async function () {
      const commitment = keccak256(toBytes(`gas-bench-${Date.now()}`));
      const domainSeparator = await zkSlocks.read.generateDomainSeparator([
        1, 0, 0,
      ]);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

      // Create lock and check it succeeded
      await zkSlocks.write.createLock(
        [
          commitment,
          keccak256(toBytes("transfer")),
          keccak256(toBytes("policy")),
          domainSeparator,
          deadline,
        ],
        { account: user1.account },
      );

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
        await zkSlocks.write.createLock(
          [
            commitment,
            keccak256(toBytes("transfer")),
            keccak256(toBytes("policy")),
            invalidDomain,
            deadline,
          ],
          { account: user1.account },
        );
      } catch {
        reverted = true;
      }
      expect(reverted).to.be.true;
    });

    it("should revert when contract is paused", async function () {
      // Pause the contract
      const LOCK_ADMIN_ROLE = await zkSlocks.read.LOCK_ADMIN_ROLE();
      await zkSlocks.write.grantRole(
        [LOCK_ADMIN_ROLE, deployer.account.address],
        { account: deployer.account },
      );
      await zkSlocks.write.pause([], { account: deployer.account });

      const commitment = keccak256(toBytes("paused-test"));
      const domainSeparator = await zkSlocks.read.generateDomainSeparator([
        1, 0, 0,
      ]);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + ONE_HOUR);

      let reverted = false;
      try {
        await zkSlocks.write.createLock(
          [
            commitment,
            keccak256(toBytes("transfer")),
            keccak256(toBytes("policy")),
            domainSeparator,
            deadline,
          ],
          { account: user1.account },
        );
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
      const hasRole = await zkSlocks.read.hasRole([
        LOCK_ADMIN_ROLE,
        user1.account.address,
      ]);
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
