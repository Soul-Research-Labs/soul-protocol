import { expect } from "chai";
import hre from "hardhat";
import {
  keccak256,
  toBytes,
  encodeAbiParameters,
  parseAbiParameters,
} from "viem";

/**
 * PrivacyZoneManager Test Suite
 *
 * Tests the multi-core Privacy Zone system inspired by LayerZero Zero's
 * Atomicity Zones. Each zone operates as an independent privacy domain.
 */
describe("PrivacyZoneManager", function () {
  this.timeout(120000);

  // BN254 scalar field size (must match contract's FIELD_SIZE)
  const FIELD_SIZE =
    21888242871839275222246405745257275088548364400416034343698204186575808495617n;

  // Helper to generate test commitment (mod-reduced to be within BN254 field)
  function generateCommitment(value: bigint): `0x${string}` {
    const raw = keccak256(
      encodeAbiParameters(parseAbiParameters("uint256 value"), [value]),
    );
    // Reduce modulo FIELD_SIZE to ensure commitment is a valid field element
    const reduced = BigInt(raw) % FIELD_SIZE;
    // Convert back to 0x-prefixed hex string, padded to 32 bytes
    return ("0x" + reduced.toString(16).padStart(64, "0")) as `0x${string}`;
  }

  const ZERO_BYTES32 = ("0x" + "00".repeat(32)) as `0x${string}`;

  // Default zone config
  function getDefaultZoneConfig(name: string = "TestZone") {
    return {
      name,
      privacyLevel: 0, // Standard
      policyHash: ZERO_BYTES32,
      maxThroughput: 1000n,
      epochDuration: 3600n,
      minDepositAmount: BigInt(1e15), // 0.001 ETH
      maxDepositAmount: BigInt(10e18), // 10 ETH
      merkleTreeDepth: 20,
      crossZoneMigration: true,
      maxTotalDeposits: BigInt(1000e18), // 1000 ETH TVL cap
    };
  }

  // ==========================================================================
  // Zone Creation Tests
  // ==========================================================================
  describe("Zone Creation", function () {
    it("should create a new privacy zone", async function () {
      const { viem } = await hre.network.connect();
      const [deployer] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true, // test mode
      ]);

      const config = getDefaultZoneConfig("AlphaZone");

      await manager.write.createZone([config], { account: deployer.account });

      const totalZones = await manager.read.getTotalZones();
      expect(totalZones).to.equal(1n);

      const activeIds = await manager.read.getActiveZoneIds();
      expect(activeIds.length).to.equal(1);
    });

    it("should create multiple zones with unique IDs", async function () {
      const { viem } = await hre.network.connect();
      const [deployer] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      await manager.write.createZone([getDefaultZoneConfig("Zone_A")], {
        account: deployer.account,
      });
      await manager.write.createZone([getDefaultZoneConfig("Zone_B")], {
        account: deployer.account,
      });
      await manager.write.createZone([getDefaultZoneConfig("Zone_C")], {
        account: deployer.account,
      });

      const totalZones = await manager.read.getTotalZones();
      expect(totalZones).to.equal(3n);

      const activeIds = await manager.read.getActiveZoneIds();
      expect(activeIds.length).to.equal(3);

      // All IDs should be unique
      const uniqueIds = new Set(activeIds);
      expect(uniqueIds.size).to.equal(3);
    });

    it("should create zones with different privacy levels", async function () {
      const { viem } = await hre.network.connect();
      const [deployer] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      const configs = [
        { ...getDefaultZoneConfig("Standard"), privacyLevel: 0 },
        { ...getDefaultZoneConfig("Enhanced"), privacyLevel: 1 },
        { ...getDefaultZoneConfig("Maximum"), privacyLevel: 2 },
        { ...getDefaultZoneConfig("Compliant"), privacyLevel: 3 },
      ];

      for (const config of configs) {
        await manager.write.createZone([config], { account: deployer.account });
      }

      expect(await manager.read.getTotalZones()).to.equal(4n);
    });
  });

  // ==========================================================================
  // Zone Status Management Tests
  // ==========================================================================
  describe("Zone Status Management", function () {
    it("should update zone status", async function () {
      const { viem } = await hre.network.connect();
      const [deployer] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      await manager.write.createZone([getDefaultZoneConfig()], {
        account: deployer.account,
      });
      const activeIds = await manager.read.getActiveZoneIds();
      const zoneId = activeIds[0];

      // Pause the zone
      await manager.write.setZoneStatus([zoneId, 2], {
        account: deployer.account,
      }); // Paused

      const zone = await manager.read.getZone([zoneId]);
      expect(zone.status).to.equal(2); // Paused
    });

    it("should remove zone from active list on shutdown", async function () {
      const { viem } = await hre.network.connect();
      const [deployer] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      await manager.write.createZone([getDefaultZoneConfig("Zone1")], {
        account: deployer.account,
      });
      await manager.write.createZone([getDefaultZoneConfig("Zone2")], {
        account: deployer.account,
      });

      let activeIds = await manager.read.getActiveZoneIds();
      expect(activeIds.length).to.equal(2);

      // Shutdown first zone
      await manager.write.setZoneStatus([activeIds[0], 4], {
        account: deployer.account,
      }); // Shutdown

      activeIds = await manager.read.getActiveZoneIds();
      expect(activeIds.length).to.equal(1);
    });
  });

  // ==========================================================================
  // Deposit Tests
  // ==========================================================================
  describe("Deposits", function () {
    it("should accept deposits into a zone", async function () {
      const { viem } = await hre.network.connect();
      const [deployer, user1] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      // Grant zone admin role so deployer can create zones
      await manager.write.createZone([getDefaultZoneConfig()], {
        account: deployer.account,
      });
      const activeIds = await manager.read.getActiveZoneIds();
      const zoneId = activeIds[0];

      const commitment = generateCommitment(1000n);
      const depositAmount = BigInt(1e16); // 0.01 ETH

      await manager.write.depositToZone([zoneId, commitment], {
        account: user1.account,
        value: depositAmount,
      });

      // Verify commitment was inserted
      const exists = await manager.read.zoneCommitments([zoneId, commitment]);
      expect(exists).to.be.true;

      // Verify Merkle root changed from default
      const merkleRoot = await manager.read.getZoneMerkleRoot([zoneId]);
      expect(merkleRoot).to.not.equal(ZERO_BYTES32);
    });

    it("should reject deposits below minimum", async function () {
      const { viem } = await hre.network.connect();
      const [deployer, user1] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      const config = getDefaultZoneConfig();
      config.minDepositAmount = BigInt(1e17); // 0.1 ETH minimum

      await manager.write.createZone([config], { account: deployer.account });
      const activeIds = await manager.read.getActiveZoneIds();
      const zoneId = activeIds[0];

      const commitment = generateCommitment(100n);

      try {
        await manager.write.depositToZone([zoneId, commitment], {
          account: user1.account,
          value: BigInt(1e15), // 0.001 ETH (below minimum)
        });
        expect.fail("Should have reverted");
      } catch (e: any) {
        expect(e.message).to.include("DepositBelowMinimum");
      }
    });

    it("should track zone statistics after deposits", async function () {
      const { viem } = await hre.network.connect();
      const [deployer, user1] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      await manager.write.createZone([getDefaultZoneConfig()], {
        account: deployer.account,
      });
      const activeIds = await manager.read.getActiveZoneIds();
      const zoneId = activeIds[0];

      // Make 3 deposits
      for (let i = 1; i <= 3; i++) {
        const commitment = generateCommitment(BigInt(i * 1000));
        await manager.write.depositToZone([zoneId, commitment], {
          account: user1.account,
          value: BigInt(1e16),
        });
      }

      const stats = await manager.read.getZoneStats([zoneId]);
      expect(stats.totalDeposits).to.equal(3n);
      expect(stats.activeCommitments).to.equal(3n);
    });
  });

  // ==========================================================================
  // Withdrawal Tests
  // ==========================================================================
  describe("Withdrawals (Test Mode)", function () {
    it("should process withdrawal in test mode", async function () {
      const { viem } = await hre.network.connect();
      const [deployer, user1] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true, // test mode
      ]);

      await manager.write.createZone([getDefaultZoneConfig()], {
        account: deployer.account,
      });
      const activeIds = await manager.read.getActiveZoneIds();
      const zoneId = activeIds[0];

      // Deposit first
      const commitment = generateCommitment(5000n);
      const depositAmount = BigInt(1e16);
      await manager.write.depositToZone([zoneId, commitment], {
        account: user1.account,
        value: depositAmount,
      });

      // Withdraw in test mode (no proof verification)
      const nullifier = generateCommitment(99999n);
      const withdrawAmount = BigInt(5e15); // 0.005 ETH

      await manager.write.withdrawFromZone(
        [zoneId, nullifier, user1.account.address, withdrawAmount, "0x"],
        { account: user1.account },
      );

      // Verify nullifier was spent
      const spent = await manager.read.isNullifierSpent([zoneId, nullifier]);
      expect(spent).to.be.true;
    });

    it("should prevent double-spend via nullifier", async function () {
      const { viem } = await hre.network.connect();
      const [deployer, user1] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      await manager.write.createZone([getDefaultZoneConfig()], {
        account: deployer.account,
      });
      const activeIds = await manager.read.getActiveZoneIds();
      const zoneId = activeIds[0];

      // Deposit
      await manager.write.depositToZone([zoneId, generateCommitment(5000n)], {
        account: user1.account,
        value: BigInt(1e16),
      });

      const nullifier = generateCommitment(99999n);

      // First withdrawal should succeed
      await manager.write.withdrawFromZone(
        [zoneId, nullifier, user1.account.address, BigInt(5e15), "0x"],
        { account: user1.account },
      );

      // Second withdrawal with same nullifier should fail
      try {
        await manager.write.withdrawFromZone(
          [zoneId, nullifier, user1.account.address, BigInt(5e15), "0x"],
          { account: user1.account },
        );
        expect.fail("Should have reverted");
      } catch (e: any) {
        expect(e.message).to.include("NullifierAlreadySpent");
      }
    });
  });

  // ==========================================================================
  // Cross-Zone Migration Tests
  // ==========================================================================
  describe("Cross-Zone Migration", function () {
    it("should migrate state between zones in test mode", async function () {
      const { viem } = await hre.network.connect();
      const [deployer, user1] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      // Create two zones
      await manager.write.createZone([getDefaultZoneConfig("Source")], {
        account: deployer.account,
      });
      await manager.write.createZone([getDefaultZoneConfig("Dest")], {
        account: deployer.account,
      });

      const activeIds = await manager.read.getActiveZoneIds();
      const sourceZone = activeIds[0];
      const destZone = activeIds[1];

      // Deposit into source zone
      const commitment = generateCommitment(10000n);
      await manager.write.depositToZone([sourceZone, commitment], {
        account: user1.account,
        value: BigInt(1e16),
      });

      // Migrate from source to dest
      const nullifier = generateCommitment(77777n);
      const newCommitment = generateCommitment(88888n);

      await manager.write.migrateState(
        [sourceZone, destZone, nullifier, newCommitment, "0x"],
        { account: user1.account },
      );

      // Verify nullifier spent on source
      expect(await manager.read.isNullifierSpent([sourceZone, nullifier])).to.be
        .true;

      // Verify nullifier NOT spent on dest (different scope)
      expect(await manager.read.isNullifierSpent([destZone, nullifier])).to.be
        .false;

      // Verify new commitment exists on dest
      expect(await manager.read.zoneCommitments([destZone, newCommitment])).to
        .be.true;

      // Verify total migrations counter
      const migrations = await manager.read.totalMigrations();
      expect(migrations).to.equal(1n);
    });

    it("should reject migration when zone has migration disabled", async function () {
      const { viem } = await hre.network.connect();
      const [deployer, user1] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      // Source zone with migration enabled
      await manager.write.createZone([getDefaultZoneConfig("Source")], {
        account: deployer.account,
      });

      // Dest zone with migration DISABLED
      const noMigrationConfig = getDefaultZoneConfig("Locked");
      noMigrationConfig.crossZoneMigration = false;
      await manager.write.createZone([noMigrationConfig], {
        account: deployer.account,
      });

      const activeIds = await manager.read.getActiveZoneIds();

      try {
        await manager.write.migrateState(
          [
            activeIds[0],
            activeIds[1],
            generateCommitment(1n),
            generateCommitment(2n),
            "0x",
          ],
          { account: user1.account },
        );
        expect.fail("Should have reverted");
      } catch (e: any) {
        expect(e.message).to.include("MigrationNotAllowed");
      }
    });
  });

  // ==========================================================================
  // Zone Isolation Tests
  // ==========================================================================
  describe("Zone Isolation", function () {
    it("should maintain separate Merkle roots per zone", async function () {
      const { viem } = await hre.network.connect();
      const [deployer, user1] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      await manager.write.createZone([getDefaultZoneConfig("ZoneA")], {
        account: deployer.account,
      });
      await manager.write.createZone([getDefaultZoneConfig("ZoneB")], {
        account: deployer.account,
      });

      const activeIds = await manager.read.getActiveZoneIds();

      // Deposit different commitments into each zone
      await manager.write.depositToZone(
        [activeIds[0], generateCommitment(1111n)],
        { account: user1.account, value: BigInt(1e16) },
      );

      await manager.write.depositToZone(
        [activeIds[1], generateCommitment(2222n)],
        { account: user1.account, value: BigInt(1e16) },
      );

      // Merkle roots should be different
      const rootA = await manager.read.getZoneMerkleRoot([activeIds[0]]);
      const rootB = await manager.read.getZoneMerkleRoot([activeIds[1]]);

      expect(rootA).to.not.equal(rootB);
    });

    it("should have independent nullifier registries", async function () {
      const { viem } = await hre.network.connect();
      const [deployer, user1] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      await manager.write.createZone([getDefaultZoneConfig("ZoneA")], {
        account: deployer.account,
      });
      await manager.write.createZone([getDefaultZoneConfig("ZoneB")], {
        account: deployer.account,
      });

      const activeIds = await manager.read.getActiveZoneIds();

      // Deposit into both zones
      await manager.write.depositToZone(
        [activeIds[0], generateCommitment(100n)],
        { account: user1.account, value: BigInt(1e16) },
      );
      await manager.write.depositToZone(
        [activeIds[1], generateCommitment(200n)],
        { account: user1.account, value: BigInt(1e16) },
      );

      // Use same nullifier in zone A
      const nullifier = generateCommitment(55555n);
      await manager.write.withdrawFromZone(
        [activeIds[0], nullifier, user1.account.address, BigInt(5e15), "0x"],
        { account: user1.account },
      );

      // Same nullifier should NOT be spent in zone B
      expect(await manager.read.isNullifierSpent([activeIds[0], nullifier])).to
        .be.true;
      expect(await manager.read.isNullifierSpent([activeIds[1], nullifier])).to
        .be.false;
    });
  });

  // ==========================================================================
  // Policy Management Tests
  // ==========================================================================
  describe("Policy Management", function () {
    it("should update zone policy", async function () {
      const { viem } = await hre.network.connect();
      const [deployer] = await viem.getWalletClients();

      const manager = await viem.deployContract("PrivacyZoneManager", [
        deployer.account.address,
        true,
      ]);

      await manager.write.createZone([getDefaultZoneConfig()], {
        account: deployer.account,
      });
      const activeIds = await manager.read.getActiveZoneIds();
      const zoneId = activeIds[0];

      const newPolicy = generateCommitment(42n);
      await manager.write.setZonePolicy([zoneId, newPolicy], {
        account: deployer.account,
      });

      const zone = await manager.read.getZone([zoneId]);
      expect(zone.policyHash).to.equal(newPolicy);
    });
  });
});
