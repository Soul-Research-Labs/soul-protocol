import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, toHex, zeroHash, hexToBigInt } from "viem";

/**
 * Security Vulnerability Tests for Hardhat v3 (viem)
 */
describe("Security Tests (viem)", function () {
  this.timeout(120000);

  describe("Reentrancy Protection", function () {
    it("Should prevent nullifier reuse", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const nullifier = keccak256(toBytes("reentry_null"));

      await stateContainer.write.registerState([
        toHex(toBytes("state1")),
        keccak256(toBytes("commit1")),
        nullifier,
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      try {
        await stateContainer.write.registerState([
          toHex(toBytes("state2")),
          keccak256(toBytes("commit2")),
          nullifier,
          toHex(toBytes("proof")),
          zeroHash
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("NullifierAlreadyUsed");
      }
    });
  });

  describe("Access Control", function () {
    it("Should prevent unauthorized pause", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, attacker] = await viem.getWalletClients();

      try {
        await stateContainer.write.pause({ account: attacker.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("AccessControl");
      }
    });

    it("Should prevent unauthorized role grants", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, attacker, victim] = await viem.getWalletClients();

      const ADMIN_ROLE = zeroHash;

      try {
        await stateContainer.write.grantRole([ADMIN_ROLE, victim.account.address], { account: attacker.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("AccessControl");
      }
    });

    it("Should enforce role hierarchy", async function () {
      const { viem } = await hre.network.connect();
      
      const proofHub = await viem.deployContract("CrossChainProofHubV3");
      const [owner, relayer] = await viem.getWalletClients();

      const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
      const ADMIN_ROLE = zeroHash;

      // Grant relayer role
      await proofHub.write.grantRole([RELAYER_ROLE, relayer.account.address], { account: owner.account });
      expect(await proofHub.read.hasRole([RELAYER_ROLE, relayer.account.address])).to.be.true;

      // Relayer cannot grant admin role
      try {
        await proofHub.write.grantRole([ADMIN_ROLE, relayer.account.address], { account: relayer.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("AccessControl");
      }
    });
  });

  describe("Integer Overflow Protection", function () {
    it("Should handle max uint256 values", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const maxCommitment = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" as `0x${string}`;

      await stateContainer.write.registerState([
        toHex(toBytes("max_state")),
        maxCommitment,
        keccak256(toBytes("max_null")),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      expect(await stateContainer.read.isStateActive([maxCommitment])).to.be.true;
    });

    it("Should handle duplicate commitment rejection", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      const commitment = keccak256(toBytes("duplicate_commit"));
      
      // First registration should succeed
      await stateContainer.write.registerState([
        toHex(toBytes("first_state")),
        commitment,
        keccak256(toBytes("first_null")),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      // Second registration with same commitment should fail
      try {
        await stateContainer.write.registerState([
          toHex(toBytes("second_state")),
          commitment, // Same commitment
          keccak256(toBytes("second_null")),
          toHex(toBytes("proof")),
          zeroHash
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("CommitmentAlreadyExists");
      }
    });
  });

  describe("Front-Running Protection", function () {
    it("Should bind nullifier to first registration", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner, user1, attacker] = await viem.getWalletClients();

      // Grant REGISTRAR_ROLE to users so they can register nullifiers
      const REGISTRAR_ROLE = keccak256(toBytes("REGISTRAR_ROLE"));
      await nullifierRegistry.write.grantRole([REGISTRAR_ROLE, attacker.account.address], { account: owner.account });
      await nullifierRegistry.write.grantRole([REGISTRAR_ROLE, user1.account.address], { account: owner.account });

      const nullifier = keccak256(toBytes("frontrun_null"));

      // Attacker front-runs
      await nullifierRegistry.write.registerNullifier([nullifier, zeroHash], { account: attacker.account });

      // User's transaction fails
      try {
        await nullifierRegistry.write.registerNullifier([nullifier, zeroHash], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("NullifierAlreadyExists");
      }
    });

    it("Should bind commitment to first registration", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1, attacker] = await viem.getWalletClients();

      const commitment = keccak256(toBytes("frontrun_commit"));

      // First registration succeeds
      await stateContainer.write.registerState([
        toHex(toBytes("original_state")),
        commitment,
        keccak256(toBytes("frontrun_null1")),
        toHex(toBytes("proof")),
        zeroHash
      ], { account: user1.account });

      // Attacker cannot steal the commitment
      try {
        await stateContainer.write.registerState([
          toHex(toBytes("attacker_state")),
          commitment,
          keccak256(toBytes("frontrun_null2")),
          toHex(toBytes("proof")),
          zeroHash
        ], { account: attacker.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("CommitmentAlreadyExists");
      }
    });
  });

  describe("Denial of Service Protection", function () {
    it("Should handle high volume operations", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([true]);
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();

      const count = 20;
      const gasUsages: bigint[] = [];

      for (let i = 0; i < count; i++) {
        const txHash = await stateContainer.write.registerState([
          toHex(toBytes(`dos_state_${i}`)),
          keccak256(toBytes(`dos_commit_${i}`)),
          keccak256(toBytes(`dos_null_${i}`)),
          toHex(toBytes("proof")),
          zeroHash
        ], { account: user1.account });

        const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
        gasUsages.push(receipt.gasUsed);
      }

      // Gas should scale linearly (not exponentially)
      const avgGas = gasUsages.reduce((a, b) => a + b, 0n) / BigInt(count);
      const maxGas = gasUsages.reduce((a, b) => a > b ? a : b, 0n);
      const minGas = gasUsages.reduce((a, b) => a < b ? a : b, maxGas);

      expect(Number(maxGas) / Number(minGas)).to.be.lessThan(2);
    });

    it("Should enforce batch size limits", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();

      // Try to register 100 nullifiers (should fail - max batch size is 20)
      const nullifiers: `0x${string}`[] = [];
      const commitments: `0x${string}`[] = [];

      for (let i = 0; i < 100; i++) {
        nullifiers.push(keccak256(toBytes(`batch_null_${i}`)));
        commitments.push(keccak256(toBytes(`batch_commit_${i}`)));
      }

      try {
        await nullifierRegistry.write.batchRegisterNullifiers([nullifiers, commitments], { account: owner.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("BatchTooLarge");
      }
    });
  });

  describe("Emergency Recovery", function () {
    it("Should deploy emergency recovery contract", async function () {
      const { viem } = await hre.network.connect();
      
      const emergencyRecovery = await viem.deployContract("EmergencyRecovery");
      const [owner] = await viem.getWalletClients();

      const currentStage = await emergencyRecovery.read.currentStage();
      expect(Number(currentStage)).to.equal(0); // Normal stage
    });

    it("Should add guardians", async function () {
      const { viem } = await hre.network.connect();
      
      const emergencyRecovery = await viem.deployContract("EmergencyRecovery");
      const [owner, guardian1] = await viem.getWalletClients();

      await emergencyRecovery.write.addGuardian([guardian1.account.address], { account: owner.account });
      
      // Check via hasRole
      const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
      expect(await emergencyRecovery.read.hasRole([GUARDIAN_ROLE, guardian1.account.address])).to.be.true;
    });
  });

  describe("Merkle Tree Integrity", function () {
    it("Should update merkle root on each registration", async function () {
      const { viem } = await hre.network.connect();
      
      const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
      const [owner] = await viem.getWalletClients();

      const roots: string[] = [];
      roots.push(await nullifierRegistry.read.merkleRoot());

      for (let i = 0; i < 5; i++) {
        await nullifierRegistry.write.registerNullifier([
          keccak256(toBytes(`merkle_test_${i}`)),
          zeroHash
        ], { account: owner.account });

        const newRoot = await nullifierRegistry.read.merkleRoot();
        expect(roots).to.not.include(newRoot);
        roots.push(newRoot);
      }

      // All roots should be unique
      expect(new Set(roots).size).to.equal(roots.length);
    });
  });

  describe("State Verification", function () {
    it("Should reject invalid proof", async function () {
      const { viem } = await hre.network.connect();
      
      const mockVerifier = await viem.deployContract("MockProofVerifier");
      await mockVerifier.write.setVerificationResult([false]); // Set to fail
      const stateContainer = await viem.deployContract("ConfidentialStateContainerV3", [mockVerifier.address]);
      const [owner, user1] = await viem.getWalletClients();

      try {
        await stateContainer.write.registerState([
          toHex(toBytes("invalid_state")),
          keccak256(toBytes("invalid_commit")),
          keccak256(toBytes("invalid_null")),
          toHex(toBytes("bad_proof")),
          zeroHash
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("InvalidProof");
      }
    });
  });
});
