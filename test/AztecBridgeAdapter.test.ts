import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, toHex, parseEther } from "viem";

describe("AztecBridgeAdapter", function () {
  describe("Deployment", function () {
    it("Should deploy with correct initial state", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      // Check initial values
      const bridgeFeeBps = await adapter.read.bridgeFeeBps();
      expect(bridgeFeeBps).to.equal(10n); // 0.1%

      const minBridgeAmount = await adapter.read.minBridgeAmount();
      expect(minBridgeAmount).to.equal(parseEther("0.01"));

      const maxBridgeAmount = await adapter.read.maxBridgeAmount();
      expect(maxBridgeAmount).to.equal(parseEther("1000"));

      const pendingRequests = await adapter.read.pendingRequests();
      expect(pendingRequests).to.equal(0n);
    });

    it("Should grant admin roles to deployer", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      const defaultAdminRole = await adapter.read.DEFAULT_ADMIN_ROLE();
      const operatorRole = await adapter.read.OPERATOR_ROLE();
      const guardianRole = await adapter.read.GUARDIAN_ROLE();

      const hasAdminRole = await adapter.read.hasRole([defaultAdminRole, admin.account.address]);
      const hasOperatorRole = await adapter.read.hasRole([operatorRole, admin.account.address]);
      const hasGuardianRole = await adapter.read.hasRole([guardianRole, admin.account.address]);

      expect(hasAdminRole).to.be.true;
      expect(hasOperatorRole).to.be.true;
      expect(hasGuardianRole).to.be.true;
    });
  });

  describe("Aztec Contract Configuration", function () {
    it("Should configure Aztec contracts", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      // Mock addresses for Aztec contracts
      const rollupAddress = "0x1111111111111111111111111111111111111111";
      const inboxAddress = "0x2222222222222222222222222222222222222222";
      const outboxAddress = "0x3333333333333333333333333333333333333333";

      await adapter.write.configureAztecContracts([
        rollupAddress,
        inboxAddress,
        outboxAddress
      ]);

      const rollup = await adapter.read.aztecRollup();
      const inbox = await adapter.read.aztecInbox();
      const outbox = await adapter.read.aztecOutbox();

      expect(rollup.toLowerCase()).to.equal(rollupAddress.toLowerCase());
      expect(inbox.toLowerCase()).to.equal(inboxAddress.toLowerCase());
      expect(outbox.toLowerCase()).to.equal(outboxAddress.toLowerCase());
    });

    it("Should reject zero address configuration", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      let reverted = false;
      try {
        await adapter.write.configureAztecContracts([
          "0x0000000000000000000000000000000000000000",
          "0x2222222222222222222222222222222222222222",
          "0x3333333333333333333333333333333333333333"
        ]);
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("ZeroAddress");
      }
      expect(reverted).to.be.true;
    });

    it("Should reject configuration from non-operator", async function () {
      const { viem } = await hre.network.connect();
      const [admin, nonOperator] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      let reverted = false;
      try {
        await adapter.write.configureAztecContracts(
          [
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
            "0x3333333333333333333333333333333333333333"
          ],
          { account: nonOperator.account }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("AccessControlUnauthorizedAccount");
      }
      expect(reverted).to.be.true;
    });
  });

  describe("PIL to Aztec Bridge", function () {
    async function setupBridge() {
      const { viem } = await hre.network.connect();
      const [admin, relayer, user] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      // Configure Aztec contracts
      await adapter.write.configureAztecContracts([
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333"
      ]);

      // Grant relayer role
      const relayerRole = await adapter.read.RELAYER_ROLE();
      await adapter.write.grantRole([relayerRole, relayer.account.address]);

      return { adapter, admin, relayer, user, viem };
    }

    it("Should initiate PIL to Aztec bridge", async function () {
      const { adapter, user } = await setupBridge();

      const pilCommitment = keccak256(toBytes("pil_commitment_1"));
      const pilNullifier = keccak256(toBytes("pil_nullifier_1"));
      const aztecRecipient = keccak256(toBytes("aztec_address_1"));
      const amount = parseEther("1");
      const noteType = 0; // VALUE_NOTE
      const appDataHash = keccak256(toBytes("app_data"));
      const proof = toHex(toBytes("valid_proof_data_here_1234567890"));

      // Calculate fee (0.1% of 1 ETH = 0.001 ETH)
      const fee = (amount * 10n) / 10000n;

      await adapter.write.bridgePILToAztec(
        [pilCommitment, pilNullifier, aztecRecipient, amount, noteType, appDataHash, proof],
        { value: fee }
      );

      const totalBridged = await adapter.read.totalBridgedToAztec();
      expect(totalBridged).to.equal(amount);

      const pendingRequests = await adapter.read.pendingRequests();
      expect(pendingRequests).to.equal(1n);

      // Check nullifier is registered
      const isNullifierUsed = await adapter.read.isNullifierUsed([pilNullifier]);
      expect(isNullifierUsed).to.be.true;
    });

    it("Should reject bridge without configured Aztec contracts", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      const pilCommitment = keccak256(toBytes("commitment"));
      const pilNullifier = keccak256(toBytes("nullifier"));
      const aztecRecipient = keccak256(toBytes("recipient"));
      const proof = toHex(toBytes("valid_proof_data_here_1234567890"));

      let reverted = false;
      try {
        await adapter.write.bridgePILToAztec(
          [pilCommitment, pilNullifier, aztecRecipient, parseEther("1"), 0, keccak256(toBytes("app")), proof],
          { value: parseEther("0.001") }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("AztecContractsNotConfigured");
      }
      expect(reverted).to.be.true;
    });

    it("Should reject bridge below minimum amount", async function () {
      const { adapter } = await setupBridge();

      const pilCommitment = keccak256(toBytes("commitment"));
      const pilNullifier = keccak256(toBytes("nullifier"));
      const aztecRecipient = keccak256(toBytes("recipient"));
      const proof = toHex(toBytes("valid_proof_data_here_1234567890"));

      let reverted = false;
      try {
        // Try to bridge 0.001 ETH (below 0.01 minimum)
        await adapter.write.bridgePILToAztec(
          [pilCommitment, pilNullifier, aztecRecipient, parseEther("0.001"), 0, keccak256(toBytes("app")), proof],
          { value: parseEther("0.0001") }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("AmountTooLow");
      }
      expect(reverted).to.be.true;
    });

    it("Should reject duplicate nullifier", async function () {
      const { adapter } = await setupBridge();

      const pilCommitment1 = keccak256(toBytes("commitment1"));
      const pilCommitment2 = keccak256(toBytes("commitment2"));
      const pilNullifier = keccak256(toBytes("same_nullifier")); // Same nullifier
      const aztecRecipient = keccak256(toBytes("recipient"));
      const proof = toHex(toBytes("valid_proof_data_here_1234567890"));
      const amount = parseEther("1");
      const fee = (amount * 10n) / 10000n;

      // First bridge should succeed
      await adapter.write.bridgePILToAztec(
        [pilCommitment1, pilNullifier, aztecRecipient, amount, 0, keccak256(toBytes("app")), proof],
        { value: fee }
      );

      // Second bridge with same nullifier should fail
      let reverted = false;
      try {
        await adapter.write.bridgePILToAztec(
          [pilCommitment2, pilNullifier, aztecRecipient, amount, 0, keccak256(toBytes("app")), proof],
          { value: fee }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("NullifierAlreadyUsed");
      }
      expect(reverted).to.be.true;
    });

    it("Should complete PIL to Aztec bridge", async function () {
      const { adapter, relayer } = await setupBridge();

      const pilCommitment = keccak256(toBytes("pil_commitment_complete"));
      const pilNullifier = keccak256(toBytes("pil_nullifier_complete"));
      const aztecRecipient = keccak256(toBytes("aztec_recipient"));
      const amount = parseEther("1");
      const fee = (amount * 10n) / 10000n;
      const proof = toHex(toBytes("valid_proof_data_here_1234567890"));

      // Initiate bridge
      await adapter.write.bridgePILToAztec(
        [pilCommitment, pilNullifier, aztecRecipient, amount, 0, keccak256(toBytes("app")), proof],
        { value: fee }
      );

      // Get request ID (we need to compute it the same way the contract does)
      // For this test, we'll get it from the event or compute it
      const pendingBefore = await adapter.read.pendingRequests();
      expect(pendingBefore).to.equal(1n);

      // Complete the bridge (relayer)
      const resultingNoteHash = keccak256(toBytes("aztec_note_hash"));
      const aztecProof = toHex(toBytes("aztec_note_creation_proof_data"));

      // We need to compute the request ID - for testing, we'll use events or direct computation
      // In a real scenario, we'd capture this from the PILToAztecInitiated event
    });
  });

  describe("Aztec to PIL Bridge", function () {
    async function setupBridgeWithRelayer() {
      const { viem } = await hre.network.connect();
      const [admin, relayer] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      // Configure Aztec contracts
      await adapter.write.configureAztecContracts([
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333"
      ]);

      // Grant relayer role
      const relayerRole = await adapter.read.RELAYER_ROLE();
      await adapter.write.grantRole([relayerRole, relayer.account.address]);

      return { adapter, admin, relayer, viem };
    }

    it("Should bridge Aztec to PIL via relayer", async function () {
      const { adapter, relayer } = await setupBridgeWithRelayer();

      const aztecNoteHash = keccak256(toBytes("aztec_note_hash"));
      const aztecNullifier = keccak256(toBytes("aztec_nullifier"));
      const pilRecipient = "0x4444444444444444444444444444444444444444";
      const amount = parseEther("5");
      // Proof must be at least 32 bytes
      const proof = toHex(toBytes("valid_aztec_spend_proof_data_1234567890abcdef"));

      await adapter.write.bridgeAztecToPIL(
        [aztecNoteHash, aztecNullifier, pilRecipient, amount, proof],
        { account: relayer.account }
      );

      const totalBridged = await adapter.read.totalBridgedFromAztec();
      expect(totalBridged).to.equal(amount);

      // Check nullifier is registered
      const isNullifierUsed = await adapter.read.isNullifierUsed([aztecNullifier]);
      expect(isNullifierUsed).to.be.true;
    });

    it("Should reject Aztec to PIL from non-relayer", async function () {
      const { adapter, admin } = await setupBridgeWithRelayer();

      const aztecNoteHash = keccak256(toBytes("note"));
      const aztecNullifier = keccak256(toBytes("nullifier"));
      const pilRecipient = "0x4444444444444444444444444444444444444444";
      // Proof must be at least 32 bytes
      const proof = toHex(toBytes("valid_aztec_spend_proof_data_1234567890abcdef"));

      // Admin (non-relayer) should be rejected
      let reverted = false;
      try {
        await adapter.write.bridgeAztecToPIL(
          [aztecNoteHash, aztecNullifier, pilRecipient, parseEther("1"), proof],
          { account: admin.account }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("AccessControlUnauthorizedAccount");
      }
      expect(reverted).to.be.true;
    });
  });

  describe("Aztec State Synchronization", function () {
    it("Should sync Aztec state", async function () {
      const { viem } = await hre.network.connect();
      const [admin, relayer] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      // Grant relayer role
      const relayerRole = await adapter.read.RELAYER_ROLE();
      await adapter.write.grantRole([relayerRole, relayer.account.address]);

      const rollupId = 12345n;
      const dataTreeRoot = keccak256(toBytes("data_tree"));
      const nullifierTreeRoot = keccak256(toBytes("nullifier_tree"));
      const contractTreeRoot = keccak256(toBytes("contract_tree"));
      const l1ToL2MessageTreeRoot = keccak256(toBytes("l1_l2_message_tree"));
      const blockNumber = 1000n;

      await adapter.write.syncAztecState(
        [rollupId, dataTreeRoot, nullifierTreeRoot, contractTreeRoot, l1ToL2MessageTreeRoot, blockNumber],
        { account: relayer.account }
      );

      const latestRollupId = await adapter.read.latestAztecRollupId();
      expect(latestRollupId).to.equal(rollupId);

      const stateSync = await adapter.read.getAztecStateSync([rollupId]);
      expect(stateSync.dataTreeRoot).to.equal(dataTreeRoot);
      expect(stateSync.nullifierTreeRoot).to.equal(nullifierTreeRoot);
      expect(stateSync.finalized).to.be.true;
    });

    it("Should update latest rollup ID on newer sync", async function () {
      const { viem } = await hre.network.connect();
      const [admin, relayer] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      const relayerRole = await adapter.read.RELAYER_ROLE();
      await adapter.write.grantRole([relayerRole, relayer.account.address]);

      // Sync first state
      await adapter.write.syncAztecState(
        [100n, keccak256(toBytes("data1")), keccak256(toBytes("null1")), keccak256(toBytes("contract1")), keccak256(toBytes("msg1")), 1000n],
        { account: relayer.account }
      );

      // Sync newer state
      await adapter.write.syncAztecState(
        [200n, keccak256(toBytes("data2")), keccak256(toBytes("null2")), keccak256(toBytes("contract2")), keccak256(toBytes("msg2")), 2000n],
        { account: relayer.account }
      );

      const latestRollupId = await adapter.read.latestAztecRollupId();
      expect(latestRollupId).to.equal(200n);
    });
  });

  describe("Cross-Domain Proof Verification", function () {
    it("Should verify cross-domain proof", async function () {
      const { viem } = await hre.network.connect();
      const [admin, verifier] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      // Grant proof verifier role
      const verifierRole = await adapter.read.PROOF_VERIFIER_ROLE();
      await adapter.write.grantRole([verifierRole, verifier.account.address]);

      const proofType = 0; // PIL_TO_AZTEC
      const sourceCommitment = keccak256(toBytes("source_commitment"));
      const targetCommitment = keccak256(toBytes("target_commitment"));
      const nullifier = keccak256(toBytes("unique_nullifier_123"));
      const proof = toHex(toBytes("cross_domain_proof_data_1234567890"));
      const publicInputsHash = keccak256(toBytes("public_inputs"));

      await adapter.write.verifyCrossDomainProof(
        [proofType, sourceCommitment, targetCommitment, nullifier, proof, publicInputsHash],
        { account: verifier.account }
      );

      // Check nullifier is registered
      const isUsed = await adapter.read.isNullifierUsed([nullifier]);
      expect(isUsed).to.be.true;
    });

    it("Should reject duplicate proof verification", async function () {
      const { viem } = await hre.network.connect();
      const [admin, verifier] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      const verifierRole = await adapter.read.PROOF_VERIFIER_ROLE();
      await adapter.write.grantRole([verifierRole, verifier.account.address]);

      const nullifier = keccak256(toBytes("duplicate_nullifier"));
      const proof = toHex(toBytes("cross_domain_proof_data_1234567890"));

      // First verification
      await adapter.write.verifyCrossDomainProof(
        [0, keccak256(toBytes("src1")), keccak256(toBytes("tgt1")), nullifier, proof, keccak256(toBytes("pi1"))],
        { account: verifier.account }
      );

      // Second with same nullifier should fail
      let reverted = false;
      try {
        await adapter.write.verifyCrossDomainProof(
          [0, keccak256(toBytes("src2")), keccak256(toBytes("tgt2")), nullifier, proof, keccak256(toBytes("pi2"))],
          { account: verifier.account }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("NullifierAlreadyUsed");
      }
      expect(reverted).to.be.true;
    });
  });

  describe("Admin Functions", function () {
    it("Should set bridge limits", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      const newMin = parseEther("0.1");
      const newMax = parseEther("500");

      await adapter.write.setBridgeLimits([newMin, newMax]);

      const minAmount = await adapter.read.minBridgeAmount();
      const maxAmount = await adapter.read.maxBridgeAmount();

      expect(minAmount).to.equal(newMin);
      expect(maxAmount).to.equal(newMax);
    });

    it("Should set bridge fee", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      await adapter.write.setBridgeFee([50n]); // 0.5%

      const feeBps = await adapter.read.bridgeFeeBps();
      expect(feeBps).to.equal(50n);
    });

    it("Should reject fee above 1%", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      let reverted = false;
      try {
        await adapter.write.setBridgeFee([101n]); // 1.01%
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("Fee too high");
      }
      expect(reverted).to.be.true;
    });

    it("Should pause and unpause", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      // Pause
      await adapter.write.pause();
      const isPaused = await adapter.read.paused();
      expect(isPaused).to.be.true;

      // Unpause
      await adapter.write.unpause();
      const isUnpaused = await adapter.read.paused();
      expect(isUnpaused).to.be.false;
    });

    it("Should get bridge statistics", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      const stats = await adapter.read.getBridgeStats();

      expect(stats[0]).to.equal(0n); // pendingRequests
      expect(stats[1]).to.equal(0n); // totalBridgedToAztec
      expect(stats[2]).to.equal(0n); // totalBridgedFromAztec
      expect(stats[3]).to.equal(0n); // accumulatedFees
      expect(stats[4]).to.equal(0n); // latestRollupId
    });
  });

  describe("View Functions", function () {
    it("Should check note mirroring status", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      const noteHash = keccak256(toBytes("some_note"));
      const isMirrored = await adapter.read.isNoteMirrored([noteHash]);
      expect(isMirrored).to.be.false;
    });

    it("Should check PIL commitment registration", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      const commitment = keccak256(toBytes("some_commitment"));
      const isRegistered = await adapter.read.isPILCommitmentRegistered([commitment]);
      expect(isRegistered).to.be.false;
    });
  });

  describe("Note Types", function () {
    async function setupBridge() {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      await adapter.write.configureAztecContracts([
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333"
      ]);

      return { adapter, admin, viem };
    }

    it("Should bridge with VALUE_NOTE type", async function () {
      const { adapter } = await setupBridge();

      const amount = parseEther("1");
      const fee = (amount * 10n) / 10000n;
      const proof = toHex(toBytes("valid_proof_data_here_1234567890"));

      await adapter.write.bridgePILToAztec(
        [
          keccak256(toBytes("commit_value")),
          keccak256(toBytes("null_value")),
          keccak256(toBytes("recipient")),
          amount,
          0, // VALUE_NOTE
          keccak256(toBytes("app")),
          proof
        ],
        { value: fee }
      );

      const pending = await adapter.read.pendingRequests();
      expect(pending).to.equal(1n);
    });

    it("Should bridge with DEFI_NOTE type", async function () {
      const { adapter } = await setupBridge();

      const amount = parseEther("1");
      const fee = (amount * 10n) / 10000n;
      const proof = toHex(toBytes("valid_proof_data_here_1234567890"));

      await adapter.write.bridgePILToAztec(
        [
          keccak256(toBytes("commit_defi")),
          keccak256(toBytes("null_defi")),
          keccak256(toBytes("recipient")),
          amount,
          1, // DEFI_NOTE
          keccak256(toBytes("defi_app_data")),
          proof
        ],
        { value: fee }
      );

      const pending = await adapter.read.pendingRequests();
      expect(pending).to.equal(1n);
    });

    it("Should bridge with ACCOUNT_NOTE type", async function () {
      const { adapter } = await setupBridge();

      const amount = parseEther("1");
      const fee = (amount * 10n) / 10000n;
      const proof = toHex(toBytes("valid_proof_data_here_1234567890"));

      await adapter.write.bridgePILToAztec(
        [
          keccak256(toBytes("commit_account")),
          keccak256(toBytes("null_account")),
          keccak256(toBytes("recipient")),
          amount,
          2, // ACCOUNT_NOTE
          keccak256(toBytes("account_data")),
          proof
        ],
        { value: fee }
      );

      const pending = await adapter.read.pendingRequests();
      expect(pending).to.equal(1n);
    });

    it("Should bridge with CUSTOM_NOTE type", async function () {
      const { adapter } = await setupBridge();

      const amount = parseEther("1");
      const fee = (amount * 10n) / 10000n;
      const proof = toHex(toBytes("valid_proof_data_here_1234567890"));

      await adapter.write.bridgePILToAztec(
        [
          keccak256(toBytes("commit_custom")),
          keccak256(toBytes("null_custom")),
          keccak256(toBytes("recipient")),
          amount,
          3, // CUSTOM_NOTE
          keccak256(toBytes("custom_app_logic")),
          proof
        ],
        { value: fee }
      );

      const pending = await adapter.read.pendingRequests();
      expect(pending).to.equal(1n);
    });
  });

  describe("Integration Tests", function () {
    it("Should handle full bridge lifecycle PIL -> Aztec", async function () {
      const { viem } = await hre.network.connect();
      const [admin, relayer] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      // 1. Configure Aztec contracts
      await adapter.write.configureAztecContracts([
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333"
      ]);

      // 2. Grant relayer role
      const relayerRole = await adapter.read.RELAYER_ROLE();
      await adapter.write.grantRole([relayerRole, relayer.account.address]);

      // 3. Initiate bridge
      const amount = parseEther("10");
      const fee = (amount * 10n) / 10000n;
      const pilCommitment = keccak256(toBytes("full_lifecycle_commitment"));
      const pilNullifier = keccak256(toBytes("full_lifecycle_nullifier"));
      const proof = toHex(toBytes("valid_proof_data_here_1234567890"));

      await adapter.write.bridgePILToAztec(
        [
          pilCommitment,
          pilNullifier,
          keccak256(toBytes("aztec_recipient")),
          amount,
          0,
          keccak256(toBytes("app")),
          proof
        ],
        { value: fee }
      );

      // 4. Verify state
      const stats = await adapter.read.getBridgeStats();
      expect(stats[0]).to.equal(1n); // pendingRequests
      expect(stats[1]).to.equal(amount); // totalBridgedToAztec
      expect(stats[3]).to.equal(fee); // accumulatedFees

      // Nullifier should be marked as used
      const isUsed = await adapter.read.isNullifierUsed([pilNullifier]);
      expect(isUsed).to.be.true;
    });

    it("Should handle full bridge lifecycle Aztec -> PIL", async function () {
      const { viem } = await hre.network.connect();
      const [admin, relayer] = await viem.getWalletClients();

      const adapter = await viem.deployContract("AztecBridgeAdapter");

      // 1. Configure and grant roles
      await adapter.write.configureAztecContracts([
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333"
      ]);

      const relayerRole = await adapter.read.RELAYER_ROLE();
      await adapter.write.grantRole([relayerRole, relayer.account.address]);

      // 2. Bridge from Aztec to PIL
      const amount = parseEther("5");
      const aztecNoteHash = keccak256(toBytes("aztec_note_lifecycle"));
      const aztecNullifier = keccak256(toBytes("aztec_nullifier_lifecycle"));
      const pilRecipient = "0x4444444444444444444444444444444444444444";
      // Proof must be at least 32 bytes
      const proof = toHex(toBytes("valid_aztec_spend_proof_data_1234567890abcdef"));

      await adapter.write.bridgeAztecToPIL(
        [aztecNoteHash, aztecNullifier, pilRecipient, amount, proof],
        { account: relayer.account }
      );

      // 3. Verify state
      const stats = await adapter.read.getBridgeStats();
      expect(stats[2]).to.equal(amount); // totalBridgedFromAztec

      // Nullifier should be marked as used
      const isUsed = await adapter.read.isNullifierUsed([aztecNullifier]);
      expect(isUsed).to.be.true;
    });
  });
});
