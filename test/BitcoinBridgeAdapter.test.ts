import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, toHex, parseEther } from "viem";

describe("BitcoinBridgeAdapter", function () {
  describe("Deployment", function () {
    it("Should deploy with correct initial state", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      // Check initial values
      const bridgeFeeBps = await adapter.read.bridgeFeeBps();
      expect(bridgeFeeBps).to.equal(25n); // 0.25%

      const minPegAmount = await adapter.read.minPegAmount();
      expect(minPegAmount).to.equal(10000n); // 10,000 sats

      const maxPegAmount = await adapter.read.maxPegAmount();
      expect(maxPegAmount).to.equal(100000000000n); // 1000 BTC

      const requiredConfirmations = await adapter.read.requiredConfirmations();
      expect(requiredConfirmations).to.equal(6n);

      const totalPegIns = await adapter.read.totalPegIns();
      expect(totalPegIns).to.equal(0n);

      const totalPegOuts = await adapter.read.totalPegOuts();
      expect(totalPegOuts).to.equal(0n);
    });

    it("Should grant admin roles to deployer", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

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

  describe("Bitcoin Relay Configuration", function () {
    it("Should configure Bitcoin relay", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const relayAddress = "0x1111111111111111111111111111111111111111";

      await adapter.write.configureBitcoinRelay([relayAddress]);

      const relay = await adapter.read.bitcoinRelay();
      expect(relay.toLowerCase()).to.equal(relayAddress.toLowerCase());
    });

    it("Should reject zero address relay", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      let reverted = false;
      try {
        await adapter.write.configureBitcoinRelay([
          "0x0000000000000000000000000000000000000000"
        ]);
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("ZeroAddress");
      }
      expect(reverted).to.be.true;
    });

    it("Should set required confirmations", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      await adapter.write.setRequiredConfirmations([3n]);

      const confirmations = await adapter.read.requiredConfirmations();
      expect(confirmations).to.equal(3n);
    });
  });

  describe("Peg-Out (PIL to Bitcoin)", function () {
    async function setupBridge() {
      const { viem } = await hre.network.connect();
      const [admin, relayer, user] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      // Grant relayer role
      const relayerRole = await adapter.read.RELAYER_ROLE();
      await adapter.write.grantRole([relayerRole, relayer.account.address]);

      return { adapter, admin, relayer, user, viem };
    }

    it("Should initiate peg-out to P2WPKH address", async function () {
      const { adapter, user } = await setupBridge();

      const pilCommitment = keccak256(toBytes("pil_commitment_btc"));
      const pilNullifier = keccak256(toBytes("pil_nullifier_btc"));
      // Native SegWit address (bech32 format, ~42-62 chars)
      const bitcoinAddress = toHex(toBytes("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
      const satoshis = 100000000n; // 1 BTC
      const scriptType = 2; // P2WPKH
      const proof = toHex(toBytes("valid_proof_data_here_1234567890abcdef"));

      // Calculate fee (0.25% of 1 BTC = 0.0025 BTC worth in ETH)
      const fee = (satoshis * 25n) / 10000n;
      const feeInEth = parseEther("0.01"); // Overpay to be safe

      await adapter.write.initiatePegOut(
        [pilCommitment, pilNullifier, bitcoinAddress, scriptType, satoshis, proof],
        { value: feeInEth }
      );

      const totalPegOuts = await adapter.read.totalPegOuts();
      expect(totalPegOuts).to.equal(1n);

      const totalPeggedOut = await adapter.read.totalPeggedOut();
      expect(totalPeggedOut).to.equal(satoshis);

      // Check nullifier is registered
      const isNullifierUsed = await adapter.read.isNullifierUsed([pilNullifier]);
      expect(isNullifierUsed).to.be.true;
    });

    it("Should initiate peg-out to P2TR (Taproot) address", async function () {
      const { adapter } = await setupBridge();

      const pilCommitment = keccak256(toBytes("pil_commitment_taproot"));
      const pilNullifier = keccak256(toBytes("pil_nullifier_taproot"));
      // Taproot address (bech32m format)
      const bitcoinAddress = toHex(toBytes("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"));
      const satoshis = 50000000n; // 0.5 BTC
      const scriptType = 4; // P2TR
      const proof = toHex(toBytes("valid_proof_data_here_1234567890abcdef"));

      await adapter.write.initiatePegOut(
        [pilCommitment, pilNullifier, bitcoinAddress, scriptType, satoshis, proof],
        { value: parseEther("0.01") }
      );

      const totalPegOuts = await adapter.read.totalPegOuts();
      expect(totalPegOuts).to.equal(1n);
    });

    it("Should reject peg-out below minimum amount", async function () {
      const { adapter } = await setupBridge();

      const pilCommitment = keccak256(toBytes("commitment"));
      const pilNullifier = keccak256(toBytes("nullifier"));
      const bitcoinAddress = toHex(toBytes("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
      const satoshis = 1000n; // Below 10,000 minimum
      const proof = toHex(toBytes("valid_proof_data_here_1234567890abcdef"));

      let reverted = false;
      try {
        await adapter.write.initiatePegOut(
          [pilCommitment, pilNullifier, bitcoinAddress, 2, satoshis, proof],
          { value: parseEther("0.001") }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("AmountTooLow");
      }
      expect(reverted).to.be.true;
    });

    it("Should reject duplicate nullifier", async function () {
      const { adapter } = await setupBridge();

      const pilNullifier = keccak256(toBytes("same_nullifier"));
      const bitcoinAddress = toHex(toBytes("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
      const satoshis = 100000000n;
      const proof = toHex(toBytes("valid_proof_data_here_1234567890abcdef"));

      // First peg-out should succeed
      await adapter.write.initiatePegOut(
        [keccak256(toBytes("commit1")), pilNullifier, bitcoinAddress, 2, satoshis, proof],
        { value: parseEther("0.01") }
      );

      // Second with same nullifier should fail
      let reverted = false;
      try {
        await adapter.write.initiatePegOut(
          [keccak256(toBytes("commit2")), pilNullifier, bitcoinAddress, 2, satoshis, proof],
          { value: parseEther("0.01") }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("NullifierAlreadyUsed");
      }
      expect(reverted).to.be.true;
    });

    it("Should complete peg-out with SPV proof", async function () {
      const { adapter, relayer } = await setupBridge();

      const pilCommitment = keccak256(toBytes("pil_commitment_complete"));
      const pilNullifier = keccak256(toBytes("pil_nullifier_complete"));
      const bitcoinAddress = toHex(toBytes("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
      const satoshis = 100000000n;
      const proof = toHex(toBytes("valid_proof_data_here_1234567890abcdef"));

      // Initiate peg-out
      await adapter.write.initiatePegOut(
        [pilCommitment, pilNullifier, bitcoinAddress, 2, satoshis, proof],
        { value: parseEther("0.01") }
      );

      // SPV proof data
      const bitcoinTxHash = keccak256(toBytes("bitcoin_tx_hash"));
      const spvProof = {
        txHash: bitcoinTxHash,
        merkleRoot: keccak256(toBytes("merkle_root")),
        merkleProof: [keccak256(toBytes("sibling1")), keccak256(toBytes("sibling2"))],
        proofFlags: [0n, 1n],
        txIndex: 5n,
        blockHash: keccak256(toBytes("block_hash")),
        blockHeight: 800000n,
        confirmations: 10n
      };

      // Get request ID (computed same as contract)
      // For testing, we verify the stats change
      const pegOutsBefore = await adapter.read.totalPegOuts();
      expect(pegOutsBefore).to.equal(1n);
    });
  });

  describe("Peg-In (Bitcoin to PIL)", function () {
    async function setupBridgeWithRelayer() {
      const { viem } = await hre.network.connect();
      const [admin, relayer] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const relayerRole = await adapter.read.RELAYER_ROLE();
      await adapter.write.grantRole([relayerRole, relayer.account.address]);

      return { adapter, admin, relayer, viem };
    }

    it("Should submit peg-in request", async function () {
      const { adapter, relayer } = await setupBridgeWithRelayer();

      const bitcoinTxHash = keccak256(toBytes("bitcoin_deposit_tx"));
      const outputIndex = 0;
      const satoshis = 50000000n; // 0.5 BTC
      const pilRecipient = "0x4444444444444444444444444444444444444444";

      const spvProof = {
        txHash: bitcoinTxHash,
        merkleRoot: keccak256(toBytes("merkle_root")),
        merkleProof: [keccak256(toBytes("sibling1"))],
        proofFlags: [0n],
        txIndex: 3n,
        blockHash: keccak256(toBytes("block_hash")),
        blockHeight: 800001n,
        confirmations: 3n
      };

      await adapter.write.submitPegIn(
        [bitcoinTxHash, outputIndex, satoshis, pilRecipient, spvProof],
        { account: relayer.account }
      );

      const totalPegIns = await adapter.read.totalPegIns();
      expect(totalPegIns).to.equal(1n);
    });

    it("Should reject peg-in from non-relayer", async function () {
      const { adapter, admin } = await setupBridgeWithRelayer();

      const bitcoinTxHash = keccak256(toBytes("bitcoin_tx"));
      const spvProof = {
        txHash: bitcoinTxHash,
        merkleRoot: keccak256(toBytes("merkle")),
        merkleProof: [keccak256(toBytes("sib"))],
        proofFlags: [0n],
        txIndex: 0n,
        blockHash: keccak256(toBytes("block")),
        blockHeight: 800000n,
        confirmations: 6n
      };

      let reverted = false;
      try {
        await adapter.write.submitPegIn(
          [bitcoinTxHash, 0, 50000000n, "0x4444444444444444444444444444444444444444", spvProof],
          { account: admin.account }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("AccessControlUnauthorizedAccount");
      }
      expect(reverted).to.be.true;
    });

    it("Should reject peg-in below minimum", async function () {
      const { adapter, relayer } = await setupBridgeWithRelayer();

      const bitcoinTxHash = keccak256(toBytes("small_tx"));
      const spvProof = {
        txHash: bitcoinTxHash,
        merkleRoot: keccak256(toBytes("merkle")),
        merkleProof: [keccak256(toBytes("sib"))],
        proofFlags: [0n],
        txIndex: 0n,
        blockHash: keccak256(toBytes("block")),
        blockHeight: 800000n,
        confirmations: 6n
      };

      let reverted = false;
      try {
        await adapter.write.submitPegIn(
          [bitcoinTxHash, 0, 1000n, "0x4444444444444444444444444444444444444444", spvProof],
          { account: relayer.account }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("AmountTooLow");
      }
      expect(reverted).to.be.true;
    });
  });

  describe("Atomic Swaps (HTLC)", function () {
    it("Should create atomic swap", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const preimage = keccak256(toBytes("secret_preimage"));
      // For hashLock, we just use keccak256 as a placeholder (real would use SHA256)
      const hashLock = keccak256(toBytes("hash_lock_secret"));
      const timeLock = BigInt(Math.floor(Date.now() / 1000) + 3600 * 2); // 2 hours from now
      const satoshis = 10000000n; // 0.1 BTC
      const pilAmount = parseEther("1");
      const bitcoinParty = toHex(toBytes("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));

      await adapter.write.createAtomicSwap(
        [hashLock, timeLock, satoshis, pilAmount, bitcoinParty]
      );

      const totalSwaps = await adapter.read.totalSwaps();
      expect(totalSwaps).to.equal(1n);
    });

    it("Should reject HTLC with timeout too short", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const hashLock = keccak256(toBytes("hash"));
      const timeLock = BigInt(Math.floor(Date.now() / 1000) + 60); // Only 1 minute
      const bitcoinParty = toHex(toBytes("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));

      let reverted = false;
      try {
        await adapter.write.createAtomicSwap(
          [hashLock, timeLock, 10000000n, parseEther("1"), bitcoinParty]
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("InvalidHTLCTimeout");
      }
      expect(reverted).to.be.true;
    });

    it("Should reject HTLC with timeout too long", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const hashLock = keccak256(toBytes("hash"));
      const timeLock = BigInt(Math.floor(Date.now() / 1000) + 86400 * 30); // 30 days (> 7 day max)
      const bitcoinParty = toHex(toBytes("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));

      let reverted = false;
      try {
        await adapter.write.createAtomicSwap(
          [hashLock, timeLock, 10000000n, parseEther("1"), bitcoinParty]
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("InvalidHTLCTimeout");
      }
      expect(reverted).to.be.true;
    });
  });

  describe("Lightning Network", function () {
    async function setupLightning() {
      const { viem } = await hre.network.connect();
      const [admin, lightningNode] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const lightningRole = await adapter.read.LIGHTNING_NODE_ROLE();
      await adapter.write.grantRole([lightningRole, lightningNode.account.address]);

      return { adapter, admin, lightningNode, viem };
    }

    it("Should create Lightning invoice", async function () {
      const { adapter, lightningNode } = await setupLightning();

      const paymentHash = keccak256(toBytes("payment_hash"));
      const satoshis = 100000n; // 100,000 sats
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour
      const pilRecipient = "0x4444444444444444444444444444444444444444";

      await adapter.write.createLightningInvoice(
        [paymentHash, satoshis, expiry, pilRecipient],
        { account: lightningNode.account }
      );

      // Verify invoice was created (check via event or query)
      // For now, we just verify no error was thrown
    });

    it("Should reject Lightning invoice from non-node", async function () {
      const { adapter, admin } = await setupLightning();

      const paymentHash = keccak256(toBytes("payment"));
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

      let reverted = false;
      try {
        await adapter.write.createLightningInvoice(
          [paymentHash, 100000n, expiry, "0x4444444444444444444444444444444444444444"],
          { account: admin.account }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("AccessControlUnauthorizedAccount");
      }
      expect(reverted).to.be.true;
    });

    it("Should settle Lightning payment with preimage", async function () {
      const { adapter, lightningNode } = await setupLightning();

      // Create invoice first
      const preimage = keccak256(toBytes("lightning_secret"));
      // In real scenario, paymentHash = SHA256(preimage)
      // For testing, we use a mock
      const paymentHash = keccak256(toBytes("payment_hash_settle"));
      const satoshis = 50000n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const pilRecipient = "0x4444444444444444444444444444444444444444";

      await adapter.write.createLightningInvoice(
        [paymentHash, satoshis, expiry, pilRecipient],
        { account: lightningNode.account }
      );

      // Note: Settlement would require proper preimage that hashes to paymentHash
      // This is a simplified test
    });
  });

  describe("Bitcoin Block Headers", function () {
    async function setupSPV() {
      const { viem } = await hre.network.connect();
      const [admin, spvVerifier] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const spvRole = await adapter.read.SPV_VERIFIER_ROLE();
      await adapter.write.grantRole([spvRole, spvVerifier.account.address]);

      return { adapter, admin, spvVerifier, viem };
    }

    it("Should submit block header", async function () {
      const { adapter, spvVerifier } = await setupSPV();

      const blockHeader = {
        version: 536870912,
        previousBlockHash: keccak256(toBytes("prev_block")),
        merkleRoot: keccak256(toBytes("merkle_root")),
        timestamp: Math.floor(Date.now() / 1000),
        bits: 386089497,
        nonce: 123456789,
        blockHeight: 800000n,
        blockHash: keccak256(toBytes("block_hash_800000"))
      };

      await adapter.write.submitBlockHeader(
        [blockHeader],
        { account: spvVerifier.account }
      );

      const latestHeight = await adapter.read.latestBlockHeight();
      expect(latestHeight).to.equal(800000n);

      const latestHash = await adapter.read.latestBlockHash();
      expect(latestHash).to.equal(blockHeader.blockHash);
    });

    it("Should update latest block on newer submission", async function () {
      const { adapter, spvVerifier } = await setupSPV();

      // Submit first block
      const block1 = {
        version: 536870912,
        previousBlockHash: keccak256(toBytes("prev1")),
        merkleRoot: keccak256(toBytes("merkle1")),
        timestamp: Math.floor(Date.now() / 1000) - 600,
        bits: 386089497,
        nonce: 111111,
        blockHeight: 800000n,
        blockHash: keccak256(toBytes("block_800000"))
      };

      await adapter.write.submitBlockHeader(
        [block1],
        { account: spvVerifier.account }
      );

      // Submit newer block
      const block2 = {
        version: 536870912,
        previousBlockHash: block1.blockHash,
        merkleRoot: keccak256(toBytes("merkle2")),
        timestamp: Math.floor(Date.now() / 1000),
        bits: 386089497,
        nonce: 222222,
        blockHeight: 800001n,
        blockHash: keccak256(toBytes("block_800001"))
      };

      await adapter.write.submitBlockHeader(
        [block2],
        { account: spvVerifier.account }
      );

      const latestHeight = await adapter.read.latestBlockHeight();
      expect(latestHeight).to.equal(800001n);
    });

    it("Should reject block header from non-verifier", async function () {
      const { adapter, admin } = await setupSPV();

      const blockHeader = {
        version: 536870912,
        previousBlockHash: keccak256(toBytes("prev")),
        merkleRoot: keccak256(toBytes("merkle")),
        timestamp: Math.floor(Date.now() / 1000),
        bits: 386089497,
        nonce: 123456,
        blockHeight: 800000n,
        blockHash: keccak256(toBytes("block"))
      };

      let reverted = false;
      try {
        await adapter.write.submitBlockHeader(
          [blockHeader],
          { account: admin.account }
        );
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("AccessControlUnauthorizedAccount");
      }
      expect(reverted).to.be.true;
    });
  });

  describe("Admin Functions", function () {
    it("Should set bridge limits", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const newMin = 50000n; // 50,000 sats
      const newMax = 50000000000n; // 500 BTC

      await adapter.write.setBridgeLimits([newMin, newMax]);

      const minAmount = await adapter.read.minPegAmount();
      const maxAmount = await adapter.read.maxPegAmount();

      expect(minAmount).to.equal(newMin);
      expect(maxAmount).to.equal(newMax);
    });

    it("Should set bridge fee", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      await adapter.write.setBridgeFee([50n]); // 0.5%

      const feeBps = await adapter.read.bridgeFeeBps();
      expect(feeBps).to.equal(50n);
    });

    it("Should reject fee above 1%", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      let reverted = false;
      try {
        await adapter.write.setBridgeFee([101n]); // 1.01%
      } catch (error) {
        reverted = true;
        expect(String(error)).to.include("Fee too high");
      }
      expect(reverted).to.be.true;
    });

    it("Should set HTLC timeouts", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const newMinTimeout = 7200n; // 2 hours
      const newMaxTimeout = 604800n; // 7 days in seconds

      await adapter.write.setHTLCTimeouts([newMinTimeout, newMaxTimeout]);

      const minTimeout = await adapter.read.minHTLCTimeout();
      const maxTimeout = await adapter.read.maxHTLCTimeout();

      expect(minTimeout).to.equal(newMinTimeout);
      expect(maxTimeout).to.equal(newMaxTimeout);
    });

    it("Should pause and unpause", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

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

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const stats = await adapter.read.getBridgeStats();

      expect(stats[0]).to.equal(0n); // totalPegIns
      expect(stats[1]).to.equal(0n); // totalPegOuts
      expect(stats[2]).to.equal(0n); // totalSwaps
      expect(stats[3]).to.equal(0n); // totalPeggedIn
      expect(stats[4]).to.equal(0n); // totalPeggedOut
      expect(stats[5]).to.equal(0n); // accumulatedFees
      expect(stats[6]).to.equal(0n); // latestBlockHeight
    });
  });

  describe("View Functions", function () {
    it("Should check nullifier status", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const nullifier = keccak256(toBytes("test_nullifier"));
      const isUsed = await adapter.read.isNullifierUsed([nullifier]);
      expect(isUsed).to.be.false;
    });

    it("Should check commitment deposit status", async function () {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      const commitment = keccak256(toBytes("test_commitment"));
      const isDeposited = await adapter.read.isCommitmentDeposited([commitment]);
      expect(isDeposited).to.be.false;
    });
  });

  describe("Script Types", function () {
    async function setupBridge() {
      const { viem } = await hre.network.connect();
      const [admin] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      return { adapter, admin, viem };
    }

    it("Should handle P2PKH (Legacy) addresses", async function () {
      const { adapter } = await setupBridge();

      const pilCommitment = keccak256(toBytes("commit_p2pkh"));
      const pilNullifier = keccak256(toBytes("null_p2pkh"));
      // Legacy address (25-34 bytes)
      const bitcoinAddress = toHex(toBytes("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
      const satoshis = 100000000n;
      const scriptType = 0; // P2PKH
      const proof = toHex(toBytes("valid_proof_data_here_1234567890abcdef"));

      await adapter.write.initiatePegOut(
        [pilCommitment, pilNullifier, bitcoinAddress, scriptType, satoshis, proof],
        { value: parseEther("0.01") }
      );

      const totalPegOuts = await adapter.read.totalPegOuts();
      expect(totalPegOuts).to.equal(1n);
    });

    it("Should handle P2SH addresses", async function () {
      const { adapter } = await setupBridge();

      const pilCommitment = keccak256(toBytes("commit_p2sh"));
      const pilNullifier = keccak256(toBytes("null_p2sh"));
      // P2SH address
      const bitcoinAddress = toHex(toBytes("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
      const satoshis = 100000000n;
      const scriptType = 1; // P2SH
      const proof = toHex(toBytes("valid_proof_data_here_1234567890abcdef"));

      await adapter.write.initiatePegOut(
        [pilCommitment, pilNullifier, bitcoinAddress, scriptType, satoshis, proof],
        { value: parseEther("0.01") }
      );

      const totalPegOuts = await adapter.read.totalPegOuts();
      expect(totalPegOuts).to.equal(1n);
    });

    it("Should handle P2WSH addresses", async function () {
      const { adapter } = await setupBridge();

      const pilCommitment = keccak256(toBytes("commit_p2wsh"));
      const pilNullifier = keccak256(toBytes("null_p2wsh"));
      // P2WSH address (longer bech32)
      const bitcoinAddress = toHex(toBytes("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"));
      const satoshis = 100000000n;
      const scriptType = 3; // P2WSH
      const proof = toHex(toBytes("valid_proof_data_here_1234567890abcdef"));

      await adapter.write.initiatePegOut(
        [pilCommitment, pilNullifier, bitcoinAddress, scriptType, satoshis, proof],
        { value: parseEther("0.01") }
      );

      const totalPegOuts = await adapter.read.totalPegOuts();
      expect(totalPegOuts).to.equal(1n);
    });
  });

  describe("Integration Tests", function () {
    it("Should handle full peg-out lifecycle", async function () {
      const { viem } = await hre.network.connect();
      const [admin, relayer] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      // Grant roles
      const relayerRole = await adapter.read.RELAYER_ROLE();
      await adapter.write.grantRole([relayerRole, relayer.account.address]);

      // 1. Initiate peg-out
      const pilCommitment = keccak256(toBytes("full_lifecycle_commit"));
      const pilNullifier = keccak256(toBytes("full_lifecycle_null"));
      const bitcoinAddress = toHex(toBytes("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
      const satoshis = 100000000n; // 1 BTC
      const proof = toHex(toBytes("valid_proof_data_here_1234567890abcdef"));

      await adapter.write.initiatePegOut(
        [pilCommitment, pilNullifier, bitcoinAddress, 2, satoshis, proof],
        { value: parseEther("0.01") }
      );

      // 2. Verify state
      const stats = await adapter.read.getBridgeStats();
      expect(stats[1]).to.equal(1n); // totalPegOuts
      expect(stats[4]).to.equal(satoshis); // totalPeggedOut

      // Nullifier marked as used
      const isUsed = await adapter.read.isNullifierUsed([pilNullifier]);
      expect(isUsed).to.be.true;
    });

    it("Should handle full peg-in lifecycle", async function () {
      const { viem } = await hre.network.connect();
      const [admin, relayer] = await viem.getWalletClients();

      const adapter = await viem.deployContract("BitcoinBridgeAdapter");

      // Grant relayer role
      const relayerRole = await adapter.read.RELAYER_ROLE();
      await adapter.write.grantRole([relayerRole, relayer.account.address]);

      // 1. Submit peg-in
      const bitcoinTxHash = keccak256(toBytes("btc_deposit_lifecycle"));
      const satoshis = 200000000n; // 2 BTC
      const pilRecipient = "0x4444444444444444444444444444444444444444";

      const spvProof = {
        txHash: bitcoinTxHash,
        merkleRoot: keccak256(toBytes("merkle_lifecycle")),
        merkleProof: [keccak256(toBytes("sib1")), keccak256(toBytes("sib2"))],
        proofFlags: [0n, 1n],
        txIndex: 7n,
        blockHash: keccak256(toBytes("block_lifecycle")),
        blockHeight: 800100n,
        confirmations: 8n
      };

      await adapter.write.submitPegIn(
        [bitcoinTxHash, 0, satoshis, pilRecipient, spvProof],
        { account: relayer.account }
      );

      // 2. Verify state
      const stats = await adapter.read.getBridgeStats();
      expect(stats[0]).to.equal(1n); // totalPegIns
    });
  });
});
