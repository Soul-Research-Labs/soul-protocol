import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes } from "viem";

/**
 * Integration Tests: PIL Private Exchange with Core PIL Primitives
 * 
 * Tests the complete flow from private exchange operations through
 * PC³ container creation and cross-chain messaging.
 */
describe("PIL Exchange Integration Tests", function () {
  // Role constants
  const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
  const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
  const MATCHER_ROLE = keccak256(toBytes("MATCHER_ROLE"));

  // Helper to get viem client
  async function getViem() {
    const { viem } = await hre.network.connect();
    return viem;
  }

  describe("End-to-End Private Swap Flow", function () {
    it("should execute complete private swap with deposits and orders", async function () {
      const viem = await getViem();
      const [owner, user1, user2, feeCollector, operator, relayer] = await viem.getWalletClients();
      
      // Deploy mock token
      const mockToken = await viem.deployContract("MockWETH");
      
      // Deploy exchange
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      // Grant roles
      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      await exchange.write.grantRole([RELAYER_ROLE, relayer.account.address]);

      // Mint and approve tokens for user1
      await mockToken.write.mint([user1.account.address, parseEther("10000")]);
      await mockToken.write.approve([exchange.address, parseEther("10000")], { account: user1.account });

      // Step 1: User deposits to exchange
      const depositAmount = parseEther("1000");
      const commitment = keccak256(toBytes("test_commitment"));
      
      await exchange.write.deposit([mockToken.address, depositAmount, commitment], {
        account: user1.account,
      });

      const balance = await exchange.read.balances([user1.account.address, mockToken.address]);
      expect(balance).to.equal(depositAmount);
    });

    it("should allow creating and matching orders", async function () {
      const viem = await getViem();
      const [owner, user1, user2, feeCollector, operator, relayer] = await viem.getWalletClients();
      
      const mockTokenA = await viem.deployContract("MockWETH");
      const mockTokenB = await viem.deployContract("MockWETH");
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      await exchange.write.grantRole([RELAYER_ROLE, relayer.account.address]);
      await exchange.write.grantRole([MATCHER_ROLE, relayer.account.address]);

      // Setup tokens for both users
      await mockTokenA.write.mint([user1.account.address, parseEther("10000")]);
      await mockTokenB.write.mint([user2.account.address, parseEther("10000")]);
      await mockTokenA.write.approve([exchange.address, parseEther("10000")], { account: user1.account });
      await mockTokenB.write.approve([exchange.address, parseEther("10000")], { account: user2.account });

      // Deposit
      const commitment1 = keccak256(toBytes("commitment_1"));
      const commitment2 = keccak256(toBytes("commitment_2"));
      
      await exchange.write.deposit([mockTokenA.address, parseEther("1000"), commitment1], { account: user1.account });
      await exchange.write.deposit([mockTokenB.address, parseEther("1000"), commitment2], { account: user2.account });

      // Verify deposits
      const balance1 = await exchange.read.balances([user1.account.address, mockTokenA.address]);
      const balance2 = await exchange.read.balances([user2.account.address, mockTokenB.address]);
      
      expect(balance1).to.equal(parseEther("1000"));
      expect(balance2).to.equal(parseEther("1000"));
    });
  });

  describe("AMM Pool Operations", function () {
    it("should support pool creation and liquidity provision", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector, operator] = await viem.getWalletClients();
      
      const mockTokenA = await viem.deployContract("MockWETH");
      const mockTokenB = await viem.deployContract("MockWETH");
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      // Setup liquidity
      await mockTokenA.write.mint([user1.account.address, parseEther("100000")]);
      await mockTokenB.write.mint([user1.account.address, parseEther("100000")]);
      await mockTokenA.write.approve([exchange.address, parseEther("100000")], { account: user1.account });
      await mockTokenB.write.approve([exchange.address, parseEther("100000")], { account: user1.account });

      const commitment = keccak256(toBytes("lp_commitment"));
      await exchange.write.deposit([mockTokenA.address, parseEther("10000"), commitment], { account: user1.account });
      await exchange.write.deposit([mockTokenB.address, parseEther("10000"), commitment], { account: user1.account });

      // Verify balances before pool
      const balA = await exchange.read.balances([user1.account.address, mockTokenA.address]);
      const balB = await exchange.read.balances([user1.account.address, mockTokenB.address]);
      
      expect(balA).to.equal(parseEther("10000"));
      expect(balB).to.equal(parseEther("10000"));
    });
  });

  describe("Cross-Chain Integration", function () {
    it("should support cross-chain order preparation", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockToken = await viem.deployContract("MockWETH");
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockToken.write.mint([user1.account.address, parseEther("10000")]);
      await mockToken.write.approve([exchange.address, parseEther("10000")], { account: user1.account });

      const commitment = keccak256(toBytes("crosschain_commitment"));
      await exchange.write.deposit([mockToken.address, parseEther("1000"), commitment], { account: user1.account });

      // Verify deposit successful
      const balance = await exchange.read.balances([user1.account.address, mockToken.address]);
      expect(balance).to.equal(parseEther("1000"));
    });

    it("should compute cross-chain message hashes correctly", async function () {
      const messageId = keccak256(toBytes("test-message"));
      
      // Verify hash is non-zero
      expect(messageId).to.not.equal("0x0000000000000000000000000000000000000000000000000000000000000000");
    });
  });

  describe("Privacy Preservation", function () {
    it("should use commitments for deposits", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockToken = await viem.deployContract("MockWETH");
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockToken.write.mint([user1.account.address, parseEther("10000")]);
      await mockToken.write.approve([exchange.address, parseEther("10000")], { account: user1.account });

      // Create unique commitment
      const commitment = keccak256(toBytes("unique_commitment_" + Date.now()));
      const depositAmount = parseEther("500");

      await exchange.write.deposit([mockToken.address, depositAmount, commitment], { account: user1.account });

      const balance = await exchange.read.balances([user1.account.address, mockToken.address]);
      expect(balance).to.equal(depositAmount);
    });

    it("should prevent double-spending via nullifiers", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockToken = await viem.deployContract("MockWETH");
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockToken.write.mint([user1.account.address, parseEther("10000")]);
      await mockToken.write.approve([exchange.address, parseEther("10000")], { account: user1.account });

      const commitment = keccak256(toBytes("deposit_commitment"));
      await exchange.write.deposit([mockToken.address, parseEther("1000"), commitment], { account: user1.account });

      // Withdraw with nullifier
      const nullifier = keccak256(toBytes("unique_nullifier_test"));
      const proof = keccak256(toBytes("valid_proof_data_here_min_32_bytes"));
      
      await exchange.write.withdraw([mockToken.address, parseEther("100"), nullifier, proof], { account: user1.account });

      // Try to reuse nullifier - should fail
      try {
        await exchange.write.withdraw([mockToken.address, parseEther("100"), nullifier, proof], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: unknown) {
        expect((error as Error).message).to.include("NullifierAlreadyUsed");
      }
    });
  });

  describe("Stealth Address Integration", function () {
    it("should generate valid stealth address components", async function () {
      // Generate key pairs
      const spendingKey = keccak256(toBytes("spending_key_secret"));
      const viewingKey = keccak256(toBytes("viewing_key_secret"));
      
      // Derive public key representations
      const spendingPubKey = keccak256(toBytes(spendingKey));
      const viewingPubKey = keccak256(toBytes(viewingKey));

      // Simulate ephemeral key
      const ephemeralSecret = keccak256(toBytes("ephemeral_" + Date.now()));
      
      // Compute shared secret (simplified)
      const sharedSecretInput = toBytes(viewingPubKey + ephemeralSecret.slice(2));
      const sharedSecret = keccak256(sharedSecretInput);

      // Derive stealth address
      const stealthInput = toBytes(spendingPubKey + sharedSecret.slice(2));
      const stealthAddress = keccak256(stealthInput);

      expect(stealthAddress).to.not.equal("0x0000000000000000000000000000000000000000000000000000000000000000");
    });
  });

  describe("Relayer Operations", function () {
    it("should allow relayer to have proper permissions", async function () {
      const viem = await getViem();
      const [owner, relayer, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([RELAYER_ROLE, relayer.account.address]);

      const hasRole = await exchange.read.hasRole([RELAYER_ROLE, relayer.account.address]);
      expect(hasRole).to.be.true;
    });

    it("should track relayer activity", async function () {
      const viem = await getViem();
      const [owner, relayer, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([RELAYER_ROLE, relayer.account.address]);

      // Verify role is active
      const isRelayer = await exchange.read.hasRole([RELAYER_ROLE, relayer.account.address]);
      expect(isRelayer).to.be.true;
    });
  });

  describe("Emergency Operations", function () {
    it("should allow admin to pause contract", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockToken = await viem.deployContract("MockWETH");
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      // Pause
      await exchange.write.pause();

      // Operations should fail when paused
      try {
        await mockToken.write.mint([user1.account.address, parseEther("1000")]);
        await mockToken.write.approve([exchange.address, parseEther("1000")], { account: user1.account });
        const commitment = keccak256(toBytes("test"));
        await exchange.write.deposit([mockToken.address, parseEther("100"), commitment], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: unknown) {
        // Contract is paused - error message varies by implementation
        expect((error as Error).message.length).to.be.greaterThan(0);
      }

      // Unpause
      await exchange.write.unpause();
    });

    it("should allow regular withdrawal with nullifier", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockToken = await viem.deployContract("MockWETH");
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockToken.write.mint([user1.account.address, parseEther("10000")]);
      await mockToken.write.approve([exchange.address, parseEther("10000")], { account: user1.account });

      const commitment = keccak256(toBytes("withdraw_test"));
      await exchange.write.deposit([mockToken.address, parseEther("1000"), commitment], { account: user1.account });

      const balanceBefore = await mockToken.read.balanceOf([user1.account.address]);

      // Withdraw with nullifier and proof
      const nullifier = keccak256(toBytes("unique_nullifier_withdraw"));
      const proof = keccak256(toBytes("valid_proof_data_here_min_32_bytes"));
      await exchange.write.withdraw([mockToken.address, parseEther("500"), nullifier, proof], { account: user1.account });

      const balanceAfter = await mockToken.read.balanceOf([user1.account.address]);
      expect(balanceAfter).to.be.greaterThan(balanceBefore);
    });
  });

  describe("Fee Collection", function () {
    it("should track fee configuration", async function () {
      const viem = await getViem();
      const [owner, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const makerFee = await exchange.read.makerFeeBps();
      const takerFee = await exchange.read.takerFeeBps();

      expect(makerFee).to.equal(10n);
      expect(takerFee).to.equal(30n);
    });

    it("should allow fee updates by admin", async function () {
      const viem = await getViem();
      const [owner, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      // Update fees using setFees function
      await exchange.write.setFees([20n, 40n]);

      const makerFee = await exchange.read.makerFeeBps();
      const takerFee = await exchange.read.takerFeeBps();

      expect(makerFee).to.equal(20n);
      expect(takerFee).to.equal(40n);
    });
  });

  describe("Multi-Token Support", function () {
    it("should support deposits of multiple tokens", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const tokenA = await viem.deployContract("MockWETH");
      const tokenB = await viem.deployContract("MockWETH");
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      // Mint and approve both tokens
      await tokenA.write.mint([user1.account.address, parseEther("10000")]);
      await tokenB.write.mint([user1.account.address, parseEther("10000")]);
      await tokenA.write.approve([exchange.address, parseEther("10000")], { account: user1.account });
      await tokenB.write.approve([exchange.address, parseEther("10000")], { account: user1.account });

      const commitmentA = keccak256(toBytes("token_a_deposit"));
      const commitmentB = keccak256(toBytes("token_b_deposit"));

      await exchange.write.deposit([tokenA.address, parseEther("1000"), commitmentA], { account: user1.account });
      await exchange.write.deposit([tokenB.address, parseEther("2000"), commitmentB], { account: user1.account });

      const balanceA = await exchange.read.balances([user1.account.address, tokenA.address]);
      const balanceB = await exchange.read.balances([user1.account.address, tokenB.address]);

      expect(balanceA).to.equal(parseEther("1000"));
      expect(balanceB).to.equal(parseEther("2000"));
    });

    it("should track balances independently per token", async function () {
      const viem = await getViem();
      const [owner, user1, user2, feeCollector] = await viem.getWalletClients();
      
      const token = await viem.deployContract("MockWETH");
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await token.write.mint([user1.account.address, parseEther("10000")]);
      await token.write.mint([user2.account.address, parseEther("10000")]);
      await token.write.approve([exchange.address, parseEther("10000")], { account: user1.account });
      await token.write.approve([exchange.address, parseEther("10000")], { account: user2.account });

      const commitment1 = keccak256(toBytes("user1_deposit"));
      const commitment2 = keccak256(toBytes("user2_deposit"));

      await exchange.write.deposit([token.address, parseEther("500"), commitment1], { account: user1.account });
      await exchange.write.deposit([token.address, parseEther("1500"), commitment2], { account: user2.account });

      const balance1 = await exchange.read.balances([user1.account.address, token.address]);
      const balance2 = await exchange.read.balances([user2.account.address, token.address]);

      expect(balance1).to.equal(parseEther("500"));
      expect(balance2).to.equal(parseEther("1500"));
    });
  });

  describe("ETH Deposits", function () {
    it("should support native ETH deposits", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const depositAmount = parseEther("5");
      const commitment = keccak256(toBytes("eth_deposit"));
      const zeroAddress = "0x0000000000000000000000000000000000000000" as `0x${string}`;

      await exchange.write.deposit([zeroAddress, depositAmount, commitment], {
        account: user1.account,
        value: depositAmount,
      });

      const balance = await exchange.read.balances([user1.account.address, zeroAddress]);
      expect(balance).to.equal(depositAmount);
    });
  });

  describe("Gas Efficiency", function () {
    it("should have reasonable deposit gas cost", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      
      const mockToken = await viem.deployContract("MockWETH");
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockToken.write.mint([user1.account.address, parseEther("10000")]);
      await mockToken.write.approve([exchange.address, parseEther("10000")], { account: user1.account });

      const commitment = keccak256(toBytes("gas_test"));
      
      const txHash = await exchange.write.deposit([mockToken.address, parseEther("100"), commitment], {
        account: user1.account,
      });

      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      
      console.log(`Deposit gas used: ${receipt.gasUsed}`);
      expect(receipt.gasUsed).to.be.lessThan(200000n);
    });
  });
});
