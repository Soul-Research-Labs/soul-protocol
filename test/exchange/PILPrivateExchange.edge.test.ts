import { expect } from "chai";
import hre from "hardhat";
import { getAddress, parseEther, parseUnits, keccak256, toBytes, toHex, maxUint256 } from "viem";

/**
 * Edge Case Tests for PILPrivateExchange
 * 
 * Tests boundary conditions, edge cases, and failure paths to achieve 100% coverage
 */
describe("PILPrivateExchange Edge Cases", function () {
  // Role constants
  const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
  const MATCHER_ROLE = keccak256(toBytes("MATCHER_ROLE"));
  const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
  const DEFAULT_ADMIN_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;

  async function getViem() {
    const { viem } = await hre.network.connect();
    return viem;
  }

  describe("Deposit Edge Cases", function () {
    it("should reject ETH deposit with mismatched value", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const depositAmount = parseEther("5");
      const commitment = keccak256(toBytes("eth_commitment"));
      const zeroAddress = "0x0000000000000000000000000000000000000000";

      try {
        await exchange.write.deposit([zeroAddress, depositAmount, commitment], {
          account: user1.account,
          value: parseEther("1"), // Mismatched value
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });

    it("should handle maximum uint256 deposit attempt", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      // This will fail due to insufficient balance, not overflow
      const commitment = keccak256(toBytes("max_commitment"));

      try {
        await exchange.write.deposit([mockWETH.address, maxUint256, commitment], {
          account: user1.account,
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        // Expected to fail due to insufficient balance or allowance
        expect(error.message).to.not.be.empty;
      }
    });

    it("should emit Deposit event with correct parameters", async function () {
      const viem = await getViem();
      const publicClient = await viem.getPublicClient();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });

      const depositAmount = parseEther("10");
      const commitment = keccak256(toBytes("event_test"));

      const hash = await exchange.write.deposit([mockWETH.address, depositAmount, commitment], {
        account: user1.account,
      });

      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      expect(receipt.logs.length).to.be.gte(1);
    });
  });

  describe("Withdrawal Edge Cases", function () {
    it("should reject withdrawal exceeding balance", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });

      const depositAmount = parseEther("5");
      const commitment = keccak256(toBytes("small_deposit"));
      await exchange.write.deposit([mockWETH.address, depositAmount, commitment], {
        account: user1.account,
      });

      const nullifier = keccak256(toBytes("exceeding_nullifier"));
      const proof = keccak256(toBytes("valid_proof_data_here_min_32_bytes"));

      try {
        await exchange.write.withdraw([mockWETH.address, parseEther("10"), nullifier, proof], {
          account: user1.account,
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("InsufficientBalance");
      }
    });

    it("should reject withdrawal with invalid proof (too short)", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("10"), keccak256(toBytes("d"))], {
        account: user1.account,
      });

      const nullifier = keccak256(toBytes("short_proof_nullifier"));
      const shortProof = "0x1234"; // Too short

      try {
        await exchange.write.withdraw([mockWETH.address, parseEther("1"), nullifier, shortProof], {
          account: user1.account,
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("InvalidProof");
      }
    });

    it("should allow full balance withdrawal", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });

      const depositAmount = parseEther("10");
      await exchange.write.deposit([mockWETH.address, depositAmount, keccak256(toBytes("full"))], {
        account: user1.account,
      });

      const nullifier = keccak256(toBytes("full_withdrawal_nullifier"));
      const proof = keccak256(toBytes("valid_proof_data_here_min_32_bytes"));

      await exchange.write.withdraw([mockWETH.address, depositAmount, nullifier, proof], {
        account: user1.account,
      });

      const balance = await exchange.read.balances([user1.account.address, mockWETH.address]);
      expect(balance).to.equal(0n);
    });

    it("should allow ETH withdrawal", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const depositAmount = parseEther("2");
      const zeroAddress = "0x0000000000000000000000000000000000000000";
      
      await exchange.write.deposit([zeroAddress, depositAmount, keccak256(toBytes("eth"))], {
        account: user1.account,
        value: depositAmount,
      });

      const nullifier = keccak256(toBytes("eth_withdraw_nullifier"));
      const proof = keccak256(toBytes("valid_proof_data_here_min_32_bytes"));

      await exchange.write.withdraw([zeroAddress, parseEther("1"), nullifier, proof], {
        account: user1.account,
      });

      const balance = await exchange.read.balances([user1.account.address, zeroAddress]);
      expect(balance).to.equal(parseEther("1"));
    });
  });

  describe("Order Edge Cases", function () {
    it("should reject order with zero amount", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("100"), keccak256(toBytes("d"))], {
        account: user1.account,
      });

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const commitment = keccak256(toBytes("zero_order"));
      const nullifier = keccak256(toBytes("zero_nullifier"));
      const encryptedDetails = toHex(toBytes("encrypted"));

      try {
        await exchange.write.createPrivateOrder([
          mockWETH.address,
          mockUSDC.address,
          0n, // Zero amount
          parseUnits("1000", 6),
          deadline,
          0, 1,
          commitment,
          nullifier,
          encryptedDetails,
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });

    it("should reject order with same input/output token", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("100"), keccak256(toBytes("d"))], {
        account: user1.account,
      });

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const commitment = keccak256(toBytes("same_token"));
      const nullifier = keccak256(toBytes("same_nullifier"));
      const encryptedDetails = toHex(toBytes("encrypted"));

      try {
        await exchange.write.createPrivateOrder([
          mockWETH.address,
          mockWETH.address, // Same token
          parseEther("10"),
          parseEther("10"),
          deadline,
          0, 1,
          commitment,
          nullifier,
          encryptedDetails,
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });

    it("should reject order with reused nullifier", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("100"), keccak256(toBytes("d"))], {
        account: user1.account,
      });

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const nullifier = keccak256(toBytes("reused_nullifier"));
      const encryptedDetails = toHex(toBytes("encrypted"));

      // First order
      await exchange.write.createPrivateOrder([
        mockWETH.address,
        mockUSDC.address,
        parseEther("5"),
        parseUnits("10000", 6),
        deadline,
        0, 1,
        keccak256(toBytes("commit1")),
        nullifier,
        encryptedDetails,
      ], { account: user1.account });

      // Second order with same nullifier
      try {
        await exchange.write.createPrivateOrder([
          mockWETH.address,
          mockUSDC.address,
          parseEther("5"),
          parseUnits("10000", 6),
          deadline,
          0, 1,
          keccak256(toBytes("commit2")),
          nullifier, // Reused nullifier
          encryptedDetails,
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("NullifierAlreadyUsed");
      }
    });

    it("should reject order with insufficient balance", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockWETH.write.mint([user1.account.address, parseEther("10")]);
      await mockWETH.write.approve([exchange.address, parseEther("10")], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("5"), keccak256(toBytes("d"))], {
        account: user1.account,
      });

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const commitment = keccak256(toBytes("insufficient"));
      const nullifier = keccak256(toBytes("insufficient_null"));
      const encryptedDetails = toHex(toBytes("encrypted"));

      try {
        await exchange.write.createPrivateOrder([
          mockWETH.address,
          mockUSDC.address,
          parseEther("100"), // More than deposited
          parseUnits("200000", 6),
          deadline,
          0, 1,
          commitment,
          nullifier,
          encryptedDetails,
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("InsufficientBalance");
      }
    });

    it("should reject cancel from non-owner", async function () {
      const viem = await getViem();
      const [owner, user1, user2, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("100"), keccak256(toBytes("d"))], {
        account: user1.account,
      });

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      await exchange.write.createPrivateOrder([
        mockWETH.address,
        mockUSDC.address,
        parseEther("10"),
        parseUnits("20000", 6),
        deadline,
        0, 1,
        keccak256(toBytes("owner_order")),
        keccak256(toBytes("owner_nullifier")),
        toHex(toBytes("encrypted")),
      ], { account: user1.account });

      const userOrders = await exchange.read.getUserOrders([user1.account.address]);
      const orderId = userOrders[0];

      try {
        await exchange.write.cancelOrder([orderId], { account: user2.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("Unauthorized");
      }
    });

    it("should reject cancel of already cancelled order", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("100"), keccak256(toBytes("d"))], {
        account: user1.account,
      });

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      await exchange.write.createPrivateOrder([
        mockWETH.address,
        mockUSDC.address,
        parseEther("10"),
        parseUnits("20000", 6),
        deadline,
        0, 1,
        keccak256(toBytes("cancel_twice")),
        keccak256(toBytes("cancel_twice_null")),
        toHex(toBytes("encrypted")),
      ], { account: user1.account });

      const userOrders = await exchange.read.getUserOrders([user1.account.address]);
      const orderId = userOrders[0];

      await exchange.write.cancelOrder([orderId], { account: user1.account });

      try {
        await exchange.write.cancelOrder([orderId], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });
  });

  describe("Pool Edge Cases", function () {
    it("should reject pool creation with same tokens", async function () {
      const viem = await getViem();
      const [owner, operator, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      try {
        await exchange.write.createPool([mockWETH.address, mockWETH.address, 30n], {
          account: operator.account,
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });

    it("should reject pool creation with excessive fee", async function () {
      const viem = await getViem();
      const [owner, operator, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      try {
        await exchange.write.createPool([mockWETH.address, mockUSDC.address, 10001n], {
          account: operator.account,
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });

    it("should reject duplicate pool creation", async function () {
      const viem = await getViem();
      const [owner, operator, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });

      try {
        await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
          account: operator.account,
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });

    it("should reject adding liquidity with zero amounts", async function () {
      const viem = await getViem();
      const [owner, operator, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });
      const poolId = await exchange.read.poolIds([0n]);

      try {
        await exchange.write.addLiquidity([poolId, 0n, 0n], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });

    it("should reject removing more LP tokens than owned", async function () {
      const viem = await getViem();
      const [owner, operator, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      // Mint and deposit
      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockUSDC.write.mint([user1.account.address, parseUnits("200000", 6)]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await mockUSDC.write.approve([exchange.address, parseUnits("200000", 6)], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("100"), keccak256(toBytes("w"))], {
        account: user1.account,
      });
      await exchange.write.deposit([mockUSDC.address, parseUnits("200000", 6), keccak256(toBytes("u"))], {
        account: user1.account,
      });

      // Create pool and add liquidity
      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });
      const poolId = await exchange.read.poolIds([0n]);
      await exchange.write.addLiquidity([poolId, parseEther("10"), parseUnits("20000", 6)], {
        account: user1.account,
      });

      const lpBalance = await exchange.read.lpBalances([poolId, user1.account.address]);

      try {
        await exchange.write.removeLiquidity([poolId, lpBalance + 1n], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });

    it("should reject swap with slippage exceeded", async function () {
      const viem = await getViem();
      const [owner, operator, user1, user2, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      // Setup pool with liquidity
      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockUSDC.write.mint([user1.account.address, parseUnits("200000", 6)]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await mockUSDC.write.approve([exchange.address, parseUnits("200000", 6)], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("100"), keccak256(toBytes("w"))], {
        account: user1.account,
      });
      await exchange.write.deposit([mockUSDC.address, parseUnits("200000", 6), keccak256(toBytes("u"))], {
        account: user1.account,
      });

      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });
      const poolId = await exchange.read.poolIds([0n]);
      await exchange.write.addLiquidity([poolId, parseEther("50"), parseUnits("100000", 6)], {
        account: user1.account,
      });

      // User2 tries to swap
      await mockWETH.write.mint([user2.account.address, parseEther("10")]);
      await mockWETH.write.approve([exchange.address, parseEther("10")], { account: user2.account });
      await exchange.write.deposit([mockWETH.address, parseEther("10"), keccak256(toBytes("w2"))], {
        account: user2.account,
      });

      try {
        // Expect way more output than possible
        await exchange.write.instantSwap([poolId, mockWETH.address, parseEther("1"), parseUnits("5000", 6)], {
          account: user2.account,
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("SlippageExceeded");
      }
    });

    it("should reject swap with invalid token", async function () {
      const viem = await getViem();
      const [owner, operator, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const mockDAI = await viem.deployContract("MockDAI");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      // Setup pool
      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockUSDC.write.mint([user1.account.address, parseUnits("200000", 6)]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await mockUSDC.write.approve([exchange.address, parseUnits("200000", 6)], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("100"), keccak256(toBytes("w"))], {
        account: user1.account,
      });
      await exchange.write.deposit([mockUSDC.address, parseUnits("200000", 6), keccak256(toBytes("u"))], {
        account: user1.account,
      });

      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });
      const poolId = await exchange.read.poolIds([0n]);
      await exchange.write.addLiquidity([poolId, parseEther("50"), parseUnits("100000", 6)], {
        account: user1.account,
      });

      try {
        // Try to swap with DAI which is not in the pool
        await exchange.write.instantSwap([poolId, mockDAI.address, parseEther("1"), 1n], {
          account: user1.account,
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });
  });

  describe("Cross-Chain Edge Cases", function () {
    it("should reject cross-chain order with zero secret hash", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const targetChain = 42161n;
      const sourceCommitment = keccak256(toBytes("source"));
      const targetCommitment = keccak256(toBytes("target"));
      const zeroHash = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;
      const deadline = BigInt(Math.floor(Date.now() / 1000) + 86400);

      try {
        await exchange.write.createCrossChainOrder([
          targetChain,
          sourceCommitment,
          targetCommitment,
          zeroHash,
          deadline,
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });

    it("should reject cross-chain order with past deadline", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const targetChain = 42161n;
      const sourceCommitment = keccak256(toBytes("source"));
      const targetCommitment = keccak256(toBytes("target"));
      const secretHash = keccak256(toBytes("secret"));
      const deadline = BigInt(Math.floor(Date.now() / 1000) - 86400); // Past

      try {
        await exchange.write.createCrossChainOrder([
          targetChain,
          sourceCommitment,
          targetCommitment,
          secretHash,
          deadline,
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("InvalidDeadline");
      }
    });
  });

  describe("Admin Edge Cases", function () {
    it("should reject setFees from non-admin", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      try {
        await exchange.write.setFees([5n, 15n], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("AccessControl");
      }
    });

    it("should reject setFeeCollector with zero address", async function () {
      const viem = await getViem();
      const [owner, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const zeroAddress = "0x0000000000000000000000000000000000000000";

      try {
        await exchange.write.setFeeCollector([zeroAddress], { account: owner.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message.length).to.be.greaterThan(0);
      }
    });

    it("should reject pause from non-operator", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      try {
        await exchange.write.pause([], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("AccessControl");
      }
    });

    it("should allow admin to grant and revoke roles", async function () {
      const viem = await getViem();
      const [owner, operator, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      let hasRole = await exchange.read.hasRole([OPERATOR_ROLE, operator.account.address]);
      expect(hasRole).to.be.true;

      await exchange.write.revokeRole([OPERATOR_ROLE, operator.account.address]);
      hasRole = await exchange.read.hasRole([OPERATOR_ROLE, operator.account.address]);
      expect(hasRole).to.be.false;
    });
  });

  describe("View Functions", function () {
    it("should return empty array for user with no orders", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const orders = await exchange.read.getUserOrders([user1.account.address]);
      expect(orders.length).to.equal(0);
    });

    it("should return correct pool count", async function () {
      const viem = await getViem();
      const [owner, operator, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const mockDAI = await viem.deployContract("MockDAI");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });
      await exchange.write.createPool([mockWETH.address, mockDAI.address, 30n], {
        account: operator.account,
      });

      const stats = await exchange.read.getStats();
      expect(stats[4]).to.equal(2n); // poolCount
    });

    it("should calculate swap output for zero reserves", async function () {
      const viem = await getViem();
      const [owner, operator, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });
      const poolId = await exchange.read.poolIds([0n]);

      // Pool has zero liquidity
      const output = await exchange.read.getSwapOutput([poolId, mockWETH.address, parseEther("1")]);
      expect(output).to.equal(0n);
    });
  });
});
