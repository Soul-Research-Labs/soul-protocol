import { expect } from "chai";
import hre from "hardhat";
import { getAddress, parseEther, parseUnits, keccak256, toBytes, toHex } from "viem";

describe("PILPrivateExchange", function () {
  // Role constants
  const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
  const MATCHER_ROLE = keccak256(toBytes("MATCHER_ROLE"));
  const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));

  // Helper to get viem
  async function getViem() {
    const { viem } = await hre.network.connect();
    return viem;
  }

  describe("Deployment", function () {
    it("should deploy with correct initial state", async function () {
      const viem = await getViem();
      const [owner, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const totalOrders = await exchange.read.totalOrders();
      const totalTrades = await exchange.read.totalTrades();
      const makerFeeBps = await exchange.read.makerFeeBps();
      const takerFeeBps = await exchange.read.takerFeeBps();
      const collector = await exchange.read.feeCollector();

      expect(totalOrders).to.equal(0n);
      expect(totalTrades).to.equal(0n);
      expect(makerFeeBps).to.equal(10n);
      expect(takerFeeBps).to.equal(30n);
      expect(getAddress(collector)).to.equal(getAddress(feeCollector.account.address));
    });

    it("should grant correct roles", async function () {
      const viem = await getViem();
      const [owner, operator, matcher, relayer, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      await exchange.write.grantRole([MATCHER_ROLE, matcher.account.address]);
      await exchange.write.grantRole([RELAYER_ROLE, relayer.account.address]);

      const hasOperator = await exchange.read.hasRole([OPERATOR_ROLE, operator.account.address]);
      const hasMatcher = await exchange.read.hasRole([MATCHER_ROLE, matcher.account.address]);
      const hasRelayer = await exchange.read.hasRole([RELAYER_ROLE, relayer.account.address]);

      expect(hasOperator).to.be.true;
      expect(hasMatcher).to.be.true;
      expect(hasRelayer).to.be.true;
    });
  });

  describe("Deposits", function () {
    it("should allow token deposits with commitment", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      // Mint and approve
      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });

      const depositAmount = parseEther("10");
      const commitment = keccak256(toBytes("test_commitment"));

      await exchange.write.deposit([mockWETH.address, depositAmount, commitment], { 
        account: user1.account 
      });

      const balance = await exchange.read.balances([user1.account.address, mockWETH.address]);
      expect(balance).to.equal(depositAmount);
    });

    it("should allow ETH deposits", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const depositAmount = parseEther("5");
      const commitment = keccak256(toBytes("eth_commitment"));
      const zeroAddress = "0x0000000000000000000000000000000000000000";

      await exchange.write.deposit([zeroAddress, depositAmount, commitment], {
        account: user1.account,
        value: depositAmount,
      });

      const balance = await exchange.read.balances([user1.account.address, zeroAddress]);
      expect(balance).to.equal(depositAmount);
    });

    it("should reject deposit with zero amount", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const commitment = keccak256(toBytes("test_commitment"));

      try {
        await exchange.write.deposit([mockWETH.address, 0n, commitment], { 
          account: user1.account 
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("InvalidAmount");
      }
    });
  });

  describe("Withdrawals", function () {
    it("should allow withdrawal with valid nullifier and proof", async function () {
      const viem = await getViem();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      // Mint and approve
      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });

      // Deposit
      const depositAmount = parseEther("10");
      const commitment = keccak256(toBytes("test_commitment"));
      await exchange.write.deposit([mockWETH.address, depositAmount, commitment], {
        account: user1.account,
      });

      // Withdraw
      const withdrawAmount = parseEther("5");
      const nullifier = keccak256(toBytes("unique_nullifier_1"));
      const proof = keccak256(toBytes("valid_proof_data_here_min_32_bytes"));

      await exchange.write.withdraw([mockWETH.address, withdrawAmount, nullifier, proof], {
        account: user1.account,
      });

      const balance = await exchange.read.balances([user1.account.address, mockWETH.address]);
      expect(balance).to.equal(depositAmount - withdrawAmount);
    });

    it("should reject withdrawal with reused nullifier", async function () {
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
      const commitment = keccak256(toBytes("test_commitment"));
      await exchange.write.deposit([mockWETH.address, depositAmount, commitment], {
        account: user1.account,
      });

      const withdrawAmount = parseEther("2");
      const nullifier = keccak256(toBytes("reused_nullifier"));
      const proof = keccak256(toBytes("valid_proof_data_here_min_32_bytes"));

      await exchange.write.withdraw([mockWETH.address, withdrawAmount, nullifier, proof], {
        account: user1.account,
      });

      try {
        await exchange.write.withdraw([mockWETH.address, withdrawAmount, nullifier, proof], {
          account: user1.account,
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("NullifierAlreadyUsed");
      }
    });
  });

  describe("Private Orders", function () {
    it("should create a private order", async function () {
      const viem = await getViem();
      const publicClient = await viem.getPublicClient();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      // Mint and approve WETH
      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });

      // Deposit
      await exchange.write.deposit([mockWETH.address, parseEther("100"), keccak256(toBytes("d"))], {
        account: user1.account,
      });

      const amountIn = parseEther("10");
      const minAmountOut = parseUnits("20000", 6);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const commitment = keccak256(toBytes("order_details_commitment"));
      const nullifier = keccak256(toBytes("order_nullifier_1"));
      const encryptedDetails = toHex(toBytes("encrypted_metadata"));

      const hash = await exchange.write.createPrivateOrder([
        mockWETH.address,
        mockUSDC.address,
        amountIn,
        minAmountOut,
        deadline,
        0, 1,
        commitment,
        nullifier,
        encryptedDetails,
      ], { account: user1.account });

      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      expect(receipt.status).to.equal("success");

      const totalOrders = await exchange.read.totalOrders();
      expect(totalOrders).to.equal(1n);
    });

    it("should cancel an active order", async function () {
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

      const amountIn = parseEther("10");
      const minAmountOut = parseUnits("20000", 6);
      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const commitment = keccak256(toBytes("cancel_order_commitment"));
      const nullifier = keccak256(toBytes("cancel_order_nullifier"));
      const encryptedDetails = toHex(toBytes("encrypted"));

      await exchange.write.createPrivateOrder([
        mockWETH.address,
        mockUSDC.address,
        amountIn,
        minAmountOut,
        deadline,
        0, 1,
        commitment,
        nullifier,
        encryptedDetails,
      ], { account: user1.account });

      const userOrders = await exchange.read.getUserOrders([user1.account.address]);
      const orderId = userOrders[0];
      const balanceBefore = await exchange.read.balances([user1.account.address, mockWETH.address]);

      await exchange.write.cancelOrder([orderId], { account: user1.account });

      const order = await exchange.read.getOrder([orderId]);
      expect(order.status).to.equal(4);

      const balanceAfter = await exchange.read.balances([user1.account.address, mockWETH.address]);
      expect(balanceAfter).to.equal(balanceBefore + amountIn);
    });

    it("should reject order with expired deadline", async function () {
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

      const amountIn = parseEther("10");
      const minAmountOut = parseUnits("20000", 6);
      const deadline = BigInt(Math.floor(Date.now() / 1000) - 3600); // Past deadline
      const commitment = keccak256(toBytes("expired_order"));
      const nullifier = keccak256(toBytes("expired_nullifier"));
      const encryptedDetails = toHex(toBytes("encrypted"));

      try {
        await exchange.write.createPrivateOrder([
          mockWETH.address,
          mockUSDC.address,
          amountIn,
          minAmountOut,
          deadline,
          0, 1,
          commitment,
          nullifier,
          encryptedDetails,
        ], { account: user1.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("InvalidDeadline");
      }
    });
  });

  describe("Liquidity Pools", function () {
    it("should create a liquidity pool", async function () {
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
      const pool = await exchange.read.getPool([poolId]);

      expect(getAddress(pool.tokenA)).to.equal(getAddress(mockWETH.address));
      expect(getAddress(pool.tokenB)).to.equal(getAddress(mockUSDC.address));
      expect(pool.feeRate).to.equal(30n);
      expect(pool.active).to.be.true;
    });

    it("should add liquidity to a pool", async function () {
      const viem = await getViem();
      const publicClient = await viem.getPublicClient();
      const [owner, operator, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      // Mint tokens
      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockUSDC.write.mint([user1.account.address, parseUnits("200000", 6)]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await mockUSDC.write.approve([exchange.address, parseUnits("200000", 6)], { account: user1.account });

      // Deposit
      await exchange.write.deposit([mockWETH.address, parseEther("100"), keccak256(toBytes("w"))], {
        account: user1.account,
      });
      await exchange.write.deposit([mockUSDC.address, parseUnits("200000", 6), keccak256(toBytes("u"))], {
        account: user1.account,
      });

      // Create pool
      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });
      const poolId = await exchange.read.poolIds([0n]);

      // Add liquidity
      const amountA = parseEther("10");
      const amountB = parseUnits("20000", 6);

      const hash = await exchange.write.addLiquidity([poolId, amountA, amountB], {
        account: user1.account,
      });

      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      expect(receipt.status).to.equal("success");

      const pool = await exchange.read.getPool([poolId]);
      expect(pool.reserveA).to.equal(amountA);
      expect(pool.reserveB).to.equal(amountB);
      expect(pool.totalLPTokens > 0n).to.be.true;

      const lpBalance = await exchange.read.lpBalances([poolId, user1.account.address]);
      expect(lpBalance > 0n).to.be.true;
    });

    it("should perform instant swap", async function () {
      const viem = await getViem();
      const publicClient = await viem.getPublicClient();
      const [owner, operator, user1, user2, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      // Mint and deposit for user1 (liquidity provider)
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

      // Mint and deposit for user2 (swapper)
      await mockWETH.write.mint([user2.account.address, parseEther("10")]);
      await mockWETH.write.approve([exchange.address, parseEther("10")], { account: user2.account });
      await exchange.write.deposit([mockWETH.address, parseEther("10"), keccak256(toBytes("w2"))], {
        account: user2.account,
      });

      // Create pool and add liquidity
      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });
      const poolId = await exchange.read.poolIds([0n]);
      await exchange.write.addLiquidity([poolId, parseEther("50"), parseUnits("100000", 6)], {
        account: user1.account,
      });

      // Swap
      const swapAmount = parseEther("1");
      const minOutput = parseUnits("1900", 6);
      const balanceBefore = await exchange.read.balances([user2.account.address, mockUSDC.address]);

      const hash = await exchange.write.instantSwap([poolId, mockWETH.address, swapAmount, minOutput], {
        account: user2.account,
      });

      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      expect(receipt.status).to.equal("success");

      const balanceAfter = await exchange.read.balances([user2.account.address, mockUSDC.address]);
      expect(balanceAfter).to.be.gt(balanceBefore);
    });

    it("should calculate swap output correctly", async function () {
      const viem = await getViem();
      const [owner, operator, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      await mockWETH.write.mint([user1.account.address, parseEther("200")]);
      await mockUSDC.write.mint([user1.account.address, parseUnits("400000", 6)]);
      await mockWETH.write.approve([exchange.address, parseEther("200")], { account: user1.account });
      await mockUSDC.write.approve([exchange.address, parseUnits("400000", 6)], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("200"), keccak256(toBytes("w"))], {
        account: user1.account,
      });
      await exchange.write.deposit([mockUSDC.address, parseUnits("400000", 6), keccak256(toBytes("u"))], {
        account: user1.account,
      });

      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });
      const poolId = await exchange.read.poolIds([0n]);
      await exchange.write.addLiquidity([poolId, parseEther("100"), parseUnits("200000", 6)], {
        account: user1.account,
      });

      const swapAmount = parseEther("1");
      const output = await exchange.read.getSwapOutput([poolId, mockWETH.address, swapAmount]);

      expect(output > parseUnits("1900", 6)).to.be.true;
      expect(output < parseUnits("2000", 6)).to.be.true;
    });
  });

  describe("Cross-Chain Orders", function () {
    it("should create a cross-chain order", async function () {
      const viem = await getViem();
      const publicClient = await viem.getPublicClient();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const targetChain = 42161n;
      const sourceCommitment = keccak256(toBytes("source_commitment"));
      const targetCommitment = keccak256(toBytes("target_commitment"));
      const secretHash = keccak256(toBytes("secret_for_htlc"));
      const deadline = BigInt(Math.floor(Date.now() / 1000) + 86400);

      const hash = await exchange.write.createCrossChainOrder([
        targetChain,
        sourceCommitment,
        targetCommitment,
        secretHash,
        deadline,
      ], { account: user1.account });

      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      expect(receipt.status).to.equal("success");

      const totalCrossChain = await exchange.read.totalCrossChainOrders();
      expect(totalCrossChain).to.equal(1n);
    });
  });

  describe("Stealth Addresses", function () {
    it("should register a stealth address", async function () {
      const viem = await getViem();
      const publicClient = await viem.getPublicClient();
      const [owner, user1, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      const pubKeyX = keccak256(toBytes("pub_key_x"));
      const pubKeyY = keccak256(toBytes("pub_key_y"));
      const viewingKey = keccak256(toBytes("viewing_key"));

      const hash = await exchange.write.registerStealthAddress([pubKeyX, pubKeyY, viewingKey], {
        account: user1.account,
      });

      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      expect(receipt.status).to.equal("success");

      const stealthAddr = await exchange.read.stealthAddresses([user1.account.address]);
      expect(stealthAddr[0]).to.equal(pubKeyX);
      expect(stealthAddr[1]).to.equal(pubKeyY);
      expect(stealthAddr[2]).to.equal(viewingKey);
    });
  });

  describe("Admin Functions", function () {
    it("should update fees", async function () {
      const viem = await getViem();
      const [owner, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.setFees([5n, 15n], { account: owner.account });

      const makerFee = await exchange.read.makerFeeBps();
      const takerFee = await exchange.read.takerFeeBps();

      expect(makerFee).to.equal(5n);
      expect(takerFee).to.equal(15n);
    });

    it("should reject fees above maximum", async function () {
      const viem = await getViem();
      const [owner, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      try {
        await exchange.write.setFees([150n, 200n], { account: owner.account });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("InvalidAmount");
      }
    });

    it("should pause and unpause", async function () {
      const viem = await getViem();
      const [owner, operator, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });

      // Pause
      await exchange.write.pause([], { account: operator.account });

      const commitment = keccak256(toBytes("paused_deposit"));
      try {
        await exchange.write.deposit([mockWETH.address, parseEther("1"), commitment], {
          account: user1.account,
        });
        expect.fail("Should have reverted");
      } catch (error: any) {
        expect(error.message).to.include("EnforcedPause");
      }

      // Unpause
      await exchange.write.unpause([], { account: operator.account });

      await exchange.write.deposit([mockWETH.address, parseEther("1"), commitment], {
        account: user1.account,
      });

      const balance = await exchange.read.balances([user1.account.address, mockWETH.address]);
      expect(balance).to.equal(parseEther("1"));
    });

    it("should update fee collector", async function () {
      const viem = await getViem();
      const [owner, user2, feeCollector] = await viem.getWalletClients();
      
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.setFeeCollector([user2.account.address], { account: owner.account });

      const collector = await exchange.read.feeCollector();
      expect(getAddress(collector)).to.equal(getAddress(user2.account.address));
    });
  });

  describe("Statistics", function () {
    it("should return correct statistics", async function () {
      const viem = await getViem();
      const [owner, operator, user1, feeCollector] = await viem.getWalletClients();
      
      const mockWETH = await viem.deployContract("MockWETH");
      const mockUSDC = await viem.deployContract("MockUSDC");
      const exchange = await viem.deployContract("PILPrivateExchange", [
        feeCollector.account.address,
        owner.account.address,
      ]);

      await exchange.write.grantRole([OPERATOR_ROLE, operator.account.address]);

      // Create pool
      await exchange.write.createPool([mockWETH.address, mockUSDC.address, 30n], {
        account: operator.account,
      });

      // Create order
      await mockWETH.write.mint([user1.account.address, parseEther("100")]);
      await mockWETH.write.approve([exchange.address, parseEther("100")], { account: user1.account });
      await exchange.write.deposit([mockWETH.address, parseEther("10"), keccak256(toBytes("s1"))], {
        account: user1.account,
      });

      await exchange.write.createPrivateOrder([
        mockWETH.address,
        mockUSDC.address,
        parseEther("1"),
        parseUnits("1000", 6),
        BigInt(Math.floor(Date.now() / 1000) + 3600),
        0, 1,
        keccak256(toBytes("stat_order")),
        keccak256(toBytes("stat_null")),
        toHex(toBytes("enc")),
      ], { account: user1.account });

      const stats = await exchange.read.getStats();
      expect(stats[0]).to.equal(1n); // totalOrders
      expect(stats[4]).to.equal(1n); // poolCount
    });
  });
});
