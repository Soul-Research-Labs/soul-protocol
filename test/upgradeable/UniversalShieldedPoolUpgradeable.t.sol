// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/upgradeable/UniversalShieldedPoolUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Mock withdrawal verifier that always returns true
contract MockWithdrawalVerifier {
    bool public result;

    constructor(bool _result) {
        result = _result;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return result;
    }

    function setResult(bool _v) external {
        result = _v;
    }
}

/// @dev Mock batch verifier
contract MockBatchVerifier {
    bool public result;

    constructor(bool _result) {
        result = _result;
    }

    function verify(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return result;
    }
}

/// @dev Mock sanctions oracle
contract MockSanctionsOracle {
    mapping(address => bool) public sanctioned;

    function isSanctioned(address addr) external view returns (bool) {
        return sanctioned[addr];
    }

    function setSanctioned(address addr, bool val) external {
        sanctioned[addr] = val;
    }
}

/// @dev Simple ERC20 for testing
contract MockERC20 is ERC20 {
    constructor() ERC20("TestToken", "TST") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev V2 implementation for upgrade testing
contract UniversalShieldedPoolV2 is UniversalShieldedPoolUpgradeable {
    function version() external pure returns (string memory) {
        return "v2";
    }
}

contract UniversalShieldedPoolUpgradeableTest is Test {
    UniversalShieldedPoolUpgradeable public pool;
    UniversalShieldedPoolUpgradeable public impl;
    ERC1967Proxy public proxy;

    MockWithdrawalVerifier public withdrawVerifier;
    MockBatchVerifier public batchVerifier;
    MockSanctionsOracle public oracle;
    MockERC20 public token;

    address admin = address(0xAD01);
    address relayer = address(0xBE01);
    address oper = address(0xCE01);
    address user = address(0xDE01);
    address upgrader = address(0xEE01);

    bytes32 RELAYER_ROLE;
    bytes32 OPERATOR_ROLE;
    bytes32 COMPLIANCE_ROLE;
    bytes32 UPGRADER_ROLE;

    function setUp() public {
        vm.warp(10_000);

        // Deploy mocks
        withdrawVerifier = new MockWithdrawalVerifier(true);
        batchVerifier = new MockBatchVerifier(true);
        oracle = new MockSanctionsOracle();
        token = new MockERC20();

        // Deploy via proxy
        impl = new UniversalShieldedPoolUpgradeable();
        bytes memory initData = abi.encodeCall(
            UniversalShieldedPoolUpgradeable.initialize,
            (admin, address(withdrawVerifier), false)
        );
        proxy = new ERC1967Proxy(address(impl), initData);
        pool = UniversalShieldedPoolUpgradeable(payable(address(proxy)));

        // Cache roles
        RELAYER_ROLE = pool.RELAYER_ROLE();
        OPERATOR_ROLE = pool.OPERATOR_ROLE();
        COMPLIANCE_ROLE = pool.COMPLIANCE_ROLE();
        UPGRADER_ROLE = pool.UPGRADER_ROLE();

        // Grant roles
        vm.startPrank(admin);
        pool.grantRole(RELAYER_ROLE, relayer);
        pool.grantRole(OPERATOR_ROLE, oper);
        pool.grantRole(UPGRADER_ROLE, upgrader);
        pool.grantRole(COMPLIANCE_ROLE, admin);
        pool.setBatchVerifier(address(batchVerifier));
        vm.stopPrank();

        // Fund user
        vm.deal(user, 100 ether);
        token.mint(user, 100 ether);
    }

    // ──────── Initialization ────────

    function test_init_adminRoles() public view {
        assertTrue(pool.hasRole(pool.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(pool.hasRole(OPERATOR_ROLE, admin));
        assertTrue(pool.hasRole(UPGRADER_ROLE, admin));
    }

    function test_init_testMode() public view {
        assertFalse(pool.testMode());
    }

    function test_init_merkleRoot() public view {
        assertTrue(pool.currentRoot() != bytes32(0));
        assertEq(pool.nextLeafIndex(), 0);
    }

    function test_init_nativeAssetRegistered() public view {
        bytes32[] memory ids = pool.getRegisteredAssets();
        assertEq(ids.length, 1);
        assertEq(ids[0], pool.NATIVE_ASSET());
    }

    function test_init_cannotDoubleInit() public {
        vm.expectRevert();
        pool.initialize(admin, address(0), false);
    }

    function test_init_zeroAdminReverts() public {
        UniversalShieldedPoolUpgradeable impl2 = new UniversalShieldedPoolUpgradeable();
        bytes memory initData = abi.encodeCall(
            UniversalShieldedPoolUpgradeable.initialize,
            (address(0), address(0), false)
        );
        vm.expectRevert();
        new ERC1967Proxy(address(impl2), initData);
    }

    function test_init_contractVersion() public view {
        assertEq(pool.contractVersion(), 1);
    }

    // ──────── ETH Deposit ────────

    function _validCommitment(uint256 seed) internal view returns (bytes32) {
        bytes32 c = keccak256(abi.encode(seed, "commitment"));
        // Ensure < FIELD_SIZE
        uint256 v = uint256(c) % pool.FIELD_SIZE();
        if (v == 0) v = 1;
        return bytes32(v);
    }

    function _deployPool(
        address verifier,
        bool enableTestMode
    ) internal returns (UniversalShieldedPoolUpgradeable localPool) {
        UniversalShieldedPoolUpgradeable localImpl = new UniversalShieldedPoolUpgradeable();
        bytes memory initData = abi.encodeCall(
            UniversalShieldedPoolUpgradeable.initialize,
            (admin, verifier, enableTestMode)
        );
        ERC1967Proxy localProxy = new ERC1967Proxy(
            address(localImpl),
            initData
        );
        localPool = UniversalShieldedPoolUpgradeable(
            payable(address(localProxy))
        );
    }

    function test_depositETH_success() public {
        bytes32 commitment = _validCommitment(1);

        vm.prank(user);
        pool.depositETH{value: 1 ether}(commitment);

        assertEq(pool.nextLeafIndex(), 1);
        assertEq(pool.totalDeposits(), 1);
        assertTrue(pool.commitmentExists(commitment));
    }

    function test_depositETH_emitsEvent() public {
        bytes32 commitment = _validCommitment(2);

        vm.prank(user);
        vm.expectEmit(true, true, false, false);
        emit UniversalShieldedPoolUpgradeable.Deposit(
            commitment,
            pool.NATIVE_ASSET(),
            0,
            1 ether,
            block.timestamp
        );
        pool.depositETH{value: 1 ether}(commitment);
    }

    function test_depositETH_belowMinReverts() public {
        bytes32 commitment = _validCommitment(3);
        vm.prank(user);
        vm.expectRevert(
            UniversalShieldedPoolUpgradeable.DepositTooSmall.selector
        );
        pool.depositETH{value: 0.0001 ether}(commitment);
    }

    function test_depositETH_aboveMaxReverts() public {
        bytes32 commitment = _validCommitment(4);
        vm.deal(user, 20_000 ether);
        vm.prank(user);
        vm.expectRevert(
            UniversalShieldedPoolUpgradeable.DepositTooLarge.selector
        );
        pool.depositETH{value: 10_001 ether}(commitment);
    }

    function test_depositETH_zeroCommitmentReverts() public {
        vm.prank(user);
        vm.expectRevert(
            UniversalShieldedPoolUpgradeable.InvalidCommitment.selector
        );
        pool.depositETH{value: 1 ether}(bytes32(0));
    }

    function test_depositETH_doubleCommitmentReverts() public {
        bytes32 commitment = _validCommitment(5);
        vm.startPrank(user);
        pool.depositETH{value: 1 ether}(commitment);
        vm.expectRevert(
            UniversalShieldedPoolUpgradeable.InvalidCommitment.selector
        );
        pool.depositETH{value: 1 ether}(commitment);
        vm.stopPrank();
    }

    function test_depositETH_whenPausedReverts() public {
        vm.prank(admin);
        pool.pause();

        bytes32 commitment = _validCommitment(6);
        vm.prank(user);
        vm.expectRevert();
        pool.depositETH{value: 1 ether}(commitment);
    }

    function test_depositETH_testModeReverts() public {
        UniversalShieldedPoolUpgradeable localPool = _deployPool(
            address(withdrawVerifier),
            true
        );
        bytes32 commitment = _validCommitment(7);

        vm.prank(user);
        vm.expectRevert(
            UniversalShieldedPoolUpgradeable.DepositsDisabledInTestMode.selector
        );
        localPool.depositETH{value: 1 ether}(commitment);
    }

    function test_depositETH_multipleUpdatesRoot() public {
        bytes32 root0 = pool.currentRoot();

        vm.startPrank(user);
        pool.depositETH{value: 1 ether}(_validCommitment(10));
        bytes32 root1 = pool.currentRoot();
        pool.depositETH{value: 1 ether}(_validCommitment(11));
        bytes32 root2 = pool.currentRoot();
        vm.stopPrank();

        assertTrue(root0 != root1);
        assertTrue(root1 != root2);
        assertTrue(pool.isKnownRoot(root1));
        assertTrue(pool.isKnownRoot(root2));
    }

    // ──────── ERC20 Deposit ────────

    function test_depositERC20_success() public {
        // Register token asset
        bytes32 assetId = keccak256("TST");
        vm.prank(oper);
        pool.registerAsset(assetId, address(token));

        bytes32 commitment = _validCommitment(20);
        vm.startPrank(user);
        token.approve(address(pool), 1 ether);
        pool.depositERC20(assetId, 1 ether, commitment);
        vm.stopPrank();

        assertEq(pool.nextLeafIndex(), 1);
        assertEq(pool.totalDeposits(), 1);
    }

    function test_depositERC20_unregisteredAssetReverts() public {
        bytes32 assetId = keccak256("UNKNOWN");
        bytes32 commitment = _validCommitment(21);

        vm.prank(user);
        vm.expectRevert();
        pool.depositERC20(assetId, 1 ether, commitment);
    }

    function test_depositERC20_testModeReverts() public {
        UniversalShieldedPoolUpgradeable localPool = _deployPool(
            address(withdrawVerifier),
            true
        );
        bytes32 assetId = keccak256("TST_TESTMODE");
        bytes32 commitment = _validCommitment(22);

        vm.prank(admin);
        localPool.registerAsset(assetId, address(token));

        vm.startPrank(user);
        token.approve(address(localPool), 1 ether);
        vm.expectRevert(
            UniversalShieldedPoolUpgradeable.DepositsDisabledInTestMode.selector
        );
        localPool.depositERC20(assetId, 1 ether, commitment);
        vm.stopPrank();
    }

    // ──────── Withdrawal (test mode) ────────

    function test_withdraw_testMode() public {
        UniversalShieldedPoolUpgradeable localPool = _deployPool(
            address(0),
            true
        );
        bytes32 nullifier = keccak256("nullifier_1");
        vm.deal(address(localPool), 1 ether);

        UniversalShieldedPoolUpgradeable.WithdrawalProof
            memory wp = UniversalShieldedPoolUpgradeable.WithdrawalProof({
                proof: new bytes(32),
                merkleRoot: localPool.currentRoot(),
                nullifier: nullifier,
                recipient: user,
                relayerAddress: address(0),
                amount: 0.5 ether,
                relayerFee: 0,
                assetId: localPool.NATIVE_ASSET(),
                destChainId: bytes32(0)
            });

        uint256 balBefore = user.balance;

        vm.expectEmit(true, true, false, false);
        emit UniversalShieldedPoolUpgradeable.TestModeWithdrawalBypassed(
            nullifier,
            user
        );
        localPool.withdraw(wp);

        assertEq(user.balance - balBefore, 0.5 ether);
        assertTrue(localPool.isSpent(nullifier));
    }

    function test_withdraw_testMode_shortProofReverts() public {
        UniversalShieldedPoolUpgradeable localPool = _deployPool(
            address(0),
            true
        );
        vm.deal(address(localPool), 1 ether);

        UniversalShieldedPoolUpgradeable.WithdrawalProof
            memory wp = UniversalShieldedPoolUpgradeable.WithdrawalProof({
                proof: new bytes(31),
                merkleRoot: localPool.currentRoot(),
                nullifier: keccak256("nullifier_short"),
                recipient: user,
                relayerAddress: address(0),
                amount: 0.5 ether,
                relayerFee: 0,
                assetId: localPool.NATIVE_ASSET(),
                destChainId: bytes32(0)
            });

        vm.expectRevert(
            UniversalShieldedPoolUpgradeable.TestModeProofTooShort.selector
        );
        localPool.withdraw(wp);
    }

    function test_withdraw_doubleSpendReverts() public {
        bytes32 commitment = _validCommitment(31);
        vm.prank(user);
        pool.depositETH{value: 2 ether}(commitment);

        bytes32 root = pool.currentRoot();
        bytes32 nullifier = keccak256("nullifier_2");

        UniversalShieldedPoolUpgradeable.WithdrawalProof
            memory wp = UniversalShieldedPoolUpgradeable.WithdrawalProof({
                proof: bytes("fake"),
                merkleRoot: root,
                nullifier: nullifier,
                recipient: user,
                relayerAddress: address(0),
                amount: 0.5 ether,
                relayerFee: 0,
                assetId: pool.NATIVE_ASSET(),
                destChainId: bytes32(0)
            });

        pool.withdraw(wp);

        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalShieldedPoolUpgradeable.NullifierAlreadySpent.selector,
                nullifier
            )
        );
        pool.withdraw(wp);
    }

    function test_withdraw_invalidRootReverts() public {
        bytes32 commitment = _validCommitment(32);
        vm.prank(user);
        pool.depositETH{value: 1 ether}(commitment);

        UniversalShieldedPoolUpgradeable.WithdrawalProof
            memory wp = UniversalShieldedPoolUpgradeable.WithdrawalProof({
                proof: bytes("fake"),
                merkleRoot: bytes32(uint256(123)),
                nullifier: keccak256("n"),
                recipient: user,
                relayerAddress: address(0),
                amount: 0.5 ether,
                relayerFee: 0,
                assetId: pool.NATIVE_ASSET(),
                destChainId: bytes32(0)
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalShieldedPoolUpgradeable.InvalidMerkleRoot.selector,
                bytes32(uint256(123))
            )
        );
        pool.withdraw(wp);
    }

    function test_withdraw_zeroRecipientReverts() public {
        bytes32 commitment = _validCommitment(33);
        vm.prank(user);
        pool.depositETH{value: 1 ether}(commitment);

        UniversalShieldedPoolUpgradeable.WithdrawalProof
            memory wp = UniversalShieldedPoolUpgradeable.WithdrawalProof({
                proof: bytes("fake"),
                merkleRoot: pool.currentRoot(),
                nullifier: keccak256("n2"),
                recipient: address(0),
                relayerAddress: address(0),
                amount: 0.5 ether,
                relayerFee: 0,
                assetId: pool.NATIVE_ASSET(),
                destChainId: bytes32(0)
            });

        vm.expectRevert(
            UniversalShieldedPoolUpgradeable.InvalidRecipient.selector
        );
        pool.withdraw(wp);
    }

    function test_withdraw_withRelayerFee() public {
        bytes32 commitment = _validCommitment(34);
        vm.prank(user);
        pool.depositETH{value: 2 ether}(commitment);

        address relayerAddr = address(0xFACE);
        vm.deal(relayerAddr, 0);

        UniversalShieldedPoolUpgradeable.WithdrawalProof
            memory wp = UniversalShieldedPoolUpgradeable.WithdrawalProof({
                proof: bytes("fake"),
                merkleRoot: pool.currentRoot(),
                nullifier: keccak256("n3"),
                recipient: user,
                relayerAddress: relayerAddr,
                amount: 1 ether,
                relayerFee: 0.01 ether,
                assetId: pool.NATIVE_ASSET(),
                destChainId: bytes32(0)
            });

        pool.withdraw(wp);
        assertEq(relayerAddr.balance, 0.01 ether);
    }

    // ──────── Cross-chain Commitments ────────

    function test_insertCrossChain_success() public {
        bytes32[] memory comms = new bytes32[](2);
        comms[0] = _validCommitment(40);
        comms[1] = _validCommitment(41);
        bytes32[] memory aids = new bytes32[](2);
        aids[0] = pool.NATIVE_ASSET();
        aids[1] = pool.NATIVE_ASSET();

        UniversalShieldedPoolUpgradeable.CrossChainCommitmentBatch
            memory batch = UniversalShieldedPoolUpgradeable
                .CrossChainCommitmentBatch({
                    sourceChainId: keccak256("ETH_MAINNET"),
                    commitments: comms,
                    assetIds: aids,
                    batchRoot: keccak256("batch1"),
                    proof: bytes("batchproof"),
                    sourceTreeSize: 100
                });

        vm.prank(relayer);
        pool.insertCrossChainCommitments(batch);

        assertEq(pool.nextLeafIndex(), 2);
        assertEq(pool.totalCrossChainDeposits(), 2);
    }

    function test_insertCrossChain_nonRelayerReverts() public {
        bytes32[] memory comms = new bytes32[](1);
        comms[0] = _validCommitment(42);
        bytes32[] memory aids = new bytes32[](1);
        aids[0] = pool.NATIVE_ASSET();

        UniversalShieldedPoolUpgradeable.CrossChainCommitmentBatch
            memory batch = UniversalShieldedPoolUpgradeable
                .CrossChainCommitmentBatch({
                    sourceChainId: keccak256("X"),
                    commitments: comms,
                    assetIds: aids,
                    batchRoot: keccak256("b2"),
                    proof: bytes("p"),
                    sourceTreeSize: 10
                });

        vm.prank(user);
        vm.expectRevert();
        pool.insertCrossChainCommitments(batch);
    }

    function test_insertCrossChain_doubleBatchReverts() public {
        bytes32[] memory comms = new bytes32[](1);
        comms[0] = _validCommitment(43);
        bytes32[] memory aids = new bytes32[](1);
        aids[0] = pool.NATIVE_ASSET();

        UniversalShieldedPoolUpgradeable.CrossChainCommitmentBatch
            memory batch = UniversalShieldedPoolUpgradeable
                .CrossChainCommitmentBatch({
                    sourceChainId: keccak256("X"),
                    commitments: comms,
                    assetIds: aids,
                    batchRoot: keccak256("b3"),
                    proof: bytes("p"),
                    sourceTreeSize: 10
                });

        vm.prank(relayer);
        pool.insertCrossChainCommitments(batch);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalShieldedPoolUpgradeable.BatchAlreadyProcessed.selector,
                keccak256("b3")
            )
        );
        pool.insertCrossChainCommitments(batch);
    }

    // ──────── Admin ────────

    function test_registerAsset() public {
        bytes32 assetId = keccak256("TST2");
        vm.prank(oper);
        pool.registerAsset(assetId, address(token));

        bytes32[] memory ids = pool.getRegisteredAssets();
        assertEq(ids.length, 2);
    }

    function test_registerAsset_zeroAddressReverts() public {
        vm.prank(oper);
        vm.expectRevert(UniversalShieldedPoolUpgradeable.ZeroAddress.selector);
        pool.registerAsset(keccak256("X"), address(0));
    }

    function test_registerAsset_duplicateReverts() public {
        bytes32 assetId = keccak256("DUP");
        vm.startPrank(oper);
        pool.registerAsset(assetId, address(token));
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalShieldedPoolUpgradeable
                    .AssetAlreadyRegistered
                    .selector,
                assetId
            )
        );
        pool.registerAsset(assetId, address(token));
        vm.stopPrank();
    }

    function test_deactivateAsset() public {
        bytes32 assetId = keccak256("DEACT");
        vm.startPrank(oper);
        pool.registerAsset(assetId, address(token));
        pool.deactivateAsset(assetId);
        vm.stopPrank();
    }

    function test_setWithdrawalVerifier() public {
        address newV = address(0xABCD);
        vm.prank(oper);
        pool.setWithdrawalVerifier(newV);
        assertEq(pool.withdrawalVerifier(), newV);
    }

    function test_setWithdrawalVerifier_zeroReverts() public {
        vm.prank(oper);
        vm.expectRevert(UniversalShieldedPoolUpgradeable.ZeroAddress.selector);
        pool.setWithdrawalVerifier(address(0));
    }

    function test_disableTestMode() public {
        UniversalShieldedPoolUpgradeable localPool = _deployPool(
            address(withdrawVerifier),
            true
        );
        assertTrue(localPool.testMode());
        vm.prank(admin);
        localPool.disableTestMode();
        assertFalse(localPool.testMode());
    }

    function test_confirmProductionReady() public {
        vm.prank(admin);
        pool.confirmProductionReady();
    }

    function test_confirmProductionReady_testModeReverts() public {
        UniversalShieldedPoolUpgradeable localPool = _deployPool(
            address(withdrawVerifier),
            true
        );
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSignature("TestModeStillEnabled()"));
        localPool.confirmProductionReady();
    }

    function test_setDepositRateLimit() public {
        vm.prank(oper);
        pool.setDepositRateLimit(2 hours, 200);
        assertEq(pool.depositRateLimitWindow(), 2 hours);
        assertEq(pool.maxDepositsPerWindow(), 200);
    }

    function test_setCircuitBreaker() public {
        vm.prank(oper);
        pool.setCircuitBreaker(25, 30 minutes);
        assertEq(pool.circuitBreakerThreshold(), 25);
        assertEq(pool.withdrawalWindow(), 30 minutes);
    }

    function test_pause_unpause() public {
        vm.prank(admin);
        pool.pause();
        assertTrue(pool.paused());

        vm.prank(admin);
        pool.unpause();
        assertFalse(pool.paused());
    }

    // ──────── Sanctions ────────

    function test_sanctions_blockDeposit() public {
        vm.prank(admin);
        pool.setSanctionsOracle(address(oracle));

        oracle.setSanctioned(user, true);

        bytes32 commitment = _validCommitment(50);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalShieldedPoolUpgradeable.SanctionedAddress.selector,
                user
            )
        );
        pool.depositETH{value: 1 ether}(commitment);
    }

    // ──────── Rate Limit ────────

    function test_depositRateLimit_enforced() public {
        vm.prank(oper);
        pool.setDepositRateLimit(1 hours, 3);

        // Cache commitments before startPrank to avoid FIELD_SIZE() getter consuming vm.expectRevert
        bytes32 c60 = _validCommitment(60);
        bytes32 c61 = _validCommitment(61);
        bytes32 c62 = _validCommitment(62);
        bytes32 c63 = _validCommitment(63);

        vm.startPrank(user);
        pool.depositETH{value: 0.01 ether}(c60);
        pool.depositETH{value: 0.01 ether}(c61);
        pool.depositETH{value: 0.01 ether}(c62);

        vm.expectRevert(
            UniversalShieldedPoolUpgradeable.DepositRateLimitExceeded.selector
        );
        pool.depositETH{value: 0.01 ether}(c63);
        vm.stopPrank();
    }

    function test_depositRateLimit_resetsAfterWindow() public {
        vm.prank(oper);
        pool.setDepositRateLimit(1 hours, 2);

        vm.startPrank(user);
        pool.depositETH{value: 0.01 ether}(_validCommitment(70));
        pool.depositETH{value: 0.01 ether}(_validCommitment(71));

        vm.warp(block.timestamp + 2 hours);
        pool.depositETH{value: 0.01 ether}(_validCommitment(72)); // Should succeed
        vm.stopPrank();
    }

    // ──────── UUPS Upgrade ────────

    function test_upgrade_success() public {
        UniversalShieldedPoolV2 implV2 = new UniversalShieldedPoolV2();

        vm.prank(upgrader);
        pool.upgradeToAndCall(address(implV2), "");

        assertEq(pool.contractVersion(), 2);
        assertEq(
            UniversalShieldedPoolV2(payable(address(pool))).version(),
            "v2"
        );
    }

    function test_upgrade_nonUpgraderReverts() public {
        UniversalShieldedPoolV2 implV2 = new UniversalShieldedPoolV2();

        vm.prank(user);
        vm.expectRevert();
        pool.upgradeToAndCall(address(implV2), "");
    }

    // ──────── View Functions ────────

    function test_getPoolStats() public {
        vm.prank(user);
        pool.depositETH{value: 1 ether}(_validCommitment(80));

        (uint256 d, uint256 w, uint256 cc, uint256 tree, bytes32 root) = pool
            .getPoolStats();
        assertEq(d, 1);
        assertEq(w, 0);
        assertEq(cc, 0);
        assertEq(tree, 1);
        assertTrue(root != bytes32(0));
    }

    function test_isKnownRoot_false() public view {
        assertFalse(pool.isKnownRoot(bytes32(0)));
        assertFalse(pool.isKnownRoot(bytes32(uint256(999))));
    }

    function test_receive_acceptsETH() public {
        vm.prank(user);
        (bool ok, ) = address(pool).call{value: 1 ether}("");
        assertTrue(ok);
    }

    // ──────── Fuzz ────────

    function testFuzz_depositETH_validAmount(uint256 amount) public {
        amount = bound(amount, 0.001 ether, 10_000 ether);
        vm.deal(user, amount);

        bytes32 commitment = _validCommitment(amount);
        vm.prank(user);
        pool.depositETH{value: amount}(commitment);

        assertEq(pool.totalDeposits(), 1);
    }
}
