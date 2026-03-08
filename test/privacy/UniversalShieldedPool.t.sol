// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {UniversalShieldedPool} from "../../contracts/privacy/UniversalShieldedPool.sol";
import {IUniversalShieldedPool} from "../../contracts/interfaces/IUniversalShieldedPool.sol";

/// @dev Mock withdrawal verifier that always returns true
contract MockWithdrawalVerifier {
    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }
}

/**
 * @title UniversalShieldedPoolTest
 * @notice Comprehensive tests for the Universal Shielded Pool
 */
contract UniversalShieldedPoolTest is Test {
    UniversalShieldedPool public pool;
    MockWithdrawalVerifier public mockVerifier;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public user = makeAddr("user");
    address public recipient = makeAddr("recipient");
    address public relayerAddr = makeAddr("relayerAddr");

    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant COMPLIANCE_ROLE =
        0x364d3d7565c7a8982189c6ab03c2167d1f2cc9c82a4c902413ce8d68cfbe88c3;

    /// @dev BN254 scalar field order — commitments must be < this value
    uint256 internal constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Precomputed native ETH asset ID
    bytes32 public NATIVE_ASSET;

    /// @dev Helper: produce a valid BN254 commitment from arbitrary seed
    function _validCommitment(
        bytes memory seed
    ) internal pure returns (bytes32) {
        return bytes32((uint256(keccak256(seed)) % (FIELD_SIZE - 1)) + 1);
    }

    function setUp() public {
        vm.startPrank(admin);
        // Deploy mock withdrawal verifier
        mockVerifier = new MockWithdrawalVerifier();
        // Deploy with testMode=false so deposits work (security fix blocks deposits in testMode)
        pool = new UniversalShieldedPool(admin, address(mockVerifier), false);
        pool.grantRole(RELAYER_ROLE, relayer);
        pool.grantRole(COMPLIANCE_ROLE, admin);
        NATIVE_ASSET = pool.NATIVE_ASSET();
        vm.stopPrank();

        // Fund user
        vm.deal(user, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_InitializeCorrectly() public view {
        assertEq(pool.nextLeafIndex(), 0, "Tree should start empty");
        assertFalse(pool.testMode(), "Should not be in test mode");
        assertEq(
            pool.withdrawalVerifier(),
            address(mockVerifier),
            "Mock verifier should be set"
        );
        assertEq(pool.totalDeposits(), 0);
        assertEq(pool.totalWithdrawals(), 0);
    }

    function test_NativeAssetRegistered() public view {
        (address token, , , , bool active) = pool.assets(NATIVE_ASSET);
        assertEq(token, address(0), "Native ETH token is address(0)");
        assertTrue(active, "Native ETH should be active");
    }

    function test_MerkleTreeInitialized() public view {
        bytes32 root = pool.currentRoot();
        assertTrue(root != bytes32(0), "Root should be initialized");
    }

    /*//////////////////////////////////////////////////////////////
                           ETH DEPOSITS
    //////////////////////////////////////////////////////////////*/

    function test_DepositETH() public {
        bytes32 commitment = _validCommitment(
            abi.encodePacked("secret1", uint256(1 ether))
        );

        vm.prank(user);
        pool.depositETH{value: 1 ether}(commitment);

        assertEq(pool.nextLeafIndex(), 1, "Leaf index should increment");
        assertEq(pool.totalDeposits(), 1, "Deposit count should increment");
        assertTrue(
            pool.commitmentExists(commitment),
            "Commitment should be stored"
        );
        assertEq(address(pool).balance, 1 ether, "Pool should hold ETH");
    }

    function test_DepositETHEmitsEvent() public {
        bytes32 commitment = _validCommitment(
            abi.encodePacked("secret2", uint256(2 ether))
        );

        vm.expectEmit(true, true, false, true);
        emit IUniversalShieldedPool.Deposit(
            commitment,
            NATIVE_ASSET,
            0,
            2 ether,
            block.timestamp
        );

        vm.prank(user);
        pool.depositETH{value: 2 ether}(commitment);
    }

    function test_RevertDepositETHZeroValue() public {
        bytes32 commitment = _validCommitment(abi.encodePacked("secret"));

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUniversalShieldedPool.DepositTooSmall.selector
            )
        );
        pool.depositETH{value: 0}(commitment);
    }

    function test_RevertDepositETHZeroCommitment() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUniversalShieldedPool.InvalidCommitment.selector
            )
        );
        pool.depositETH{value: 1 ether}(bytes32(0));
    }

    function test_RevertDuplicateCommitment() public {
        bytes32 commitment = _validCommitment(abi.encodePacked("duplicate"));

        vm.startPrank(user);
        pool.depositETH{value: 1 ether}(commitment);

        vm.expectRevert();
        pool.depositETH{value: 1 ether}(commitment);
        vm.stopPrank();
    }

    function test_MultipleDeposits() public {
        vm.startPrank(user);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 commitment = _validCommitment(
                abi.encodePacked("secret", i)
            );
            pool.depositETH{value: 1 ether}(commitment);
        }
        vm.stopPrank();

        assertEq(pool.nextLeafIndex(), 5, "Should have 5 leaves");
        assertEq(pool.totalDeposits(), 5, "Should have 5 deposits");
        assertEq(address(pool).balance, 5 ether, "Pool should hold 5 ETH");
    }

    /*//////////////////////////////////////////////////////////////
                        MERKLE ROOT HISTORY
    //////////////////////////////////////////////////////////////*/

    function test_RootChangesAfterDeposit() public {
        bytes32 rootBefore = pool.currentRoot();

        vm.prank(user);
        pool.depositETH{value: 1 ether}(_validCommitment("commitment1"));

        bytes32 rootAfter = pool.currentRoot();
        assertTrue(rootBefore != rootAfter, "Root should change after deposit");
    }

    function test_IsKnownRoot() public {
        bytes32 root0 = pool.currentRoot();

        vm.prank(user);
        pool.depositETH{value: 1 ether}(_validCommitment("commitment1"));

        bytes32 root1 = pool.currentRoot();

        assertTrue(pool.isKnownRoot(root0), "Historical root should be known");
        assertTrue(pool.isKnownRoot(root1), "Current root should be known");
        assertFalse(
            pool.isKnownRoot(bytes32(uint256(999))),
            "Random root should not be known"
        );
    }

    /*//////////////////////////////////////////////////////////////
                         WITHDRAWAL (TEST MODE)
    //////////////////////////////////////////////////////////////*/

    function test_WithdrawInTestMode() public {
        // Deposit first
        bytes32 commitment = _validCommitment(
            abi.encodePacked("secret", uint256(1 ether))
        );
        vm.prank(user);
        pool.depositETH{value: 1 ether}(commitment);

        bytes32 root = pool.currentRoot();
        bytes32 nullifier = keccak256(abi.encodePacked("nullifier1"));

        // Generate a dummy proof (test mode accepts >= 64 bytes)
        bytes memory proof = new bytes(64);

        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: proof,
                merkleRoot: root,
                nullifier: nullifier,
                recipient: recipient,
                relayerAddress: address(0),
                amount: 1 ether,
                relayerFee: 0,
                assetId: NATIVE_ASSET,
                destChainId: bytes32(0)
            });

        uint256 recipientBalBefore = recipient.balance;

        vm.prank(user);
        pool.withdraw(wp);

        assertEq(
            recipient.balance,
            recipientBalBefore + 1 ether,
            "Recipient should receive ETH"
        );
        assertTrue(pool.isSpent(nullifier), "Nullifier should be spent");
        assertEq(
            pool.totalWithdrawals(),
            1,
            "Withdrawal count should increment"
        );
    }

    function test_RevertDoubleSpendNullifier() public {
        bytes32 commitment1 = _validCommitment(
            abi.encodePacked("s1", uint256(1 ether))
        );
        bytes32 commitment2 = _validCommitment(
            abi.encodePacked("s2", uint256(1 ether))
        );
        vm.startPrank(user);
        pool.depositETH{value: 1 ether}(commitment1);
        pool.depositETH{value: 1 ether}(commitment2);

        bytes32 root = pool.currentRoot();
        bytes32 nullifier = keccak256(abi.encodePacked("nullifier_dup"));
        bytes memory proof = new bytes(64);

        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: proof,
                merkleRoot: root,
                nullifier: nullifier,
                recipient: recipient,
                relayerAddress: address(0),
                amount: 1 ether,
                relayerFee: 0,
                assetId: NATIVE_ASSET,
                destChainId: bytes32(0)
            });

        pool.withdraw(wp);

        // Second withdrawal with same nullifier should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                IUniversalShieldedPool.NullifierAlreadySpent.selector,
                nullifier
            )
        );
        pool.withdraw(wp);
        vm.stopPrank();
    }

    function test_WithdrawWithRelayerFee() public {
        bytes32 commitment = _validCommitment(
            abi.encodePacked("s_relay", uint256(1 ether))
        );
        vm.prank(user);
        pool.depositETH{value: 1 ether}(commitment);

        bytes32 root = pool.currentRoot();
        bytes32 nullifier = keccak256(abi.encodePacked("nullifier_relay"));
        bytes memory proof = new bytes(64);

        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: proof,
                merkleRoot: root,
                nullifier: nullifier,
                recipient: recipient,
                relayerAddress: relayerAddr,
                amount: 1 ether,
                relayerFee: 0.01 ether,
                assetId: NATIVE_ASSET,
                destChainId: bytes32(0)
            });

        uint256 recipientBalBefore = recipient.balance;
        uint256 relayerBalBefore = relayerAddr.balance;

        vm.prank(user);
        pool.withdraw(wp);

        assertEq(
            recipient.balance,
            recipientBalBefore + 0.99 ether,
            "Recipient gets amount - fee"
        );
        assertEq(
            relayerAddr.balance,
            relayerBalBefore + 0.01 ether,
            "Relayer gets fee"
        );
    }

    /*//////////////////////////////////////////////////////////////
                         TEST MODE SECURITY
    //////////////////////////////////////////////////////////////*/

    function test_DisableTestMode() public {
        // Create a fresh pool with testMode=true to verify disable works
        vm.startPrank(admin);
        UniversalShieldedPool testPool = new UniversalShieldedPool(
            admin,
            address(0),
            true
        );
        assertTrue(testPool.testMode());
        testPool.disableTestMode();
        assertFalse(testPool.testMode());
        vm.stopPrank();
    }

    function test_RevertWithdrawAfterTestModeDisabled() public {
        // Create a fresh pool with no verifier and testMode=false
        vm.startPrank(admin);
        UniversalShieldedPool noVerifierPool = new UniversalShieldedPool(
            admin,
            address(0),
            false
        );
        vm.stopPrank();

        // Deposit into the no-verifier pool
        bytes32 commitment = _validCommitment(
            abi.encodePacked("sec", uint256(1 ether))
        );
        vm.prank(user);
        noVerifierPool.depositETH{value: 1 ether}(commitment);

        bytes32 root = noVerifierPool.currentRoot();
        bytes32 nullifier = keccak256(abi.encodePacked("null_disabled"));
        bytes memory proof = new bytes(64);

        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: proof,
                merkleRoot: root,
                nullifier: nullifier,
                recipient: recipient,
                relayerAddress: address(0),
                amount: 1 ether,
                relayerFee: 0,
                assetId: noVerifierPool.NATIVE_ASSET(),
                destChainId: bytes32(0)
            });

        // Should revert because no verifier is configured and test mode is off
        vm.prank(user);
        vm.expectRevert(IUniversalShieldedPool.NoVerifierConfigured.selector);
        noVerifierPool.withdraw(wp);
    }

    /*//////////////////////////////////////////////////////////////
                       ASSET REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterERC20Asset() public {
        address token = makeAddr("mockERC20");
        bytes32 assetId = keccak256(abi.encodePacked("USDC"));

        vm.prank(admin);
        pool.registerAsset(assetId, token);

        (address registeredToken, , , , bool active) = pool.assets(assetId);
        assertEq(registeredToken, token);
        assertTrue(active);
    }

    function test_RevertDuplicateAssetRegistration() public {
        address token = makeAddr("mockERC20");
        bytes32 assetId = keccak256(abi.encodePacked("USDC"));

        vm.startPrank(admin);
        pool.registerAsset(assetId, token);

        vm.expectRevert(
            abi.encodeWithSelector(
                IUniversalShieldedPool.AssetAlreadyRegistered.selector,
                assetId
            )
        );
        pool.registerAsset(assetId, token);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_Pause() public {
        vm.prank(admin);
        pool.pause();

        bytes32 commitment = _validCommitment("paused_test");
        vm.prank(user);
        vm.expectRevert();
        pool.depositETH{value: 1 ether}(commitment);
    }

    function test_Unpause() public {
        vm.startPrank(admin);
        pool.pause();
        pool.unpause();
        vm.stopPrank();

        bytes32 commitment = _validCommitment("unpaused_test");
        vm.prank(user);
        pool.depositETH{value: 1 ether}(commitment);

        assertEq(pool.totalDeposits(), 1);
    }

    function test_SetWithdrawalVerifier() public {
        address verifier = makeAddr("verifier");
        vm.prank(admin);
        pool.setWithdrawalVerifier(verifier);

        assertEq(pool.withdrawalVerifier(), verifier);
    }

    function test_RevertSetVerifierZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(IUniversalShieldedPool.ZeroAddress.selector)
        );
        pool.setWithdrawalVerifier(address(0));
    }

    function test_SetSanctionsOracle() public {
        address oracle = makeAddr("oracle");
        vm.prank(admin);
        pool.setSanctionsOracle(oracle);

        assertEq(pool.sanctionsOracle(), oracle);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetPoolStats() public {
        vm.prank(user);
        pool.depositETH{value: 1 ether}(_validCommitment("stat_test"));

        (uint256 deposits, , , uint256 treeSize, bytes32 root) = pool
            .getPoolStats();
        assertEq(deposits, 1, "Should report 1 deposit");
        assertEq(treeSize, 1, "Tree size should be 1");
        assertTrue(root != bytes32(0), "Root should be valid");
    }

    function test_GetRegisteredAssets() public {
        bytes32[] memory assetList = pool.getRegisteredAssets();
        assertEq(assetList.length, 1, "Should have 1 asset (native ETH)");
        assertEq(assetList[0], NATIVE_ASSET);
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_DepositETHAnyAmount(uint256 amount) public {
        uint256 minDeposit = pool.MIN_DEPOSIT();
        uint256 maxDeposit = pool.MAX_DEPOSIT();
        amount = bound(amount, minDeposit, maxDeposit);
        vm.deal(user, amount);

        bytes32 commitment = _validCommitment(
            abi.encodePacked("fuzz_secret", amount)
        );

        vm.prank(user);
        pool.depositETH{value: amount}(commitment);

        assertEq(pool.totalDeposits(), 1);
        assertEq(address(pool).balance, amount);
    }

    function testFuzz_UniqueCommitmentsProduceUniqueRoots(
        uint256 seed1,
        uint256 seed2
    ) public {
        // Use _validCommitment to guarantee field-valid, non-zero commitments
        bytes32 commitment1 = _validCommitment(
            abi.encodePacked("root_fuzz_a", seed1)
        );
        bytes32 commitment2 = _validCommitment(
            abi.encodePacked("root_fuzz_b", seed2)
        );
        vm.assume(commitment1 != commitment2);

        uint256 minDeposit = pool.MIN_DEPOSIT();

        vm.deal(user, minDeposit * 2);
        vm.startPrank(user);

        pool.depositETH{value: minDeposit}(commitment1);
        bytes32 root1 = pool.currentRoot();

        pool.depositETH{value: minDeposit}(commitment2);
        bytes32 root2 = pool.currentRoot();

        vm.stopPrank();

        assertTrue(
            root1 != root2,
            "Different commitments should produce different roots"
        );
    }
}
