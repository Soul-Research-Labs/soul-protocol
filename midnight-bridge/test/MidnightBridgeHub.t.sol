// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/MidnightBridgeHub.sol";
import "../contracts/MidnightProofVerifier.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title Mock ERC20 Token for testing
 */
contract MockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {
        _mint(msg.sender, 1000000 * 10 ** 18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/**
 * @title Mock wNIGHT Token for testing
 */
contract MockWNIGHT is ERC20 {
    constructor() ERC20("Wrapped NIGHT", "wNIGHT") {
        _mint(msg.sender, 1000000 * 10 ** 18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/**
 * @title Mock Proof Verifier for testing - always returns true
 */
contract MockProofVerifier {
    function verifyMidnightProof(
        bytes32,
        bytes32,
        bytes32,
        address,
        uint256,
        address,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifyStateTransition(
        bytes32,
        bytes32,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifyNullifierBatch(
        bytes32[] calldata,
        bytes32,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }
}

/**
 * @title MidnightBridgeHub Test Suite
 * @notice Comprehensive tests for the Midnight Bridge Hub contract
 */
contract MidnightBridgeHubTest is Test {
    MidnightBridgeHub public bridgeHub;
    MockProofVerifier public verifier;
    MockERC20 public mockToken;
    MockWNIGHT public wNight;

    address public owner;
    address public admin;
    address public user1;
    address public user2;
    address public relayer;

    bytes32 public constant MOCK_COMMITMENT = keccak256("test_commitment");
    bytes32 public constant MOCK_MIDNIGHT_RECIPIENT =
        keccak256("midnight_address");
    bytes32 public constant MOCK_NULLIFIER = keccak256("test_nullifier");
    bytes32 public constant MOCK_MERKLE_ROOT = keccak256("merkle_root");
    bytes32 public constant MOCK_STATE_ROOT = keccak256("state_root");

    uint256 public constant INITIAL_BALANCE = 100 ether;
    uint256 public constant LOCK_AMOUNT = 1 ether;

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        owner = address(this);
        admin = makeAddr("admin");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        relayer = makeAddr("relayer");

        // Deploy wNIGHT
        wNight = new MockWNIGHT();

        // Deploy mock verifier that always returns true
        verifier = new MockProofVerifier();

        // Deploy bridge hub with proper constructor args
        bridgeHub = new MidnightBridgeHub(
            address(wNight),
            address(verifier),
            admin
        );

        // Deploy mock token
        mockToken = new MockERC20();

        // Fund users
        vm.deal(user1, INITIAL_BALANCE);
        vm.deal(user2, INITIAL_BALANCE);
        vm.deal(address(bridgeHub), 100 ether); // Fund bridge for claims
        mockToken.mint(user1, 1000 * 10 ** 18);
        wNight.mint(user1, 1000 * 10 ** 18);
    }

    // =========================================================================
    // ETH LOCK TESTS
    // =========================================================================

    function test_LockETHForMidnight() public {
        vm.prank(user1);
        bytes32 lockId = bridgeHub.lockETHForMidnight{value: LOCK_AMOUNT}(
            MOCK_COMMITMENT,
            MOCK_MIDNIGHT_RECIPIENT
        );

        assertTrue(lockId != bytes32(0), "Lock ID should be non-zero");
        assertEq(
            address(bridgeHub).balance,
            100 ether + LOCK_AMOUNT,
            "Bridge should hold locked ETH"
        );
    }

    function test_LockETHForMidnight_RevertOnZeroAmount() public {
        vm.prank(user1);
        vm.expectRevert();
        bridgeHub.lockETHForMidnight{value: 0}(
            MOCK_COMMITMENT,
            MOCK_MIDNIGHT_RECIPIENT
        );
    }

    // Note: Contract allows zero commitment, testing that lock succeeds
    function test_LockETHForMidnight_AllowsZeroCommitment() public {
        vm.prank(user1);
        bytes32 lockId = bridgeHub.lockETHForMidnight{value: LOCK_AMOUNT}(
            bytes32(0),
            MOCK_MIDNIGHT_RECIPIENT
        );
        assertTrue(lockId != bytes32(0));
    }

    function test_LockETHForMidnight_RevertOnZeroRecipient() public {
        vm.prank(user1);
        vm.expectRevert();
        bridgeHub.lockETHForMidnight{value: LOCK_AMOUNT}(
            MOCK_COMMITMENT,
            bytes32(0)
        );
    }

    function testFuzz_LockETHForMidnight(
        uint256 amount,
        bytes32 commitment,
        bytes32 recipient
    ) public {
        vm.assume(amount > 0 && amount <= INITIAL_BALANCE);
        vm.assume(commitment != bytes32(0));
        vm.assume(recipient != bytes32(0));

        vm.prank(user1);
        bytes32 lockId = bridgeHub.lockETHForMidnight{value: amount}(
            commitment,
            recipient
        );

        assertTrue(lockId != bytes32(0));
    }

    // =========================================================================
    // VIEW FUNCTION TESTS
    // =========================================================================

    function test_GetLock() public {
        vm.prank(user1);
        bytes32 lockId = bridgeHub.lockETHForMidnight{value: LOCK_AMOUNT}(
            MOCK_COMMITMENT,
            MOCK_MIDNIGHT_RECIPIENT
        );

        MidnightBridgeHub.Lock memory lock = bridgeHub.getLock(lockId);
        assertEq(lock.amount, LOCK_AMOUNT);
        assertEq(lock.ethSender, user1);
        assertEq(lock.commitment, MOCK_COMMITMENT);
    }

    function test_IsNullifierUsed_ReturnsFalseInitially() public view {
        bool isUsed = bridgeHub.isNullifierUsed(MOCK_NULLIFIER);
        assertFalse(isUsed);
    }

    function test_GetTVL() public {
        vm.prank(user1);
        bridgeHub.lockETHForMidnight{value: LOCK_AMOUNT}(
            MOCK_COMMITMENT,
            MOCK_MIDNIGHT_RECIPIENT
        );

        uint256 tvl = bridgeHub.getTVL(address(0));
        assertEq(tvl, LOCK_AMOUNT);
    }

    // =========================================================================
    // ACCESS CONTROL TESTS
    // =========================================================================

    function test_OnlyAdminCanPause() public {
        // Non-admin cannot pause
        vm.prank(user1);
        vm.expectRevert();
        bridgeHub.pause();

        // Admin can pause
        vm.prank(admin);
        bridgeHub.pause();
        assertTrue(bridgeHub.paused());
    }

    function test_OnlyAdminCanUnpause() public {
        // First pause
        vm.prank(admin);
        bridgeHub.pause();

        // Non-admin cannot unpause
        vm.prank(user1);
        vm.expectRevert();
        bridgeHub.unpause();

        // Admin can unpause
        vm.prank(admin);
        bridgeHub.unpause();
        assertFalse(bridgeHub.paused());
    }

    function test_CannotLockWhenPaused() public {
        vm.prank(admin);
        bridgeHub.pause();

        vm.prank(user1);
        vm.expectRevert();
        bridgeHub.lockETHForMidnight{value: LOCK_AMOUNT}(
            MOCK_COMMITMENT,
            MOCK_MIDNIGHT_RECIPIENT
        );
    }

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    function _generateMockProof() internal pure returns (bytes memory) {
        // Generate 256 bytes of mock proof data
        return
            abi.encodePacked(
                bytes32(uint256(1)),
                bytes32(uint256(2)),
                bytes32(uint256(3)),
                bytes32(uint256(4)),
                bytes32(uint256(5)),
                bytes32(uint256(6)),
                bytes32(uint256(7)),
                bytes32(uint256(8))
            );
    }
}
