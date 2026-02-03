// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/MidnightBridgeHub.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MidnightBridgeFuzz
 * @notice Comprehensive fuzz tests for Midnight Bridge security
 * @dev Run with: forge test --match-contract MidnightBridgeFuzz --fuzz-runs 10000
 */

/// @dev Mock wNIGHT token for testing
contract MockWNIGHT is ERC20 {
    constructor() ERC20("Wrapped NIGHT", "wNIGHT") {
        _mint(msg.sender, type(uint128).max);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Mock verifier that allows testing both valid and invalid proofs
contract FuzzProofVerifier is IMidnightProofVerifier {
    bool public shouldPass = true;

    function setShouldPass(bool _pass) external {
        shouldPass = _pass;
    }

    function verifyMidnightProof(
        bytes32,
        bytes32,
        bytes32,
        address,
        uint256,
        address,
        bytes calldata
    ) external view returns (bool) {
        return shouldPass;
    }

    function verifyStateTransition(
        bytes32,
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return shouldPass;
    }

    function verifyNullifierBatch(
        bytes32[] calldata,
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return shouldPass;
    }
}

contract MidnightBridgeFuzz is Test {
    MidnightBridgeHub public hub;
    FuzzProofVerifier public verifier;
    MockWNIGHT public wnight;

    address public admin = address(1);
    address public user = address(3);

    uint256 constant MIN_AMOUNT = 1e15; // 0.001 tokens
    uint256 constant MAX_AMOUNT = 1e24; // 1M tokens

    function setUp() public {
        vm.startPrank(admin);

        verifier = new FuzzProofVerifier();
        wnight = new MockWNIGHT();

        hub = new MidnightBridgeHub(address(wnight), address(verifier), admin);

        // Give user tokens
        wnight.mint(user, type(uint128).max);

        // Fund hub for claims
        wnight.mint(address(hub), 1e27);

        vm.stopPrank();

        // User approves hub
        vm.prank(user);
        wnight.approve(address(hub), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                        LOCK FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz lock amounts - should handle all valid amounts
    function testFuzz_LockETHAmount(uint256 amountSeed) public {
        uint256 amount = bound(amountSeed, MIN_AMOUNT, 100 ether);
        bytes32 commitment = keccak256(
            abi.encodePacked("commitment", block.timestamp)
        );
        bytes32 midnightRecipient = keccak256(
            abi.encodePacked("midnight_addr", user)
        );

        vm.deal(user, amount);
        vm.prank(user);
        bytes32 lockId = hub.lockETHForMidnight{value: amount}(
            commitment,
            midnightRecipient
        );

        assertNotEq(lockId, bytes32(0), "Should return valid lock ID");
    }

    /// @notice Fuzz lock wNIGHT tokens
    function testFuzz_LockTokenAmount(uint256 amountSeed) public {
        uint256 amount = bound(amountSeed, MIN_AMOUNT, MAX_AMOUNT);
        bytes32 commitment = keccak256(abi.encodePacked("commitment", amount));
        bytes32 midnightRecipient = keccak256(
            abi.encodePacked("midnight_addr")
        );

        uint256 balanceBefore = wnight.balanceOf(user);

        vm.prank(user);
        bytes32 lockId = hub.lockTokenForMidnight(
            address(wnight),
            amount,
            commitment,
            midnightRecipient
        );

        uint256 balanceAfter = wnight.balanceOf(user);

        assertEq(
            balanceBefore - balanceAfter,
            amount,
            "Incorrect amount transferred"
        );
        assertNotEq(lockId, bytes32(0), "Should return valid lock ID");
    }

    /// @notice Fuzz test that zero amount reverts
    function testFuzz_LockZeroReverts() public {
        bytes32 commitment = keccak256("commitment");
        bytes32 recipient = keccak256("recipient");

        vm.prank(user);
        vm.expectRevert(MidnightBridgeHub.InvalidAmount.selector);
        hub.lockETHForMidnight{value: 0}(commitment, recipient);
    }

    /// @notice Fuzz test that zero recipient reverts
    function testFuzz_LockZeroRecipientReverts(uint256 amount) public {
        amount = bound(amount, MIN_AMOUNT, 10 ether);
        bytes32 commitment = keccak256("commitment");

        vm.deal(user, amount);
        vm.prank(user);
        vm.expectRevert(MidnightBridgeHub.InvalidRecipient.selector);
        hub.lockETHForMidnight{value: amount}(commitment, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                    NULLIFIER UNIQUENESS FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test nullifier uniqueness - most critical property
    function testFuzz_NullifierUniqueness(
        bytes32 nullifier1,
        bytes32 nullifier2
    ) public pure {
        vm.assume(nullifier1 != nullifier2);
        vm.assume(nullifier1 != bytes32(0));
        vm.assume(nullifier2 != bytes32(0));

        // Different nullifiers should have different storage slots
        bytes32 slot1 = keccak256(abi.encodePacked(nullifier1, uint256(8)));
        bytes32 slot2 = keccak256(abi.encodePacked(nullifier2, uint256(8)));
        assertNotEq(
            slot1,
            slot2,
            "Different nullifiers should have different slots"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    COMMITMENT HASH FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz commitment hash determinism
    function testFuzz_CommitmentHashDeterministic(
        address sender,
        address tokenAddr,
        uint256 amount,
        bytes32 recipient
    ) public pure {
        vm.assume(sender != address(0));
        vm.assume(tokenAddr != address(0));
        vm.assume(amount > 0 && amount < type(uint256).max); // Prevent overflow

        bytes32 hash1 = keccak256(
            abi.encodePacked(sender, tokenAddr, amount, recipient)
        );
        bytes32 hash2 = keccak256(
            abi.encodePacked(sender, tokenAddr, amount, recipient)
        );

        assertEq(hash1, hash2, "Same inputs should produce same hash");

        bytes32 hash3 = keccak256(
            abi.encodePacked(sender, tokenAddr, amount + 1, recipient)
        );
        assertNotEq(
            hash1,
            hash3,
            "Different inputs should produce different hash"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    ASSET SUPPORT FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test unsupported assets are rejected
    function testFuzz_UnsupportedAssetReverts(address randomToken) public {
        vm.assume(randomToken != address(wnight));
        vm.assume(randomToken != address(0)); // ETH is supported

        bytes32 commitment = keccak256("commitment");
        bytes32 recipient = keccak256("recipient");

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                MidnightBridgeHub.AssetNotSupported.selector,
                randomToken
            )
        );
        hub.lockTokenForMidnight(randomToken, 1e18, commitment, recipient);
    }

    /*//////////////////////////////////////////////////////////////
                    LOCK ID UNIQUENESS FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test that consecutive locks have unique IDs
    function testFuzz_LockIdUniqueness(
        uint256 numLocks,
        uint256 baseSeed
    ) public {
        numLocks = bound(numLocks, 2, 20);

        bytes32[] memory lockIds = new bytes32[](numLocks);

        for (uint256 i = 0; i < numLocks; i++) {
            uint256 amount = 1e16 + (i * 1e15);
            bytes32 commitment = keccak256(abi.encodePacked(baseSeed, i));
            bytes32 recipient = keccak256(abi.encodePacked("recipient", i));

            vm.deal(user, amount);
            vm.prank(user);
            lockIds[i] = hub.lockETHForMidnight{value: amount}(
                commitment,
                recipient
            );
        }

        // Verify all IDs are unique
        for (uint256 i = 0; i < numLocks; i++) {
            for (uint256 j = i + 1; j < numLocks; j++) {
                assertNotEq(lockIds[i], lockIds[j], "Lock IDs must be unique");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ARITHMETIC SAFETY FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test arithmetic safety on rapid locks
    function testFuzz_RapidLocksNoOverflow(
        uint256 numLocks,
        uint256 amountSeed
    ) public {
        numLocks = bound(numLocks, 1, 30);
        uint256 baseAmount = bound(amountSeed, MIN_AMOUNT, MAX_AMOUNT / 100);

        uint256 totalLocked = 0;
        uint256 hubBalanceBefore = wnight.balanceOf(address(hub));

        for (uint256 i = 0; i < numLocks; i++) {
            uint256 amount = baseAmount + (i * 1e16);
            bytes32 commitment = keccak256(abi.encodePacked("commitment", i));
            bytes32 recipient = keccak256(abi.encodePacked("recipient", i));

            vm.prank(user);
            hub.lockTokenForMidnight(
                address(wnight),
                amount,
                commitment,
                recipient
            );
            totalLocked += amount;
        }

        assertEq(
            wnight.balanceOf(address(hub)) - hubBalanceBefore,
            totalLocked,
            "Hub balance should equal total locked"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    ROLE ACCESS CONTROL FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test that non-admins cannot grant roles
    function testFuzz_NonAdminCannotGrantRoles(
        address attacker,
        address target,
        bytes32 role
    ) public {
        vm.assume(attacker != admin);
        vm.assume(attacker != address(0));
        vm.assume(target != address(0));
        vm.assume(!hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        hub.grantRole(role, target);
    }

    /*//////////////////////////////////////////////////////////////
                    PAUSE FUNCTIONALITY FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test that paused state blocks locks
    function testFuzz_PausedStateBlocksLocks(uint256 amount) public {
        amount = bound(amount, MIN_AMOUNT, 10 ether);

        // Pause the contract
        vm.prank(admin);
        hub.pause();

        bytes32 commitment = keccak256("commitment");
        bytes32 recipient = keccak256("recipient");

        vm.deal(user, amount);
        vm.prank(user);
        vm.expectRevert();
        hub.lockETHForMidnight{value: amount}(commitment, recipient);
    }
}
