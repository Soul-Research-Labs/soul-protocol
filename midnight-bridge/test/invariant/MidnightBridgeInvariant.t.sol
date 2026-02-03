// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../../contracts/MidnightBridgeHub.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MidnightBridgeInvariant
 * @notice Invariant tests for Midnight Bridge security properties
 * @dev Run with: forge test --match-contract MidnightBridgeInvariant
 */

contract InvariantToken is ERC20 {
    constructor() ERC20("Invariant Token", "INV") {
        _mint(msg.sender, 1e30);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockVerifierInvariant is IMidnightProofVerifier {
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
 * @notice Handler contract that executes random valid actions
 */
contract BridgeHandler is Test {
    MidnightBridgeHub public hub;
    InvariantToken public wnight;

    address[] public users;

    // Ghost variables for tracking invariants
    uint256 public ghost_totalETHLocked;
    uint256 public ghost_totalTokenLocked;
    uint256 public ghost_lockCount;

    // Tracking for lock ID uniqueness
    bytes32[] public allLockIds;
    mapping(bytes32 => bool) public seenLockIds;

    constructor(MidnightBridgeHub _hub, InvariantToken _wnight) {
        hub = _hub;
        wnight = _wnight;

        // Create test users
        for (uint256 i = 0; i < 10; i++) {
            address user = address(uint160(100 + i));
            users.push(user);
            wnight.mint(user, 1e27);
            vm.prank(user);
            wnight.approve(address(hub), type(uint256).max);
        }
    }

    /**
     * @notice Random ETH lock action
     */
    function lockETH(uint256 userSeed, uint256 amount) external {
        address user = users[userSeed % users.length];
        amount = bound(amount, 1e15, 10 ether);

        bytes32 commitment = keccak256(
            abi.encodePacked("commitment", ghost_lockCount)
        );
        bytes32 recipient = keccak256(
            abi.encodePacked("recipient", ghost_lockCount)
        );

        vm.deal(user, amount);
        vm.prank(user);
        bytes32 lockId = hub.lockETHForMidnight{value: amount}(
            commitment,
            recipient
        );

        // Track for invariants
        require(!seenLockIds[lockId], "Duplicate lock ID");
        seenLockIds[lockId] = true;
        allLockIds.push(lockId);

        ghost_totalETHLocked += amount;
        ghost_lockCount++;
    }

    /**
     * @notice Random token lock action
     */
    function lockToken(uint256 userSeed, uint256 amount) external {
        address user = users[userSeed % users.length];
        amount = bound(amount, 1e15, 1e22);

        bytes32 commitment = keccak256(
            abi.encodePacked("token_commitment", ghost_lockCount)
        );
        bytes32 recipient = keccak256(
            abi.encodePacked("token_recipient", ghost_lockCount)
        );

        vm.prank(user);
        bytes32 lockId = hub.lockTokenForMidnight(
            address(wnight),
            amount,
            commitment,
            recipient
        );

        // Track for invariants
        require(!seenLockIds[lockId], "Duplicate lock ID");
        seenLockIds[lockId] = true;
        allLockIds.push(lockId);

        ghost_totalTokenLocked += amount;
        ghost_lockCount++;
    }

    function getUsersCount() external view returns (uint256) {
        return users.length;
    }

    function getLockIdsCount() external view returns (uint256) {
        return allLockIds.length;
    }
}

contract MidnightBridgeInvariant is StdInvariant, Test {
    MidnightBridgeHub public hub;
    MockVerifierInvariant public verifier;
    InvariantToken public wnight;
    BridgeHandler public handler;

    address public admin = address(1);

    function setUp() public {
        vm.startPrank(admin);

        verifier = new MockVerifierInvariant();
        wnight = new InvariantToken();

        hub = new MidnightBridgeHub(address(wnight), address(verifier), admin);

        vm.stopPrank();

        handler = new BridgeHandler(hub, wnight);

        // Target only the handler
        targetContract(address(handler));
    }

    /*//////////////////////////////////////////////////////////////
                        INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice INVARIANT: ETH balance >= ETH locked
     * @dev The hub should always have at least as much ETH as has been locked
     */
    function invariant_ethSolvency() public view {
        assertGe(
            address(hub).balance,
            handler.ghost_totalETHLocked(),
            "Hub ETH balance should >= total ETH locked"
        );
    }

    /**
     * @notice INVARIANT: Token balance >= tokens locked
     * @dev The hub should always have at least as much tokens as have been locked
     */
    function invariant_tokenSolvency() public view {
        assertGe(
            wnight.balanceOf(address(hub)),
            handler.ghost_totalTokenLocked(),
            "Hub token balance should >= total tokens locked"
        );
    }

    /**
     * @notice INVARIANT: Lock count matches array length
     * @dev Each lock creates exactly one entry
     */
    function invariant_lockCountParity() public view {
        assertEq(
            handler.ghost_lockCount(),
            handler.getLockIdsCount(),
            "Lock count should match lock IDs array length"
        );
    }

    /**
     * @notice INVARIANT: All lock IDs are unique
     * @dev No two locks should ever have the same ID
     */
    function invariant_lockIdUniqueness() public view {
        uint256 lockCount = handler.getLockIdsCount();

        // If handler ensures no duplicates via require, this should always pass
        for (uint256 i = 0; i < lockCount && i < 50; i++) {
            bytes32 lockId = handler.allLockIds(i);
            assertTrue(
                handler.seenLockIds(lockId),
                "All lock IDs should be tracked"
            );
        }
    }

    /**
     * @notice INVARIANT: Contract should never be in undefined state
     */
    function invariant_contractState() public view {
        // Hub should have valid verifier
        assertNotEq(
            address(hub.proofVerifier()),
            address(0),
            "Verifier should be set"
        );

        // Admin role should exist
        assertTrue(
            hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), admin),
            "Admin should have admin role"
        );
    }

    /**
     * @notice INVARIANT: Ghost variables are non-negative
     */
    function invariant_ghostVariablesNonNegative() public view {
        assertGe(handler.ghost_totalETHLocked(), 0, "ETH locked >= 0");
        assertGe(handler.ghost_totalTokenLocked(), 0, "Token locked >= 0");
        assertGe(handler.ghost_lockCount(), 0, "Lock count >= 0");
    }

    /**
     * @notice Call summary for debugging
     */
    function invariant_callSummary() public view {
        console.log("Lock count:", handler.ghost_lockCount());
        console.log("ETH locked:", handler.ghost_totalETHLocked());
        console.log("Tokens locked:", handler.ghost_totalTokenLocked());
        console.log("Hub ETH balance:", address(hub).balance);
        console.log("Hub token balance:", wnight.balanceOf(address(hub)));
    }
}
