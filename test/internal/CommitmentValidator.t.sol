// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/internal/validators/CommitmentValidator.sol";

/// @dev Harness for internal CommitmentValidator library
contract CommitmentValidatorHarness {
    function computeHashCommitment(
        uint256 value,
        bytes32 blinding
    ) external pure returns (bytes32) {
        return CommitmentValidator.computeHashCommitment(value, blinding);
    }

    function computeStateCommitment(
        bytes memory encryptedState,
        bytes32 metadata,
        address owner
    ) external pure returns (bytes32) {
        return
            CommitmentValidator.computeStateCommitment(
                encryptedState,
                metadata,
                owner
            );
    }

    function computeTransitionCommitment(
        bytes32 oldCommitment,
        bytes32 newCommitment,
        bytes32 transitionHash
    ) external pure returns (bytes32) {
        return
            CommitmentValidator.computeTransitionCommitment(
                oldCommitment,
                newCommitment,
                transitionHash
            );
    }

    function isValidCommitment(
        bytes32 commitment
    ) external pure returns (bool) {
        return CommitmentValidator.isValidCommitment(commitment);
    }

    function validateMatch(
        bytes32 commitment,
        bytes32 expected
    ) external pure returns (bool) {
        return CommitmentValidator.validateMatch(commitment, expected);
    }

    function validateHashOpening(
        bytes32 commitment,
        uint256 value,
        bytes32 blinding
    ) external pure returns (bool) {
        return
            CommitmentValidator.validateHashOpening(
                commitment,
                value,
                blinding
            );
    }

    function validateStateCommitment(
        bytes32 commitment,
        bytes memory encryptedState,
        bytes32 metadata,
        address owner
    ) external pure returns (bool) {
        return
            CommitmentValidator.validateStateCommitment(
                commitment,
                encryptedState,
                metadata,
                owner
            );
    }

    function validateCommitmentChain(
        CommitmentValidator.StateCommitment memory currentState,
        bytes32 previousState,
        bytes32 storedPrevious
    ) external pure returns (bool) {
        return
            CommitmentValidator.validateCommitmentChain(
                currentState,
                previousState,
                storedPrevious
            );
    }

    function validateValueRange(
        uint256 value,
        uint256 minValue,
        uint256 maxValue
    ) external pure returns (bool) {
        return
            CommitmentValidator.validateValueRange(value, minValue, maxValue);
    }

    function isValidAmountCommitment(
        bytes32 commitment,
        uint256 maxAmount
    ) external pure returns (bool) {
        return
            CommitmentValidator.isValidAmountCommitment(commitment, maxAmount);
    }
}

contract CommitmentValidatorTest is Test {
    CommitmentValidatorHarness lib;

    function setUp() public {
        lib = new CommitmentValidatorHarness();
    }

    /* ══════════════════════════════════════════════════
                 COMPUTE HASH COMMITMENT
       ══════════════════════════════════════════════════ */

    function test_computeHashCommitment_deterministic() public view {
        bytes32 c1 = lib.computeHashCommitment(100, bytes32(uint256(0xABC)));
        bytes32 c2 = lib.computeHashCommitment(100, bytes32(uint256(0xABC)));
        assertEq(c1, c2);
    }

    function test_computeHashCommitment_differentInputs() public view {
        bytes32 c1 = lib.computeHashCommitment(100, bytes32(uint256(1)));
        bytes32 c2 = lib.computeHashCommitment(200, bytes32(uint256(1)));
        assertTrue(c1 != c2);
    }

    function test_computeHashCommitment_differentBlinding() public view {
        bytes32 c1 = lib.computeHashCommitment(100, bytes32(uint256(1)));
        bytes32 c2 = lib.computeHashCommitment(100, bytes32(uint256(2)));
        assertTrue(c1 != c2);
    }

    function testFuzz_computeHashCommitment_nonZero(
        uint256 value,
        bytes32 blinding
    ) public view {
        bytes32 c = lib.computeHashCommitment(value, blinding);
        assertTrue(c != bytes32(0));
    }

    /* ══════════════════════════════════════════════════
                COMPUTE STATE COMMITMENT
       ══════════════════════════════════════════════════ */

    function test_computeStateCommitment_deterministic() public view {
        bytes memory state = hex"DEADBEEF";
        bytes32 meta = bytes32(uint256(42));
        address owner = address(0xBEEF);

        bytes32 c1 = lib.computeStateCommitment(state, meta, owner);
        bytes32 c2 = lib.computeStateCommitment(state, meta, owner);
        assertEq(c1, c2);
    }

    function test_computeStateCommitment_differentOwner() public view {
        bytes memory state = hex"AA";
        bytes32 meta = bytes32(uint256(1));

        bytes32 c1 = lib.computeStateCommitment(state, meta, address(0x1));
        bytes32 c2 = lib.computeStateCommitment(state, meta, address(0x2));
        assertTrue(c1 != c2);
    }

    /* ══════════════════════════════════════════════════
              COMPUTE TRANSITION COMMITMENT
       ══════════════════════════════════════════════════ */

    function test_computeTransitionCommitment_deterministic() public view {
        bytes32 oldC = bytes32(uint256(1));
        bytes32 newC = bytes32(uint256(2));
        bytes32 txHash = bytes32(uint256(3));

        bytes32 c1 = lib.computeTransitionCommitment(oldC, newC, txHash);
        bytes32 c2 = lib.computeTransitionCommitment(oldC, newC, txHash);
        assertEq(c1, c2);
    }

    /* ══════════════════════════════════════════════════
                   IS VALID COMMITMENT
       ══════════════════════════════════════════════════ */

    function test_isValidCommitment_nonZero() public view {
        assertTrue(lib.isValidCommitment(bytes32(uint256(1))));
    }

    function test_isValidCommitment_zero() public view {
        assertFalse(lib.isValidCommitment(bytes32(0)));
    }

    /* ══════════════════════════════════════════════════
                    VALIDATE MATCH
       ══════════════════════════════════════════════════ */

    function test_validateMatch_equal() public view {
        bytes32 val = bytes32(uint256(0xABC));
        assertTrue(lib.validateMatch(val, val));
    }

    function test_validateMatch_notEqual() public view {
        assertFalse(
            lib.validateMatch(bytes32(uint256(1)), bytes32(uint256(2)))
        );
    }

    /* ══════════════════════════════════════════════════
                VALIDATE HASH OPENING
       ══════════════════════════════════════════════════ */

    function test_validateHashOpening_valid() public view {
        uint256 value = 500;
        bytes32 blinding = bytes32(uint256(0xDEAD));
        bytes32 commitment = lib.computeHashCommitment(value, blinding);

        assertTrue(lib.validateHashOpening(commitment, value, blinding));
    }

    function test_validateHashOpening_invalid() public view {
        uint256 value = 500;
        bytes32 blinding = bytes32(uint256(0xDEAD));
        bytes32 commitment = lib.computeHashCommitment(value, blinding);

        assertFalse(lib.validateHashOpening(commitment, value + 1, blinding));
    }

    /* ══════════════════════════════════════════════════
             VALIDATE STATE COMMITMENT
       ══════════════════════════════════════════════════ */

    function test_validateStateCommitment_valid() public view {
        bytes memory state = hex"AABB";
        bytes32 meta = bytes32(uint256(10));
        address owner = address(0xCAFE);

        bytes32 c = lib.computeStateCommitment(state, meta, owner);
        assertTrue(lib.validateStateCommitment(c, state, meta, owner));
    }

    function test_validateStateCommitment_invalidOwner() public view {
        bytes memory state = hex"AABB";
        bytes32 meta = bytes32(uint256(10));

        bytes32 c = lib.computeStateCommitment(state, meta, address(0xCAFE));
        assertFalse(
            lib.validateStateCommitment(c, state, meta, address(0xBEEF))
        );
    }

    /* ══════════════════════════════════════════════════
              VALIDATE COMMITMENT CHAIN
       ══════════════════════════════════════════════════ */

    function test_validateCommitmentChain_valid() public view {
        bytes32 prev = bytes32(uint256(1));
        CommitmentValidator.StateCommitment memory current = CommitmentValidator
            .StateCommitment({
                current: bytes32(uint256(2)),
                previous: prev,
                version: 1,
                timestamp: block.timestamp
            });

        assertTrue(lib.validateCommitmentChain(current, prev, prev));
    }

    function test_validateCommitmentChain_brokenChain() public view {
        CommitmentValidator.StateCommitment memory current = CommitmentValidator
            .StateCommitment({
                current: bytes32(uint256(2)),
                previous: bytes32(uint256(1)),
                version: 1,
                timestamp: block.timestamp
            });

        assertFalse(
            lib.validateCommitmentChain(
                current,
                bytes32(uint256(99)), // wrong previous
                bytes32(uint256(1))
            )
        );
    }

    /* ══════════════════════════════════════════════════
                VALIDATE VALUE RANGE
       ══════════════════════════════════════════════════ */

    function test_validateValueRange_inRange() public view {
        assertTrue(lib.validateValueRange(50, 10, 100));
    }

    function test_validateValueRange_atBoundaries() public view {
        assertTrue(lib.validateValueRange(10, 10, 100));
        assertTrue(lib.validateValueRange(100, 10, 100));
    }

    function test_validateValueRange_outOfRange() public view {
        assertFalse(lib.validateValueRange(9, 10, 100));
        assertFalse(lib.validateValueRange(101, 10, 100));
    }

    /* ══════════════════════════════════════════════════
             IS VALID AMOUNT COMMITMENT
       ══════════════════════════════════════════════════ */

    function test_isValidAmountCommitment_nonZero() public view {
        assertTrue(lib.isValidAmountCommitment(bytes32(uint256(42)), 1000));
    }

    function test_isValidAmountCommitment_zero() public view {
        assertFalse(lib.isValidAmountCommitment(bytes32(0), 1000));
    }
}
