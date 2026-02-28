// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/internal/validators/NullifierValidator.sol";

/// @dev Harness for internal NullifierValidator library
contract NullifierValidatorHarness {
    function computeStandardNullifier(
        bytes32 secret,
        bytes32 commitment,
        uint256 chainId
    ) external pure returns (bytes32) {
        return
            NullifierValidator.computeStandardNullifier(
                secret,
                commitment,
                chainId
            );
    }

    function computeCrossDomainNullifier(
        bytes32 sourceNullifier,
        uint256 sourceChainId,
        uint256 destChainId
    ) external pure returns (bytes32) {
        return
            NullifierValidator.computeCrossDomainNullifier(
                sourceNullifier,
                sourceChainId,
                destChainId
            );
    }

    function computeTimeBoundNullifier(
        bytes32 secret,
        bytes32 commitment,
        uint256 epoch
    ) external pure returns (bytes32) {
        return
            NullifierValidator.computeTimeBoundNullifier(
                secret,
                commitment,
                epoch
            );
    }

    function computeZaseonBinding(
        bytes32 sourceNullifier,
        bytes32 domainTag
    ) external pure returns (bytes32) {
        return
            NullifierValidator.computeZaseonBinding(sourceNullifier, domainTag);
    }

    function isValidFormat(bytes32 nullifier) external pure returns (bool) {
        return NullifierValidator.isValidFormat(nullifier);
    }

    function isExpired(
        NullifierValidator.NullifierRecord memory record
    ) external view returns (bool) {
        return NullifierValidator.isExpired(record);
    }

    function validateCrossDomainBinding(
        NullifierValidator.CrossDomainBinding memory binding,
        bytes32 expectedSource
    ) external pure returns (bool) {
        return
            NullifierValidator.validateCrossDomainBinding(
                binding,
                expectedSource
            );
    }

    function computeBatchRoot(
        bytes32[] memory nullifiers
    ) external pure returns (bytes32) {
        return NullifierValidator.computeBatchRoot(nullifiers);
    }

    function validateBatchUniqueness(
        bytes32[] memory nullifiers
    ) external pure returns (bool) {
        return NullifierValidator.validateBatchUniqueness(nullifiers);
    }
}

contract NullifierValidatorTest is Test {
    NullifierValidatorHarness lib;

    function setUp() public {
        lib = new NullifierValidatorHarness();
    }

    /* ══════════════════════════════════════════════════
                COMPUTE STANDARD NULLIFIER
       ══════════════════════════════════════════════════ */

    function test_computeStandardNullifier_deterministic() public view {
        bytes32 secret = bytes32(uint256(0xAA));
        bytes32 commitment = bytes32(uint256(0xBB));
        uint256 chainId = 1;

        bytes32 n1 = lib.computeStandardNullifier(secret, commitment, chainId);
        bytes32 n2 = lib.computeStandardNullifier(secret, commitment, chainId);
        assertEq(n1, n2);
    }

    function test_computeStandardNullifier_differentChainId() public view {
        bytes32 secret = bytes32(uint256(0xAA));
        bytes32 commitment = bytes32(uint256(0xBB));

        bytes32 n1 = lib.computeStandardNullifier(secret, commitment, 1);
        bytes32 n2 = lib.computeStandardNullifier(secret, commitment, 42161);
        assertTrue(n1 != n2);
    }

    function test_computeStandardNullifier_differentSecret() public view {
        bytes32 commitment = bytes32(uint256(0xBB));
        uint256 chainId = 1;

        bytes32 n1 = lib.computeStandardNullifier(
            bytes32(uint256(1)),
            commitment,
            chainId
        );
        bytes32 n2 = lib.computeStandardNullifier(
            bytes32(uint256(2)),
            commitment,
            chainId
        );
        assertTrue(n1 != n2);
    }

    function testFuzz_computeStandardNullifier_nonZero(
        bytes32 secret,
        bytes32 commitment,
        uint256 chainId
    ) public view {
        bytes32 n = lib.computeStandardNullifier(secret, commitment, chainId);
        assertTrue(n != bytes32(0));
    }

    /* ══════════════════════════════════════════════════
             COMPUTE CROSS-DOMAIN NULLIFIER
       ══════════════════════════════════════════════════ */

    function test_computeCrossDomainNullifier_deterministic() public view {
        bytes32 source = bytes32(uint256(0xFF));
        bytes32 n1 = lib.computeCrossDomainNullifier(source, 1, 42161);
        bytes32 n2 = lib.computeCrossDomainNullifier(source, 1, 42161);
        assertEq(n1, n2);
    }

    function test_computeCrossDomainNullifier_differentDests() public view {
        bytes32 source = bytes32(uint256(0xFF));
        bytes32 n1 = lib.computeCrossDomainNullifier(source, 1, 42161);
        bytes32 n2 = lib.computeCrossDomainNullifier(source, 1, 10);
        assertTrue(n1 != n2);
    }

    /* ══════════════════════════════════════════════════
              COMPUTE TIME-BOUND NULLIFIER
       ══════════════════════════════════════════════════ */

    function test_computeTimeBoundNullifier_differentEpochs() public view {
        bytes32 secret = bytes32(uint256(0xAA));
        bytes32 commitment = bytes32(uint256(0xBB));

        bytes32 n1 = lib.computeTimeBoundNullifier(secret, commitment, 100);
        bytes32 n2 = lib.computeTimeBoundNullifier(secret, commitment, 200);
        assertTrue(n1 != n2);
    }

    /* ══════════════════════════════════════════════════
                  COMPUTE ZASEON BINDING
       ══════════════════════════════════════════════════ */

    function test_computeZaseonBinding_deterministic() public view {
        bytes32 source = bytes32(uint256(0xAA));
        bytes32 domain = bytes32(uint256(0xBB));

        bytes32 b1 = lib.computeZaseonBinding(source, domain);
        bytes32 b2 = lib.computeZaseonBinding(source, domain);
        assertEq(b1, b2);
    }

    function test_computeZaseonBinding_differentDomains() public view {
        bytes32 source = bytes32(uint256(0xAA));
        bytes32 b1 = lib.computeZaseonBinding(source, bytes32(uint256(1)));
        bytes32 b2 = lib.computeZaseonBinding(source, bytes32(uint256(2)));
        assertTrue(b1 != b2);
    }

    /* ══════════════════════════════════════════════════
                    IS VALID FORMAT
       ══════════════════════════════════════════════════ */

    function test_isValidFormat_nonZero() public view {
        assertTrue(lib.isValidFormat(bytes32(uint256(1))));
    }

    function test_isValidFormat_zero() public view {
        assertFalse(lib.isValidFormat(bytes32(0)));
    }

    /* ══════════════════════════════════════════════════
                      IS EXPIRED
       ══════════════════════════════════════════════════ */

    function test_isExpired_expired() public {
        vm.warp(2000);
        NullifierValidator.NullifierRecord memory r = NullifierValidator
            .NullifierRecord({
                commitment: bytes32(uint256(1)),
                chainId: 1,
                timestamp: block.timestamp - 1000,
                expiresAt: block.timestamp - 1,
                spent: false
            });
        assertTrue(lib.isExpired(r));
    }

    function test_isExpired_notExpired() public view {
        NullifierValidator.NullifierRecord memory r = NullifierValidator
            .NullifierRecord({
                commitment: bytes32(uint256(1)),
                chainId: 1,
                timestamp: block.timestamp,
                expiresAt: block.timestamp + 1000,
                spent: false
            });
        assertFalse(lib.isExpired(r));
    }

    function test_isExpired_zeroExpiresAt() public view {
        NullifierValidator.NullifierRecord memory r = NullifierValidator
            .NullifierRecord({
                commitment: bytes32(uint256(1)),
                chainId: 1,
                timestamp: block.timestamp,
                expiresAt: 0,
                spent: false
            });
        // expiresAt == 0 means no expiry
        assertFalse(lib.isExpired(r));
    }

    /* ══════════════════════════════════════════════════
            VALIDATE CROSS-DOMAIN BINDING
       ══════════════════════════════════════════════════ */

    function test_validateCrossDomainBinding_valid() public view {
        bytes32 source = bytes32(uint256(0xAA));
        bytes32 dest = lib.computeCrossDomainNullifier(source, 1, 42161);
        NullifierValidator.CrossDomainBinding
            memory binding = NullifierValidator.CrossDomainBinding({
                sourceNullifier: source,
                destNullifier: dest,
                sourceChainId: 1,
                destChainId: 42161,
                verified: true
            });

        assertTrue(lib.validateCrossDomainBinding(binding, source));
    }

    function test_validateCrossDomainBinding_wrongSource() public view {
        NullifierValidator.CrossDomainBinding
            memory binding = NullifierValidator.CrossDomainBinding({
                sourceNullifier: bytes32(uint256(0xAA)),
                destNullifier: bytes32(uint256(0xBB)),
                sourceChainId: 1,
                destChainId: 42161,
                verified: true
            });

        assertFalse(
            lib.validateCrossDomainBinding(binding, bytes32(uint256(0xCC)))
        );
    }

    function test_validateCrossDomainBinding_unverified() public view {
        bytes32 source = bytes32(uint256(0xAA));
        NullifierValidator.CrossDomainBinding
            memory binding = NullifierValidator.CrossDomainBinding({
                sourceNullifier: source,
                destNullifier: bytes32(uint256(0xBB)),
                sourceChainId: 1,
                destChainId: 42161,
                verified: false
            });

        assertFalse(lib.validateCrossDomainBinding(binding, source));
    }

    /* ══════════════════════════════════════════════════
                  COMPUTE BATCH ROOT
       ══════════════════════════════════════════════════ */

    function test_computeBatchRoot_deterministic() public view {
        bytes32[] memory ns = new bytes32[](3);
        ns[0] = bytes32(uint256(1));
        ns[1] = bytes32(uint256(2));
        ns[2] = bytes32(uint256(3));

        bytes32 r1 = lib.computeBatchRoot(ns);
        bytes32 r2 = lib.computeBatchRoot(ns);
        assertEq(r1, r2);
    }

    function test_computeBatchRoot_singleElement() public view {
        bytes32[] memory ns = new bytes32[](1);
        ns[0] = bytes32(uint256(42));

        bytes32 root = lib.computeBatchRoot(ns);
        assertEq(root, ns[0]);
    }

    function test_computeBatchRoot_nonZero() public view {
        bytes32[] memory ns = new bytes32[](2);
        ns[0] = bytes32(uint256(1));
        ns[1] = bytes32(uint256(2));

        bytes32 root = lib.computeBatchRoot(ns);
        assertTrue(root != bytes32(0));
    }

    /* ══════════════════════════════════════════════════
               VALIDATE BATCH UNIQUENESS
       ══════════════════════════════════════════════════ */

    function test_validateBatchUniqueness_allUnique() public view {
        bytes32[] memory ns = new bytes32[](3);
        ns[0] = bytes32(uint256(1));
        ns[1] = bytes32(uint256(2));
        ns[2] = bytes32(uint256(3));
        assertTrue(lib.validateBatchUniqueness(ns));
    }

    function test_validateBatchUniqueness_hasDuplicate() public view {
        bytes32[] memory ns = new bytes32[](3);
        ns[0] = bytes32(uint256(1));
        ns[1] = bytes32(uint256(2));
        ns[2] = bytes32(uint256(1));
        assertFalse(lib.validateBatchUniqueness(ns));
    }

    function test_validateBatchUniqueness_singleElement() public view {
        bytes32[] memory ns = new bytes32[](1);
        ns[0] = bytes32(uint256(1));
        assertTrue(lib.validateBatchUniqueness(ns));
    }

    /* ══════════════════════════════════════════════════
                    DOMAIN CONSTANTS
       ══════════════════════════════════════════════════ */

    function test_domainConstants_nonZero() public pure {
        assertTrue(NullifierValidator.STANDARD_DOMAIN != bytes32(0));
        assertTrue(NullifierValidator.CROSS_DOMAIN != bytes32(0));
        assertTrue(NullifierValidator.TIME_BOUND_DOMAIN != bytes32(0));
    }

    function test_domainConstants_allDifferent() public pure {
        assertTrue(
            NullifierValidator.STANDARD_DOMAIN !=
                NullifierValidator.CROSS_DOMAIN
        );
        assertTrue(
            NullifierValidator.STANDARD_DOMAIN !=
                NullifierValidator.TIME_BOUND_DOMAIN
        );
        assertTrue(
            NullifierValidator.CROSS_DOMAIN !=
                NullifierValidator.TIME_BOUND_DOMAIN
        );
    }
}
