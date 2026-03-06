// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/StealthAddressRegistry.sol";
import "../../contracts/interfaces/IStealthAddressRegistry.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract StealthAddressRegistryFuzzTest is Test {
    StealthAddressRegistry internal registry;
    address internal admin = address(0xA1);

    function setUp() public {
        // Deploy implementation
        StealthAddressRegistry impl = new StealthAddressRegistry();

        // Deploy proxy with initialize() encoded
        bytes memory initData = abi.encodeCall(
            StealthAddressRegistry.initialize,
            (admin)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);

        registry = StealthAddressRegistry(address(proxy));
    }

    // =========================================================================
    // Fuzz: registerMetaAddress key length validation for SECP256K1
    // =========================================================================

    function testFuzz_registerMetaAddress_keyLengthValidation(
        uint8 keyLen
    ) public {
        // Skip zero-length keys — those revert with InvalidPubKey before curve validation
        vm.assume(keyLen > 0);

        bytes memory key = new bytes(keyLen);
        // Fill with non-zero data so it's a plausible key
        for (uint256 i = 0; i < keyLen; i++) {
            key[i] = bytes1(uint8(0x02));
        }

        if (keyLen == 33 || keyLen == 65) {
            // Valid compressed (33) or uncompressed (65) secp256k1 key lengths
            registry.registerMetaAddress(
                key,
                key,
                IStealthAddressRegistry.CurveType.SECP256K1,
                1
            );

            IStealthAddressRegistry.StealthMetaAddress memory meta = registry
                .getMetaAddress(address(this));
            assertEq(
                uint8(meta.status),
                uint8(IStealthAddressRegistry.KeyStatus.ACTIVE)
            );
            assertEq(meta.spendingPubKey.length, keyLen);
        } else {
            // Invalid length — should revert with InvalidSecp256k1Key
            vm.expectRevert(
                IStealthAddressRegistry.InvalidSecp256k1Key.selector
            );
            registry.registerMetaAddress(
                key,
                key,
                IStealthAddressRegistry.CurveType.SECP256K1,
                1
            );
        }
    }

    // =========================================================================
    // Fuzz: computeDualKeyStealth is deterministic
    // =========================================================================

    function testFuzz_computeDualKeyStealth_deterministic(
        bytes32 spendKey,
        bytes32 viewKey,
        bytes32 ephKey
    ) public {
        uint256 chainId = 42;

        // First call
        (bytes32 hash1, address addr1) = registry.computeDualKeyStealth(
            spendKey,
            viewKey,
            ephKey,
            chainId
        );

        // Second call with identical inputs (overwrites same record, returns same values)
        (bytes32 hash2, address addr2) = registry.computeDualKeyStealth(
            spendKey,
            viewKey,
            ephKey,
            chainId
        );

        assertEq(hash1, hash2, "stealthHash must be deterministic");
        assertEq(addr1, addr2, "derivedAddress must be deterministic");
        assertEq(
            addr1,
            address(uint160(uint256(hash1))),
            "address must derive from hash"
        );
    }

    // =========================================================================
    // Fuzz: announce stores view tag index correctly
    // =========================================================================

    function testFuzz_announce_viewTagIndexing(
        uint256 schemeId,
        uint8 viewTagByte
    ) public {
        bytes1 tag = bytes1(viewTagByte);
        address stealthAddr = address(
            uint160(uint256(keccak256(abi.encode(schemeId, viewTagByte))))
        );
        // Ensure non-zero stealth address
        vm.assume(stealthAddr != address(0));

        bytes memory ephKey = new bytes(33);
        ephKey[0] = 0x02;
        bytes memory viewTag = new bytes(1);
        viewTag[0] = tag;

        // announce requires ANNOUNCER_ROLE
        vm.prank(admin);
        registry.announce(schemeId, stealthAddr, ephKey, viewTag, "");

        // Verify the stealth address is indexed under the view tag
        address[] memory tagAddrs = registry.getAnnouncementsByViewTag(tag);
        bool found = false;
        for (uint256 i = 0; i < tagAddrs.length; i++) {
            if (tagAddrs[i] == stealthAddr) {
                found = true;
                break;
            }
        }
        assertTrue(found, "stealth address must appear in view tag index");

        // Verify the announcement is stored correctly
        IStealthAddressRegistry.Announcement memory ann = registry
            .getAnnouncement(stealthAddr);
        assertEq(ann.stealthAddress, stealthAddr);
        assertEq(ann.schemeId, bytes32(schemeId));
    }

    // =========================================================================
    // Fuzz: announcePrivate fee enforcement
    // =========================================================================

    function testFuzz_announcePrivate_feeEnforcement(uint256 value) public {
        // Bound to below the minimum fee (0.0001 ether)
        value = bound(value, 0, 0.0001 ether - 1);

        address stealthAddr = address(0xBEEF);
        bytes memory ephKey = new bytes(33);
        ephKey[0] = 0x02;

        vm.deal(address(this), value);
        vm.expectRevert(IStealthAddressRegistry.InsufficientFee.selector);
        registry.announcePrivate{value: value}(1, stealthAddr, ephKey, "", "");
    }

    // =========================================================================
    // Fuzz: deriveCrossChainStealth uniqueness for different keys
    // =========================================================================

    function testFuzz_deriveCrossChainStealth_uniqueness(
        bytes32 key1,
        bytes32 key2,
        uint256 chainId
    ) public {
        // Keys must differ and be non-zero
        vm.assume(key1 != key2);
        vm.assume(key1 != bytes32(0));
        vm.assume(key2 != bytes32(0));

        // destChainId must be valid: non-zero and not the current chain (31337)
        chainId = bound(chainId, 1, type(uint64).max);
        vm.assume(chainId != block.chainid);

        bytes32 stealthDomain = registry.STEALTH_DOMAIN();

        // Build valid derivation proof for key1
        bytes memory proof1 = _buildDerivationProof(
            key1,
            chainId,
            stealthDomain
        );

        // Build valid derivation proof for key2
        bytes memory proof2 = _buildDerivationProof(
            key2,
            chainId,
            stealthDomain
        );

        bytes32 dest1 = registry.deriveCrossChainStealth(key1, chainId, proof1);
        bytes32 dest2 = registry.deriveCrossChainStealth(key2, chainId, proof2);

        assertTrue(
            dest1 != dest2,
            "different source keys must produce different dest keys"
        );
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    /// @dev Build a valid testnet derivation proof that passes _verifyDerivationProof
    function _buildDerivationProof(
        bytes32 sourceKey,
        uint256 destChainId,
        bytes32 stealthDomain
    ) internal pure returns (bytes memory) {
        // proof[0:32]  = proofCommitment (non-zero, != sourceKey)
        bytes32 proofCommitment = keccak256(
            abi.encode(sourceKey, "COMMITMENT_SALT")
        );

        // proof[32:64] = expectedDerivation matching the contract formula
        bytes32 expectedDerivation = keccak256(
            abi.encodePacked(
                sourceKey,
                destChainId,
                stealthDomain,
                "CROSS_CHAIN_DERIVATION"
            )
        );

        // Pad to >= MIN_DERIVATION_PROOF_LENGTH (192 bytes)
        bytes memory proof = abi.encodePacked(
            proofCommitment,
            expectedDerivation,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );

        return proof;
    }
}
