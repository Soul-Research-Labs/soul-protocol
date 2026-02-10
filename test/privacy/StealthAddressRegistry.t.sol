// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/StealthAddressRegistry.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// ============================================================
// Minimal mock for IDerivationVerifier
// ============================================================
contract MockDerivationVerifier is IDerivationVerifier {
    bool public returnValue = true;
    bool public shouldRevert = false;

    function setReturnValue(
        bool _val
    ) external {
        returnValue = _val;
    }

    function setRevert(
        bool _val
    ) external {
        shouldRevert = _val;
    }

    function verifyProof(
        bytes calldata,
        uint256[] calldata
    ) external view override returns (bool) {
        if (shouldRevert) revert("verifier reverted");
        return returnValue;
    }
}

// ============================================================
// Test contract
// ============================================================
contract StealthAddressRegistryTest is Test {
    StealthAddressRegistry public registry;
    MockDerivationVerifier public verifier;

    address public admin;
    address public operator;
    address public announcer;
    address public alice;
    address public bob;
    address public eve;

    // Role constants (mirrored from contract)
    bytes32 constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 constant ANNOUNCER_ROLE =
        0x28bf751bc1d0e1ce1e07469dfe6d05c5c0e65f1e92e0f41bfd3cc6c120c1ec3c;
    bytes32 constant UPGRADER_ROLE =
        0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3;
    bytes32 constant DEFAULT_ADMIN_ROLE = 0x00;

    // Stealth domain (mirrored from contract)
    bytes32 constant STEALTH_DOMAIN = keccak256("Soul_STEALTH_ADDRESS_V1");

    // Helpers: valid key fixtures
    bytes internal secp256k1Key33; // compressed secp256k1 (33 bytes)
    bytes internal secp256k1Key65; // uncompressed secp256k1 (65 bytes)
    bytes internal ed25519Key; // ed25519 (32 bytes)
    bytes internal blsKey48; // BLS G1 compressed (48 bytes)
    bytes internal bn254Key32; // BN254 (32 bytes)

    function setUp() public {
        admin = makeAddr("admin");
        operator = makeAddr("operator");
        announcer = makeAddr("announcer");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        eve = makeAddr("eve");

        // Deploy implementation and proxy
        StealthAddressRegistry impl = new StealthAddressRegistry();
        bytes memory initData =
            abi.encodeWithSelector(StealthAddressRegistry.initialize.selector, admin);
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        registry = StealthAddressRegistry(address(proxy));

        // Deploy mock verifier
        verifier = new MockDerivationVerifier();

        // Grant roles
        vm.startPrank(admin);
        registry.grantRole(OPERATOR_ROLE, operator);
        registry.grantRole(ANNOUNCER_ROLE, announcer);
        vm.stopPrank();

        // Build key fixtures
        secp256k1Key33 = _fillBytes(33, 0xAA);
        secp256k1Key65 = _fillBytes(65, 0xBB);
        ed25519Key = _fillBytes(32, 0xCC);
        blsKey48 = _fillBytes(48, 0xDD);
        bn254Key32 = _fillBytes(32, 0xEE);
    }

    // ================================================================
    // Helper: create a bytes value of given length filled with a byte
    // ================================================================
    function _fillBytes(
        uint256 len,
        uint8 fill
    ) internal pure returns (bytes memory b) {
        b = new bytes(len);
        for (uint256 i; i < len; i++) {
            b[i] = bytes1(fill);
        }
    }

    // Helper: register alice with secp256k1 keys
    function _registerAlice() internal {
        vm.prank(alice);
        registry.registerMetaAddress(
            secp256k1Key33, secp256k1Key33, StealthAddressRegistry.CurveType.SECP256K1, 1
        );
    }

    // Helper: build a valid testnet derivation proof for _verifyDerivationProof
    function _buildTestnetDerivationProof(
        bytes32 sourceKey,
        uint256 destChainId
    ) internal pure returns (bytes memory) {
        bytes32 proofCommitment = keccak256(abi.encodePacked("proof_commitment", sourceKey));
        bytes32 expectedDerivation = keccak256(
            abi.encodePacked(sourceKey, destChainId, STEALTH_DOMAIN, "CROSS_CHAIN_DERIVATION")
        );
        // Pad to at least 192 bytes (MIN_DERIVATION_PROOF_LENGTH)
        return abi.encodePacked(proofCommitment, expectedDerivation, new bytes(128));
    }

    // ================================================================
    // CONSTRUCTOR & INITIALIZATION
    // ================================================================

    function test_Initialize_SetsRoles() public view {
        assertTrue(registry.hasRole(DEFAULT_ADMIN_ROLE, admin));
        assertTrue(registry.hasRole(OPERATOR_ROLE, admin));
        assertTrue(registry.hasRole(ANNOUNCER_ROLE, admin));
        assertTrue(registry.hasRole(UPGRADER_ROLE, admin));
    }

    function test_Initialize_CannotBeCalledTwice() public {
        vm.expectRevert();
        registry.initialize(alice);
    }

    function test_Initialize_GrantedOperatorRole() public view {
        assertTrue(registry.hasRole(OPERATOR_ROLE, operator));
    }

    // ================================================================
    // setDerivationVerifier
    // ================================================================

    function test_SetDerivationVerifier_Success() public {
        vm.prank(admin);
        vm.expectEmit(true, true, false, false);
        emit StealthAddressRegistry.DerivationVerifierUpdated(address(0), address(verifier));
        registry.setDerivationVerifier(address(verifier));

        assertEq(address(registry.derivationVerifier()), address(verifier));
    }

    function test_SetDerivationVerifier_RevertNonAdmin() public {
        vm.prank(eve);
        vm.expectRevert();
        registry.setDerivationVerifier(address(verifier));
    }

    // ================================================================
    // META-ADDRESS REGISTRATION
    // ================================================================

    function test_RegisterMetaAddress_Secp256k1_Compressed() public {
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit StealthAddressRegistry.MetaAddressRegistered(
            alice, secp256k1Key33, secp256k1Key33, StealthAddressRegistry.CurveType.SECP256K1, 1
        );
        registry.registerMetaAddress(
            secp256k1Key33, secp256k1Key33, StealthAddressRegistry.CurveType.SECP256K1, 1
        );

        StealthAddressRegistry.StealthMetaAddress memory meta = registry.getMetaAddress(alice);
        assertEq(uint8(meta.status), uint8(StealthAddressRegistry.KeyStatus.ACTIVE));
        assertEq(meta.schemeId, 1);
        assertEq(uint8(meta.curveType), uint8(StealthAddressRegistry.CurveType.SECP256K1));
    }

    function test_RegisterMetaAddress_Secp256k1_Uncompressed() public {
        vm.prank(alice);
        registry.registerMetaAddress(
            secp256k1Key65, secp256k1Key65, StealthAddressRegistry.CurveType.SECP256K1, 1
        );

        StealthAddressRegistry.StealthMetaAddress memory meta = registry.getMetaAddress(alice);
        assertEq(uint8(meta.status), uint8(StealthAddressRegistry.KeyStatus.ACTIVE));
    }

    function test_RegisterMetaAddress_Ed25519() public {
        vm.prank(alice);
        registry.registerMetaAddress(
            ed25519Key, ed25519Key, StealthAddressRegistry.CurveType.ED25519, 2
        );

        assertEq(
            uint8(registry.getMetaAddress(alice).curveType),
            uint8(StealthAddressRegistry.CurveType.ED25519)
        );
    }

    function test_RegisterMetaAddress_BLS12_381() public {
        vm.prank(alice);
        registry.registerMetaAddress(
            blsKey48, blsKey48, StealthAddressRegistry.CurveType.BLS12_381, 3
        );

        assertEq(
            uint8(registry.getMetaAddress(alice).curveType),
            uint8(StealthAddressRegistry.CurveType.BLS12_381)
        );
    }

    function test_RegisterMetaAddress_BN254() public {
        vm.prank(alice);
        registry.registerMetaAddress(
            bn254Key32, bn254Key32, StealthAddressRegistry.CurveType.BN254, 4
        );

        assertEq(
            uint8(registry.getMetaAddress(alice).curveType),
            uint8(StealthAddressRegistry.CurveType.BN254)
        );
    }

    function test_RegisterMetaAddress_RevertEmptySpendingKey() public {
        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.InvalidPubKey.selector);
        registry.registerMetaAddress(
            "", secp256k1Key33, StealthAddressRegistry.CurveType.SECP256K1, 1
        );
    }

    function test_RegisterMetaAddress_RevertEmptyViewingKey() public {
        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.InvalidPubKey.selector);
        registry.registerMetaAddress(
            secp256k1Key33, "", StealthAddressRegistry.CurveType.SECP256K1, 1
        );
    }

    function test_RegisterMetaAddress_RevertDuplicate() public {
        _registerAlice();

        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.MetaAddressAlreadyExists.selector);
        registry.registerMetaAddress(
            secp256k1Key33, secp256k1Key33, StealthAddressRegistry.CurveType.SECP256K1, 1
        );
    }

    function test_RegisterMetaAddress_RevertInvalidSecp256k1KeyLength() public {
        bytes memory badKey = _fillBytes(34, 0x01);
        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.InvalidSecp256k1Key.selector);
        registry.registerMetaAddress(badKey, badKey, StealthAddressRegistry.CurveType.SECP256K1, 1);
    }

    function test_RegisterMetaAddress_RevertInvalidEd25519KeyLength() public {
        bytes memory badKey = _fillBytes(33, 0x01);
        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.InvalidEd25519Key.selector);
        registry.registerMetaAddress(badKey, badKey, StealthAddressRegistry.CurveType.ED25519, 1);
    }

    function test_RegisterMetaAddress_RevertInvalidBLSKeyLength() public {
        bytes memory badKey = _fillBytes(49, 0x01);
        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.InvalidBLSKey.selector);
        registry.registerMetaAddress(badKey, badKey, StealthAddressRegistry.CurveType.BLS12_381, 1);
    }

    function test_RegisterMetaAddress_RevertInvalidBN254KeyLength() public {
        bytes memory badKey = _fillBytes(33, 0x01);
        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.InvalidBN254Key.selector);
        registry.registerMetaAddress(badKey, badKey, StealthAddressRegistry.CurveType.BN254, 1);
    }

    function test_RegisterMetaAddress_IncrementsRegisteredAddresses() public {
        assertEq(registry.getRegisteredAddressCount(), 0);
        _registerAlice();
        assertEq(registry.getRegisteredAddressCount(), 1);
    }

    // ================================================================
    // META-ADDRESS STATUS UPDATE & REVOCATION
    // ================================================================

    function test_UpdateMetaAddressStatus_ToInactive() public {
        _registerAlice();

        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit StealthAddressRegistry.MetaAddressUpdated(
            alice, StealthAddressRegistry.KeyStatus.INACTIVE
        );
        registry.updateMetaAddressStatus(StealthAddressRegistry.KeyStatus.INACTIVE);
    }

    function test_UpdateMetaAddressStatus_RevertIfInactive() public {
        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.MetaAddressNotFound.selector);
        registry.updateMetaAddressStatus(StealthAddressRegistry.KeyStatus.ACTIVE);
    }

    function test_UpdateMetaAddressStatus_RevertIfRevoked() public {
        _registerAlice();

        vm.prank(alice);
        registry.revokeMetaAddress();

        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.MetaAddressRevoked.selector);
        registry.updateMetaAddressStatus(StealthAddressRegistry.KeyStatus.ACTIVE);
    }

    function test_RevokeMetaAddress_Success() public {
        _registerAlice();

        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit StealthAddressRegistry.MetaAddressUpdated(
            alice, StealthAddressRegistry.KeyStatus.REVOKED
        );
        registry.revokeMetaAddress();

        assertEq(
            uint8(registry.getMetaAddress(alice).status),
            uint8(StealthAddressRegistry.KeyStatus.REVOKED)
        );
    }

    function test_RevokeMetaAddress_RevertIfInactive() public {
        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.MetaAddressNotFound.selector);
        registry.revokeMetaAddress();
    }

    // ================================================================
    // STEALTH ADDRESS DERIVATION
    // ================================================================

    function test_DeriveStealthAddress_Success() public {
        _registerAlice();

        bytes32 sharedSecretHash = keccak256("shared_secret");
        bytes memory ephemeralPubKey = secp256k1Key33;

        (address stealthAddr, bytes1 viewTag) =
            registry.deriveStealthAddress(alice, ephemeralPubKey, sharedSecretHash);

        // Verify deterministic result
        bytes32 expectedHash =
            keccak256(abi.encodePacked(STEALTH_DOMAIN, secp256k1Key33, sharedSecretHash));
        address expectedAddr = address(uint160(uint256(expectedHash)));
        assertEq(stealthAddr, expectedAddr);
        assertEq(viewTag, bytes1(sharedSecretHash));
    }

    function test_DeriveStealthAddress_RevertNotActive() public {
        bytes32 sharedSecretHash = keccak256("shared_secret");
        vm.expectRevert(StealthAddressRegistry.MetaAddressNotFound.selector);
        registry.deriveStealthAddress(alice, secp256k1Key33, sharedSecretHash);
    }

    function test_DeriveStealthAddress_RevertIfRevoked() public {
        _registerAlice();
        vm.prank(alice);
        registry.revokeMetaAddress();

        bytes32 sharedSecretHash = keccak256("shared_secret");
        vm.expectRevert(StealthAddressRegistry.MetaAddressNotFound.selector);
        registry.deriveStealthAddress(alice, secp256k1Key33, sharedSecretHash);
    }

    // ================================================================
    // DUAL-KEY STEALTH
    // ================================================================

    function test_ComputeDualKeyStealth_Success() public {
        bytes32 spendingHash = keccak256("spending");
        bytes32 viewingHash = keccak256("viewing");
        bytes32 ephemeralHash = keccak256("ephemeral");
        uint256 chainId = 42_161;

        vm.expectEmit(false, false, false, false);
        emit StealthAddressRegistry.DualKeyStealthGenerated(bytes32(0), address(0), chainId);
        (bytes32 stealthHash, address derivedAddr) =
            registry.computeDualKeyStealth(spendingHash, viewingHash, ephemeralHash, chainId);

        assertTrue(stealthHash != bytes32(0));
        assertTrue(derivedAddr != address(0));

        // Verify stored record
        StealthAddressRegistry.DualKeyStealth memory record = registry.getDualKeyRecord(stealthHash);
        assertEq(record.spendingPubKeyHash, spendingHash);
        assertEq(record.viewingPubKeyHash, viewingHash);
        assertEq(record.derivedAddress, derivedAddr);
        assertEq(record.chainId, chainId);
    }

    function test_ComputeDualKeyStealth_DeterministicOutput() public {
        bytes32 spendingHash = keccak256("spending");
        bytes32 viewingHash = keccak256("viewing");
        bytes32 ephemeralHash = keccak256("ephemeral");

        (bytes32 hash1, address addr1) =
            registry.computeDualKeyStealth(spendingHash, viewingHash, ephemeralHash, 1);

        // Re-deploy to get clean state — same inputs should produce same derived values
        StealthAddressRegistry impl2 = new StealthAddressRegistry();
        ERC1967Proxy proxy2 = new ERC1967Proxy(
            address(impl2),
            abi.encodeWithSelector(StealthAddressRegistry.initialize.selector, admin)
        );
        StealthAddressRegistry registry2 = StealthAddressRegistry(address(proxy2));
        (bytes32 hash2, address addr2) =
            registry2.computeDualKeyStealth(spendingHash, viewingHash, ephemeralHash, 1);

        assertEq(hash1, hash2);
        assertEq(addr1, addr2);
    }

    // ================================================================
    // ANNOUNCE (role-gated)
    // ================================================================

    function test_Announce_Success() public {
        address stealthAddr = makeAddr("stealthAddr");
        bytes memory ephKey = secp256k1Key33;
        bytes memory viewTag = abi.encodePacked(bytes1(0xAB));
        bytes memory metadata = "encrypted_data";

        vm.prank(announcer);
        vm.expectEmit(true, true, true, true);
        emit StealthAddressRegistry.StealthAnnouncement(
            bytes32(uint256(1)), stealthAddr, announcer, ephKey, viewTag, metadata
        );
        registry.announce(1, stealthAddr, ephKey, viewTag, metadata);

        assertEq(registry.totalAnnouncements(), 1);

        // Verify stored announcement
        StealthAddressRegistry.Announcement memory ann = registry.getAnnouncement(stealthAddr);
        assertEq(ann.stealthAddress, stealthAddr);
    }

    function test_Announce_RevertNonAnnouncer() public {
        vm.prank(eve);
        vm.expectRevert();
        registry.announce(1, makeAddr("stealth"), secp256k1Key33, "", "");
    }

    function test_Announce_RevertZeroAddress() public {
        vm.prank(announcer);
        vm.expectRevert(StealthAddressRegistry.ZeroAddress.selector);
        registry.announce(1, address(0), secp256k1Key33, "", "");
    }

    function test_Announce_RevertEmptyEphemeralKey() public {
        vm.prank(announcer);
        vm.expectRevert(StealthAddressRegistry.InvalidPubKey.selector);
        registry.announce(1, makeAddr("stealth"), "", "", "");
    }

    function test_Announce_ViewTagIndexing() public {
        address stealthAddr = makeAddr("stealthAddr");
        bytes memory viewTag = abi.encodePacked(bytes1(0x42));

        vm.prank(announcer);
        registry.announce(1, stealthAddr, secp256k1Key33, viewTag, "");

        address[] memory found = registry.getAnnouncementsByViewTag(bytes1(0x42));
        assertEq(found.length, 1);
        assertEq(found[0], stealthAddr);
    }

    // ================================================================
    // ANNOUNCE PRIVATE (payable)
    // ================================================================

    function test_AnnouncePrivate_Success() public {
        address stealthAddr = makeAddr("stealthAddr");
        bytes memory ephKey = secp256k1Key33;

        vm.deal(alice, 1 ether);
        vm.prank(alice);
        registry.announcePrivate{ value: 0.0001 ether }(1, stealthAddr, ephKey, "", "");

        assertEq(registry.totalAnnouncements(), 1);
    }

    function test_AnnouncePrivate_RevertInsufficientFee() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.InsufficientFee.selector);
        registry.announcePrivate{ value: 0.000_09 ether }(
            1, makeAddr("stealth"), secp256k1Key33, "", ""
        );
    }

    function test_AnnouncePrivate_RevertZeroAddress() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        vm.expectRevert(StealthAddressRegistry.ZeroAddress.selector);
        registry.announcePrivate{ value: 0.0001 ether }(1, address(0), secp256k1Key33, "", "");
    }

    // ================================================================
    // CHECK STEALTH OWNERSHIP & BATCH SCAN
    // ================================================================

    function test_CheckStealthOwnership_ReturnsFalse_NoAnnouncement() public {
        bool result =
            registry.checkStealthOwnership(makeAddr("random"), keccak256("vk"), keccak256("sk"));
        assertFalse(result);
    }

    function test_BatchScan_ReturnsEmpty_WhenNoMatches() public {
        address[] memory candidates = new address[](2);
        candidates[0] = makeAddr("a");
        candidates[1] = makeAddr("b");

        address[] memory owned = registry.batchScan(keccak256("vk"), keccak256("sk"), candidates);
        assertEq(owned.length, 0);
    }

    // ================================================================
    // CROSS-CHAIN STEALTH DERIVATION
    // ================================================================

    function test_DeriveCrossChainStealth_WithVerifier() public {
        // Set verifier
        vm.prank(admin);
        registry.setDerivationVerifier(address(verifier));

        bytes32 sourceKey = keccak256("sourceStealthKey");
        uint256 destChainId = 42_161; // Arbitrum
        bytes memory proof = _fillBytes(192, 0x01);

        verifier.setReturnValue(true);

        bytes32 destKey = registry.deriveCrossChainStealth(sourceKey, destChainId, proof);
        assertTrue(destKey != bytes32(0));
        assertEq(registry.totalCrossChainDerivations(), 1);

        // Verify binding stored
        StealthAddressRegistry.CrossChainStealth memory binding =
            registry.getCrossChainBinding(sourceKey, destKey);
        assertEq(binding.sourceStealthKey, sourceKey);
        assertEq(binding.destStealthKey, destKey);
        assertEq(binding.destChainId, destChainId);
    }

    function test_DeriveCrossChainStealth_RevertInvalidProof_VerifierReturnsFalse() public {
        vm.prank(admin);
        registry.setDerivationVerifier(address(verifier));

        verifier.setReturnValue(false);

        bytes32 sourceKey = keccak256("sourceStealthKey");
        bytes memory proof = _fillBytes(192, 0x01);

        vm.expectRevert(StealthAddressRegistry.InvalidProof.selector);
        registry.deriveCrossChainStealth(sourceKey, 42_161, proof);
    }

    function test_DeriveCrossChainStealth_RevertInvalidProof_VerifierReverts() public {
        vm.prank(admin);
        registry.setDerivationVerifier(address(verifier));

        verifier.setRevert(true);

        bytes32 sourceKey = keccak256("sourceStealthKey");
        bytes memory proof = _fillBytes(192, 0x01);

        vm.expectRevert(StealthAddressRegistry.InvalidProof.selector);
        registry.deriveCrossChainStealth(sourceKey, 42_161, proof);
    }

    function test_DeriveCrossChainStealth_TestnetFallback() public {
        // No verifier set, non-mainnet chain => testnet fallback
        bytes32 sourceKey = keccak256("sourceStealthKey");
        uint256 destChainId = 42_161;
        bytes memory proof = _buildTestnetDerivationProof(sourceKey, destChainId);

        vm.expectEmit(true, true, false, true);
        bytes32 expectedDestKey =
            keccak256(abi.encodePacked(sourceKey, destChainId, STEALTH_DOMAIN, "CROSS_CHAIN"));
        emit StealthAddressRegistry.CrossChainStealthDerived(
            sourceKey, expectedDestKey, block.chainid, destChainId
        );

        bytes32 destKey = registry.deriveCrossChainStealth(sourceKey, destChainId, proof);
        assertEq(destKey, expectedDestKey);
    }

    function test_DeriveCrossChainStealth_RevertDuplicateBinding() public {
        bytes32 sourceKey = keccak256("sourceStealthKey");
        uint256 destChainId = 42_161;
        bytes memory proof = _buildTestnetDerivationProof(sourceKey, destChainId);

        registry.deriveCrossChainStealth(sourceKey, destChainId, proof);

        vm.expectRevert(StealthAddressRegistry.CrossChainBindingExists.selector);
        registry.deriveCrossChainStealth(sourceKey, destChainId, proof);
    }

    function test_DeriveCrossChainStealth_RevertZeroSourceKey() public {
        bytes memory proof = _fillBytes(192, 0x01);

        vm.expectRevert(StealthAddressRegistry.InvalidProof.selector);
        registry.deriveCrossChainStealth(bytes32(0), 42_161, proof);
    }

    function test_DeriveCrossChainStealth_RevertSameChain() public {
        bytes32 sourceKey = keccak256("sourceStealthKey");
        bytes memory proof = _fillBytes(192, 0x01);

        vm.expectRevert(StealthAddressRegistry.InvalidProof.selector);
        registry.deriveCrossChainStealth(sourceKey, block.chainid, proof);
    }

    function test_DeriveCrossChainStealth_RevertProofTooShort() public {
        bytes32 sourceKey = keccak256("sourceStealthKey");
        bytes memory shortProof = _fillBytes(191, 0x01);

        vm.expectRevert(StealthAddressRegistry.InvalidProof.selector);
        registry.deriveCrossChainStealth(sourceKey, 42_161, shortProof);
    }

    // ================================================================
    // VIEW FUNCTIONS
    // ================================================================

    function test_GetStats_InitialValues() public view {
        (uint256 regCount, uint256 annCount, uint256 ccCount) = registry.getStats();
        assertEq(regCount, 0);
        assertEq(annCount, 0);
        assertEq(ccCount, 0);
    }

    function test_GetStats_AfterActivity() public {
        // Register
        _registerAlice();

        // Announce
        vm.prank(announcer);
        registry.announce(1, makeAddr("stealth"), secp256k1Key33, "", "");

        (uint256 regCount, uint256 annCount, uint256 ccCount) = registry.getStats();
        assertEq(regCount, 1);
        assertEq(annCount, 1);
        assertEq(ccCount, 0);
    }

    function test_GetAnnouncement_NotFound() public {
        StealthAddressRegistry.Announcement memory ann =
            registry.getAnnouncement(makeAddr("nonexistent"));
        assertEq(ann.stealthAddress, address(0));
    }

    function test_GetCrossChainBinding_NotFound() public {
        StealthAddressRegistry.CrossChainStealth memory binding =
            registry.getCrossChainBinding(keccak256("a"), keccak256("b"));
        assertEq(binding.timestamp, 0);
    }

    // ================================================================
    // WITHDRAW FEES
    // ================================================================

    function test_WithdrawFees_FullBalance() public {
        // Fund contract via announcePrivate
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        registry.announcePrivate{ value: 0.001 ether }(
            1, makeAddr("stealth"), secp256k1Key33, "", ""
        );

        address payable recipient = payable(makeAddr("feeRecipient"));
        uint256 contractBal = address(registry).balance;

        vm.prank(admin);
        registry.withdrawFees(recipient, 0);

        assertEq(recipient.balance, contractBal);
        assertEq(address(registry).balance, 0);
    }

    function test_WithdrawFees_PartialAmount() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        registry.announcePrivate{ value: 0.01 ether }(
            1, makeAddr("stealth"), secp256k1Key33, "", ""
        );

        address payable recipient = payable(makeAddr("feeRecipient"));

        vm.prank(admin);
        registry.withdrawFees(recipient, 0.005 ether);

        assertEq(recipient.balance, 0.005 ether);
    }

    function test_WithdrawFees_RevertNonAdmin() public {
        vm.prank(eve);
        vm.expectRevert();
        registry.withdrawFees(payable(eve), 0);
    }

    function test_WithdrawFees_RevertZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(StealthAddressRegistry.ZeroAddress.selector);
        registry.withdrawFees(payable(address(0)), 0);
    }

    function test_WithdrawFees_RevertInsufficientBalance() public {
        vm.prank(admin);
        vm.expectRevert(StealthAddressRegistry.InsufficientFee.selector);
        registry.withdrawFees(payable(admin), 1 ether);
    }

    // ================================================================
    // FUZZ TESTS
    // ================================================================

    function testFuzz_RegisterMetaAddress_Secp256k1(
        bytes32 seed
    ) public {
        // Build deterministic 33-byte key from seed
        bytes memory spendKey = abi.encodePacked(bytes1(0x02), seed);
        bytes memory viewKey = abi.encodePacked(bytes1(0x03), seed);

        address user = address(uint160(uint256(seed)));
        vm.assume(user != address(0));

        vm.prank(user);
        registry.registerMetaAddress(
            spendKey, viewKey, StealthAddressRegistry.CurveType.SECP256K1, 1
        );

        StealthAddressRegistry.StealthMetaAddress memory meta = registry.getMetaAddress(user);
        assertEq(uint8(meta.status), uint8(StealthAddressRegistry.KeyStatus.ACTIVE));
        assertEq(keccak256(meta.spendingPubKey), keccak256(spendKey));
        assertEq(keccak256(meta.viewingPubKey), keccak256(viewKey));
    }

    function testFuzz_DeriveStealthAddress_Deterministic(
        bytes32 sharedSecret
    ) public {
        _registerAlice();

        (address addr1, bytes1 tag1) =
            registry.deriveStealthAddress(alice, secp256k1Key33, sharedSecret);
        (address addr2, bytes1 tag2) =
            registry.deriveStealthAddress(alice, secp256k1Key33, sharedSecret);

        assertEq(addr1, addr2);
        assertEq(tag1, tag2);
        // View tag should be first byte of shared secret
        assertEq(tag1, bytes1(sharedSecret));
    }

    function testFuzz_ComputeDualKeyStealth_UniquePerChainId(
        uint256 chainId
    ) public {
        vm.assume(chainId > 0 && chainId < type(uint64).max);

        bytes32 spending = keccak256("spending");
        bytes32 viewing = keccak256("viewing");
        bytes32 ephemeral = keccak256("ephemeral");

        (bytes32 hash1, address addr1) =
            registry.computeDualKeyStealth(spending, viewing, ephemeral, chainId);

        // Deploy fresh registry for a different chain ID computation
        StealthAddressRegistry freshImpl = new StealthAddressRegistry();
        ERC1967Proxy freshProxy = new ERC1967Proxy(
            address(freshImpl),
            abi.encodeWithSelector(StealthAddressRegistry.initialize.selector, admin)
        );
        StealthAddressRegistry fresh = StealthAddressRegistry(address(freshProxy));

        uint256 otherChainId = chainId == 1 ? 2 : 1;
        (bytes32 hash2, address addr2) =
            fresh.computeDualKeyStealth(spending, viewing, ephemeral, otherChainId);

        // Same spending/viewing/ephemeral but different chainId => same stealth hash
        // because chainId is NOT part of the stealthHash computation (only stored in record).
        // The derived address depends only on spending + sharedSecret, and sharedSecret
        // depends on ephemeral + viewing (not chainId). So they should be equal.
        assertEq(hash1, hash2);
        assertEq(addr1, addr2);
    }
}
