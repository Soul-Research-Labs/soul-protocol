// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PQCStealthIntegration} from "../../contracts/experimental/privacy/PQCStealthIntegration.sol";
import {IPQCVerifier} from "../../contracts/interfaces/IPQCVerifier.sol";

/**
 * @title PQCStealthIntegrationTest
 * @notice Tests for PQC stealth address integration
 */
contract PQCStealthIntegrationTest is Test {
    PQCStealthIntegration public integration;

    address public admin;
    address public user1;
    address public user2;

    // Key sizes for test fixtures
    uint256 constant FN_DSA_512_PK_SIZE = 897;
    uint256 constant ML_KEM_768_PK_SIZE = 1184;
    uint256 constant ML_KEM_768_CT_SIZE = 1088;
    uint256 constant ML_KEM_512_PK_SIZE = 800;
    uint256 constant ML_KEM_512_CT_SIZE = 768;
    uint256 constant ML_KEM_1024_PK_SIZE = 1568;
    uint256 constant ML_KEM_1024_CT_SIZE = 1568;
    uint256 constant ML_DSA_44_PK_SIZE = 1312;
    uint256 constant ML_DSA_65_PK_SIZE = 1952;
    uint256 constant ML_DSA_87_PK_SIZE = 2592;
    uint256 constant SLH_DSA_128S_PK_SIZE = 32;
    uint256 constant SLH_DSA_128F_PK_SIZE = 32;
    uint256 constant SLH_DSA_256S_PK_SIZE = 64;
    uint256 constant FN_DSA_1024_PK_SIZE = 1793;

    function setUp() public {
        admin = makeAddr("admin");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");

        vm.prank(admin);
        integration = new PQCStealthIntegration(
            admin,
            address(0x1234),
            address(0x5678)
        );
    }

    /*//////////////////////////////////////////////////////////////
                           DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    function test_Deployment() public view {
        assertTrue(
            integration.hasRole(integration.DEFAULT_ADMIN_ROLE(), admin)
        );
        assertTrue(integration.hasRole(integration.OPERATOR_ROLE(), admin));
        assertTrue(integration.hasRole(integration.PAUSER_ROLE(), admin));
        assertEq(integration.hybridPQCVerifier(), address(0x1234));
        assertEq(integration.stealthRegistry(), address(0x5678));
        assertEq(integration.totalPQCMetaAddresses(), 0);
        assertEq(integration.totalPQCAnnouncements(), 0);
    }

    function test_RevertZeroAdmin() public {
        vm.expectRevert(PQCStealthIntegration.ZeroAddress.selector);
        new PQCStealthIntegration(address(0), address(0x1234), address(0x5678));
    }

    /*//////////////////////////////////////////////////////////////
                  PQC META-ADDRESS REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterPQCMetaAddress_Falcon512_KEM768() public {
        bytes memory spendingKey = _generateBytes(FN_DSA_512_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        assertEq(integration.totalPQCMetaAddresses(), 1);

        PQCStealthIntegration.PQCStealthMeta memory meta = integration
            .getPQCMetaAddress(user1);
        assertTrue(meta.active);
        assertEq(
            uint8(meta.sigAlgorithm),
            uint8(IPQCVerifier.PQCAlgorithm.FN_DSA_512)
        );
        assertEq(
            uint8(meta.kemVariant),
            uint8(PQCStealthIntegration.KEMVariant.ML_KEM_768)
        );
        assertEq(meta.registeredAt, block.timestamp);
    }

    function test_RegisterPQCMetaAddress_Dilithium44_KEM512() public {
        bytes memory spendingKey = _generateBytes(ML_DSA_44_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_512_PK_SIZE);

        vm.prank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.ML_DSA_44,
            PQCStealthIntegration.KEMVariant.ML_KEM_512
        );

        assertEq(integration.totalPQCMetaAddresses(), 1);
    }

    function test_RegisterPQCMetaAddress_Dilithium65_KEM1024() public {
        bytes memory spendingKey = _generateBytes(ML_DSA_65_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_1024_PK_SIZE);

        vm.prank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.ML_DSA_65,
            PQCStealthIntegration.KEMVariant.ML_KEM_1024
        );

        assertEq(integration.totalPQCMetaAddresses(), 1);
    }

    function test_RegisterPQCMetaAddress_Dilithium87() public {
        bytes memory spendingKey = _generateBytes(ML_DSA_87_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.ML_DSA_87,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        assertEq(integration.totalPQCMetaAddresses(), 1);
    }

    function test_RegisterPQCMetaAddress_Falcon1024() public {
        bytes memory spendingKey = _generateBytes(FN_DSA_1024_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.FN_DSA_1024,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        assertEq(integration.totalPQCMetaAddresses(), 1);
    }

    function test_RegisterPQCMetaAddress_SPHINCS_128s() public {
        bytes memory spendingKey = _generateBytes(SLH_DSA_128S_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.SLH_DSA_128S,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        assertEq(integration.totalPQCMetaAddresses(), 1);
    }

    function test_RegisterPQCMetaAddress_SPHINCS_128f() public {
        bytes memory spendingKey = _generateBytes(SLH_DSA_128F_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.SLH_DSA_128F,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        assertEq(integration.totalPQCMetaAddresses(), 1);
    }

    function test_RegisterPQCMetaAddress_SPHINCS_256s() public {
        bytes memory spendingKey = _generateBytes(SLH_DSA_256S_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.SLH_DSA_256S,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        assertEq(integration.totalPQCMetaAddresses(), 1);
    }

    function test_RevertDuplicateRegistration() public {
        bytes memory spendingKey = _generateBytes(FN_DSA_512_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.startPrank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                PQCStealthIntegration.PQCMetaAddressAlreadyExists.selector,
                user1
            )
        );
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
        vm.stopPrank();
    }

    function test_RevertKEMAsSignatureAlgorithm() public {
        bytes memory spendingKey = _generateBytes(800);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        vm.expectRevert(PQCStealthIntegration.SignatureAlgorithmIsKEM.selector);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.ML_KEM_512,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
    }

    function test_RevertInvalidSpendingKeySize() public {
        bytes memory spendingKey = _generateBytes(100); // wrong size
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQCStealthIntegration.InvalidPQCSpendingKeySize.selector,
                IPQCVerifier.PQCAlgorithm.FN_DSA_512,
                100
            )
        );
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
    }

    function test_RevertInvalidViewingKeySize() public {
        bytes memory spendingKey = _generateBytes(FN_DSA_512_PK_SIZE);
        bytes memory viewingKey = _generateBytes(100); // wrong size

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQCStealthIntegration.InvalidPQCViewingKeySize.selector,
                PQCStealthIntegration.KEMVariant.ML_KEM_768,
                100
            )
        );
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
    }

    /*//////////////////////////////////////////////////////////////
                     META-ADDRESS REVOCATION
    //////////////////////////////////////////////////////////////*/

    function test_RevokePQCMetaAddress() public {
        _registerUser1MetaAddress();

        vm.prank(user1);
        integration.revokePQCMetaAddress();

        PQCStealthIntegration.PQCStealthMeta memory meta = integration
            .getPQCMetaAddress(user1);
        assertFalse(meta.active);
    }

    function test_RevertRevokeNonExistent() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQCStealthIntegration.PQCMetaAddressNotFound.selector,
                user1
            )
        );
        integration.revokePQCMetaAddress();
    }

    /*//////////////////////////////////////////////////////////////
                   PQC STEALTH ANNOUNCEMENTS
    //////////////////////////////////////////////////////////////*/

    function test_AnnouncePQCStealth() public {
        address stealthAddr = makeAddr("stealth");
        bytes32 schemeId = keccak256("pqc-stealth-v1");
        bytes memory kemCiphertext = _generateBytes(ML_KEM_768_CT_SIZE);
        bytes memory viewTag = hex"ab";
        bytes memory metadata = hex"";

        vm.prank(user1);
        integration.announcePQCStealth(
            schemeId,
            stealthAddr,
            kemCiphertext,
            viewTag,
            metadata,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        assertEq(integration.totalPQCAnnouncements(), 1);

        PQCStealthIntegration.PQCAnnouncement memory ann = integration
            .getPQCAnnouncement(stealthAddr);
        assertEq(ann.schemeId, schemeId);
        assertEq(ann.stealthAddress, stealthAddr);
        assertEq(ann.timestamp, block.timestamp);
        assertEq(ann.chainId, block.chainid);
    }

    function test_AnnouncePQCStealth_KEM512() public {
        address stealthAddr = makeAddr("stealth512");
        bytes memory kemCiphertext = _generateBytes(ML_KEM_512_CT_SIZE);

        vm.prank(user1);
        integration.announcePQCStealth(
            keccak256("scheme"),
            stealthAddr,
            kemCiphertext,
            hex"",
            hex"",
            PQCStealthIntegration.KEMVariant.ML_KEM_512
        );

        assertEq(integration.totalPQCAnnouncements(), 1);
    }

    function test_AnnouncePQCStealth_KEM1024() public {
        address stealthAddr = makeAddr("stealth1024");
        bytes memory kemCiphertext = _generateBytes(ML_KEM_1024_CT_SIZE);

        vm.prank(user1);
        integration.announcePQCStealth(
            keccak256("scheme"),
            stealthAddr,
            kemCiphertext,
            hex"",
            hex"",
            PQCStealthIntegration.KEMVariant.ML_KEM_1024
        );

        assertEq(integration.totalPQCAnnouncements(), 1);
    }

    function test_RevertAnnouncementInvalidCiphertextSize() public {
        address stealthAddr = makeAddr("stealth");
        bytes memory kemCiphertext = _generateBytes(100); // wrong size

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQCStealthIntegration.InvalidKEMCiphertextSize.selector,
                PQCStealthIntegration.KEMVariant.ML_KEM_768,
                ML_KEM_768_CT_SIZE,
                100
            )
        );
        integration.announcePQCStealth(
            keccak256("scheme"),
            stealthAddr,
            kemCiphertext,
            hex"",
            hex"",
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
    }

    function test_RevertAnnouncementZeroAddress() public {
        bytes memory kemCiphertext = _generateBytes(ML_KEM_768_CT_SIZE);

        vm.prank(user1);
        vm.expectRevert(PQCStealthIntegration.ZeroAddress.selector);
        integration.announcePQCStealth(
            keccak256("scheme"),
            address(0),
            kemCiphertext,
            hex"",
            hex"",
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
    }

    function test_ViewTagIndex() public {
        address stealth1 = makeAddr("stealth1");
        address stealth2 = makeAddr("stealth2");
        bytes memory ct = _generateBytes(ML_KEM_768_CT_SIZE);

        vm.startPrank(user1);
        integration.announcePQCStealth(
            keccak256("scheme"),
            stealth1,
            ct,
            hex"ab",
            hex"",
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
        integration.announcePQCStealth(
            keccak256("scheme"),
            stealth2,
            ct,
            hex"ab",
            hex"",
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
        vm.stopPrank();

        address[] memory results = integration.getPQCAnnouncementsByViewTag(
            0xab
        );
        assertEq(results.length, 2);
        assertEq(results[0], stealth1);
        assertEq(results[1], stealth2);
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN PQC STEALTH
    //////////////////////////////////////////////////////////////*/

    function test_DerivePQCCrossChainStealth() public {
        bytes32 sourceKey = keccak256("sourceStealthKey");
        uint256 destChainId = 42161; // Arbitrum
        bytes memory kemCiphertext = _generateBytes(ML_KEM_768_CT_SIZE);
        bytes memory derivationProof = _generateBytes(128);

        vm.prank(user1);
        bytes32 destKey = integration.derivePQCCrossChainStealth(
            sourceKey,
            destChainId,
            kemCiphertext,
            derivationProof,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        assertTrue(destKey != bytes32(0));
        assertEq(integration.totalPQCCrossChainDerivations(), 1);
    }

    function test_RevertCrossChainDuplicateBinding() public {
        bytes32 sourceKey = keccak256("sourceStealthKey");
        uint256 destChainId = 42161;
        bytes memory kemCiphertext = _generateBytes(ML_KEM_768_CT_SIZE);
        bytes memory derivationProof = _generateBytes(128);

        vm.startPrank(user1);

        integration.derivePQCCrossChainStealth(
            sourceKey,
            destChainId,
            kemCiphertext,
            derivationProof,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        vm.expectRevert(PQCStealthIntegration.CrossChainBindingExists.selector);
        integration.derivePQCCrossChainStealth(
            sourceKey,
            destChainId,
            kemCiphertext,
            derivationProof,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
        vm.stopPrank();
    }

    function test_RevertCrossChainZeroSourceKey() public {
        vm.prank(user1);
        vm.expectRevert(
            PQCStealthIntegration.InvalidStealthDerivation.selector
        );
        integration.derivePQCCrossChainStealth(
            bytes32(0),
            42161,
            _generateBytes(ML_KEM_768_CT_SIZE),
            _generateBytes(128),
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
    }

    function test_RevertCrossChainSameChain() public {
        vm.prank(user1);
        vm.expectRevert(
            PQCStealthIntegration.InvalidStealthDerivation.selector
        );
        integration.derivePQCCrossChainStealth(
            keccak256("key"),
            block.chainid,
            _generateBytes(ML_KEM_768_CT_SIZE),
            _generateBytes(128),
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
    }

    function test_RevertCrossChainShortProof() public {
        vm.prank(user1);
        vm.expectRevert(
            PQCStealthIntegration.InvalidStealthDerivation.selector
        );
        integration.derivePQCCrossChainStealth(
            keccak256("key"),
            42161,
            _generateBytes(ML_KEM_768_CT_SIZE),
            _generateBytes(32),
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
    }

    /*//////////////////////////////////////////////////////////////
                       ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_SetHybridPQCVerifier() public {
        address newVerifier = makeAddr("newVerifier");

        vm.prank(admin);
        integration.setHybridPQCVerifier(newVerifier);

        assertEq(integration.hybridPQCVerifier(), newVerifier);
    }

    function test_SetStealthRegistry() public {
        address newRegistry = makeAddr("newRegistry");

        vm.prank(admin);
        integration.setStealthRegistry(newRegistry);

        assertEq(integration.stealthRegistry(), newRegistry);
    }

    function test_RevertSetVerifierZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(PQCStealthIntegration.ZeroAddress.selector);
        integration.setHybridPQCVerifier(address(0));
    }

    function test_RevertSetRegistryZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(PQCStealthIntegration.ZeroAddress.selector);
        integration.setStealthRegistry(address(0));
    }

    function test_PauseUnpause() public {
        vm.startPrank(admin);
        integration.pause();
        assertTrue(integration.paused());

        integration.unpause();
        assertFalse(integration.paused());
        vm.stopPrank();
    }

    function test_RevertWhenPaused() public {
        vm.prank(admin);
        integration.pause();

        bytes memory spendingKey = _generateBytes(FN_DSA_512_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        vm.expectRevert();
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
    }

    /*//////////////////////////////////////////////////////////////
                          STATS
    //////////////////////////////////////////////////////////////*/

    function test_GetStats() public {
        _registerUser1MetaAddress();

        (uint256 metaCount, uint256 annCount, uint256 ccCount) = integration
            .getStats();
        assertEq(metaCount, 1);
        assertEq(annCount, 0);
        assertEq(ccCount, 0);
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_RegisterAndRevoke(uint8 algoIdx) public {
        // Bound to valid signature algorithms (0-7)
        uint8 boundedAlgo = uint8(bound(algoIdx, 0, 7));
        IPQCVerifier.PQCAlgorithm algo = IPQCVerifier.PQCAlgorithm(boundedAlgo);

        uint256 keySize = _getExpectedSpendingKeySize(algo);
        bytes memory spendingKey = _generateBytes(keySize);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.startPrank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            algo,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );

        PQCStealthIntegration.PQCStealthMeta memory meta = integration
            .getPQCMetaAddress(user1);
        assertTrue(meta.active);

        integration.revokePQCMetaAddress();
        meta = integration.getPQCMetaAddress(user1);
        assertFalse(meta.active);
        vm.stopPrank();
    }

    function testFuzz_AnnouncementCiphertextSize(uint8 kemIdx) public {
        uint8 bounded = uint8(bound(kemIdx, 0, 2));
        PQCStealthIntegration.KEMVariant variant = PQCStealthIntegration
            .KEMVariant(bounded);

        uint256 ctSize;
        if (bounded == 0) ctSize = ML_KEM_512_CT_SIZE;
        else if (bounded == 1) ctSize = ML_KEM_768_CT_SIZE;
        else ctSize = ML_KEM_1024_CT_SIZE;

        bytes memory ct = _generateBytes(ctSize);
        address stealthAddr = address(
            uint160(uint256(keccak256(abi.encode(kemIdx))))
        );

        vm.prank(user1);
        integration.announcePQCStealth(
            keccak256("scheme"),
            stealthAddr,
            ct,
            hex"ff",
            hex"",
            variant
        );

        assertEq(integration.totalPQCAnnouncements(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                          HELPERS
    //////////////////////////////////////////////////////////////*/

    function _registerUser1MetaAddress() internal {
        bytes memory spendingKey = _generateBytes(FN_DSA_512_PK_SIZE);
        bytes memory viewingKey = _generateBytes(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        integration.registerPQCMetaAddress(
            spendingKey,
            viewingKey,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            PQCStealthIntegration.KEMVariant.ML_KEM_768
        );
    }

    function _generateBytes(uint256 size) internal pure returns (bytes memory) {
        bytes memory data = new bytes(size);
        for (uint256 i = 0; i < size; i++) {
            data[i] = bytes1(uint8((i * 7 + 13) % 256));
        }
        return data;
    }

    function _getExpectedSpendingKeySize(
        IPQCVerifier.PQCAlgorithm algo
    ) internal pure returns (uint256) {
        if (algo == IPQCVerifier.PQCAlgorithm.FN_DSA_512)
            return FN_DSA_512_PK_SIZE;
        if (algo == IPQCVerifier.PQCAlgorithm.FN_DSA_1024)
            return FN_DSA_1024_PK_SIZE;
        if (algo == IPQCVerifier.PQCAlgorithm.ML_DSA_44)
            return ML_DSA_44_PK_SIZE;
        if (algo == IPQCVerifier.PQCAlgorithm.ML_DSA_65)
            return ML_DSA_65_PK_SIZE;
        if (algo == IPQCVerifier.PQCAlgorithm.ML_DSA_87)
            return ML_DSA_87_PK_SIZE;
        if (algo == IPQCVerifier.PQCAlgorithm.SLH_DSA_128S)
            return SLH_DSA_128S_PK_SIZE;
        if (algo == IPQCVerifier.PQCAlgorithm.SLH_DSA_128F)
            return SLH_DSA_128F_PK_SIZE;
        if (algo == IPQCVerifier.PQCAlgorithm.SLH_DSA_256S)
            return SLH_DSA_256S_PK_SIZE;
        return 0;
    }
}
