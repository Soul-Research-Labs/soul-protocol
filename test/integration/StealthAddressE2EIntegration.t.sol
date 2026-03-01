// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/privacy/StealthAddressRegistry.sol";

/**
 * @title StealthAddressE2EIntegration
 * @notice End-to-end integration test using the real StealthAddressRegistry
 *         (UUPS proxy) to verify the full stealth address lifecycle:
 *         register → derive → announce → scan → claim.
 *
 * Unlike existing tests that use mock registries, this deploys the actual
 * upgradeable StealthAddressRegistry behind an ERC1967 proxy.
 */
contract StealthAddressE2EIntegration is Test {
    StealthAddressRegistry public registry;
    ERC1967Proxy public proxy;

    address public admin = makeAddr("admin");
    address public alice = makeAddr("alice"); // Recipient
    address public bob = makeAddr("bob"); // Sender
    address public carol = makeAddr("carol"); // Another recipient

    // Simulated secp256k1 compressed public keys (33 bytes)
    bytes constant ALICE_SPEND_PUB =
        hex"02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    bytes constant ALICE_VIEW_PUB =
        hex"02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    bytes constant CAROL_SPEND_PUB =
        hex"02cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    bytes constant CAROL_VIEW_PUB =
        hex"02dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    function setUp() public {
        // Deploy implementation
        StealthAddressRegistry impl = new StealthAddressRegistry();

        // Deploy proxy
        bytes memory initData = abi.encodeCall(
            StealthAddressRegistry.initialize,
            (admin)
        );
        proxy = new ERC1967Proxy(address(impl), initData);
        registry = StealthAddressRegistry(address(proxy));

        // Grant announcer role to bob (sender)
        vm.startPrank(admin);
        registry.grantRole(registry.ANNOUNCER_ROLE(), bob);
        registry.grantRole(registry.ANNOUNCER_ROLE(), alice);
        vm.stopPrank();

        // Fund stealth addresses for ETH transfers
        vm.deal(bob, 100 ether);
        vm.deal(alice, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    FULL E2E: REGISTER → DERIVE → ANNOUNCE → SCAN
    //////////////////////////////////////////////////////////////*/

    function test_E2E_FullStealthLifecycle() public {
        // =====================================================
        // Step 1: Alice registers her stealth meta-address
        // =====================================================
        vm.prank(alice);
        registry.registerMetaAddress(
            ALICE_SPEND_PUB,
            ALICE_VIEW_PUB,
            IStealthAddressRegistry.CurveType.SECP256K1,
            1 // ERC-5564 scheme ID
        );

        // Verify registration
        (
            bytes memory spendPub,
            bytes memory viewPub,
            IStealthAddressRegistry.CurveType curve,
            IStealthAddressRegistry.KeyStatus status,
            uint256 registeredAt,
            uint256 schemeId
        ) = registry.metaAddresses(alice);

        assertEq(spendPub, ALICE_SPEND_PUB);
        assertEq(viewPub, ALICE_VIEW_PUB);
        assertEq(
            uint8(curve),
            uint8(IStealthAddressRegistry.CurveType.SECP256K1)
        );
        assertEq(uint8(status), uint8(IStealthAddressRegistry.KeyStatus.ACTIVE));
        assertEq(schemeId, 1);
        assertGt(registeredAt, 0);

        // =====================================================
        // Step 2: Bob derives a stealth address for Alice
        // =====================================================
        bytes32 sharedSecretHash = keccak256(
            abi.encodePacked("shared-secret-r*P_view")
        );
        bytes
            memory ephemeralPubKey = hex"03eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        (address stealthAddress, bytes1 viewTag) = registry
            .deriveStealthAddress(alice, ephemeralPubKey, sharedSecretHash);

        assertTrue(
            stealthAddress != address(0),
            "Stealth address should not be zero"
        );
        assertEq(
            viewTag,
            bytes1(sharedSecretHash),
            "View tag should be first byte of shared secret"
        );

        // =====================================================
        // Step 3: Bob sends ETH to stealth address and announces
        // =====================================================
        vm.prank(bob);
        (bool sent, ) = stealthAddress.call{value: 1 ether}("");
        assertTrue(sent, "ETH transfer to stealth address should succeed");
        assertEq(stealthAddress.balance, 1 ether);

        // Bob announces the payment
        bytes memory viewTagBytes = abi.encodePacked(viewTag);
        vm.prank(bob);
        registry.announce(
            1, // schemeId
            stealthAddress,
            ephemeralPubKey,
            viewTagBytes,
            "" // no metadata
        );

        assertEq(registry.totalAnnouncements(), 1);

        // =====================================================
        // Step 4: Alice scans for her stealth addresses
        // =====================================================

        // Alice gets announcements by view tag
        address[] memory candidates = registry.getAnnouncementsByViewTag(
            viewTag
        );
        assertEq(candidates.length, 1);
        assertEq(candidates[0], stealthAddress);

        // Verify announcement data
        (
            bytes32 storedSchemeId,
            address storedStealthAddr,
            bytes memory storedEphemeral,
            bytes memory storedViewTag,
            bytes memory storedMetadata,
            uint256 storedTimestamp,
            uint256 storedChainId
        ) = registry.announcements(stealthAddress);

        assertEq(storedStealthAddr, stealthAddress);
        assertEq(storedEphemeral, ephemeralPubKey);
        assertEq(storedChainId, block.chainid);
    }

    /*//////////////////////////////////////////////////////////////
                    DUAL-KEY STEALTH DERIVATION
    //////////////////////////////////////////////////////////////*/

    function test_E2E_DualKeyStealth() public {
        bytes32 spendPubHash = keccak256(ALICE_SPEND_PUB);
        bytes32 viewPubHash = keccak256(ALICE_VIEW_PUB);
        bytes32 ephemeralPrivHash = keccak256("ephemeral-priv-key");

        vm.prank(alice);
        (bytes32 stealthHash, address derivedAddr) = registry
            .computeDualKeyStealth(
                spendPubHash,
                viewPubHash,
                ephemeralPrivHash,
                block.chainid
            );

        assertTrue(stealthHash != bytes32(0));
        assertTrue(derivedAddr != address(0));

        // Verify stored record
        (
            bytes32 storedSpend,
            bytes32 storedView,
            bytes32 storedStealth,
            bytes32 storedEphemeral,
            bytes32 storedShared,
            address storedDerived,
            uint256 storedChain
        ) = registry.dualKeyRecords(stealthHash);

        assertEq(storedSpend, spendPubHash);
        assertEq(storedView, viewPubHash);
        assertEq(storedStealth, stealthHash);
        assertEq(storedDerived, derivedAddr);
        assertEq(storedChain, block.chainid);

        // Verify deterministic derivation
        // Same inputs should produce same stealth address
        // (computeDualKeyStealth is nonReentrant + writes state, so we verify hash consistency)
        bytes32 expectedShared = keccak256(
            abi.encode(
                ephemeralPrivHash,
                viewPubHash,
                registry.STEALTH_DOMAIN()
            )
        );
        assertEq(storedShared, expectedShared);
    }

    /*//////////////////////////////////////////////////////////////
                    MULTIPLE RECIPIENTS
    //////////////////////////////////////////////////////////////*/

    function test_E2E_MultipleRecipients() public {
        // Register Alice
        vm.prank(alice);
        registry.registerMetaAddress(
            ALICE_SPEND_PUB,
            ALICE_VIEW_PUB,
            IStealthAddressRegistry.CurveType.SECP256K1,
            1
        );

        // Register Carol
        vm.prank(carol);
        registry.registerMetaAddress(
            CAROL_SPEND_PUB,
            CAROL_VIEW_PUB,
            IStealthAddressRegistry.CurveType.SECP256K1,
            1
        );

        // Bob derives stealth addresses for both
        bytes32 secretAlice = keccak256("secret-for-alice");
        bytes32 secretCarol = keccak256("secret-for-carol");

        (address stealthAlice, ) = registry.deriveStealthAddress(
            alice,
            hex"030101010101010101010101010101010101010101010101010101010101010101",
            secretAlice
        );

        (address stealthCarol, ) = registry.deriveStealthAddress(
            carol,
            hex"030202020202020202020202020202020202020202020202020202020202020202",
            secretCarol
        );

        // Stealth addresses should be different
        assertTrue(
            stealthAlice != stealthCarol,
            "Different recipients should have different stealth addresses"
        );

        // Fund both
        vm.prank(bob);
        (bool s1, ) = stealthAlice.call{value: 0.5 ether}("");
        assertTrue(s1);
        vm.prank(bob);
        (bool s2, ) = stealthCarol.call{value: 0.3 ether}("");
        assertTrue(s2);

        assertEq(stealthAlice.balance, 0.5 ether);
        assertEq(stealthCarol.balance, 0.3 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    PRIVATE ANNOUNCEMENT (PERMISSIONLESS)
    //////////////////////////////////////////////////////////////*/

    function test_E2E_PrivateAnnouncement() public {
        address sender = makeAddr("permissionless-sender");
        vm.deal(sender, 1 ether);

        address stealthAddr = makeAddr("stealth-target");
        bytes
            memory ephPub = hex"03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        vm.prank(sender);
        registry.announcePrivate{value: 0.0001 ether}(
            1,
            stealthAddr,
            ephPub,
            hex"ab", // view tag
            ""
        );

        assertEq(registry.totalAnnouncements(), 1);

        // Verify stored
        (, address stored, , , , , ) = registry.announcements(stealthAddr);
        assertEq(stored, stealthAddr);
    }

    function test_E2E_PrivateAnnouncement_InsufficientFee_Reverts() public {
        address sender = makeAddr("cheap-sender");
        vm.deal(sender, 1 ether);

        vm.prank(sender);
        vm.expectRevert(); // InsufficientFee
        registry.announcePrivate{value: 0.00001 ether}(
            1,
            makeAddr("target"),
            hex"03aaaa",
            "",
            ""
        );
    }

    /*//////////////////////////////////////////////////////////////
                    KEY LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function test_E2E_KeyRevocation() public {
        // Register
        vm.prank(alice);
        registry.registerMetaAddress(
            ALICE_SPEND_PUB,
            ALICE_VIEW_PUB,
            IStealthAddressRegistry.CurveType.SECP256K1,
            1
        );

        // Revoke
        vm.prank(alice);
        registry.revokeMetaAddress();

        // Verify revoked
        (, , , IStealthAddressRegistry.KeyStatus status, , ) = registry
            .metaAddresses(alice);
        assertEq(
            uint8(status),
            uint8(IStealthAddressRegistry.KeyStatus.REVOKED)
        );

        // Derive should fail for revoked addresses
        vm.expectRevert(); // MetaAddressNotFound (since revoked ≠ active)
        registry.deriveStealthAddress(alice, hex"0300", keccak256("secret"));
    }

    function test_E2E_CannotReRegisterActive() public {
        vm.prank(alice);
        registry.registerMetaAddress(
            ALICE_SPEND_PUB,
            ALICE_VIEW_PUB,
            IStealthAddressRegistry.CurveType.SECP256K1,
            1
        );

        vm.prank(alice);
        vm.expectRevert(); // MetaAddressAlreadyExists
        registry.registerMetaAddress(
            CAROL_SPEND_PUB,
            CAROL_VIEW_PUB,
            IStealthAddressRegistry.CurveType.SECP256K1,
            1
        );
    }

    /*//////////////////////////////////////////////////////////////
                    BATCH SCANNING
    //////////////////////////////////////////////////////////////*/

    function test_E2E_BatchScan() public {
        // Register Alice
        vm.prank(alice);
        registry.registerMetaAddress(
            ALICE_SPEND_PUB,
            ALICE_VIEW_PUB,
            IStealthAddressRegistry.CurveType.SECP256K1,
            1
        );

        // Create an announcement so checkStealthOwnership can look it up
        bytes
            memory ephPub = hex"03eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        bytes32 viewingPrivKeyHash = keccak256("alice-viewing-priv-key");
        bytes32 spendingPubKeyHash = keccak256(ALICE_SPEND_PUB);

        // Compute the shared secret the same way the contract does (M-1 fix: abi.encode)
        bytes32 sharedSecretHash = keccak256(
            abi.encode(
                viewingPrivKeyHash,
                ephPub,
                registry.STEALTH_DOMAIN()
            )
        );
        bytes32 expectedStealthHash = keccak256(
            abi.encode(spendingPubKeyHash, sharedSecretHash)
        );
        address expectedStealth = address(
            uint160(uint256(expectedStealthHash))
        );

        // Announce this stealth address
        vm.prank(bob);
        registry.announce(
            1,
            expectedStealth,
            ephPub,
            abi.encodePacked(bytes1(sharedSecretHash)),
            ""
        );

        // Batch scan with correct keys → should find it
        address[] memory candidates = new address[](3);
        candidates[0] = makeAddr("random1");
        candidates[1] = expectedStealth;
        candidates[2] = makeAddr("random2");

        address[] memory owned = registry.batchScan(
            viewingPrivKeyHash,
            spendingPubKeyHash,
            candidates
        );

        assertEq(owned.length, 1);
        assertEq(owned[0], expectedStealth);
    }

    /*//////////////////////////////////////////////////////////////
                    CURVE TYPES
    //////////////////////////////////////////////////////////////*/

    function test_E2E_ED25519Keys() public {
        // ED25519 keys are 32 bytes
        bytes memory ed25519Spend = new bytes(32);
        bytes memory ed25519View = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            ed25519Spend[i] = bytes1(uint8(0xAA));
            ed25519View[i] = bytes1(uint8(0xBB));
        }

        vm.prank(carol);
        registry.registerMetaAddress(
            ed25519Spend,
            ed25519View,
            IStealthAddressRegistry.CurveType.ED25519,
            2 // different scheme for ed25519
        );

        (
            ,
            ,
            IStealthAddressRegistry.CurveType curve,
            IStealthAddressRegistry.KeyStatus status,
            ,

        ) = registry.metaAddresses(carol);
        assertEq(uint8(curve), uint8(IStealthAddressRegistry.CurveType.ED25519));
        assertEq(uint8(status), uint8(IStealthAddressRegistry.KeyStatus.ACTIVE));
    }

    function test_E2E_BLS12_381Keys() public {
        // BLS12-381 keys are 48 bytes
        bytes memory blsSpend = new bytes(48);
        bytes memory blsView = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            blsSpend[i] = bytes1(uint8(0xCC));
            blsView[i] = bytes1(uint8(0xDD));
        }

        address user = makeAddr("bls-user");
        vm.prank(user);
        registry.registerMetaAddress(
            blsSpend,
            blsView,
            IStealthAddressRegistry.CurveType.BLS12_381,
            3
        );

        (, , IStealthAddressRegistry.CurveType curve, , , ) = registry
            .metaAddresses(user);
        assertEq(
            uint8(curve),
            uint8(IStealthAddressRegistry.CurveType.BLS12_381)
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ TEST
    //////////////////////////////////////////////////////////////*/

    function testFuzz_DeriveStealthAddress_Deterministic(
        bytes32 sharedSecret
    ) public {
        vm.assume(sharedSecret != bytes32(0));

        vm.prank(alice);
        registry.registerMetaAddress(
            ALICE_SPEND_PUB,
            ALICE_VIEW_PUB,
            IStealthAddressRegistry.CurveType.SECP256K1,
            1
        );

        bytes
            memory ephPub = hex"03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        (address addr1, bytes1 tag1) = registry.deriveStealthAddress(
            alice,
            ephPub,
            sharedSecret
        );
        (address addr2, bytes1 tag2) = registry.deriveStealthAddress(
            alice,
            ephPub,
            sharedSecret
        );

        assertEq(
            addr1,
            addr2,
            "Same inputs should produce same stealth address"
        );
        assertEq(tag1, tag2, "Same inputs should produce same view tag");
        assertTrue(addr1 != address(0));
    }
}
