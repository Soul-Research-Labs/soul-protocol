// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/EncryptedStealthAnnouncements.sol";

contract EncryptedStealthAnnouncementsTest is Test {
    EncryptedStealthAnnouncements public announcements;
    StealthAnnouncementScanner public scanner;

    address public admin = address(this);
    address public operator = makeAddr("operator");
    address public pauser = makeAddr("pauser");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public feeRecipient = makeAddr("feeRecipient");

    uint256 public constant ANNOUNCEMENT_FEE = 0.001 ether;

    function setUp() public {
        announcements = new EncryptedStealthAnnouncements(ANNOUNCEMENT_FEE, feeRecipient);
        scanner = new StealthAnnouncementScanner(address(announcements));

        announcements.grantRole(announcements.OPERATOR_ROLE(), operator);
        announcements.grantRole(announcements.PAUSER_ROLE(), pauser);

        deal(user1, 10 ether);
        deal(user2, 10 ether);
    }

    // ======== Constructor ========

    function test_constructor() public view {
        assertTrue(announcements.hasRole(announcements.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(announcements.hasRole(announcements.OPERATOR_ROLE(), admin));
        assertTrue(announcements.hasRole(announcements.PAUSER_ROLE(), admin));
        assertEq(announcements.getAnnouncementCount(), 0);
    }

    // ======== Announce ========

    function test_announce() public {
        bytes32 ephemeralPubKey = keccak256("ephemeral1");
        bytes memory payload = abi.encodePacked(
            bytes32(keccak256("nonce")),
            bytes8(0),
            bytes32(keccak256("encrypted_data"))
        );
        bytes32 viewTagCommitment = keccak256("viewtag1");

        vm.prank(user1);
        uint256 id = announcements.announce{value: ANNOUNCEMENT_FEE}(
            ephemeralPubKey, payload, viewTagCommitment
        );

        assertEq(id, 0);
        assertEq(announcements.getAnnouncementCount(), 1);
    }

    function test_announce_revert_insufficientFee() public {
        bytes32 ephemeralPubKey = keccak256("ephemeral1");
        bytes memory payload = abi.encodePacked(
            bytes32(keccak256("nonce")),
            bytes8(0),
            bytes32(keccak256("encrypted_data"))
        );
        bytes32 viewTagCommitment = keccak256("viewtag1");

        vm.prank(user1);
        vm.expectRevert();
        announcements.announce{value: ANNOUNCEMENT_FEE - 1}(
            ephemeralPubKey, payload, viewTagCommitment
        );
    }

    function test_announce_revert_invalidCiphertext() public {
        bytes32 ephemeralPubKey = keccak256("ephemeral1");
        bytes memory tooSmall = new bytes(10); // Below MIN_CIPHERTEXT_OVERHEAD (40)
        bytes32 viewTagCommitment = keccak256("viewtag1");

        vm.prank(user1);
        vm.expectRevert();
        announcements.announce{value: ANNOUNCEMENT_FEE}(
            ephemeralPubKey, tooSmall, viewTagCommitment
        );
    }

    function test_announce_revert_invalidEphemeralKey() public {
        bytes memory payload = abi.encodePacked(
            bytes32(keccak256("nonce")),
            bytes8(0),
            bytes32(keccak256("data"))
        );

        vm.prank(user1);
        vm.expectRevert();
        announcements.announce{value: ANNOUNCEMENT_FEE}(
            bytes32(0), payload, keccak256("viewtag")
        );
    }

    // ======== Batch Announce ========

    function test_announceBatch() public {
        bytes32[] memory ephemeralKeys = new bytes32[](3);
        bytes[] memory payloads = new bytes[](3);
        bytes32[] memory viewTagCommitments = new bytes32[](3);

        for (uint256 i = 0; i < 3; i++) {
            ephemeralKeys[i] = keccak256(abi.encodePacked("eph", i));
            payloads[i] = abi.encodePacked(
                bytes32(keccak256(abi.encodePacked("nonce", i))),
                bytes8(0),
                bytes32(keccak256(abi.encodePacked("data", i)))
            );
            viewTagCommitments[i] = keccak256(abi.encodePacked("vtag", i));
        }

        EncryptedStealthAnnouncements.BatchAnnouncement memory batch = EncryptedStealthAnnouncements
            .BatchAnnouncement({
            ephemeralPubKeys: ephemeralKeys,
            encryptedPayloads: payloads,
            viewTagCommitments: viewTagCommitments
        });

        vm.prank(user1);
        uint256 startId = announcements.announceBatch{value: ANNOUNCEMENT_FEE * 3}(batch);

        assertEq(startId, 0);
        assertEq(announcements.getAnnouncementCount(), 3);
    }

    // ======== View Tag Query ========

    function test_getAnnouncementsByViewTag() public {
        bytes32 viewTag = keccak256("shared_viewtag");
        bytes memory payload = abi.encodePacked(
            bytes32(keccak256("nonce")),
            bytes8(0),
            bytes32(keccak256("data"))
        );

        vm.startPrank(user1);
        announcements.announce{value: ANNOUNCEMENT_FEE}(
            keccak256("eph1"), payload, viewTag
        );
        announcements.announce{value: ANNOUNCEMENT_FEE}(
            keccak256("eph2"), payload, viewTag
        );
        vm.stopPrank();

        uint256[] memory ids = announcements.getAnnouncementsByViewTag(viewTag);
        assertEq(ids.length, 2);
    }

    // ======== View Functions ========

    function test_getAnnouncement() public {
        bytes32 ephKey = keccak256("eph1");
        bytes memory payload = abi.encodePacked(
            bytes32(keccak256("nonce")),
            bytes8(0),
            bytes32(keccak256("data"))
        );
        bytes32 viewTag = keccak256("vtag");

        vm.prank(user1);
        uint256 id = announcements.announce{value: ANNOUNCEMENT_FEE}(
            ephKey, payload, viewTag
        );

        EncryptedStealthAnnouncements.EncryptedAnnouncement memory ann = announcements.getAnnouncement(id);
        assertEq(ann.ephemeralPubKey, ephKey);
        assertEq(ann.viewTagCommitment, viewTag);
        assertEq(ann.announcer, user1);
    }

    // ======== Viewing Key Registration ========

    function test_registerViewingKey() public {
        bytes32 keyHash = keccak256("my_viewing_key");
        vm.prank(user1);
        announcements.registerViewingKey(keyHash);
    }

    // ======== Fee Management ========

    function test_setAnnouncementFee() public {
        uint256 newFee = 0.005 ether;
        announcements.setAnnouncementFee(newFee);
    }

    function test_setAnnouncementFee_revert_notAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        announcements.setAnnouncementFee(0.005 ether);
    }

    function test_setFeeRecipient() public {
        address newRecipient = makeAddr("newRecipient");
        announcements.setFeeRecipient(newRecipient);
    }

    function test_collectFees() public {
        bytes memory payload = abi.encodePacked(
            bytes32(keccak256("nonce")),
            bytes8(0),
            bytes32(keccak256("data"))
        );

        vm.prank(user1);
        announcements.announce{value: ANNOUNCEMENT_FEE}(
            keccak256("eph"), payload, keccak256("vtag")
        );

        uint256 balBefore = feeRecipient.balance;
        vm.prank(operator);
        announcements.collectFees();
        assertGt(feeRecipient.balance, balBefore);
    }

    // ======== Pause ========

    function test_pause_unpause() public {
        vm.prank(pauser);
        announcements.pause();

        bytes memory payload = abi.encodePacked(
            bytes32(keccak256("nonce")),
            bytes8(0),
            bytes32(keccak256("data"))
        );

        vm.prank(user1);
        vm.expectRevert();
        announcements.announce{value: ANNOUNCEMENT_FEE}(
            keccak256("eph"), payload, keccak256("vtag")
        );

        vm.prank(pauser);
        announcements.unpause();

        vm.prank(user1);
        announcements.announce{value: ANNOUNCEMENT_FEE}(
            keccak256("eph"), payload, keccak256("vtag")
        );
    }

    // ======== Scanner ========

    function test_scanner_computeViewTagCommitment() public view {
        bytes32 result = scanner.computeViewTagCommitment(1, keccak256("shared_secret"));
        assertTrue(result != bytes32(0));
    }

    function test_scanner_computeSharedSecret() public view {
        bytes32 result = scanner.computeSharedSecret(keccak256("a"), keccak256("b"));
        assertTrue(result != bytes32(0));
    }

    function test_scanner_deriveViewTag() public view {
        uint8 tag = scanner.deriveViewTag(keccak256("shared_secret"));
        assertTrue(tag <= 255);
    }

    // ======== Fuzz ========

    function testFuzz_announce_withVariousFees(uint256 extraFee) public {
        extraFee = bound(extraFee, 0, 1 ether);
        bytes memory payload = abi.encodePacked(
            bytes32(keccak256("nonce")),
            bytes8(0),
            bytes32(keccak256("data"))
        );

        vm.prank(user1);
        announcements.announce{value: ANNOUNCEMENT_FEE + extraFee}(
            keccak256("eph"), payload, keccak256("vtag")
        );
        assertEq(announcements.getAnnouncementCount(), 1);
    }
}
