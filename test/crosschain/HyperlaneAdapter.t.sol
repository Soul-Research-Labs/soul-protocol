// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/HyperlaneAdapter.sol";

/* ─── Mock Mailbox ──────────────────────────────────────────────── */

contract MockMailbox {
    bytes32 public lastMessageId;
    uint32 public lastDomain;
    bytes32 public lastRecipient;
    bytes public lastMessage;
    uint256 public lastValue;

    function dispatch(
        uint32 destinationDomain,
        bytes32 recipientBody,
        bytes calldata messageBody
    ) external payable returns (bytes32 messageId) {
        lastDomain = destinationDomain;
        lastRecipient = recipientBody;
        lastMessage = messageBody;
        lastValue = msg.value;
        messageId = keccak256(
            abi.encodePacked(destinationDomain, recipientBody, messageBody)
        );
        lastMessageId = messageId;
        return messageId;
    }
}

/* ─── Mock Custom ISM ───────────────────────────────────────────── */

contract MockCustomISM {
    bool public returnValue = true;

    function verify(bytes32, bytes calldata) external view returns (bool) {
        return returnValue;
    }

    function setReturnValue(bool v) external {
        returnValue = v;
    }
}

/* ─── Test contract ──────────────────────────────────────────────── */

contract HyperlaneAdapterTest is Test {
    HyperlaneAdapter public adapter;
    MockMailbox public mailbox;
    MockCustomISM public customISM;

    address admin = address(0xA);
    address operator = address(0xB);
    address guardian = address(0xC);
    address nobody = address(0xDEAD);
    address validator1;
    address validator2;
    address validator3;
    uint256 val1Pk;
    uint256 val2Pk;
    uint256 val3Pk;

    uint32 localDomain = 1;
    uint32 remoteDomain = 2;
    bytes32 remoteSender;

    function setUp() public {
        mailbox = new MockMailbox();
        customISM = new MockCustomISM();

        (validator1, val1Pk) = makeAddrAndKey("val1");
        (validator2, val2Pk) = makeAddrAndKey("val2");
        (validator3, val3Pk) = makeAddrAndKey("val3");

        vm.prank(admin);
        adapter = new HyperlaneAdapter(address(mailbox), localDomain, admin);

        remoteSender = bytes32(uint256(uint160(address(0xBEEF))));

        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);
        vm.stopPrank();

        // Configure trusted sender for remote domain
        vm.prank(operator);
        adapter.setTrustedSender(remoteDomain, remoteSender);
    }

    /* ── Constructor ────────────────────────────────── */

    function test_constructor_setsMailboxAndDomain() public view {
        assertEq(adapter.mailbox(), address(mailbox));
        assertEq(adapter.localDomain(), localDomain);
    }

    function test_constructor_revertsZeroMailbox() public {
        vm.expectRevert(HyperlaneAdapter.InvalidMailbox.selector);
        new HyperlaneAdapter(address(0), localDomain, admin);
    }

    /* ── Dispatch ───────────────────────────────────── */

    function test_dispatch_happyPath() public {
        bytes32 recipient = bytes32(uint256(uint160(address(0x123))));
        bytes memory message = hex"DEADBEEF";

        bytes32 mid = adapter.dispatch{value: 0.001 ether}(
            remoteDomain,
            recipient,
            message
        );

        assertTrue(mid != bytes32(0));
        assertEq(adapter.outboundNonce(remoteDomain), 1);
    }

    function test_dispatch_revertsInvalidDomain() public {
        uint32 unknownDomain = 999;
        vm.expectRevert(HyperlaneAdapter.InvalidDomain.selector);
        adapter.dispatch{value: 0.001 ether}(
            unknownDomain,
            bytes32(uint256(1)),
            hex"AA"
        );
    }

    function test_dispatch_whenPaused_reverts() public {
        vm.prank(guardian);
        adapter.pause();

        vm.expectRevert();
        adapter.dispatch{value: 0.001 ether}(
            remoteDomain,
            bytes32(uint256(1)),
            hex"AA"
        );
    }

    function testFuzz_dispatch(
        bytes32 recipient,
        bytes calldata message
    ) public {
        vm.assume(recipient != bytes32(0));
        vm.deal(address(this), 1 ether);

        bytes32 mid = adapter.dispatch{value: 0.001 ether}(
            remoteDomain,
            recipient,
            message
        );
        assertTrue(mid != bytes32(0));
    }

    /* ── Handle (incoming message) ──────────────────── */

    function test_handle_happyPath() public {
        uint256 nonce = 1;
        bytes memory body = hex"CAFEBABE";
        bytes memory message = abi.encodePacked(nonce, body);

        vm.prank(address(mailbox));
        adapter.handle(remoteDomain, remoteSender, message);

        assertEq(adapter.inboundNonce(remoteDomain), 0); // inboundNonce is not incremented in handle
    }

    function test_handle_revertsNotMailbox() public {
        uint256 nonce = 1;
        bytes memory message = abi.encodePacked(nonce, hex"AA");

        vm.prank(nobody);
        vm.expectRevert(HyperlaneAdapter.InvalidMailbox.selector);
        adapter.handle(remoteDomain, remoteSender, message);
    }

    function test_handle_revertsUntrustedSender() public {
        uint256 nonce = 1;
        bytes memory message = abi.encodePacked(nonce, hex"AA");
        bytes32 fakeSender = bytes32(uint256(0xFAFAFA));

        vm.prank(address(mailbox));
        vm.expectRevert(HyperlaneAdapter.UntrustedSender.selector);
        adapter.handle(remoteDomain, fakeSender, message);
    }

    function test_handle_revertsTooShortMessage() public {
        bytes memory shortMsg = hex"AABB"; // < 32 bytes

        vm.prank(address(mailbox));
        vm.expectRevert(HyperlaneAdapter.MessageNotVerified.selector);
        adapter.handle(remoteDomain, remoteSender, shortMsg);
    }

    function test_handle_revertsDoubleProcess() public {
        uint256 nonce = 1;
        bytes memory body = hex"CAFEBABE";
        bytes memory message = abi.encodePacked(nonce, body);

        vm.prank(address(mailbox));
        adapter.handle(remoteDomain, remoteSender, message);

        vm.prank(address(mailbox));
        vm.expectRevert(HyperlaneAdapter.MessageAlreadyProcessed.selector);
        adapter.handle(remoteDomain, remoteSender, message);
    }

    /* ── Quote Dispatch ─────────────────────────────── */

    function test_quoteDispatch_returnsNonZero() public view {
        uint256 fee = adapter.quoteDispatch(remoteDomain, hex"AABB");
        assertTrue(fee > 0);
    }

    /* ── ISM Configuration ──────────────────────────── */

    function test_setISMConfig() public {
        address[] memory validators = new address[](2);
        validators[0] = validator1;
        validators[1] = validator2;

        HyperlaneAdapter.ISMConfig memory config = HyperlaneAdapter.ISMConfig({
            ism: address(customISM),
            ismType: HyperlaneAdapter.ISMType.CUSTOM,
            enabled: true,
            threshold: 2,
            validators: validators
        });

        vm.prank(operator);
        adapter.setISMConfig(remoteDomain, config);

        (address ism, , bool enabled, uint8 threshold) = adapter.ismConfigs(
            remoteDomain
        );
        assertEq(ism, address(customISM));
        assertTrue(enabled);
        assertEq(threshold, 2);
    }

    /* ── Multisig ISM ───────────────────────────────── */

    function test_setMultisigParams() public {
        address[] memory validators = new address[](3);
        validators[0] = validator1;
        validators[1] = validator2;
        validators[2] = validator3;

        vm.prank(operator);
        adapter.setMultisigParams(remoteDomain, validators, 2);

        uint8 threshold = _getThreshold(remoteDomain);
        assertEq(threshold, 2);
    }

    function test_setMultisigParams_revertsThresholdTooHigh() public {
        address[] memory validators = new address[](2);
        validators[0] = validator1;
        validators[1] = validator2;

        vm.prank(operator);
        vm.expectRevert(HyperlaneAdapter.ThresholdNotMet.selector);
        adapter.setMultisigParams(remoteDomain, validators, 3);
    }

    /* ── Merkle Root Storage ────────────────────────── */

    function test_storeMerkleRoot() public {
        bytes32 root = bytes32(uint256(0x1234));

        vm.prank(operator);
        adapter.storeMerkleRoot(remoteDomain, root);

        bytes32[] memory roots = adapter.getMerkleRoots(remoteDomain);
        assertEq(roots.length, 1);
        assertEq(roots[0], root);
    }

    /* ── Validator Management ───────────────────────── */

    function test_addValidator() public {
        vm.prank(operator);
        adapter.addValidator(validator1);
        assertTrue(adapter.hasRole(adapter.VALIDATOR_ROLE(), validator1));
    }

    function test_removeValidator() public {
        vm.startPrank(operator);
        adapter.addValidator(validator1);
        adapter.removeValidator(validator1);
        vm.stopPrank();

        assertFalse(adapter.hasRole(adapter.VALIDATOR_ROLE(), validator1));
    }

    /* ── Submit Validator Signature ──────────────────── */

    function test_submitValidatorSignature() public {
        vm.prank(operator);
        adapter.addValidator(validator1);

        bytes32 messageId = bytes32(uint256(0xABCD));
        bytes memory sig = hex"112233";

        vm.prank(validator1);
        adapter.submitValidatorSignature(messageId, sig);

        assertEq(adapter.signatureCount(messageId), 1);
    }

    function test_submitValidatorSignature_skipsDuplicate() public {
        vm.prank(operator);
        adapter.addValidator(validator1);

        bytes32 messageId = bytes32(uint256(0xABCD));

        vm.startPrank(validator1);
        adapter.submitValidatorSignature(messageId, hex"112233");
        adapter.submitValidatorSignature(messageId, hex"445566");
        vm.stopPrank();

        // Should still be 1 (duplicate skipped)
        assertEq(adapter.signatureCount(messageId), 1);
    }

    /* ── Pause / Unpause ────────────────────────────── */

    function test_pause_unpause() public {
        vm.prank(guardian);
        adapter.pause();
        assertTrue(adapter.paused());

        vm.prank(guardian);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    /* ── Trusted Sender ─────────────────────────────── */

    function test_setTrustedSender() public {
        bytes32 sender = bytes32(uint256(0x999));
        vm.prank(operator);
        adapter.setTrustedSender(42, sender);
        assertEq(adapter.trustedSenders(42), sender);
    }

    /* ── Soul Hub ───────────────────────────────────── */

    function test_setPilHub() public {
        vm.prank(operator);
        adapter.setPilHub(remoteDomain, address(0x123));
        assertEq(adapter.soulHubs(remoteDomain), address(0x123));
    }

    /* ── Receive ETH ────────────────────────────────── */

    function test_receiveEth() public {
        vm.deal(address(this), 1 ether);
        (bool ok, ) = address(adapter).call{value: 0.5 ether}("");
        assertTrue(ok);
        assertEq(address(adapter).balance, 0.5 ether);
    }

    /* ── Helper ──────────────────────────────────────── */

    function _getThreshold(uint32 domain) internal view returns (uint8) {
        (uint8 threshold,) = adapter.multisigParams(domain);
        return threshold;
    }
}
