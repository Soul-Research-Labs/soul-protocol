// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CrossChainMessageVerifier} from "../../contracts/security/CrossChainMessageVerifier.sol";

contract CrossChainMessageVerifierTest is Test {
    CrossChainMessageVerifier public verifier;

    address public admin;
    address public guardian;
    address public resolver;
    address public verifierAddr1;
    address public verifierAddr2;
    address public verifierAddr3;
    address public user1;

    bytes32 constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant RESOLVER_ROLE = keccak256("RESOLVER_ROLE");

    uint256 constant SOURCE_CHAIN = 42161; // Arbitrum
    uint256 constant THRESHOLD = 6000; // 60%

    function setUp() public {
        admin = address(this);
        guardian = makeAddr("guardian");
        resolver = makeAddr("resolver");
        verifierAddr1 = makeAddr("verifier1");
        verifierAddr2 = makeAddr("verifier2");
        verifierAddr3 = makeAddr("verifier3");
        user1 = makeAddr("user1");

        verifier = new CrossChainMessageVerifier(THRESHOLD, admin);
        verifier.grantRole(GUARDIAN_ROLE, guardian);
        verifier.grantRole(RESOLVER_ROLE, resolver);

        // Register source chain
        verifier.addSourceChain(SOURCE_CHAIN);

        // Add verifiers with weights
        verifier.addVerifier(verifierAddr1, 4000); // 40%
        verifier.addVerifier(verifierAddr2, 3000); // 30%
        verifier.addVerifier(verifierAddr3, 3000); // 30%
    }

    // ──────── Helpers ────────

    function _submitMessage() internal returns (bytes32 messageId) {
        messageId = verifier.submitMessage(
            SOURCE_CHAIN,
            keccak256("payload"),
            hex"deadbeef"
        );
    }

    function _confirmAndReachThreshold(bytes32 messageId) internal {
        // verifier1 (40%) + verifier2 (30%) = 70% > 60% threshold
        vm.prank(verifierAddr1);
        verifier.confirmMessage(messageId);
        vm.prank(verifierAddr2);
        verifier.confirmMessage(messageId);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsThreshold() public view {
        assertEq(verifier.requiredThreshold(), THRESHOLD);
    }

    function test_Constructor_SetsChainId() public view {
        assertEq(verifier.chainId(), block.chainid);
    }

    function test_Constructor_SupportsCurrentChain() public view {
        assertTrue(verifier.supportedDestChains(block.chainid));
    }

    function test_Constructor_RevertInvalidThreshold() public {
        vm.expectRevert(
            CrossChainMessageVerifier.InvalidVerifierThreshold.selector
        );
        new CrossChainMessageVerifier(0, admin);

        vm.expectRevert(
            CrossChainMessageVerifier.InvalidVerifierThreshold.selector
        );
        new CrossChainMessageVerifier(10001, admin);
    }

    /*//////////////////////////////////////////////////////////////
                       VERIFIER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_AddVerifier() public view {
        assertEq(verifier.getVerifierCount(), 3);
        assertEq(verifier.totalVerifierWeight(), 10000);
    }

    function test_AddVerifier_RevertDuplicate() public {
        vm.expectRevert(
            CrossChainMessageVerifier.VerifierAlreadyRegistered.selector
        );
        verifier.addVerifier(verifierAddr1, 1000);
    }

    function test_RemoveVerifier() public {
        verifier.removeVerifier(verifierAddr3);
        assertEq(verifier.getVerifierCount(), 2);
        assertEq(verifier.totalVerifierWeight(), 7000);
    }

    function test_RemoveVerifier_RevertNotRegistered() public {
        vm.expectRevert(
            CrossChainMessageVerifier.VerifierNotRegistered.selector
        );
        verifier.removeVerifier(makeAddr("rando"));
    }

    function test_UpdateThreshold() public {
        verifier.updateThreshold(8000);
        assertEq(verifier.requiredThreshold(), 8000);
    }

    function test_UpdateThreshold_RevertInvalid() public {
        vm.expectRevert(
            CrossChainMessageVerifier.InvalidVerifierThreshold.selector
        );
        verifier.updateThreshold(0);
    }

    /*//////////////////////////////////////////////////////////////
                       MESSAGE SUBMISSION
    //////////////////////////////////////////////////////////////*/

    function test_SubmitMessage() public {
        bytes32 messageId = _submitMessage();

        (
            bytes32 id,
            uint256 sourceChain,
            uint256 destChain,
            bytes32 payloadHash, // payload
            ,
            address submitter,
            uint256 submittedAt,
            uint256 expiresAt,
            uint256 confirmations, // totalWeight
            ,
            bool executed,
            bool challenged,

        ) = // challengePeriodEnd
            verifier.messages(messageId);

        assertEq(id, messageId);
        assertEq(sourceChain, SOURCE_CHAIN);
        assertEq(destChain, block.chainid);
        assertEq(payloadHash, keccak256("payload"));
        assertEq(submitter, admin);
        assertGt(submittedAt, 0);
        assertEq(expiresAt, block.timestamp + 7 days);
        assertEq(confirmations, 0);
        assertFalse(executed);
        assertFalse(challenged);
    }

    function test_SubmitMessage_EmitsEvent() public {
        // Verify submit emits event (messageId is timestamp-dependent, check logs)
        vm.recordLogs();
        _submitMessage();

        Vm.Log[] memory entries = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < entries.length; i++) {
            if (
                entries[i].topics[0] ==
                keccak256(
                    "MessageSubmitted(bytes32,uint256,uint256,bytes32,address)"
                )
            ) {
                found = true;
                break;
            }
        }
        assertTrue(found, "MessageSubmitted event not emitted");
    }

    function test_SubmitMessage_RevertUnsupportedSource() public {
        vm.expectRevert(CrossChainMessageVerifier.InvalidSourceChain.selector);
        verifier.submitMessage(99999, keccak256("p"), hex"aa");
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIRMATION
    //////////////////////////////////////////////////////////////*/

    function test_ConfirmMessage() public {
        bytes32 messageId = _submitMessage();

        vm.prank(verifierAddr1);
        verifier.confirmMessage(messageId);

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            uint256 confirmations,
            uint256 totalWeight,
            ,
            ,

        ) = verifier.messages(messageId);
        assertEq(confirmations, 1);
        assertEq(totalWeight, 4000);
    }

    function test_ConfirmMessage_StartsChallengePeriodOnThreshold() public {
        bytes32 messageId = _submitMessage();
        _confirmAndReachThreshold(messageId);

        (, , , , , , , , , , , , uint256 challengePeriodEnd) = verifier
            .messages(messageId);
        assertGt(challengePeriodEnd, 0);
    }

    function test_ConfirmMessage_RevertNotVerifier() public {
        bytes32 messageId = _submitMessage();

        vm.prank(user1);
        vm.expectRevert(); // AccessControlUnauthorizedAccount (VERIFIER_ROLE check)
        verifier.confirmMessage(messageId);
    }

    function test_ConfirmMessage_RevertAlreadyConfirmed() public {
        bytes32 messageId = _submitMessage();

        vm.prank(verifierAddr1);
        verifier.confirmMessage(messageId);

        vm.prank(verifierAddr1);
        vm.expectRevert(CrossChainMessageVerifier.AlreadyConfirmed.selector);
        verifier.confirmMessage(messageId);
    }

    function test_ConfirmMessage_RevertExpired() public {
        bytes32 messageId = _submitMessage();

        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(verifierAddr1);
        vm.expectRevert(CrossChainMessageVerifier.MessageExpired.selector);
        verifier.confirmMessage(messageId);
    }

    /*//////////////////////////////////////////////////////////////
                       EXECUTION
    //////////////////////////////////////////////////////////////*/

    function test_ExecuteMessage() public {
        bytes32 messageId = _submitMessage();
        _confirmAndReachThreshold(messageId);

        // Wait past challenge period
        vm.warp(block.timestamp + 1 hours + 1);

        verifier.executeMessage(messageId);

        (, , , , , , , , , , bool executed, , ) = verifier.messages(messageId);
        assertTrue(executed);
    }

    function test_ExecuteMessage_RevertNotConfirmed() public {
        bytes32 messageId = _submitMessage();

        vm.expectRevert(
            CrossChainMessageVerifier.InsufficientConfirmations.selector
        );
        verifier.executeMessage(messageId);
    }

    function test_ExecuteMessage_RevertChallengePeriodActive() public {
        bytes32 messageId = _submitMessage();
        _confirmAndReachThreshold(messageId);

        // Don't wait past challenge period
        vm.expectRevert(
            CrossChainMessageVerifier.ChallengePeriodActive.selector
        );
        verifier.executeMessage(messageId);
    }

    function test_ExecuteMessage_RevertAlreadyExecuted() public {
        bytes32 messageId = _submitMessage();
        _confirmAndReachThreshold(messageId);
        vm.warp(block.timestamp + 1 hours + 1);
        verifier.executeMessage(messageId);

        vm.expectRevert(
            CrossChainMessageVerifier.MessageAlreadyExecuted.selector
        );
        verifier.executeMessage(messageId);
    }

    function test_ExecutionReady() public {
        bytes32 messageId = _submitMessage();
        _confirmAndReachThreshold(messageId);

        assertFalse(verifier.isExecutionReady(messageId));

        vm.warp(block.timestamp + 1 hours + 1);
        assertTrue(verifier.isExecutionReady(messageId));
    }

    /*//////////////////////////////////////////////////////////////
                       CHALLENGES
    //////////////////////////////////////////////////////////////*/

    function test_ChallengeMessage() public {
        bytes32 messageId = _submitMessage();
        _confirmAndReachThreshold(messageId);

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        verifier.challengeMessage{value: 0.1 ether}(messageId, "invalid proof");

        (, , , , , , , , , , , bool challenged, ) = verifier.messages(
            messageId
        );
        assertTrue(challenged);
    }

    function test_ChallengeMessage_RevertInsufficientBond() public {
        bytes32 messageId = _submitMessage();
        _confirmAndReachThreshold(messageId);

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(CrossChainMessageVerifier.InsufficientBond.selector);
        verifier.challengeMessage{value: 0.01 ether}(messageId, "invalid");
    }

    function test_ChallengeMessage_RevertNoPeriod() public {
        bytes32 messageId = _submitMessage();
        // No confirmations → challengePeriodEnd = 0

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(
            CrossChainMessageVerifier.ChallengePeriodExpired.selector
        );
        verifier.challengeMessage{value: 0.1 ether}(messageId, "invalid");
    }

    function test_ResolveChallenge_Upheld() public {
        bytes32 messageId = _submitMessage();
        _confirmAndReachThreshold(messageId);

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        verifier.challengeMessage{value: 0.1 ether}(messageId, "invalid proof");

        uint256 balBefore = user1.balance;

        vm.prank(resolver);
        verifier.resolveChallenge(messageId, true);

        // Challenger gets bond back
        assertEq(user1.balance, balBefore + 0.1 ether);
    }

    function test_ResolveChallenge_NotUpheld() public {
        bytes32 messageId = _submitMessage();
        _confirmAndReachThreshold(messageId);

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        verifier.challengeMessage{value: 0.1 ether}(messageId, "invalid");

        vm.prank(resolver);
        verifier.resolveChallenge(messageId, false);

        // Message unchalleng, execution re-enabled
        (, , , , , , , , , , , bool challenged, ) = verifier.messages(
            messageId
        );
        assertFalse(challenged);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetMessageStatus() public {
        bytes32 messageId = _submitMessage();

        // Pending = 0
        assertEq(verifier.getMessageStatus(messageId), 0);

        _confirmAndReachThreshold(messageId);
        // Confirmed = 1
        assertEq(verifier.getMessageStatus(messageId), 1);

        vm.warp(block.timestamp + 1 hours + 1);
        verifier.executeMessage(messageId);
        // Executed = 2
        assertEq(verifier.getMessageStatus(messageId), 2);
    }

    function test_GetMessageStatus_Expired() public {
        bytes32 messageId = _submitMessage();
        vm.warp(block.timestamp + 7 days + 1);

        assertEq(verifier.getMessageStatus(messageId), 4);
    }

    function test_HasReachedThreshold() public {
        bytes32 messageId = _submitMessage();
        assertFalse(verifier.hasReachedThreshold(messageId));

        _confirmAndReachThreshold(messageId);
        assertTrue(verifier.hasReachedThreshold(messageId));
    }

    /*//////////////////////////////////////////////////////////////
                         PAUSE
    //////////////////////////////////////////////////////////////*/

    function test_Pause() public {
        vm.prank(guardian);
        verifier.pause();

        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        _submitMessage();
    }

    function test_Unpause() public {
        vm.prank(guardian);
        verifier.pause();
        verifier.unpause();

        bytes32 id = _submitMessage();
        assertGt(uint256(id), 0);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_ConfirmationWeightAccumulates(
        uint256 weight1,
        uint256 weight2
    ) public {
        weight1 = bound(weight1, 100, 5000);
        weight2 = bound(weight2, 100, 5000);

        // Deploy fresh verifier with custom weights
        CrossChainMessageVerifier v2 = new CrossChainMessageVerifier(
            6000,
            admin
        );
        v2.addSourceChain(SOURCE_CHAIN);

        address v1Addr = makeAddr("fuzz_v1");
        address v2Addr = makeAddr("fuzz_v2");
        v2.addVerifier(v1Addr, weight1);
        v2.addVerifier(v2Addr, weight2);

        bytes32 msgId = v2.submitMessage(SOURCE_CHAIN, keccak256("p"), hex"aa");

        vm.prank(v1Addr);
        v2.confirmMessage(msgId);

        (, , , , , , , , uint256 conf, uint256 totalW, , , ) = v2.messages(
            msgId
        );
        assertEq(conf, 1);
        assertEq(totalW, weight1);
    }
}
