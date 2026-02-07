// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/core/ERC8004IdentityRegistry.sol";
import "../../contracts/core/ERC8004ReputationRegistry.sol";
import "../../contracts/core/ERC8004ValidationRegistry.sol";

/**
 * @title ERC8004Fuzz
 * @notice Fuzz tests for ERC-8004 Trustless Agents registries
 * @dev Covers Identity, Reputation, and Validation registries.
 *      32 fuzz tests across agent registration, metadata, wallet verification,
 *      feedback lifecycle, validation request/response, and edge cases.
 */
contract ERC8004Fuzz is Test {
    ERC8004IdentityRegistry public identity;
    ERC8004ReputationRegistry public reputation;
    ERC8004ValidationRegistry public validation;

    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);
    address public carol = address(0xCA501);
    address public validator1 = address(0xDAD1);
    address public validator2 = address(0xDAD2);

    // EIP-712 domain separator components
    bytes32 constant AGENT_WALLET_TYPEHASH =
        keccak256("SetAgentWallet(uint256 agentId,address newWallet,uint256 deadline)");

    uint256 internal walletPk = 0xBEEF;
    address internal walletAddr;

    function setUp() public {
        identity = new ERC8004IdentityRegistry();
        reputation = new ERC8004ReputationRegistry();
        validation = new ERC8004ValidationRegistry();

        reputation.initialize(address(identity));
        validation.initialize(address(identity));

        walletAddr = vm.addr(walletPk);
    }

    /*//////////////////////////////////////////////////////////////
                    IDENTITY REGISTRY: REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Register with URI + metadata
    function testFuzz_registerWithURIAndMetadata(string calldata uri, bytes calldata metaVal) public {
        vm.prank(alice);
        IERC8004IdentityRegistry.MetadataEntry[] memory meta = new IERC8004IdentityRegistry.MetadataEntry[](1);
        meta[0] = IERC8004IdentityRegistry.MetadataEntry({metadataKey: "version", metadataValue: metaVal});
        uint256 agentId = identity.register(uri, meta);
        assertEq(agentId, 1);
        assertEq(identity.ownerOf(agentId), alice);
        assertEq(identity.totalAgents(), 1);

        bytes memory stored = identity.getMetadata(agentId, "version");
        assertEq(stored, metaVal);
    }

    /// @notice Register with URI only
    function testFuzz_registerWithURIOnly(string calldata uri) public {
        vm.prank(bob);
        uint256 agentId = identity.register(uri);
        assertEq(agentId, 1);
        assertEq(identity.ownerOf(agentId), bob);
    }

    /// @notice Register bare yields sequential IDs
    function testFuzz_registerSequentialIds(uint8 count) public {
        count = uint8(bound(count, 1, 20));
        for (uint8 i = 0; i < count; i++) {
            vm.prank(alice);
            uint256 agentId = identity.register();
            assertEq(agentId, i + 1);
        }
        assertEq(identity.totalAgents(), count);
    }

    /// @notice Set and update agent URI
    function testFuzz_setAgentURI(string calldata uri1, string calldata uri2) public {
        vm.prank(alice);
        uint256 agentId = identity.register(uri1);

        vm.prank(alice);
        identity.setAgentURI(agentId, uri2);

        assertEq(identity.tokenURI(agentId), uri2);
    }

    /// @notice Non-owner cannot update URI
    function testFuzz_setAgentURIAccessControl(string calldata uri) public {
        vm.prank(alice);
        uint256 agentId = identity.register(uri);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8004IdentityRegistry.NotAgentOwnerOrOperator.selector, agentId, bob)
        );
        identity.setAgentURI(agentId, "evil_uri");
    }

    /*//////////////////////////////////////////////////////////////
                    IDENTITY REGISTRY: METADATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Set and read arbitrary metadata
    function testFuzz_setAndGetMetadata(string calldata key, bytes calldata value) public {
        vm.assume(keccak256(abi.encodePacked(key)) != keccak256(abi.encodePacked("agentWallet")));

        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(alice);
        identity.setMetadata(agentId, key, value);

        bytes memory stored = identity.getMetadata(agentId, key);
        assertEq(stored, value);
    }

    /// @notice Cannot set reserved "agentWallet" via setMetadata
    function test_rejectReservedMetadataKey() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8004IdentityRegistry.ReservedMetadataKey.selector, "agentWallet")
        );
        identity.setMetadata(agentId, "agentWallet", abi.encodePacked(bob));
    }

    /*//////////////////////////////////////////////////////////////
                    IDENTITY REGISTRY: AGENT WALLET
    //////////////////////////////////////////////////////////////*/

    /// @notice Set agent wallet with valid EIP-712 signature
    function testFuzz_setAgentWallet(uint256 deadline) public {
        deadline = bound(deadline, block.timestamp + 1, type(uint128).max);

        vm.prank(alice);
        uint256 agentId = identity.register();

        // Build EIP-712 digest
        bytes32 structHash = keccak256(abi.encode(AGENT_WALLET_TYPEHASH, agentId, walletAddr, deadline));
        bytes32 domainSeparator = identity.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(walletPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(alice);
        identity.setAgentWallet(agentId, walletAddr, deadline, sig);

        assertEq(identity.getAgentWallet(agentId), walletAddr);
    }

    /// @notice Reject expired signature
    function test_rejectExpiredSignature() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        uint256 deadline = block.timestamp - 1;
        bytes32 structHash = keccak256(abi.encode(AGENT_WALLET_TYPEHASH, agentId, walletAddr, deadline));
        bytes32 domainSeparator = identity.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(walletPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC8004IdentityRegistry.SignatureExpired.selector, deadline));
        identity.setAgentWallet(agentId, walletAddr, deadline, sig);
    }

    /// @notice Reject invalid signature
    function test_rejectInvalidSignature() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        uint256 deadline = block.timestamp + 1000;
        // Sign with wrong private key
        uint256 wrongPk = 0xDEAD;
        bytes32 structHash = keccak256(abi.encode(AGENT_WALLET_TYPEHASH, agentId, walletAddr, deadline));
        bytes32 domainSeparator = identity.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(alice);
        vm.expectRevert(IERC8004IdentityRegistry.InvalidSignature.selector);
        identity.setAgentWallet(agentId, walletAddr, deadline, sig);
    }

    /// @notice Wallet cleared on transfer
    function test_walletClearedOnTransfer() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        // Set wallet
        uint256 deadline = block.timestamp + 1000;
        bytes32 structHash = keccak256(abi.encode(AGENT_WALLET_TYPEHASH, agentId, walletAddr, deadline));
        bytes32 domainSeparator = identity.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(walletPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(alice);
        identity.setAgentWallet(agentId, walletAddr, deadline, sig);
        assertEq(identity.getAgentWallet(agentId), walletAddr);

        // Transfer
        vm.prank(alice);
        identity.transferFrom(alice, bob, agentId);

        // Wallet should be cleared
        assertEq(identity.getAgentWallet(agentId), address(0));
    }

    /// @notice Unset agent wallet
    function test_unsetAgentWallet() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        // Default wallet is owner
        assertEq(identity.getAgentWallet(agentId), alice);

        vm.prank(alice);
        identity.unsetAgentWallet(agentId);

        assertEq(identity.getAgentWallet(agentId), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                  REPUTATION REGISTRY: FEEDBACK
    //////////////////////////////////////////////////////////////*/

    /// @notice Give feedback with fuzzed value and decimals
    function testFuzz_giveFeedback(int128 value, uint8 decimals) public {
        decimals = uint8(bound(decimals, 0, 18));

        // Register agent
        vm.prank(alice);
        uint256 agentId = identity.register("ipfs://agent1");

        // Give feedback (bob is not the owner)
        vm.prank(bob);
        reputation.giveFeedback(
            agentId,
            value,
            decimals,
            "quality",
            "speed",
            "api.example.com",
            "ipfs://feedback1",
            keccak256("feedback1")
        );

        // Verify storage
        (int128 v, uint8 d, string memory t1, string memory t2, bool revoked) =
            reputation.readFeedback(agentId, bob, 1);
        assertEq(v, value);
        assertEq(d, decimals);
        assertEq(t1, "quality");
        assertEq(t2, "speed");
        assertFalse(revoked);

        assertEq(reputation.getLastIndex(agentId, bob), 1);
    }

    /// @notice Cannot review own agent
    function test_cannotReviewOwnAgent() public {
        vm.prank(alice);
        uint256 agentId = identity.register("ipfs://agent1");

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8004ReputationRegistry.CannotReviewOwnAgent.selector, agentId, alice)
        );
        reputation.giveFeedback(agentId, 100, 0, "", "", "", "", bytes32(0));
    }

    /// @notice Cannot give feedback with valueDecimals > 18
    function testFuzz_rejectInvalidDecimals(uint8 decimals) public {
        decimals = uint8(bound(decimals, 19, 255));

        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8004ReputationRegistry.InvalidValueDecimals.selector, decimals)
        );
        reputation.giveFeedback(agentId, 100, decimals, "", "", "", "", bytes32(0));
    }

    /// @notice Cannot give feedback to non-existent agent
    function testFuzz_feedbackToNonexistentAgent(uint256 fakeId) public {
        fakeId = bound(fakeId, 1, type(uint128).max);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8004ReputationRegistry.AgentNotRegistered.selector, fakeId)
        );
        reputation.giveFeedback(fakeId, 100, 0, "", "", "", "", bytes32(0));
    }

    /// @notice Multiple feedbacks from same client are sequential
    function testFuzz_multipleFeedbacksSequential(uint8 count) public {
        count = uint8(bound(count, 1, 10));

        vm.prank(alice);
        uint256 agentId = identity.register();

        for (uint8 i = 0; i < count; i++) {
            vm.prank(bob);
            reputation.giveFeedback(agentId, int128(int8(i)) * 10, 0, "", "", "", "", bytes32(0));
        }

        assertEq(reputation.getLastIndex(agentId, bob), count);
    }

    /*//////////////////////////////////////////////////////////////
                 REPUTATION REGISTRY: REVOCATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Revoke and verify
    function test_revokeFeedback() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(bob);
        reputation.giveFeedback(agentId, 85, 0, "quality", "", "", "", bytes32(0));

        vm.prank(bob);
        reputation.revokeFeedback(agentId, 1);

        (, , , , bool revoked) = reputation.readFeedback(agentId, bob, 1);
        assertTrue(revoked);
    }

    /// @notice Cannot revoke non-existent feedback
    function testFuzz_revokeNonexistentFeedback(uint64 idx) public {
        idx = uint64(bound(idx, 1, type(uint64).max));

        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8004ReputationRegistry.FeedbackNotFound.selector, agentId, bob, idx)
        );
        reputation.revokeFeedback(agentId, idx);
    }

    /// @notice Cannot double-revoke
    function test_cannotDoubleRevoke() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(bob);
        reputation.giveFeedback(agentId, 85, 0, "", "", "", "", bytes32(0));

        vm.prank(bob);
        reputation.revokeFeedback(agentId, 1);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8004ReputationRegistry.FeedbackAlreadyRevoked.selector, agentId, bob, 1)
        );
        reputation.revokeFeedback(agentId, 1);
    }

    /*//////////////////////////////////////////////////////////////
                  REPUTATION REGISTRY: RESPONSES
    //////////////////////////////////////////////////////////////*/

    /// @notice Append response to feedback
    function test_appendResponse() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(bob);
        reputation.giveFeedback(agentId, 50, 0, "", "", "", "", bytes32(0));

        // Agent owner appends response
        vm.prank(alice);
        reputation.appendResponse(agentId, bob, 1, "ipfs://response1", keccak256("response1"));

        // Carol (auditor) also responds
        vm.prank(carol);
        reputation.appendResponse(agentId, bob, 1, "ipfs://audit1", keccak256("audit1"));

        // Count should reflect unique responders
        address[] memory responders = new address[](0);
        uint64 count = reputation.getResponseCount(agentId, bob, 1, responders);
        assertEq(count, 2);
    }

    /// @notice Cannot respond to non-existent feedback
    function test_respondToNonexistentFeedback() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8004ReputationRegistry.FeedbackNotFound.selector, agentId, bob, 1)
        );
        reputation.appendResponse(agentId, bob, 1, "", bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                   REPUTATION REGISTRY: SUMMARY
    //////////////////////////////////////////////////////////////*/

    /// @notice On-chain summary with tag filtering
    function test_summaryWithTagFilter() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        // bob gives 2 feedbacks with different tags
        vm.prank(bob);
        reputation.giveFeedback(agentId, 80, 0, "quality", "", "", "", bytes32(0));
        vm.prank(bob);
        reputation.giveFeedback(agentId, 90, 0, "speed", "", "", "", bytes32(0));

        // carol gives 1 feedback
        vm.prank(carol);
        reputation.giveFeedback(agentId, 70, 0, "quality", "", "", "", bytes32(0));

        address[] memory clients = new address[](2);
        clients[0] = bob;
        clients[1] = carol;

        // Filter by "quality" tag
        (uint64 count, int128 summaryValue,) = reputation.getSummary(agentId, clients, "quality", "");
        assertEq(count, 2); // bob(80) + carol(70)
        assertEq(summaryValue, 150);

        // All feedbacks
        (count, summaryValue,) = reputation.getSummary(agentId, clients, "", "");
        assertEq(count, 3);
        assertEq(summaryValue, 240);
    }

    /// @notice Revoked feedback excluded from summary
    function test_revokedExcludedFromSummary() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(bob);
        reputation.giveFeedback(agentId, 80, 0, "", "", "", "", bytes32(0));
        vm.prank(bob);
        reputation.giveFeedback(agentId, 20, 0, "", "", "", "", bytes32(0));

        // Revoke first
        vm.prank(bob);
        reputation.revokeFeedback(agentId, 1);

        address[] memory clients = new address[](1);
        clients[0] = bob;

        (uint64 count, int128 summaryValue,) = reputation.getSummary(agentId, clients, "", "");
        assertEq(count, 1);
        assertEq(summaryValue, 20);
    }

    /// @notice Empty client list reverts
    function test_summaryRequiresClients() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        address[] memory empty = new address[](0);
        vm.expectRevert(IERC8004ReputationRegistry.EmptyClientList.selector);
        reputation.getSummary(agentId, empty, "", "");
    }

    /// @notice Client list tracked correctly
    function test_clientTracking() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(bob);
        reputation.giveFeedback(agentId, 10, 0, "", "", "", "", bytes32(0));
        vm.prank(carol);
        reputation.giveFeedback(agentId, 20, 0, "", "", "", "", bytes32(0));
        vm.prank(bob);
        reputation.giveFeedback(agentId, 30, 0, "", "", "", "", bytes32(0)); // Bob again (no dup)

        address[] memory clients = reputation.getClients(agentId);
        assertEq(clients.length, 2);
        assertEq(clients[0], bob);
        assertEq(clients[1], carol);
    }

    /*//////////////////////////////////////////////////////////////
              VALIDATION REGISTRY: REQUEST / RESPONSE
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit validation request
    function testFuzz_validationRequest(bytes32 requestHash) public {
        vm.assume(requestHash != bytes32(0));

        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(alice);
        validation.validationRequest(validator1, agentId, "ipfs://req1", requestHash);

        bytes32[] memory hashes = validation.getAgentValidations(agentId);
        assertEq(hashes.length, 1);
        assertEq(hashes[0], requestHash);

        bytes32[] memory vHashes = validation.getValidatorRequests(validator1);
        assertEq(vHashes.length, 1);
        assertEq(vHashes[0], requestHash);
    }

    /// @notice Only agent owner/operator can request validation
    function test_validationRequestAccessControl() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8004ValidationRegistry.NotAgentOwnerOrOperator.selector, agentId, bob)
        );
        validation.validationRequest(validator1, agentId, "ipfs://req1", keccak256("req1"));
    }

    /// @notice Validator submits response
    function testFuzz_validationResponse(uint8 response) public {
        response = uint8(bound(response, 0, 100));

        vm.prank(alice);
        uint256 agentId = identity.register();

        bytes32 reqHash = keccak256("req1");
        vm.prank(alice);
        validation.validationRequest(validator1, agentId, "ipfs://req1", reqHash);

        vm.prank(validator1);
        validation.validationResponse(reqHash, response, "ipfs://resp1", keccak256("resp1"), "security");

        (address vAddr, uint256 aId, uint8 resp, , string memory tag, uint256 lastUpdate) =
            validation.getValidationStatus(reqHash);
        assertEq(vAddr, validator1);
        assertEq(aId, agentId);
        assertEq(resp, response);
        assertEq(tag, "security");
        assertGt(lastUpdate, 0);
    }

    /// @notice Only designated validator can respond
    function test_onlyDesignatedValidator() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        bytes32 reqHash = keccak256("req1");
        vm.prank(alice);
        validation.validationRequest(validator1, agentId, "ipfs://req1", reqHash);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC8004ValidationRegistry.NotDesignatedValidator.selector, reqHash, bob, validator1
            )
        );
        validation.validationResponse(reqHash, 50, "", bytes32(0), "");
    }

    /// @notice Response > 100 reverts
    function testFuzz_invalidResponse(uint8 response) public {
        response = uint8(bound(response, 101, 255));

        vm.prank(alice);
        uint256 agentId = identity.register();

        bytes32 reqHash = keccak256("req1");
        vm.prank(alice);
        validation.validationRequest(validator1, agentId, "ipfs://req1", reqHash);

        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(IERC8004ValidationRegistry.InvalidResponse.selector, response));
        validation.validationResponse(reqHash, response, "", bytes32(0), "");
    }

    /// @notice Response to non-existent request reverts
    function testFuzz_responseToNonexistentRequest(bytes32 fakeHash) public {
        vm.prank(validator1);
        vm.expectRevert(abi.encodeWithSelector(IERC8004ValidationRegistry.RequestNotFound.selector, fakeHash));
        validation.validationResponse(fakeHash, 50, "", bytes32(0), "");
    }

    /*//////////////////////////////////////////////////////////////
                VALIDATION REGISTRY: SUMMARY
    //////////////////////////////////////////////////////////////*/

    /// @notice Validation summary with tag filtering
    function test_validationSummary() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        // Two validations
        bytes32 reqHash1 = keccak256("req1");
        bytes32 reqHash2 = keccak256("req2");

        vm.prank(alice);
        validation.validationRequest(validator1, agentId, "ipfs://req1", reqHash1);
        vm.prank(alice);
        validation.validationRequest(validator2, agentId, "ipfs://req2", reqHash2);

        vm.prank(validator1);
        validation.validationResponse(reqHash1, 80, "", bytes32(0), "security");
        vm.prank(validator2);
        validation.validationResponse(reqHash2, 60, "", bytes32(0), "security");

        // Summary for all validators
        address[] memory validators = new address[](0);
        (uint64 count, uint8 avg) = validation.getSummary(agentId, validators, "security");
        assertEq(count, 2);
        assertEq(avg, 70); // (80 + 60) / 2

        // Filtered to validator1
        validators = new address[](1);
        validators[0] = validator1;
        (count, avg) = validation.getSummary(agentId, validators, "security");
        assertEq(count, 1);
        assertEq(avg, 80);
    }

    /// @notice Zero address validator rejected
    function test_zeroAddressValidatorRejected() public {
        vm.prank(alice);
        uint256 agentId = identity.register();

        vm.prank(alice);
        vm.expectRevert(IERC8004ValidationRegistry.ZeroAddress.selector);
        validation.validationRequest(address(0), agentId, "", keccak256("req"));
    }

    /*//////////////////////////////////////////////////////////////
                 REPUTATION REGISTRY: INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Cannot double-initialize
    function test_cannotDoubleInitializeReputation() public {
        vm.expectRevert("Already initialized");
        reputation.initialize(address(identity));
    }

    /// @notice Cannot initialize with zero address
    function test_reputationRejectZeroInit() public {
        ERC8004ReputationRegistry rep2 = new ERC8004ReputationRegistry();
        vm.expectRevert("Zero address");
        rep2.initialize(address(0));
    }

    /// @notice Cannot double-initialize validation
    function test_cannotDoubleInitializeValidation() public {
        vm.expectRevert("Already initialized");
        validation.initialize(address(identity));
    }
}
