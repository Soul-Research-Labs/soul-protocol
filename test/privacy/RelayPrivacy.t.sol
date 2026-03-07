// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/CrossChainPrivacyHub.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @dev Mock proof verifier that always returns true
contract MockRelayVerifier {
    function verify(bytes calldata) external pure returns (bool) {
        return true;
    }
}

/**
 * @title RelayPrivacyTest
 * @notice Tests for relay jitter and multi-relayer quorum features
 */
contract RelayPrivacyTest is Test {
    CrossChainPrivacyHub public hub;
    MockRelayVerifier public verifier;

    address public admin = address(this);
    address public guardian = makeAddr("guardian");
    address public feeRecipient = makeAddr("feeRecipient");
    address public user = makeAddr("user");
    address public relayer1 = makeAddr("relayer1");
    address public relayer2 = makeAddr("relayer2");
    address public relayer3 = makeAddr("relayer3");

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    uint256 constant DEST_CHAIN = 42161;

    function setUp() public {
        CrossChainPrivacyHub impl = new CrossChainPrivacyHub();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                CrossChainPrivacyHub.initialize,
                (admin, guardian, feeRecipient)
            )
        );
        hub = CrossChainPrivacyHub(payable(address(proxy)));

        // Grant roles
        hub.grantRole(OPERATOR_ROLE, admin);
        hub.grantRole(RELAYER_ROLE, relayer1);
        hub.grantRole(RELAYER_ROLE, relayer2);
        hub.grantRole(RELAYER_ROLE, relayer3);

        // Deploy mock verifier
        verifier = new MockRelayVerifier();
        hub.setProofVerifier(
            CrossChainPrivacyHub.ProofSystem.GROTH16,
            address(verifier)
        );

        // Register adapter for DEST_CHAIN
        hub.registerAdapter(
            CrossChainPrivacyHub.AdapterRegistrationParams({
                chainId: DEST_CHAIN,
                adapter: address(0xADA0),
                chainType: CrossChainPrivacyHub.ChainType.EVM,
                proofSystem: CrossChainPrivacyHub.ProofSystem.GROTH16,
                supportsPrivacy: true,
                minConfirmations: 1,
                maxTransfer: 10_000 ether,
                dailyLimit: 10_000 ether
            })
        );

        // Set default jitter params (storage initializers don't apply through proxy)
        hub.configureRelayJitter(5 minutes, 25 minutes);

        // Fund user
        vm.deal(user, 100 ether);
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    function _emptyProof()
        internal
        pure
        returns (CrossChainPrivacyHub.PrivacyProof memory)
    {
        bytes32[] memory pubInputs = new bytes32[](0);
        return
            CrossChainPrivacyHub.PrivacyProof({
                system: CrossChainPrivacyHub.ProofSystem.NONE,
                proof: "",
                publicInputs: pubInputs,
                proofHash: bytes32(0)
            });
    }

    function _groth16Proof()
        internal
        pure
        returns (CrossChainPrivacyHub.PrivacyProof memory)
    {
        bytes32[] memory pubInputs = new bytes32[](1);
        pubInputs[0] = keccak256("input1");
        return
            CrossChainPrivacyHub.PrivacyProof({
                system: CrossChainPrivacyHub.ProofSystem.GROTH16,
                proof: abi.encode("valid_proof"),
                publicInputs: pubInputs,
                proofHash: keccak256("proof")
            });
    }

    function _initTransfer() internal returns (bytes32 requestId) {
        vm.prank(user);
        requestId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("recipient"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
    }

    function _initHighTransfer() internal returns (bytes32 requestId) {
        vm.prank(user);
        requestId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("recipient"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            _groth16Proof()
        );
    }

    // =========================================================================
    // RELAY JITTER TESTS
    // =========================================================================

    function test_relayJitter_disabledByDefault() public {
        bytes32 reqId = _initTransfer();

        // No jitter set
        assertEq(hub.transferRelayableAt(reqId), 0, "No jitter by default");

        // Relay should succeed immediately
        vm.prank(relayer1);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());
    }

    function test_relayJitter_setsRelayableAt() public {
        hub.setRelayJitterEnabled(true);

        bytes32 reqId = _initTransfer();

        uint64 relayableAt = hub.transferRelayableAt(reqId);
        assertGt(relayableAt, 0, "Should set relayableAt");
        assertGe(
            relayableAt,
            uint64(block.timestamp + hub.minRelayJitter()),
            "Must be at least minJitter in the future"
        );
        assertLe(
            relayableAt,
            uint64(
                block.timestamp + hub.minRelayJitter() + hub.maxRelayJitter()
            ),
            "Must not exceed max total jitter"
        );
    }

    function test_relayJitter_blocksEarlyRelay() public {
        hub.setRelayJitterEnabled(true);

        bytes32 reqId = _initTransfer();
        uint64 relayableAt = hub.transferRelayableAt(reqId);

        // Try to relay before jitter expires
        vm.prank(relayer1);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.TransferNotYetRelayable.selector,
                reqId,
                relayableAt
            )
        );
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());
    }

    function test_relayJitter_allowsAfterDelay() public {
        hub.setRelayJitterEnabled(true);

        bytes32 reqId = _initTransfer();
        uint64 relayableAt = hub.transferRelayableAt(reqId);

        // Advance time past jitter
        vm.warp(relayableAt);

        vm.prank(relayer1);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());

        // Verify status is RELAYED
        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            CrossChainPrivacyHub.TransferStatus status
        ) = hub.transfers(reqId);
        assertEq(
            uint8(status),
            uint8(CrossChainPrivacyHub.TransferStatus.RELAYED)
        );
    }

    function test_configureRelayJitter() public {
        hub.configureRelayJitter(10 minutes, 50 minutes);
        assertEq(hub.minRelayJitter(), 10 minutes);
        assertEq(hub.maxRelayJitter(), 50 minutes);
    }

    function test_configureRelayJitter_revertsExcessiveMin() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.InvalidAmount.selector,
                2 hours
            )
        );
        hub.configureRelayJitter(2 hours, 30 minutes);
    }

    function test_configureRelayJitter_revertsExcessiveMax() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.InvalidAmount.selector,
                7 hours
            )
        );
        hub.configureRelayJitter(5 minutes, 7 hours);
    }

    function test_setRelayJitterEnabled_onlyOperator() public {
        vm.prank(user);
        vm.expectRevert();
        hub.setRelayJitterEnabled(true);
    }

    function testFuzz_relayJitter_inRange(uint256 blockSeed) public {
        // Use different prevrandao values for different jitter outcomes
        vm.prevrandao(bytes32(blockSeed));
        hub.setRelayJitterEnabled(true);

        bytes32 reqId = _initTransfer();
        uint64 relayableAt = hub.transferRelayableAt(reqId);

        uint256 minExpected = block.timestamp + hub.minRelayJitter();
        uint256 maxExpected = block.timestamp +
            hub.minRelayJitter() +
            hub.maxRelayJitter();
        assertGe(relayableAt, minExpected, "Below min");
        assertLe(relayableAt, maxExpected, "Above max");
    }

    // =========================================================================
    // MULTI-RELAYER QUORUM TESTS
    // =========================================================================

    function test_multiRelayer_defaultSingleRelayer() public {
        bytes32 reqId = _initTransfer();

        // Single relayer should fully relay
        vm.prank(relayer1);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            CrossChainPrivacyHub.TransferStatus status
        ) = hub.transfers(reqId);
        assertEq(
            uint8(status),
            uint8(CrossChainPrivacyHub.TransferStatus.RELAYED)
        );
    }

    function test_multiRelayer_requiresTwoConfirmations() public {
        // Set HIGH privacy to require 2 confirmations
        hub.setRequiredRelayConfirmations(
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            2
        );

        bytes32 reqId = _initHighTransfer();

        // First relayer confirms — status should still be PENDING
        vm.prank(relayer1);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            CrossChainPrivacyHub.TransferStatus status1
        ) = hub.transfers(reqId);
        assertEq(
            uint8(status1),
            uint8(CrossChainPrivacyHub.TransferStatus.PENDING),
            "Should stay PENDING after 1st confirmation"
        );
        assertEq(hub.relayConfirmationCount(reqId), 1);

        // Second relayer confirms — status should transition to RELAYED
        vm.prank(relayer2);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            CrossChainPrivacyHub.TransferStatus status2
        ) = hub.transfers(reqId);
        assertEq(
            uint8(status2),
            uint8(CrossChainPrivacyHub.TransferStatus.RELAYED),
            "Should be RELAYED after 2nd confirmation"
        );
        assertEq(hub.relayConfirmationCount(reqId), 2);
    }

    function test_multiRelayer_sameRelayerCannotConfirmTwice() public {
        hub.setRequiredRelayConfirmations(
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            2
        );

        bytes32 reqId = _initHighTransfer();

        // First confirmation
        vm.prank(relayer1);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());

        // Same relayer tries again — should revert
        vm.prank(relayer1);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.TransferAlreadyProcessed.selector,
                reqId
            )
        );
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());
    }

    function test_multiRelayer_threeConfirmations() public {
        hub.setRequiredRelayConfirmations(
            CrossChainPrivacyHub.PrivacyLevel.MAXIMUM,
            3
        );

        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("recipient"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.MAXIMUM,
            _groth16Proof()
        );

        // 1st confirmation
        vm.prank(relayer1);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());
        assertEq(hub.relayConfirmationCount(reqId), 1);

        // 2nd confirmation
        vm.prank(relayer2);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());
        assertEq(hub.relayConfirmationCount(reqId), 2);

        // Still PENDING
        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            CrossChainPrivacyHub.TransferStatus status2
        ) = hub.transfers(reqId);
        assertEq(
            uint8(status2),
            uint8(CrossChainPrivacyHub.TransferStatus.PENDING)
        );

        // 3rd confirmation — reaches quorum
        vm.prank(relayer3);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());
        assertEq(hub.relayConfirmationCount(reqId), 3);

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            CrossChainPrivacyHub.TransferStatus status3
        ) = hub.transfers(reqId);
        assertEq(
            uint8(status3),
            uint8(CrossChainPrivacyHub.TransferStatus.RELAYED)
        );
    }

    function test_setRequiredRelayConfirmations_onlyOperator() public {
        vm.prank(user);
        vm.expectRevert();
        hub.setRequiredRelayConfirmations(
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            2
        );
    }

    function test_setRequiredRelayConfirmations_revertsTooHigh() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.InvalidAmount.selector,
                uint256(11)
            )
        );
        hub.setRequiredRelayConfirmations(
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            11
        );
    }

    function test_multiRelayer_emitsConfirmationEvent() public {
        hub.setRequiredRelayConfirmations(
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            2
        );

        bytes32 reqId = _initHighTransfer();

        vm.prank(relayer1);
        vm.expectEmit(true, true, false, true);
        emit CrossChainPrivacyHub.RelayConfirmationReceived(
            reqId,
            relayer1,
            1,
            2
        );
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());
    }

    // =========================================================================
    // COMBINED: JITTER + QUORUM
    // =========================================================================

    function test_combined_jitterAndQuorum() public {
        hub.setRelayJitterEnabled(true);
        hub.setRequiredRelayConfirmations(
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            2
        );

        bytes32 reqId = _initHighTransfer();
        uint64 relayableAt = hub.transferRelayableAt(reqId);

        // Relayer1 tries early — blocked by jitter
        vm.prank(relayer1);
        vm.expectRevert();
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());

        // Advance past jitter
        vm.warp(relayableAt);

        // Relayer1 confirms
        vm.prank(relayer1);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());

        // Still PENDING (quorum = 2)
        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            CrossChainPrivacyHub.TransferStatus status1
        ) = hub.transfers(reqId);
        assertEq(
            uint8(status1),
            uint8(CrossChainPrivacyHub.TransferStatus.PENDING)
        );

        // Relayer2 confirms — reaches quorum
        vm.prank(relayer2);
        hub.relayTransfer(reqId, keccak256("destNull"), _groth16Proof());

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            CrossChainPrivacyHub.TransferStatus status2
        ) = hub.transfers(reqId);
        assertEq(
            uint8(status2),
            uint8(CrossChainPrivacyHub.TransferStatus.RELAYED)
        );
    }
}
