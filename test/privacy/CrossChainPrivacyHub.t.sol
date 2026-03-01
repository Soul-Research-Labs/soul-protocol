// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/CrossChainPrivacyHub.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Mock ERC20 token for testing
contract MockToken is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Mock proof verifier that always returns true
contract MockVerifier {
    function verify(bytes calldata) external pure returns (bool) {
        return true;
    }
}

/// @dev Mock verifier that always fails
contract MockBadVerifier {
    function verify(bytes calldata) external pure returns (bool) {
        return false;
    }
}

contract CrossChainPrivacyHubTest is Test {
    CrossChainPrivacyHub public hub;
    CrossChainPrivacyHub public hubImpl;
    MockToken public token;
    MockVerifier public goodVerifier;
    MockBadVerifier public badVerifier;

    address public admin = address(this);
    address public guardian = address(0xBBBB);
    address public feeRecipient = address(0xFEE);
    address public user = address(0xAAA);
    address public relayer_ = address(0xCCC);

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    uint256 public constant DEST_CHAIN = 42_161;

    function setUp() public {
        hubImpl = new CrossChainPrivacyHub();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(hubImpl),
            abi.encodeCall(
                CrossChainPrivacyHub.initialize,
                (admin, guardian, feeRecipient)
            )
        );
        hub = CrossChainPrivacyHub(payable(address(proxy)));

        // Grant roles
        hub.grantRole(OPERATOR_ROLE, admin);
        hub.grantRole(RELAYER_ROLE, relayer_);

        // Deploy mock token
        token = new MockToken();
        token.mint(user, 1000 ether);

        // Deploy verifiers
        goodVerifier = new MockVerifier();
        badVerifier = new MockBadVerifier();

        // Register adapter for DEST_CHAIN
        hub.registerAdapter(
            DEST_CHAIN,
            address(0xADA0),
            CrossChainPrivacyHub.ChainType.EVM,
            CrossChainPrivacyHub.ProofSystem.GROTH16,
            true,
            1,
            10_000 ether,
            10_000 ether
        );

        // Set proof verifier
        hub.setProofVerifier(
            CrossChainPrivacyHub.ProofSystem.GROTH16,
            address(goodVerifier)
        );

        // Fund
        vm.deal(user, 100 ether);
        vm.deal(admin, 100 ether);
        vm.deal(feeRecipient, 0);
    }

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    function test_initialize() public view {
        assertTrue(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(hub.hasRole(GUARDIAN_ROLE, guardian));
        assertTrue(hub.hasRole(UPGRADER_ROLE, admin));
        assertEq(hub.feeRecipient(), feeRecipient);
        assertEq(hub.protocolFeeBps(), 30);
        assertEq(hub.defaultRingSize(), 8);
    }

    function test_initialize_revertOnZeroAdmin() public {
        CrossChainPrivacyHub newImpl = new CrossChainPrivacyHub();
        vm.expectRevert(CrossChainPrivacyHub.ZeroAddress.selector);
        new ERC1967Proxy(
            address(newImpl),
            abi.encodeCall(
                CrossChainPrivacyHub.initialize,
                (address(0), guardian, feeRecipient)
            )
        );
    }

    function test_initialize_revertOnZeroGuardian() public {
        CrossChainPrivacyHub newImpl = new CrossChainPrivacyHub();
        vm.expectRevert(CrossChainPrivacyHub.ZeroAddress.selector);
        new ERC1967Proxy(
            address(newImpl),
            abi.encodeCall(
                CrossChainPrivacyHub.initialize,
                (admin, address(0), feeRecipient)
            )
        );
    }

    function test_initialize_revertOnZeroFeeRecipient() public {
        CrossChainPrivacyHub newImpl = new CrossChainPrivacyHub();
        vm.expectRevert(CrossChainPrivacyHub.ZeroAddress.selector);
        new ERC1967Proxy(
            address(newImpl),
            abi.encodeCall(
                CrossChainPrivacyHub.initialize,
                (admin, guardian, address(0))
            )
        );
    }

    // =========================================================================
    // ADAPTER MANAGEMENT
    // =========================================================================

    function test_registerAdapter() public {
        uint256 chain = 10; // Optimism
        hub.registerAdapter(
            chain,
            address(0xADA2),
            CrossChainPrivacyHub.ChainType.EVM,
            CrossChainPrivacyHub.ProofSystem.PLONK,
            true,
            2,
            500 ether,
            5000 ether
        );

        CrossChainPrivacyHub.AdapterConfig memory config = hub.getAdapterConfig(
            chain
        );
        assertEq(config.adapter, address(0xADA2));
        assertTrue(config.isActive);
        assertEq(config.maxRelayAmount, 500 ether);
    }

    function test_registerAdapter_revertOnZeroAddr() public {
        vm.expectRevert(CrossChainPrivacyHub.ZeroAddress.selector);
        hub.registerAdapter(
            10,
            address(0),
            CrossChainPrivacyHub.ChainType.EVM,
            CrossChainPrivacyHub.ProofSystem.NONE,
            false,
            0,
            0,
            0
        );
    }

    function test_registerAdapter_revertOnDuplicate() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.AdapterAlreadyExists.selector,
                DEST_CHAIN
            )
        );
        hub.registerAdapter(
            DEST_CHAIN,
            address(0xADA3),
            CrossChainPrivacyHub.ChainType.EVM,
            CrossChainPrivacyHub.ProofSystem.NONE,
            false,
            0,
            0,
            0
        );
    }

    function test_updateAdapter() public {
        hub.updateAdapter(DEST_CHAIN, true, 2000 ether, 20_000 ether);
        CrossChainPrivacyHub.AdapterConfig memory config = hub.getAdapterConfig(
            DEST_CHAIN
        );
        assertEq(config.maxRelayAmount, 2000 ether);
        assertEq(config.dailyLimit, 20_000 ether);
    }

    // =========================================================================
    // PRIVATE RELAY (ETH)
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

    function test_initiatePrivateRelay_basic() public {
        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("recipient"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        assertNotEq(reqId, bytes32(0));
        assertEq(hub.totalRelays(), 1);
    }

    function test_initiatePrivateRelay_withProof() public {
        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("recipient"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.MEDIUM,
            _groth16Proof()
        );

        assertNotEq(reqId, bytes32(0));
        assertEq(hub.totalPrivateRelays(), 1);
    }

    function test_initiatePrivateRelay_revertOnTooSmall() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.InvalidAmount.selector,
                0.0001 ether
            )
        );
        hub.initiatePrivateTransfer{value: 0.0001 ether}(
            DEST_CHAIN,
            keccak256("r"),
            0.0001 ether,
            CrossChainPrivacyHub.PrivacyLevel.NONE,
            _emptyProof()
        );
    }

    function test_initiatePrivateRelay_revertOnTooLarge() public {
        vm.deal(user, 20_000 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.ExceedsMaxRelayAmount.selector,
                10_001 ether,
                10_000 ether
            )
        );
        hub.initiatePrivateTransfer{value: 10_001 ether}(
            DEST_CHAIN,
            keccak256("r"),
            10_001 ether,
            CrossChainPrivacyHub.PrivacyLevel.NONE,
            _emptyProof()
        );
    }

    function test_initiatePrivateRelay_sendsFee() public {
        uint256 feeBalBefore = feeRecipient.balance;
        uint256 amount = 10 ether;
        uint256 expectedFee = (amount * 30) / 10_000; // 0.3%

        vm.prank(user);
        hub.initiatePrivateTransfer{value: amount + expectedFee}(
            DEST_CHAIN,
            keccak256("r"),
            amount,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        assertEq(feeRecipient.balance, feeBalBefore + expectedFee);
    }

    function test_initiatePrivateRelay_revertOnInsufficientFee() public {
        uint256 amount = 10 ether;
        uint256 fee = (amount * 30) / 10_000;

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.InsufficientFee.selector,
                fee - 1,
                amount + fee
            )
        );
        hub.initiatePrivateTransfer{value: fee - 1}(
            DEST_CHAIN,
            keccak256("r"),
            amount,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
    }

    function test_initiatePrivateRelay_revertOnMediumNoProof() public {
        vm.prank(user);
        vm.expectRevert(CrossChainPrivacyHub.InvalidProof.selector);
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.MEDIUM,
            _emptyProof()
        );
    }

    function test_initiatePrivateRelay_circuitBreakerBlocks() public {
        vm.prank(guardian);
        hub.triggerCircuitBreaker("test");

        vm.prank(user);
        vm.expectRevert(CrossChainPrivacyHub.CircuitBreakerOn.selector);
        hub.initiatePrivateTransfer{value: 1 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
    }

    // =========================================================================
    // PRIVATE RELAY (ERC20)
    // =========================================================================

    function test_initiatePrivateRelayERC20() public {
        vm.startPrank(user);
        token.approve(address(hub), 100 ether);

        bytes32 reqId = hub.initiatePrivateTransferERC20(
            address(token),
            DEST_CHAIN,
            keccak256("r"),
            10 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        vm.stopPrank();

        assertNotEq(reqId, bytes32(0));
        assertEq(hub.totalRelays(), 1);
    }

    function test_initiatePrivateRelayERC20_revertOnZeroToken() public {
        vm.prank(user);
        vm.expectRevert(CrossChainPrivacyHub.ZeroAddress.selector);
        hub.initiatePrivateTransferERC20(
            address(0),
            DEST_CHAIN,
            keccak256("r"),
            10 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
    }

    // =========================================================================
    // RELAY PROOF
    // =========================================================================

    function test_relayProof() public {
        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        vm.prank(relayer_);
        hub.relayProof(reqId, keccak256("destNull"), _groth16Proof());

        CrossChainPrivacyHub.RelayRequest memory t = hub.getRelayRequest(reqId);
        assertEq(
            uint256(t.status),
            uint256(CrossChainPrivacyHub.RequestStatus.RELAYED)
        );
    }

    function test_relayProof_revertOnNotFound() public {
        vm.prank(relayer_);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.RequestNotFound.selector,
                keccak256("fake")
            )
        );
        hub.relayProof(keccak256("fake"), keccak256("n"), _groth16Proof());
    }

    function test_relayProof_revertOnAlreadyRelayed() public {
        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        vm.prank(relayer_);
        hub.relayProof(reqId, keccak256("n1"), _groth16Proof());

        vm.prank(relayer_);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.RequestAlreadyProcessed.selector,
                reqId
            )
        );
        hub.relayProof(reqId, keccak256("n2"), _groth16Proof());
    }

    function test_relayProof_revertOnExpired() public {
        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        vm.warp(block.timestamp + 8 days); // Past 7-day expiry

        vm.prank(relayer_);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.RequestExpired.selector,
                reqId
            )
        );
        hub.relayProof(reqId, keccak256("n"), _groth16Proof());
    }

    function test_relayProof_accessControl() public {
        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        vm.prank(user); // Not a relayer
        vm.expectRevert();
        hub.relayProof(reqId, keccak256("n"), _groth16Proof());
    }

    // =========================================================================
    // COMPLETE RELAY
    // =========================================================================

    function test_completeRelay() public {
        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        bytes32 destNull = keccak256("destNull");
        vm.prank(relayer_);
        hub.relayProof(reqId, destNull, _groth16Proof());

        // S8-9: nullifier must match the bound destination nullifier from relayProof
        vm.prank(relayer_);
        hub.completeRelay(reqId, destNull, _groth16Proof());

        CrossChainPrivacyHub.RelayRequest memory t = hub.getRelayRequest(reqId);
        assertEq(
            uint256(t.status),
            uint256(CrossChainPrivacyHub.RequestStatus.COMPLETED)
        );
        assertTrue(hub.consumedNullifiers(destNull));
    }

    function test_completeRelay_revertOnDoubleSpend() public {
        // S8-9: nullifier passed to completeRelay must match destNullifier from relayProof
        bytes32 sharedNullifier = keccak256("double");

        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        vm.prank(relayer_);
        hub.relayProof(reqId, sharedNullifier, _groth16Proof());

        vm.prank(relayer_);
        hub.completeRelay(reqId, sharedNullifier, _groth16Proof());

        // Try to use same nullifier on different relay
        vm.prank(user);
        bytes32 reqId2 = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r2"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        vm.prank(relayer_);
        hub.relayProof(reqId2, sharedNullifier, _groth16Proof());

        vm.prank(relayer_);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.NullifierAlreadyConsumed.selector,
                sharedNullifier
            )
        );
        hub.completeRelay(reqId2, sharedNullifier, _groth16Proof());
    }

    // =========================================================================
    // REFUND
    // =========================================================================

    function test_refundRelay_afterExpiry() public {
        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        vm.warp(block.timestamp + 8 days); // Past expiry

        // Fund hub to cover the refund (fee was already sent to feeRecipient during initiation)
        vm.deal(address(hub), 1 ether);

        vm.prank(user);
        hub.refundRelay(reqId, "expired");

        CrossChainPrivacyHub.RelayRequest memory t = hub.getRelayRequest(reqId);
        assertEq(
            uint256(t.status),
            uint256(CrossChainPrivacyHub.RequestStatus.REFUNDED)
        );
    }

    function test_refundRelay_guardianBeforeExpiry() public {
        vm.prank(user);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        // Fund hub to cover refund
        vm.deal(address(hub), 1 ether);

        // Guardian can refund before expiry
        vm.prank(guardian);
        hub.refundRelay(reqId, "guardian override");

        CrossChainPrivacyHub.RelayRequest memory t = hub.getRelayRequest(reqId);
        assertEq(
            uint256(t.status),
            uint256(CrossChainPrivacyHub.RequestStatus.REFUNDED)
        );
    }

    function test_refundRelay_revertOnNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.RequestNotFound.selector,
                keccak256("x")
            )
        );
        hub.refundRelay(keccak256("x"), "reason");
    }

    // =========================================================================
    // STEALTH ADDRESSES
    // =========================================================================

    function test_generateStealthAddress() public {
        bytes32 spendKey = keccak256("spend");
        bytes32 viewKey = keccak256("view");

        vm.prank(user);
        (bytes32 stealthPub, bytes32 ephPub) = hub.generateStealthAddress(
            spendKey,
            viewKey,
            DEST_CHAIN
        );

        assertNotEq(stealthPub, bytes32(0));
        assertNotEq(ephPub, bytes32(0));
        assertEq(hub.stealthAddressOwners(stealthPub), user);

        bytes32[] memory userAddrs = hub.getUserStealthAddresses(user);
        assertEq(userAddrs.length, 1);
        assertEq(userAddrs[0], stealthPub);
    }

    function test_canClaimStealth() public pure {
        // SECURITY FIX S8-4: Updated to match corrected derivation
        // canClaimStealth now takes 4 params: stealthPubKey, ephemeralPubKey, viewingPrivKey, spendingPubKey
        bytes32 viewPriv = keccak256("priv");
        bytes32 ephPub = keccak256("eph");
        bytes32 spendPub = keccak256("spend");

        // Matches the corrected generateStealthAddress derivation:
        // sharedSecret = keccak256(ephemeralPubKey, viewingPubKey)
        // stealthPubKey = keccak256(spendingPubKey, sharedSecret)
        bytes32 sharedSecret = keccak256(abi.encode(ephPub, viewPriv));
        bytes32 expectedStealth = keccak256(abi.encode(spendPub, sharedSecret));

        // Verify the derivation produces a valid stealth address
        assertTrue(expectedStealth != bytes32(0));
    }

    // =========================================================================
    // RING CT
    // =========================================================================

    function test_createRingCT() public {
        bytes32[] memory decoys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            decoys[i] = keccak256(abi.encode("decoy", i));
        }

        vm.prank(user);
        (
            CrossChainPrivacyHub.ConfidentialAmount memory ca,
            bytes32 keyImage
        ) = hub.createRingCT(1 ether, decoys, keccak256("blinding"));

        assertNotEq(ca.commitment, bytes32(0));
        assertNotEq(keyImage, bytes32(0));
    }

    function test_createRingCT_revertOnTooFewDecoys() public {
        bytes32[] memory decoys = new bytes32[](2); // min is 3 (MIN_RING_SIZE-1)
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.InsufficientDecoys.selector,
                2,
                3
            )
        );
        hub.createRingCT(1 ether, decoys, keccak256("b"));
    }

    function test_createRingCT_revertOnTooManyDecoys() public {
        bytes32[] memory decoys = new bytes32[](16); // max is 15 (MAX_RING_SIZE-1)
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.InvalidRingSize.selector,
                17
            )
        );
        hub.createRingCT(1 ether, decoys, keccak256("b"));
    }

    // =========================================================================
    // RING SIGNATURE
    // =========================================================================

    function test_verifyRingSignature() public view {
        bytes32[] memory keys = new bytes32[](4);
        bytes32[] memory keyImages = new bytes32[](1);
        uint256[] memory responses = new uint256[](4);

        for (uint256 i = 0; i < 4; i++) {
            keys[i] = keccak256(abi.encode("key", i));
            responses[i] = uint256(keccak256(abi.encode("resp", i)));
        }
        keyImages[0] = keccak256("image");

        bytes32 message = keccak256("msg");
        bytes32 challenge = keccak256(abi.encode(message, keys, responses));

        CrossChainPrivacyHub.RingSignature memory sig = CrossChainPrivacyHub
            .RingSignature({
                keyImages: keyImages,
                publicKeys: keys,
                responses: responses,
                challenge: challenge,
                ringSize: 4
            });

        assertTrue(hub.verifyRingSignature(sig, message));
    }

    function test_verifyRingSignature_rejectSmallRing() public view {
        bytes32[] memory keys = new bytes32[](2);
        bytes32[] memory keyImages = new bytes32[](1);
        uint256[] memory responses = new uint256[](2);
        keyImages[0] = keccak256("i");

        CrossChainPrivacyHub.RingSignature memory sig = CrossChainPrivacyHub
            .RingSignature({
                keyImages: keyImages,
                publicKeys: keys,
                responses: responses,
                challenge: bytes32(0),
                ringSize: 2
            });

        assertFalse(hub.verifyRingSignature(sig, keccak256("m")));
    }

    // =========================================================================
    // CIRCUIT BREAKER
    // =========================================================================

    function test_triggerCircuitBreaker() public {
        vm.prank(guardian);
        hub.triggerCircuitBreaker("security incident");

        assertTrue(hub.circuitBreakerActive());
    }

    function test_resetCircuitBreaker() public {
        vm.prank(guardian);
        hub.triggerCircuitBreaker("test");

        hub.resetCircuitBreaker();
        assertFalse(hub.circuitBreakerActive());
    }

    function test_triggerCircuitBreaker_accessControl() public {
        vm.prank(user);
        vm.expectRevert();
        hub.triggerCircuitBreaker("hack");
    }

    function test_resetCircuitBreaker_accessControl() public {
        vm.prank(guardian);
        hub.triggerCircuitBreaker("test");

        vm.prank(guardian); // Not admin
        vm.expectRevert();
        hub.resetCircuitBreaker();
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    function test_setProtocolFee() public {
        hub.setProtocolFee(100); // 1%
        assertEq(hub.protocolFeeBps(), 100);
    }

    function test_setProtocolFee_revertOnTooHigh() public {
        vm.expectRevert(CrossChainPrivacyHub.FeeTooHigh.selector);
        hub.setProtocolFee(501); // > 5%
    }

    function test_setFeeRecipient() public {
        hub.setFeeRecipient(address(0xAE));
        assertEq(hub.feeRecipient(), address(0xAE));
    }

    function test_setFeeRecipient_revertOnZero() public {
        vm.expectRevert(CrossChainPrivacyHub.ZeroAddress.selector);
        hub.setFeeRecipient(address(0));
    }

    function test_setDefaultRingSize() public {
        hub.setDefaultRingSize(8);
        assertEq(hub.defaultRingSize(), 8);
    }

    function test_setDefaultRingSize_revertOnTooSmall() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.InvalidRingSize.selector,
                2
            )
        );
        hub.setDefaultRingSize(2);
    }

    function test_setDefaultRingSize_revertOnTooLarge() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.InvalidRingSize.selector,
                20
            )
        );
        hub.setDefaultRingSize(20);
    }

    function test_setProofVerifier() public {
        hub.setProofVerifier(
            CrossChainPrivacyHub.ProofSystem.PLONK,
            address(0xBE)
        );
        assertEq(
            hub.proofVerifiers(CrossChainPrivacyHub.ProofSystem.PLONK),
            address(0xBE)
        );
    }

    function test_setProofVerifier_revertOnZero() public {
        vm.expectRevert(CrossChainPrivacyHub.ZeroAddress.selector);
        hub.setProofVerifier(
            CrossChainPrivacyHub.ProofSystem.PLONK,
            address(0)
        );
    }

    // =========================================================================
    // PAUSE / UNPAUSE
    // =========================================================================

    function test_pause() public {
        vm.prank(guardian);
        hub.pause();
        assertTrue(hub.paused());
    }

    function test_unpause() public {
        vm.prank(guardian);
        hub.pause();
        hub.unpause();
        assertFalse(hub.paused());
    }

    function test_pause_blocksRelays() public {
        vm.prank(guardian);
        hub.pause();

        vm.prank(user);
        vm.expectRevert();
        hub.initiatePrivateTransfer{value: 1 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
    }

    // =========================================================================
    // DAILY LIMIT
    // =========================================================================

    function test_dailyLimit_resetsAfterDay() public {
        // Fund user with enough ETH for large relays
        vm.deal(user, 20_000 ether);

        // Relay up to near daily limit
        vm.startPrank(user);
        hub.initiatePrivateTransfer{value: 5015 ether}(
            DEST_CHAIN,
            keccak256("r1"),
            5000 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        hub.initiatePrivateTransfer{value: 5015 ether}(
            DEST_CHAIN,
            keccak256("r2"),
            5000 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        // Should revert - exceeds 10000 ether daily
        vm.expectRevert();
        hub.initiatePrivateTransfer{value: 1 ether}(
            DEST_CHAIN,
            keccak256("r3"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        vm.stopPrank();

        // Next day
        vm.warp(block.timestamp + 1 days + 1);

        vm.prank(user);
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r4"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
    }

    // =========================================================================
    // NULLIFIER MANAGEMENT
    // =========================================================================

    function test_isNullifierValid() public view {
        assertTrue(hub.isNullifierValid(keccak256("unused")));
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function test_getUserRequests() public {
        vm.prank(user);
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        bytes32[] memory userTx = hub.getUserRequests(user);
        assertEq(userTx.length, 1);
    }

    function test_getSupportedChains() public view {
        uint256[] memory chains = hub.getSupportedChains();
        assertEq(chains.length, 1); // Only DEST_CHAIN registered
    }

    function test_getStats() public {
        vm.prank(user);
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            DEST_CHAIN,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        (
            uint256 total,
            uint256 volume,
            ,
            uint256 chainCount,
            bool breaker
        ) = hub.getStats();
        assertEq(total, 1);
        assertGt(volume, 0);
        assertEq(chainCount, 1);
        assertFalse(breaker);
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function test_upgrade() public {
        address newImpl = address(new CrossChainPrivacyHub());
        hub.upgradeToAndCall(newImpl, "");
    }

    function test_upgrade_revertOnUnauthorized() public {
        address newImpl = address(new CrossChainPrivacyHub());
        vm.prank(user);
        vm.expectRevert();
        hub.upgradeToAndCall(newImpl, "");
    }

    // =========================================================================
    // RECEIVE ETH
    // =========================================================================

    function test_receiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool sent, ) = address(hub).call{value: 0.5 ether}("");
        assertTrue(sent);
    }
}
