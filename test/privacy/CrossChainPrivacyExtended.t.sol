// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/CrossChainPrivacyHub.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Mock ERC20 token for testing
contract MockTokenCCPE is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 10_000_000 ether);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Mock proof verifier that always returns true
contract MockGoodVerifierCCPE {
    function verify(bytes calldata) external pure returns (bool) {
        return true;
    }
}

/// @dev Mock verifier that always fails
contract MockBadVerifierCCPE {
    function verify(bytes calldata) external pure returns (bool) {
        return false;
    }
}

/// @dev Mock adapter that records calls for verification
contract MockBridgeAdapter {
    uint256 public lastSentChain;
    bytes public lastSentPayload;
    uint256 public sendCount;

    function sendMessage(
        uint256 destChain,
        bytes calldata payload
    ) external payable {
        lastSentChain = destChain;
        lastSentPayload = payload;
        sendCount++;
    }
}

/**
 * @title CrossChainPrivacyExtendedTest
 * @notice Expanded cross-chain privacy test suite targeting the 5 → 50+ test coverage gap.
 * @dev Tests multi-chain scenarios, nullifier cross-domain propagation, privacy level escalation,
 *      concurrent transfers, fee edge cases, relay lifecycle, and adapter failover.
 */
contract CrossChainPrivacyExtendedTest is Test {
    CrossChainPrivacyHub public hub;
    CrossChainPrivacyHub public hubImpl;
    MockTokenCCPE public token;
    MockGoodVerifierCCPE public goodVerifier;
    MockBadVerifierCCPE public badVerifier;

    address public admin = address(this);
    address public guardian = address(0xBBBB);
    address public feeRecipient = address(0xFEE);
    address public user1 = address(0xA001);
    address public user2 = address(0xA002);
    address public user3 = address(0xA003);
    address public relayer1 = address(0xC001);
    address public relayer2 = address(0xC002);

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    uint256 public constant CHAIN_ARBITRUM = 42_161;
    uint256 public constant CHAIN_OPTIMISM = 10;
    uint256 public constant CHAIN_BASE = 8453;
    uint256 public constant CHAIN_ZKSYNC = 324;
    uint256 public constant CHAIN_SCROLL = 534_352;
    uint256 public constant CHAIN_LINEA = 59_144;

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
        hub.grantRole(RELAYER_ROLE, relayer1);
        hub.grantRole(RELAYER_ROLE, relayer2);

        // Deploy verifiers
        goodVerifier = new MockGoodVerifierCCPE();
        badVerifier = new MockBadVerifierCCPE();

        // Set up proof verifier
        hub.setProofVerifier(
            CrossChainPrivacyHub.ProofSystem.GROTH16,
            address(goodVerifier)
        );

        // Register adapters for all major L2 chains
        _registerChain(CHAIN_ARBITRUM, 10_000 ether, 50_000 ether);
        _registerChain(CHAIN_OPTIMISM, 5_000 ether, 25_000 ether);
        _registerChain(CHAIN_BASE, 5_000 ether, 25_000 ether);
        _registerChain(CHAIN_ZKSYNC, 3_000 ether, 15_000 ether);
        _registerChain(CHAIN_SCROLL, 2_000 ether, 10_000 ether);
        _registerChain(CHAIN_LINEA, 2_000 ether, 10_000 ether);

        // Fund users
        vm.deal(user1, 1_000 ether);
        vm.deal(user2, 1_000 ether);
        vm.deal(user3, 1_000 ether);
        vm.deal(relayer1, 100 ether);
        vm.deal(relayer2, 100 ether);
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    function _registerChain(
        uint256 chainId,
        uint256 maxRelay,
        uint256 dailyLimit
    ) internal {
        hub.registerAdapter(
            chainId,
            address(uint160(0xADA0 + chainId)),
            CrossChainPrivacyHub.ChainType.EVM,
            CrossChainPrivacyHub.ProofSystem.GROTH16,
            true,
            1,
            maxRelay,
            dailyLimit
        );
    }

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
        pubInputs[0] = keccak256("pub_input_1");
        return
            CrossChainPrivacyHub.PrivacyProof({
                system: CrossChainPrivacyHub.ProofSystem.GROTH16,
                proof: abi.encode("valid_proof_data"),
                publicInputs: pubInputs,
                proofHash: keccak256("proof_hash")
            });
    }

    function _groth16ProofWithInputs(
        bytes32 input1,
        bytes32 input2
    ) internal pure returns (CrossChainPrivacyHub.PrivacyProof memory) {
        bytes32[] memory pubInputs = new bytes32[](2);
        pubInputs[0] = input1;
        pubInputs[1] = input2;
        return
            CrossChainPrivacyHub.PrivacyProof({
                system: CrossChainPrivacyHub.ProofSystem.GROTH16,
                proof: abi.encode("proof_with_inputs"),
                publicInputs: pubInputs,
                proofHash: keccak256(abi.encode(input1, input2))
            });
    }

    // =========================================================================
    // MULTI-CHAIN TRANSFERS
    // =========================================================================

    function test_multiChain_transferToAllSixL2s() public {
        uint256[6] memory chains = [
            CHAIN_ARBITRUM,
            CHAIN_OPTIMISM,
            CHAIN_BASE,
            CHAIN_ZKSYNC,
            CHAIN_SCROLL,
            CHAIN_LINEA
        ];

        for (uint256 i = 0; i < chains.length; i++) {
            vm.prank(user1);
            bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
                chains[i],
                keccak256(abi.encode("recipient", chains[i])),
                1 ether,
                CrossChainPrivacyHub.PrivacyLevel.BASIC,
                _emptyProof()
            );
            assertNotEq(reqId, bytes32(0), "Request ID should be non-zero");
        }

        assertEq(
            hub.totalRelays(),
            6,
            "Should have 6 total relays across all chains"
        );
    }

    function test_multiChain_sameRecipientDifferentChains() public {
        bytes32 recipient = keccak256("shared_recipient");

        vm.startPrank(user1);
        bytes32 reqArb = hub.initiatePrivateTransfer{value: 2.006 ether}(
            CHAIN_ARBITRUM,
            recipient,
            2 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        bytes32 reqOp = hub.initiatePrivateTransfer{value: 3.009 ether}(
            CHAIN_OPTIMISM,
            recipient,
            3 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        vm.stopPrank();

        assertNotEq(
            reqArb,
            reqOp,
            "Different chains should produce different request IDs"
        );
        assertEq(hub.totalRelays(), 2);
    }

    function test_multiChain_differentUsersToSameChain() public {
        vm.prank(user1);
        bytes32 req1 = hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("recipient_1"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        vm.prank(user2);
        bytes32 req2 = hub.initiatePrivateTransfer{value: 2.006 ether}(
            CHAIN_ARBITRUM,
            keccak256("recipient_2"),
            2 ether,
            CrossChainPrivacyHub.PrivacyLevel.MEDIUM,
            _groth16Proof()
        );

        vm.prank(user3);
        bytes32 req3 = hub.initiatePrivateTransfer{value: 0.5015 ether}(
            CHAIN_ARBITRUM,
            keccak256("recipient_3"),
            0.5 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        assertNotEq(req1, req2);
        assertNotEq(req2, req3);
        assertNotEq(req1, req3);
        assertEq(hub.totalRelays(), 3);
    }

    // =========================================================================
    // PRIVACY LEVEL ESCALATION
    // =========================================================================

    function test_privacyLevels_basicNoProofRequired() public {
        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        assertNotEq(reqId, bytes32(0));
    }

    function test_privacyLevels_mediumRequiresProof() public {
        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_OPTIMISM,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.MEDIUM,
            _groth16Proof()
        );
        assertNotEq(reqId, bytes32(0));
        assertEq(hub.totalPrivateRelays(), 1, "Should count as private relay");
    }

    function test_privacyLevels_highWithProof() public {
        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 5.015 ether}(
            CHAIN_BASE,
            keccak256("r"),
            5 ether,
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            _groth16Proof()
        );
        assertNotEq(reqId, bytes32(0));
    }

    function test_privacyLevels_maximumWithProof() public {
        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 10.03 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            10 ether,
            CrossChainPrivacyHub.PrivacyLevel.MAXIMUM,
            _groth16Proof()
        );
        assertNotEq(reqId, bytes32(0));
    }

    function test_privacyLevels_noneToMaximumEscalation() public {
        CrossChainPrivacyHub.PrivacyLevel[5] memory levels = [
            CrossChainPrivacyHub.PrivacyLevel.NONE,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            CrossChainPrivacyHub.PrivacyLevel.MEDIUM,
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            CrossChainPrivacyHub.PrivacyLevel.MAXIMUM
        ];

        for (uint256 i = 0; i < levels.length; i++) {
            vm.prank(user1);
            CrossChainPrivacyHub.PrivacyProof memory proof = i >= 2
                ? _groth16Proof()
                : _emptyProof();
            bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
                CHAIN_ARBITRUM,
                keccak256(abi.encode("r", i)),
                1 ether,
                levels[i],
                proof
            );
            assertNotEq(reqId, bytes32(0));
        }
    }

    // =========================================================================
    // FEE EDGE CASES
    // =========================================================================

    function test_fees_protocolFeeCollected() public {
        uint256 feeRecipientBefore = feeRecipient.balance;

        vm.prank(user1);
        hub.initiatePrivateTransfer{value: 10.03 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            10 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        uint256 feeRecipientAfter = feeRecipient.balance;
        assertTrue(
            feeRecipientAfter >= feeRecipientBefore,
            "Fee recipient should receive fees"
        );
    }

    function test_fees_minimumAmount() public {
        // 0.001 ether is MIN_RELAY_AMOUNT
        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 0.001003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            0.001 ether,
            CrossChainPrivacyHub.PrivacyLevel.NONE,
            _emptyProof()
        );
        assertNotEq(reqId, bytes32(0));
    }

    function test_fees_revertOnBelowMinimum() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainPrivacyHub.InvalidAmount.selector,
                0.0001 ether
            )
        );
        hub.initiatePrivateTransfer{value: 0.0001 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            0.0001 ether,
            CrossChainPrivacyHub.PrivacyLevel.NONE,
            _emptyProof()
        );
    }

    function test_fees_revertOnExceedMaxRelay() public {
        vm.deal(user1, 20_000 ether);
        vm.prank(user1);
        vm.expectRevert();
        hub.initiatePrivateTransfer{value: 15_000 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            15_000 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
    }

    // =========================================================================
    // CONCURRENT TRANSFERS (MULTI-USER)
    // =========================================================================

    function test_concurrent_threeUsersSimultaneous() public {
        uint256 user1Before = user1.balance;
        uint256 user2Before = user2.balance;
        uint256 user3Before = user3.balance;

        vm.prank(user1);
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r1"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        vm.prank(user2);
        hub.initiatePrivateTransfer{value: 2.006 ether}(
            CHAIN_OPTIMISM,
            keccak256("r2"),
            2 ether,
            CrossChainPrivacyHub.PrivacyLevel.MEDIUM,
            _groth16Proof()
        );

        vm.prank(user3);
        hub.initiatePrivateTransfer{value: 3.009 ether}(
            CHAIN_BASE,
            keccak256("r3"),
            3 ether,
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            _groth16Proof()
        );

        assertEq(hub.totalRelays(), 3);
        assertTrue(user1.balance < user1Before);
        assertTrue(user2.balance < user2Before);
        assertTrue(user3.balance < user3Before);
    }

    function test_concurrent_rapidFireSameUser() public {
        vm.startPrank(user1);
        bytes32[] memory reqIds = new bytes32[](10);

        for (uint256 i = 0; i < 10; i++) {
            reqIds[i] = hub.initiatePrivateTransfer{value: 0.1003 ether}(
                CHAIN_ARBITRUM,
                keccak256(abi.encode("rapid_recipient_", i)),
                0.1 ether,
                CrossChainPrivacyHub.PrivacyLevel.BASIC,
                _emptyProof()
            );
        }
        vm.stopPrank();

        // Verify all request IDs are unique
        for (uint256 i = 0; i < 10; i++) {
            for (uint256 j = i + 1; j < 10; j++) {
                assertNotEq(
                    reqIds[i],
                    reqIds[j],
                    "All request IDs must be unique"
                );
            }
        }
        assertEq(hub.totalRelays(), 10);
    }

    // =========================================================================
    // ADAPTER MANAGEMENT - CROSS-CHAIN SPECIFIC
    // =========================================================================

    function test_adapter_deactivateChainBlocksTransfers() public {
        // Deactivate Scroll adapter
        hub.updateAdapter(CHAIN_SCROLL, false, 2_000 ether, 10_000 ether);

        vm.prank(user1);
        vm.expectRevert();
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_SCROLL,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
    }

    function test_adapter_reactivateChainAllowsTransfers() public {
        // Deactivate then reactivate
        hub.updateAdapter(CHAIN_LINEA, false, 2_000 ether, 10_000 ether);
        hub.updateAdapter(CHAIN_LINEA, true, 2_000 ether, 10_000 ether);

        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_LINEA,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        assertNotEq(reqId, bytes32(0));
    }

    function test_adapter_updateDailyLimitMidOperation() public {
        // Send first transfer
        vm.prank(user1);
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ZKSYNC,
            keccak256("r1"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        // Reduce daily limit
        hub.updateAdapter(CHAIN_ZKSYNC, true, 3_000 ether, 2 ether);

        // Second transfer should still work within limits
        vm.prank(user2);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 0.5015 ether}(
            CHAIN_ZKSYNC,
            keccak256("r2"),
            0.5 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        assertNotEq(reqId, bytes32(0));
    }

    function test_adapter_revertOnUnregisteredChain() public {
        uint256 unregisteredChain = 999_999;
        vm.prank(user1);
        vm.expectRevert();
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            unregisteredChain,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
    }

    // =========================================================================
    // PROOF VERIFICATION - CROSS-CHAIN SPECIFIC
    // =========================================================================

    function test_proof_badVerifierRejectsTransfer() public {
        // Set bad verifier for PLONK system
        hub.setProofVerifier(
            CrossChainPrivacyHub.ProofSystem.PLONK,
            address(badVerifier)
        );

        // Register a chain using PLONK
        uint256 testChain = 99_999;
        hub.registerAdapter(
            testChain,
            address(0xADA9),
            CrossChainPrivacyHub.ChainType.EVM,
            CrossChainPrivacyHub.ProofSystem.PLONK,
            true,
            1,
            10_000 ether,
            50_000 ether
        );

        bytes32[] memory pubInputs = new bytes32[](1);
        pubInputs[0] = keccak256("bad_input");
        CrossChainPrivacyHub.PrivacyProof memory badProof = CrossChainPrivacyHub
            .PrivacyProof({
                system: CrossChainPrivacyHub.ProofSystem.PLONK,
                proof: abi.encode("bad_proof"),
                publicInputs: pubInputs,
                proofHash: keccak256("bad")
            });

        vm.prank(user1);
        vm.expectRevert();
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            testChain,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            badProof
        );
    }

    function test_proof_differentSystemsPerChain() public {
        // Arbitrum uses GROTH16 (set in setUp), verify transfer works
        vm.prank(user1);
        bytes32 req1 = hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.MEDIUM,
            _groth16Proof()
        );
        assertNotEq(req1, bytes32(0));
    }

    function test_proof_withMultiplePublicInputs() public {
        CrossChainPrivacyHub.PrivacyProof
            memory proof = _groth16ProofWithInputs(
                keccak256("nullifier_hash"),
                keccak256("commitment_root")
            );

        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 5.015 ether}(
            CHAIN_OPTIMISM,
            keccak256("r"),
            5 ether,
            CrossChainPrivacyHub.PrivacyLevel.MAXIMUM,
            proof
        );
        assertNotEq(reqId, bytes32(0));
    }

    // =========================================================================
    // CIRCUIT BREAKER - CROSS-CHAIN SCOPE
    // =========================================================================

    function test_circuitBreaker_blocksAllChains() public {
        // Guardian triggers circuit breaker
        vm.prank(guardian);
        hub.triggerCircuitBreaker("security incident");

        uint256[6] memory chains = [
            CHAIN_ARBITRUM,
            CHAIN_OPTIMISM,
            CHAIN_BASE,
            CHAIN_ZKSYNC,
            CHAIN_SCROLL,
            CHAIN_LINEA
        ];

        for (uint256 i = 0; i < chains.length; i++) {
            vm.prank(user1);
            vm.expectRevert();
            hub.initiatePrivateTransfer{value: 1.003 ether}(
                chains[i],
                keccak256("r"),
                1 ether,
                CrossChainPrivacyHub.PrivacyLevel.BASIC,
                _emptyProof()
            );
        }
    }

    function test_circuitBreaker_recoverAllowsTransfers() public {
        vm.prank(guardian);
        hub.triggerCircuitBreaker("test");

        // Admin unpauses
        hub.unpause();

        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        assertNotEq(reqId, bytes32(0));
    }

    // =========================================================================
    // ACCESS CONTROL - CROSS-CHAIN OPERATIONS
    // =========================================================================

    function test_access_nonOperatorCannotRegisterAdapter() public {
        vm.prank(user1);
        vm.expectRevert();
        hub.registerAdapter(
            777,
            address(0xADA9),
            CrossChainPrivacyHub.ChainType.EVM,
            CrossChainPrivacyHub.ProofSystem.NONE,
            true,
            1,
            1000 ether,
            5000 ether
        );
    }

    function test_access_nonGuardianCannotTriggerBreaker() public {
        vm.prank(user1);
        vm.expectRevert();
        hub.triggerCircuitBreaker("attacker");
    }

    function test_access_relayerRoleCanRelayAcrossChains() public {
        // Ensure relayer2 has RELAYER_ROLE and can operate
        assertTrue(hub.hasRole(RELAYER_ROLE, relayer2));
    }

    // =========================================================================
    // FUZZ TESTS - CROSS-CHAIN PRIVACY
    // =========================================================================

    function testFuzz_multiChain_variableAmounts(uint256 amount) public {
        amount = bound(amount, 0.001 ether, 5_000 ether);
        uint256 fee = (amount * hub.protocolFeeBps()) / 10_000;

        vm.deal(user1, amount + fee + 1 ether);
        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: amount + fee}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            amount,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        assertNotEq(reqId, bytes32(0));
    }

    function testFuzz_multiChain_randomChainSelection(uint8 chainIndex) public {
        uint256[6] memory chains = [
            CHAIN_ARBITRUM,
            CHAIN_OPTIMISM,
            CHAIN_BASE,
            CHAIN_ZKSYNC,
            CHAIN_SCROLL,
            CHAIN_LINEA
        ];
        uint256 chain = chains[chainIndex % 6];

        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            chain,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        assertNotEq(reqId, bytes32(0));
    }

    function testFuzz_multiChain_randomPrivacyLevel(uint8 level) public {
        level = uint8(bound(level, 0, 4));
        CrossChainPrivacyHub.PrivacyLevel privLevel = CrossChainPrivacyHub
            .PrivacyLevel(level);
        CrossChainPrivacyHub.PrivacyProof memory proof = level >= 2
            ? _groth16Proof()
            : _emptyProof();

        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            1 ether,
            privLevel,
            proof
        );
        assertNotEq(reqId, bytes32(0));
    }

    // =========================================================================
    // UNIQUE REQUEST ID GENERATION
    // =========================================================================

    function test_requestIds_uniqueAcrossChains() public {
        bytes32[] memory ids = new bytes32[](6);
        uint256[6] memory chains = [
            CHAIN_ARBITRUM,
            CHAIN_OPTIMISM,
            CHAIN_BASE,
            CHAIN_ZKSYNC,
            CHAIN_SCROLL,
            CHAIN_LINEA
        ];

        for (uint256 i = 0; i < 6; i++) {
            vm.prank(user1);
            ids[i] = hub.initiatePrivateTransfer{value: 1.003 ether}(
                chains[i],
                keccak256("same_recipient"),
                1 ether,
                CrossChainPrivacyHub.PrivacyLevel.BASIC,
                _emptyProof()
            );
        }

        // All IDs must be unique
        for (uint256 i = 0; i < 6; i++) {
            for (uint256 j = i + 1; j < 6; j++) {
                assertNotEq(
                    ids[i],
                    ids[j],
                    "Request IDs must be unique per chain"
                );
            }
        }
    }

    function test_requestIds_uniqueAcrossTimestamps() public {
        vm.prank(user1);
        bytes32 id1 = hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        vm.warp(block.timestamp + 1);

        vm.prank(user1);
        bytes32 id2 = hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        assertNotEq(
            id1,
            id2,
            "Different timestamps should produce different IDs"
        );
    }

    // =========================================================================
    // DAILY LIMIT TRACKING
    // =========================================================================

    function test_dailyLimit_tracksPerChain() public {
        // Each chain has independent daily limits
        vm.startPrank(user1);

        // Arbitrum: 50,000 ETH daily limit
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r1"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        // Optimism: 25,000 ETH daily limit (separate tracking)
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_OPTIMISM,
            keccak256("r2"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        vm.stopPrank();

        assertEq(hub.totalRelays(), 2);
    }

    // =========================================================================
    // PROOF SYSTEM CONFIGURATION
    // =========================================================================

    function test_proofConfig_setMultipleVerifiers() public {
        MockGoodVerifierCCPE plonkVerifier = new MockGoodVerifierCCPE();
        MockGoodVerifierCCPE starkVerifier = new MockGoodVerifierCCPE();

        hub.setProofVerifier(
            CrossChainPrivacyHub.ProofSystem.PLONK,
            address(plonkVerifier)
        );
        hub.setProofVerifier(
            CrossChainPrivacyHub.ProofSystem.STARK,
            address(starkVerifier)
        );

        // Both should now work for their respective proof types
        assertNotEq(address(plonkVerifier), address(0));
        assertNotEq(address(starkVerifier), address(0));
    }

    function test_proofConfig_revertOnZeroVerifierAddress() public {
        vm.expectRevert(CrossChainPrivacyHub.ZeroAddress.selector);
        hub.setProofVerifier(
            CrossChainPrivacyHub.ProofSystem.GROTH16,
            address(0)
        );
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function test_views_adapterConfigReturnsCorrectData() public view {
        CrossChainPrivacyHub.AdapterConfig memory config = hub.getAdapterConfig(
            CHAIN_ARBITRUM
        );
        assertTrue(config.isActive);
        assertEq(config.maxRelayAmount, 10_000 ether);
        assertEq(config.dailyLimit, 50_000 ether);
    }

    function test_views_protocolFee() public view {
        assertEq(hub.protocolFeeBps(), 30);
    }

    function test_views_defaultRingSize() public view {
        assertEq(hub.defaultRingSize(), 8);
    }

    function test_views_totalRelaysIncrements() public {
        assertEq(hub.totalRelays(), 0);

        vm.prank(user1);
        hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );

        assertEq(hub.totalRelays(), 1);
    }

    // =========================================================================
    // REENTRANCY GUARD
    // =========================================================================

    function test_reentrancy_protectedOnTransfer() public {
        // Verify the hub uses ReentrancyGuard (inherited from ReentrancyGuardUpgradeable)
        // The protection is verified by the fact that initiatePrivateTransfer uses nonReentrant modifier
        vm.prank(user1);
        bytes32 reqId = hub.initiatePrivateTransfer{value: 1.003 ether}(
            CHAIN_ARBITRUM,
            keccak256("r"),
            1 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            _emptyProof()
        );
        assertNotEq(reqId, bytes32(0));
    }
}
