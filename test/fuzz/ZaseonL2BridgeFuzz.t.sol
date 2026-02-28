// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/BaseBridgeAdapter.sol";
import "../../contracts/crosschain/ArbitrumBridgeAdapter.sol";

/**
 * @title ZaseonL2BridgeFuzz
 * @notice Fuzz tests for Base and Arbitrum bridge adapters
 * @dev Tests cross-domain messaging, proof relay, and security invariants
 *      Updated to use BaseBridgeAdapter after L2 consolidation
 *
 * Run with: forge test --match-contract ZaseonL2BridgeFuzz --fuzz-runs 10000
 */
contract ZaseonL2BridgeFuzz is Test {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant MIN_GAS_LIMIT = 100000;
    uint256 constant MAX_GAS_LIMIT = 30000000;
    uint256 constant WITHDRAWAL_PERIOD = 604800; // 7 days

    // Chain IDs
    uint256 constant ETH_MAINNET = 1;
    uint256 constant ETH_SEPOLIA = 11155111;
    uint256 constant BASE = 8453;
    uint256 constant BASE_SEPOLIA = 84532;
    uint256 constant ARB_ONE = 42161;

    // CCTP domains
    uint32 constant CCTP_ETH_DOMAIN = 0;
    uint32 constant CCTP_BASE_DOMAIN = 6;

    /*//////////////////////////////////////////////////////////////
                              CONTRACTS
    //////////////////////////////////////////////////////////////*/

    BaseBridgeAdapter public baseL1Adapter;
    BaseBridgeAdapter public baseL2Adapter;
    ArbitrumBridgeAdapter public arbitrumAdapter;

    address public admin = address(0x1);
    address public operator = address(0x2);
    address public guardian = address(0x3);
    address public user = address(0x4);
    address public mockMessenger = address(0x5);
    address public mockPortal = address(0x6);
    address public mockTarget = address(0x7);
    address public mockUSDC = address(0x8);
    address public mockCCTP = address(0x9);

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy Base adapters
        baseL1Adapter = new BaseBridgeAdapter(
            admin,
            mockMessenger,
            mockMessenger,
            mockPortal,
            true // isL1
        );

        baseL2Adapter = new BaseBridgeAdapter(
            admin,
            mockMessenger,
            mockMessenger,
            mockPortal,
            false // isL2
        );

        // Deploy Arbitrum adapter
        arbitrumAdapter = new ArbitrumBridgeAdapter(admin);

        // Configure L2 targets
        baseL1Adapter.setL2Target(mockTarget);

        // Configure CCTP for Base
        baseL1Adapter.configureCCTP(mockCCTP, mockUSDC);

        // Grant roles
        bytes32 CCTP_ROLE = keccak256("CCTP_ROLE");
        bytes32 RELAYER_ROLE = keccak256("RELAYER_ROLE");
        baseL1Adapter.grantRole(CCTP_ROLE, admin);
        baseL2Adapter.grantRole(RELAYER_ROLE, admin);

        vm.stopPrank();

        // Fund contracts
        vm.deal(admin, 100 ether);
        vm.deal(user, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    BASE PROOF RELAY FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Base proof hash uniqueness
    function testFuzz_BaseProofHashUniqueness(
        bytes32 proofHash1,
        bytes32 proofHash2
    ) public {
        vm.assume(proofHash1 != proofHash2);
        vm.assume(proofHash1 != bytes32(0));
        vm.assume(proofHash2 != bytes32(0));

        vm.startPrank(admin);

        // Relay first proof
        baseL2Adapter.receiveProofFromL1(
            proofHash1,
            hex"1234",
            hex"5678",
            ETH_MAINNET
        );

        // Relay second proof
        baseL2Adapter.receiveProofFromL1(
            proofHash2,
            hex"1234",
            hex"5678",
            ETH_MAINNET
        );

        // Both should be relayed
        assertTrue(baseL2Adapter.isProofRelayed(proofHash1));
        assertTrue(baseL2Adapter.isProofRelayed(proofHash2));

        vm.stopPrank();
    }

    /// @notice Fuzz test proof replay prevention
    function testFuzz_BaseProofReplayPrevention(
        bytes32 proofHash,
        bytes memory proof,
        bytes memory publicInputs
    ) public {
        vm.assume(proofHash != bytes32(0));
        vm.assume(proof.length > 0 && proof.length < 10000);
        vm.assume(publicInputs.length > 0 && publicInputs.length < 10000);

        vm.startPrank(admin);

        // First relay should succeed
        baseL2Adapter.receiveProofFromL1(
            proofHash,
            proof,
            publicInputs,
            ETH_MAINNET
        );

        // Second relay should fail
        vm.expectRevert(BaseBridgeAdapter.ProofAlreadyRelayed.selector);
        baseL2Adapter.receiveProofFromL1(
            proofHash,
            proof,
            publicInputs,
            ETH_MAINNET
        );

        vm.stopPrank();
    }

    /// @notice Fuzz test gas limit validation
    function testFuzz_BaseGasLimitValidation(
        uint256 gasLimit,
        bytes32 proofHash
    ) public {
        vm.assume(proofHash != bytes32(0));

        vm.startPrank(admin);
        vm.deal(admin, 10 ether);

        if (gasLimit < MIN_GAS_LIMIT) {
            vm.expectRevert(BaseBridgeAdapter.InsufficientGasLimit.selector);
            baseL1Adapter.sendProofToL2{value: 0.01 ether}(
                proofHash,
                hex"1234",
                hex"5678",
                gasLimit
            );
        } else if (gasLimit <= MAX_GAS_LIMIT) {
            // Should succeed
            baseL1Adapter.sendProofToL2{value: 0.01 ether}(
                proofHash,
                hex"1234",
                hex"5678",
                gasLimit
            );
        }

        vm.stopPrank();
    }

    /// @notice Fuzz test message counter increments
    function testFuzz_BaseMessageCounterIncrements(uint8 numMessages) public {
        vm.assume(numMessages > 0 && numMessages <= 20);

        vm.startPrank(admin);
        vm.deal(admin, 100 ether);

        uint256 initialNonce = baseL1Adapter.messageNonce();

        for (uint8 i = 0; i < numMessages; i++) {
            bytes32 proofHash = keccak256(abi.encodePacked("proof", i));
            baseL1Adapter.sendProofToL2{value: 0.01 ether}(
                proofHash,
                hex"1234",
                hex"5678",
                MIN_GAS_LIMIT
            );
        }

        uint256 finalNonce = baseL1Adapter.messageNonce();
        assertEq(finalNonce, initialNonce + numMessages);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                       CCTP FUZZ TESTS (BASE)
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test CCTP amount validation
    function testFuzz_CCTPAmountValidation(uint256 amount) public {
        vm.startPrank(admin);

        if (amount == 0) {
            vm.expectRevert(BaseBridgeAdapter.InvalidAmount.selector);
            baseL1Adapter.initiateUSDCTransfer(user, amount, CCTP_BASE_DOMAIN);
        } else {
            // Should succeed (CCTP configured in setUp)
            baseL1Adapter.initiateUSDCTransfer(user, amount, CCTP_BASE_DOMAIN);
        }

        vm.stopPrank();
    }

    /// @notice Fuzz test CCTP nonce increments
    function testFuzz_CCTPNonceIncrements(uint8 numTransfers) public {
        vm.assume(numTransfers > 0 && numTransfers <= 20);

        vm.startPrank(admin);

        uint64 initialNonce = baseL1Adapter.cctpNonce();

        for (uint8 i = 0; i < numTransfers; i++) {
            baseL1Adapter.initiateUSDCTransfer(user, 1000000, CCTP_BASE_DOMAIN);
        }

        uint64 finalNonce = baseL1Adapter.cctpNonce();
        assertEq(finalNonce, initialNonce + numTransfers);

        vm.stopPrank();
    }

    /// @notice Fuzz test CCTP total tracking
    function testFuzz_CCTPTotalTracking(
        uint64 amount1,
        uint64 amount2,
        uint64 amount3
    ) public {
        vm.assume(amount1 > 0);
        vm.assume(amount2 > 0);
        vm.assume(amount3 > 0);

        vm.startPrank(admin);

        baseL1Adapter.initiateUSDCTransfer(user, amount1, CCTP_BASE_DOMAIN);
        baseL1Adapter.initiateUSDCTransfer(user, amount2, CCTP_BASE_DOMAIN);
        baseL1Adapter.initiateUSDCTransfer(user, amount3, CCTP_BASE_DOMAIN);

        (, , , uint256 totalUSDC, ) = baseL1Adapter.getStats();

        uint256 expectedTotal = uint256(amount1) +
            uint256(amount2) +
            uint256(amount3);
        assertEq(totalUSDC, expectedTotal);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    ATTESTATION FUZZ TESTS (BASE)
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test attestation sync
    function testFuzz_AttestationSync(
        bytes32 attestationId,
        address subject,
        bytes32 schemaId,
        bytes memory data
    ) public {
        vm.assume(attestationId != bytes32(0));
        vm.assume(subject != address(0));
        vm.assume(schemaId != bytes32(0));
        vm.assume(data.length > 0 && data.length < 10000);

        vm.startPrank(admin);

        baseL1Adapter.syncAttestation(attestationId, subject, schemaId, data);

        BaseBridgeAdapter.AttestationSync memory attestation = baseL1Adapter
            .getAttestation(attestationId);

        assertEq(attestation.attestationId, attestationId);
        assertEq(attestation.subject, subject);
        assertEq(attestation.schemaId, schemaId);
        assertTrue(attestation.synced);
        assertGt(attestation.timestamp, 0);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                      WITHDRAWAL FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test withdrawal amount tracking
    function testFuzz_WithdrawalAmountTracking(uint128 amount) public {
        vm.assume(amount > 0);

        vm.startPrank(admin);
        vm.deal(admin, uint256(amount) + 1 ether);

        bytes32 proofHash = keccak256(abi.encodePacked("withdrawal-proof"));

        baseL2Adapter.initiateWithdrawal{value: amount}(proofHash);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                      STATE SYNC FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test state root storage
    function testFuzz_StateRootStorage(
        bytes32 stateRoot,
        uint256 blockNumber
    ) public {
        vm.assume(stateRoot != bytes32(0));
        vm.assume(blockNumber > 0);

        vm.startPrank(admin);

        baseL2Adapter.receiveStateFromL1(stateRoot, blockNumber);

        uint256 storedBlock = baseL2Adapter.confirmedStateRoots(stateRoot);
        assertEq(storedBlock, blockNumber);

        vm.stopPrank();
    }

    /// @notice Fuzz test multiple state roots
    function testFuzz_MultipleStateRoots(
        bytes32 stateRoot1,
        bytes32 stateRoot2,
        uint256 blockNumber1,
        uint256 blockNumber2
    ) public {
        vm.assume(stateRoot1 != bytes32(0));
        vm.assume(stateRoot2 != bytes32(0));
        vm.assume(stateRoot1 != stateRoot2);
        vm.assume(blockNumber1 > 0);
        vm.assume(blockNumber2 > 0);

        vm.startPrank(admin);

        baseL2Adapter.receiveStateFromL1(stateRoot1, blockNumber1);
        baseL2Adapter.receiveStateFromL1(stateRoot2, blockNumber2);

        assertEq(baseL2Adapter.confirmedStateRoots(stateRoot1), blockNumber1);
        assertEq(baseL2Adapter.confirmedStateRoots(stateRoot2), blockNumber2);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                      VALUE TRACKING FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test value bridged tracking
    function testFuzz_ValueBridgedTracking(
        uint64 value1,
        uint64 value2
    ) public {
        vm.assume(value1 > 0);
        vm.assume(value2 > 0);

        vm.startPrank(admin);
        vm.deal(admin, uint256(value1) + uint256(value2) + 1 ether);

        bytes32 proofHash1 = keccak256(abi.encodePacked("proof1"));
        bytes32 proofHash2 = keccak256(abi.encodePacked("proof2"));

        baseL1Adapter.sendProofToL2{value: value1}(
            proofHash1,
            hex"1234",
            hex"5678",
            MIN_GAS_LIMIT
        );

        baseL1Adapter.sendProofToL2{value: value2}(
            proofHash2,
            hex"1234",
            hex"5678",
            MIN_GAS_LIMIT
        );

        (, , uint256 valueBridged, , ) = baseL1Adapter.getStats();
        assertEq(valueBridged, uint256(value1) + uint256(value2));

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                      ACCESS CONTROL FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test unauthorized access
    function testFuzz_UnauthorizedAccess(
        address attacker,
        bytes32 proofHash
    ) public {
        vm.assume(attacker != admin);
        vm.assume(attacker != address(0));
        vm.assume(proofHash != bytes32(0));

        vm.startPrank(attacker);
        vm.deal(attacker, 1 ether);

        // Should fail - not operator
        vm.expectRevert();
        baseL1Adapter.sendProofToL2{value: 0.01 ether}(
            proofHash,
            hex"1234",
            hex"5678",
            MIN_GAS_LIMIT
        );

        vm.stopPrank();
    }

    /// @notice Fuzz test pause functionality
    function testFuzz_PauseBlocking(bytes32 proofHash) public {
        vm.assume(proofHash != bytes32(0));

        vm.startPrank(admin);

        // Pause the adapter
        baseL1Adapter.pause();

        // All operations should fail
        vm.expectRevert();
        baseL1Adapter.sendProofToL2{value: 0.01 ether}(
            proofHash,
            hex"1234",
            hex"5678",
            MIN_GAS_LIMIT
        );

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT: MESSAGE INTEGRITY
    //////////////////////////////////////////////////////////////*/

    /// @notice Invariant: message nonce should never decrease
    function testFuzz_MessageNonceNeverDecreases(uint8 numOperations) public {
        vm.assume(numOperations > 0 && numOperations <= 50);

        vm.startPrank(admin);
        vm.deal(admin, 100 ether);

        uint256 previousNonce = baseL1Adapter.messageNonce();

        for (uint8 i = 0; i < numOperations; i++) {
            bytes32 proofHash = keccak256(abi.encodePacked("proof", i));
            baseL1Adapter.sendProofToL2{value: 0.01 ether}(
                proofHash,
                hex"1234",
                hex"5678",
                MIN_GAS_LIMIT
            );

            uint256 currentNonce = baseL1Adapter.messageNonce();
            assertGe(currentNonce, previousNonce);
            previousNonce = currentNonce;
        }

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT: PROOF IMMUTABILITY
    //////////////////////////////////////////////////////////////*/

    /// @notice Invariant: once relayed, proof status cannot change
    function testFuzz_RelayedProofImmutable(bytes32 proofHash) public {
        vm.assume(proofHash != bytes32(0));

        vm.startPrank(admin);

        // Relay proof
        baseL2Adapter.receiveProofFromL1(
            proofHash,
            hex"1234",
            hex"5678",
            ETH_MAINNET
        );

        // Verify relayed
        assertTrue(baseL2Adapter.isProofRelayed(proofHash));

        // Attempt to replay should fail
        vm.expectRevert(BaseBridgeAdapter.ProofAlreadyRelayed.selector);
        baseL2Adapter.receiveProofFromL1(
            proofHash,
            hex"1234",
            hex"5678",
            ETH_MAINNET
        );

        // Still relayed
        assertTrue(baseL2Adapter.isProofRelayed(proofHash));

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    EDGE CASE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test empty proof data
    function testFuzz_EmptyProofData(bytes32 proofHash) public {
        vm.assume(proofHash != bytes32(0));

        vm.startPrank(admin);

        // Empty proof and inputs should still work
        baseL2Adapter.receiveProofFromL1(proofHash, hex"", hex"", ETH_MAINNET);

        assertTrue(baseL2Adapter.isProofRelayed(proofHash));

        vm.stopPrank();
    }

    /// @notice Test maximum size proof data
    function testFuzz_LargeProofData(
        bytes32 proofHash,
        uint16 dataSize
    ) public {
        vm.assume(proofHash != bytes32(0));
        vm.assume(dataSize > 0 && dataSize < 5000);

        bytes memory largeProof = new bytes(dataSize);
        for (uint16 i = 0; i < dataSize; i++) {
            largeProof[i] = bytes1(uint8(i % 256));
        }

        vm.startPrank(admin);

        baseL2Adapter.receiveProofFromL1(
            proofHash,
            largeProof,
            largeProof,
            ETH_MAINNET
        );

        assertTrue(baseL2Adapter.isProofRelayed(proofHash));

        vm.stopPrank();
    }
}
