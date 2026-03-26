// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CrossChainProofHubV3} from "../../contracts/bridge/CrossChainProofHubV3.sol";
import {ICrossChainProofHubV3, BatchProofInput} from "../../contracts/interfaces/ICrossChainProofHubV3.sol";
import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";

/// @dev Mock verifier that always returns true
contract AlwaysTrueVerifier is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure returns (bool) {
        return true;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 1;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

contract CrossChainProofHubV3Fuzz is Test {
    CrossChainProofHubV3 internal hub;
    AlwaysTrueVerifier internal verifier;

    address internal admin = address(this);
    address internal relayer = address(0xBEEF);
    address internal challenger = address(0xCAFE);
    address internal operator = address(0xD00D);

    uint64 internal constant SOURCE_CHAIN = 1;
    uint64 internal constant DEST_CHAIN = 42161;

    function setUp() public {
        hub = new CrossChainProofHubV3();
        verifier = new AlwaysTrueVerifier();

        // Grant roles to separate addresses (required for role separation)
        hub.grantRole(hub.RELAYER_ROLE(), relayer);
        hub.grantRole(hub.CHALLENGER_ROLE(), challenger);
        hub.grantRole(hub.OPERATOR_ROLE(), operator);
        hub.grantRole(hub.VERIFIER_ADMIN_ROLE(), admin);

        // Register verifier for the default proof type
        hub.setVerifier(hub.DEFAULT_PROOF_TYPE(), address(verifier));

        // Add supported chains
        hub.addSupportedChain(SOURCE_CHAIN);
        hub.addSupportedChain(DEST_CHAIN);

        // Confirm role separation (admin must NOT hold RELAYER or CHALLENGER roles)
        hub.confirmRoleSeparation();

        // Stake for relayer (above minRelayerStake = 0.1 ether)
        vm.deal(relayer, 100 ether);
        vm.prank(relayer);
        hub.depositStake{value: 10 ether}();
    }

    /*//////////////////////////////////////////////////////////////
                  FUZZ: UNIQUE PROOF IDS
    //////////////////////////////////////////////////////////////*/

    /// @notice Different commitments must produce different proofIds
    function testFuzz_submitProof_uniqueProofIds(
        bytes32 commitment1,
        bytes32 commitment2
    ) public {
        vm.assume(commitment1 != commitment2);

        bytes memory proof1 = abi.encodePacked(commitment1);
        bytes memory proof2 = abi.encodePacked(commitment2);
        bytes memory pubInputs = hex"01";
        uint256 fee = hub.proofSubmissionFee();

        vm.startPrank(relayer);

        bytes32 proofId1 = hub.submitProof{value: fee}(
            proof1,
            pubInputs,
            commitment1,
            SOURCE_CHAIN,
            DEST_CHAIN
        );
        bytes32 proofId2 = hub.submitProof{value: fee}(
            proof2,
            pubInputs,
            commitment2,
            SOURCE_CHAIN,
            DEST_CHAIN
        );

        vm.stopPrank();

        assertNotEq(
            proofId1,
            proofId2,
            "Different commitments must yield different proofIds"
        );
    }

    /*//////////////////////////////////////////////////////////////
              FUZZ: CHALLENGE TIMING BOUNDARY
    //////////////////////////////////////////////////////////////*/

    /// @notice Challenges should succeed before deadline and fail after
    function testFuzz_challengeProof_timingBoundary(uint32 timeDelta) public {
        // Submit a proof first
        bytes memory proof = hex"dead";
        bytes memory pubInputs = hex"01";
        uint256 fee = hub.proofSubmissionFee();

        vm.prank(relayer);
        bytes32 proofId = hub.submitProof{value: fee}(
            proof,
            pubInputs,
            bytes32(uint256(1)),
            SOURCE_CHAIN,
            DEST_CHAIN
        );

        uint256 deadline = hub.getProof(proofId).challengeDeadline;
        uint256 minStake = hub.minChallengerStake();
        vm.deal(challenger, 100 ether);

        // Warp by the fuzzed delta from submission time
        uint256 warpTo = block.timestamp + uint256(timeDelta);
        vm.warp(warpTo);

        vm.prank(challenger);
        if (warpTo < deadline) {
            // Should succeed — still within challenge window
            hub.challengeProof{value: minStake}(proofId, "fuzz challenge");
            ICrossChainProofHubV3.ProofStatus status = hub
                .getProof(proofId)
                .status;
            assertEq(
                uint8(status),
                uint8(ICrossChainProofHubV3.ProofStatus.Challenged)
            );
        } else {
            // Should revert — challenge period is over
            vm.expectRevert(
                abi.encodeWithSelector(
                    ICrossChainProofHubV3.ChallengePeriodOver.selector,
                    proofId
                )
            );
            hub.challengeProof{value: minStake}(proofId, "late challenge");
        }
    }

    /*//////////////////////////////////////////////////////////////
              FUZZ: PARTIAL STAKE WITHDRAWAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposit and partial withdrawal must keep balance consistent
    function testFuzz_withdrawStake_partialAmounts(
        uint96 stakeAmount,
        uint96 withdrawAmount
    ) public {
        // Bound to reasonable values (at least 1 wei deposit, cap at 50 ether)
        uint256 stake = bound(uint256(stakeAmount), 1, 50 ether);
        uint256 withdraw = bound(uint256(withdrawAmount), 0, stake);

        address user = address(0x1234);
        vm.deal(user, stake);

        vm.startPrank(user);
        hub.depositStake{value: stake}();

        uint256 balBefore = user.balance;

        if (withdraw == 0) {
            // Zero withdraw — nothing happens, but should not revert
            hub.withdrawStake(0);
            assertEq(hub.relayerStakes(user), stake);
        } else {
            hub.withdrawStake(withdraw);
            assertEq(hub.relayerStakes(user), stake - withdraw);
            assertEq(user.balance, balBefore + withdraw);
        }

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
              FUZZ: BATCH SUBMISSION VARYING SIZES
    //////////////////////////////////////////////////////////////*/

    /// @notice Batches of 1..MAX_BATCH_SIZE should all store proofs correctly
    function testFuzz_submitBatch_varyingSizes(uint8 batchSize) public {
        uint256 size = bound(uint256(batchSize), 1, hub.MAX_BATCH_SIZE());
        uint256 fee = hub.proofSubmissionFee() * size;

        BatchProofInput[] memory inputs = new BatchProofInput[](size);
        for (uint256 i = 0; i < size; i++) {
            inputs[i] = BatchProofInput({
                proofHash: keccak256(abi.encodePacked("proof", i)),
                publicInputsHash: keccak256(abi.encodePacked("pi", i)),
                commitment: keccak256(abi.encodePacked("commit", i)),
                sourceChainId: SOURCE_CHAIN,
                destChainId: DEST_CHAIN
            });
        }

        bytes32 merkleRoot = keccak256(abi.encodePacked("root", size));

        vm.prank(relayer);
        bytes32 batchId = hub.submitBatch{value: fee}(inputs, merkleRoot);

        ICrossChainProofHubV3.BatchSubmission memory batch = hub.getBatch(
            batchId
        );
        assertEq(
            batch.proofCount,
            size,
            "Batch proofCount should match input size"
        );
        assertEq(batch.relayer, relayer, "Batch relayer mismatch");
        assertEq(
            uint8(batch.status),
            uint8(ICrossChainProofHubV3.ProofStatus.Pending)
        );

        // Verify each individual proof was stored
        for (uint256 i = 0; i < size; i++) {
            bytes32 proofId = keccak256(
                abi.encodePacked(
                    inputs[i].proofHash,
                    inputs[i].commitment,
                    inputs[i].sourceChainId,
                    inputs[i].destChainId,
                    i // nonce starts at 0 per fresh hub instance
                )
            );
            ICrossChainProofHubV3.ProofSubmission memory p = hub.getProof(
                proofId
            );
            assertEq(p.relayer, relayer, "Individual proof relayer mismatch");
            assertEq(p.commitment, inputs[i].commitment, "Commitment mismatch");
            assertEq(
                hub.proofToBatch(proofId),
                batchId,
                "Proof-to-batch mapping incorrect"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
              FUZZ: FEE CALCULATION NON-ZERO
    //////////////////////////////////////////////////////////////*/

    /// @notice Any non-zero value submission should have the fee accumulated
    function testFuzz_feeCalculation_nonZero(uint256 value) public {
        uint256 fee = hub.proofSubmissionFee();
        // Value must be at least the required fee and within rate limit
        value = bound(value, fee, 10 ether);

        uint256 feesBefore = hub.accumulatedFees();

        vm.prank(relayer);
        hub.submitProof{value: value}(
            hex"aabb",
            hex"01",
            keccak256(abi.encodePacked(value)),
            SOURCE_CHAIN,
            DEST_CHAIN
        );

        uint256 feesAfter = hub.accumulatedFees();
        // The full msg.value is added to accumulatedFees
        assertEq(
            feesAfter,
            feesBefore + value,
            "Fees should increase by msg.value"
        );
        assertTrue(
            feesAfter > feesBefore,
            "Fees must increase for non-zero submission"
        );
    }
}
