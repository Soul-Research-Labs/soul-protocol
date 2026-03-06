// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CrossChainProofHubV3} from "../../contracts/bridge/CrossChainProofHubV3.sol";
import {ICrossChainProofHubV3, BatchProofInput} from "../../contracts/interfaces/ICrossChainProofHubV3.sol";
import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";

contract AlwaysTrueVerifier is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure override returns (bool) {
        return true;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure override returns (bool) {
        return true;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure override returns (bool) {
        return true;
    }

    function getPublicInputCount() external pure override returns (uint256) {
        return 1;
    }

    function isReady() external pure override returns (bool) {
        return true;
    }
}

/// @title ProofHubRateLimitTest
/// @notice Security tests for _checkRateLimit enforcement in CrossChainProofHubV3
contract ProofHubRateLimitTest is Test {
    CrossChainProofHubV3 public hub;
    AlwaysTrueVerifier public verifier;

    address public admin;
    address public relayer = address(0xAA01);
    address public operator = address(0xAA03);

    bytes32 constant PROOF_TYPE =
        0x8cdf3a8b78ebe00eba9fa85c0a9029fb57ab374b0492d22d68498e28e9e5b598;

    function setUp() public {
        admin = address(this);
        hub = new CrossChainProofHubV3();

        verifier = new AlwaysTrueVerifier();

        hub.grantRole(hub.RELAYER_ROLE(), relayer);
        hub.grantRole(hub.OPERATOR_ROLE(), operator);
        hub.grantRole(hub.VERIFIER_ADMIN_ROLE(), admin);

        hub.setVerifier(PROOF_TYPE, address(verifier));
        hub.addSupportedChain(42161);
        hub.confirmRoleSeparation();

        vm.deal(relayer, 1000 ether);
    }

    function _stakeRelayer() internal {
        vm.prank(relayer);
        hub.depositStake{value: 1 ether}();
    }

    function _submitOneProof(uint256 nonce) internal returns (bytes32) {
        vm.prank(relayer);
        return
            hub.submitProof{value: 0.001 ether}(
                abi.encodePacked("proof", nonce),
                abi.encodePacked("inputs", nonce),
                keccak256(abi.encode("commit", nonce)),
                uint64(block.chainid),
                42161
            );
    }

    /*//////////////////////////////////////////////////////////////
                HOURLY PROOF COUNT RATE LIMITING
    //////////////////////////////////////////////////////////////*/

    function test_rateLimitProofCount_exactlyAtLimit() public {
        _stakeRelayer();

        // Set tight limit for testing
        hub.setRateLimits(5, 1000 ether);

        // Submit exactly 5 proofs — should all succeed
        for (uint256 i = 0; i < 5; i++) {
            _submitOneProof(i);
        }

        assertEq(hub.hourlyProofCount(), 5);
    }

    function test_rateLimitProofCount_exceedingReverts() public {
        _stakeRelayer();
        hub.setRateLimits(5, 1000 ether);

        // Submit 5 proofs
        for (uint256 i = 0; i < 5; i++) {
            _submitOneProof(i);
        }

        // 6th should revert
        vm.prank(relayer);
        vm.expectRevert(ICrossChainProofHubV3.ProofRateLimitExceeded.selector);
        hub.submitProof{value: 0.001 ether}(
            hex"aaaa",
            hex"bbbb",
            keccak256("overflow"),
            uint64(block.chainid),
            42161
        );
    }

    function test_rateLimitHourReset() public {
        _stakeRelayer();
        hub.setRateLimits(5, 1000 ether);

        // Submit 5 proofs, hitting the limit
        for (uint256 i = 0; i < 5; i++) {
            _submitOneProof(i);
        }
        assertEq(hub.hourlyProofCount(), 5);

        // Warp forward 1 hour — counters should reset
        vm.warp(block.timestamp + 1 hours);

        // Now can submit again
        _submitOneProof(100);
        assertEq(hub.hourlyProofCount(), 1);
    }

    function test_rateLimitHourReset_exactBoundary() public {
        _stakeRelayer();
        hub.setRateLimits(5, 1000 ether);

        for (uint256 i = 0; i < 5; i++) {
            _submitOneProof(i);
        }

        // Warp to exactly 1 hour (>= triggers reset)
        vm.warp(block.timestamp + 1 hours);

        // Should succeed — boundary is >=
        _submitOneProof(200);
        assertEq(hub.hourlyProofCount(), 1);
    }

    function test_rateLimitHourNotResetBeforeBoundary() public {
        _stakeRelayer();
        hub.setRateLimits(5, 1000 ether);

        // Warp to a time that triggers the initial rate-limit reset on first submit
        vm.warp(7200);

        for (uint256 i = 0; i < 5; i++) {
            _submitOneProof(i);
        }
        // After first submit, lastRateLimitReset = 7200 (reset triggered because 7200 >= 0 + 3600)
        // Counter is now full at 5

        // Warp to 1 second before the next reset boundary (7200 + 3600 - 1 = 10799)
        vm.warp(7200 + 1 hours - 1);

        // Should still revert — not yet reset (10799 < 7200 + 3600)
        vm.prank(relayer);
        vm.expectRevert(ICrossChainProofHubV3.ProofRateLimitExceeded.selector);
        hub.submitProof{value: 0.001 ether}(
            hex"cc",
            hex"dd",
            keccak256("boundary"),
            uint64(block.chainid),
            42161
        );
    }

    /*//////////////////////////////////////////////////////////////
                HOURLY VALUE RATE LIMITING
    //////////////////////////////////////////////////////////////*/

    function test_rateLimitValue_exceedingReverts() public {
        _stakeRelayer();
        // Low value limit, high proof count limit
        hub.setRateLimits(1000, 0.005 ether);

        // Submit 5 proofs at 0.001 ether each = 0.005 ether total
        for (uint256 i = 0; i < 5; i++) {
            _submitOneProof(i);
        }

        // 6th submission should trigger ValueRateLimitExceeded
        vm.prank(relayer);
        vm.expectRevert(CrossChainProofHubV3.ValueRateLimitExceeded.selector);
        hub.submitProof{value: 0.001 ether}(
            hex"ee",
            hex"ff",
            keccak256("valuelimit"),
            uint64(block.chainid),
            42161
        );
    }

    function test_rateLimitValue_resetsAfterHour() public {
        _stakeRelayer();
        hub.setRateLimits(1000, 0.003 ether);

        for (uint256 i = 0; i < 3; i++) {
            _submitOneProof(i);
        }

        // Warp 1 hour to reset
        vm.warp(block.timestamp + 1 hours);

        // Should succeed after reset
        _submitOneProof(50);
        assertEq(hub.hourlyValueRelayed(), 0.001 ether);
    }

    /*//////////////////////////////////////////////////////////////
                BATCH SUBMISSION RATE LIMITING
    //////////////////////////////////////////////////////////////*/

    function test_rateLimitBatch_countsAllProofs() public {
        _stakeRelayer();
        hub.setRateLimits(10, 1000 ether);

        // Submit batch of 8
        BatchProofInput[] memory inputs = new BatchProofInput[](8);
        for (uint256 i = 0; i < 8; i++) {
            inputs[i] = BatchProofInput({
                proofHash: keccak256(abi.encode("proof", i)),
                publicInputsHash: keccak256(abi.encode("inputs", i)),
                commitment: keccak256(abi.encode("commit", i)),
                sourceChainId: uint64(block.chainid),
                destChainId: 42161
            });
        }

        vm.prank(relayer);
        hub.submitBatch{value: 0.008 ether}(inputs, keccak256("root1"));

        // 8 proofs counted from batch
        assertEq(hub.hourlyProofCount(), 8);

        // Submitting 3 more individual proofs should fail at the 3rd (8+3=11 > 10)
        _submitOneProof(100);
        _submitOneProof(101);

        vm.prank(relayer);
        vm.expectRevert(ICrossChainProofHubV3.ProofRateLimitExceeded.selector);
        hub.submitProof{value: 0.001 ether}(
            hex"aa",
            hex"bb",
            keccak256("excess"),
            uint64(block.chainid),
            42161
        );
    }

    function test_rateLimitBatch_oversizedBatchReverts() public {
        _stakeRelayer();
        hub.setRateLimits(3, 1000 ether);

        // Submit batch of 4 — exceeds limit of 3
        BatchProofInput[] memory inputs = new BatchProofInput[](4);
        for (uint256 i = 0; i < 4; i++) {
            inputs[i] = BatchProofInput({
                proofHash: keccak256(abi.encode("bp", i)),
                publicInputsHash: keccak256(abi.encode("bi", i)),
                commitment: keccak256(abi.encode("bc", i)),
                sourceChainId: uint64(block.chainid),
                destChainId: 42161
            });
        }

        vm.prank(relayer);
        vm.expectRevert(ICrossChainProofHubV3.ProofRateLimitExceeded.selector);
        hub.submitBatch{value: 0.004 ether}(inputs, keccak256("root2"));
    }

    /*//////////////////////////////////////////////////////////////
                MULTIPLE SUBMISSIONS WITHIN HOUR
    //////////////////////////////////////////////////////////////*/

    function test_rateLimitAccumulatesAcrossSubmissions() public {
        _stakeRelayer();
        hub.setRateLimits(6, 1000 ether);

        // Submit 3 proofs
        for (uint256 i = 0; i < 3; i++) {
            _submitOneProof(i);
        }
        assertEq(hub.hourlyProofCount(), 3);

        // Submit batch of 2
        BatchProofInput[] memory inputs = new BatchProofInput[](2);
        for (uint256 i = 0; i < 2; i++) {
            inputs[i] = BatchProofInput({
                proofHash: keccak256(abi.encode("bp2", i)),
                publicInputsHash: keccak256(abi.encode("bi2", i)),
                commitment: keccak256(abi.encode("bc2", i)),
                sourceChainId: uint64(block.chainid),
                destChainId: 42161
            });
        }

        vm.prank(relayer);
        hub.submitBatch{value: 0.002 ether}(inputs, keccak256("root3"));

        // Total: 3 + 2 = 5
        assertEq(hub.hourlyProofCount(), 5);

        // 1 more is fine
        _submitOneProof(50);
        assertEq(hub.hourlyProofCount(), 6);

        // 7th should fail
        vm.prank(relayer);
        vm.expectRevert(ICrossChainProofHubV3.ProofRateLimitExceeded.selector);
        hub.submitProof{value: 0.001 ether}(
            hex"aa11",
            hex"bb22",
            keccak256("seven"),
            uint64(block.chainid),
            42161
        );
    }

    /*//////////////////////////////////////////////////////////////
                ADMIN CHANGES MID-ENFORCEMENT
    //////////////////////////////////////////////////////////////*/

    function test_rateLimitAdminReducesMidHour() public {
        _stakeRelayer();
        hub.setRateLimits(10, 1000 ether);

        // Submit 5 proofs
        for (uint256 i = 0; i < 5; i++) {
            _submitOneProof(i);
        }

        // Admin reduces limit to 3 — existing count (5) now exceeds limit
        hub.setRateLimits(3, 1000 ether);

        // Any further submission should revert since 5 + 1 > 3
        vm.prank(relayer);
        vm.expectRevert(ICrossChainProofHubV3.ProofRateLimitExceeded.selector);
        hub.submitProof{value: 0.001 ether}(
            hex"cc33",
            hex"dd44",
            keccak256("reduced"),
            uint64(block.chainid),
            42161
        );
    }

    /*//////////////////////////////////////////////////////////////
                FUZZ TEST
    //////////////////////////////////////////////////////////////*/

    function testFuzz_rateLimitCounterMonotonic(uint8 numProofs) public {
        numProofs = uint8(bound(numProofs, 1, 20));
        _stakeRelayer();
        hub.setRateLimits(100, 1000 ether);

        for (uint256 i = 0; i < numProofs; i++) {
            _submitOneProof(i);
        }

        assertEq(hub.hourlyProofCount(), numProofs);
    }
}
