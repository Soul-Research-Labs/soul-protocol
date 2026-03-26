// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CrossChainProofHubV3} from "../../contracts/bridge/CrossChainProofHubV3.sol";
import {ICrossChainProofHubV3, BatchProofInput} from "../../contracts/interfaces/ICrossChainProofHubV3.sol";

/// @dev Mock verifier that always returns true for gas benchmarking
contract MockGasVerifier {
    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }
}

/**
 * @title CrossChainProofHubGasBenchmark
 * @notice Gas benchmarks for CrossChainProofHubV3 critical operations
 *
 * TARGET BUDGETS:
 * - submitProof:       < 300,000 gas
 * - submitProofInstant:< 350,000 gas
 * - submitBatch (4):   < 800,000 gas
 * - challengeProof:    < 200,000 gas
 * - finalizeProof:     < 150,000 gas
 * - depositStake:      < 80,000 gas
 */
contract CrossChainProofHubGasBenchmark is Test {
    CrossChainProofHubV3 public hub;
    MockGasVerifier public mockVerifier;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public challenger = makeAddr("challenger");

    uint64 public constant SOURCE_CHAIN = 1;
    uint64 public constant DEST_CHAIN = 42161;

    struct GasResult {
        string operation;
        uint256 gasUsed;
    }

    GasResult[] public results;

    function setUp() public {
        vm.startPrank(admin);
        hub = new CrossChainProofHubV3();
        mockVerifier = new MockGasVerifier();

        // Register chains
        hub.addSupportedChain(SOURCE_CHAIN);
        hub.addSupportedChain(DEST_CHAIN);

        // Grant VERIFIER_ADMIN_ROLE to admin so we can set verifier
        hub.grantRole(hub.VERIFIER_ADMIN_ROLE(), admin);
        hub.setVerifier(bytes32(0), address(mockVerifier));

        // Grant RELAYER_ROLE to relayer (separate from admin per role separation)
        hub.grantRole(hub.RELAYER_ROLE(), relayer);

        // Confirm role separation (admin doesn't hold RELAYER_ROLE)
        hub.confirmRoleSeparation();

        vm.stopPrank();

        // Fund relayer and challenger
        vm.deal(relayer, 100 ether);
        vm.deal(challenger, 100 ether);

        // Relayer stakes
        vm.prank(relayer);
        hub.depositStake{value: 1 ether}();
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: depositStake
    // ─────────────────────────────────────────────────────────────

    function test_gas_DepositStake() public {
        address newRelayer = makeAddr("newRelayer");
        vm.deal(newRelayer, 10 ether);

        vm.prank(newRelayer);
        uint256 gasBefore = gasleft();
        hub.depositStake{value: 1 ether}();
        uint256 gasUsed = gasBefore - gasleft();

        results.push(GasResult("depositStake", gasUsed));
        emit log_named_uint("depositStake gas", gasUsed);
        assertLt(gasUsed, 80_000, "depositStake should be < 80k gas");
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: submitProof (optimistic)
    // ─────────────────────────────────────────────────────────────

    function test_gas_SubmitProof() public {
        bytes memory proof = _mockProof(128);
        bytes memory publicInputs = _mockInputs(64);
        bytes32 commitment = keccak256("commitment-1");

        vm.prank(relayer);
        uint256 gasBefore = gasleft();
        hub.submitProof{value: 0.001 ether}(
            proof,
            publicInputs,
            commitment,
            SOURCE_CHAIN,
            DEST_CHAIN
        );
        uint256 gasUsed = gasBefore - gasleft();

        results.push(GasResult("submitProof", gasUsed));
        emit log_named_uint("submitProof gas", gasUsed);
        assertLt(gasUsed, 350_000, "submitProof should be < 350k gas");
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: submitProofInstant (on-chain verification)
    // ─────────────────────────────────────────────────────────────

    function test_gas_SubmitProofInstant() public {
        bytes memory proof = _mockProof(128);
        bytes32 commitment = keccak256("commitment-instant");
        // H-6: publicInputs must start with binding hash
        bytes32 binding = keccak256(
            abi.encodePacked(
                commitment,
                uint64(SOURCE_CHAIN),
                uint64(DEST_CHAIN)
            )
        );
        bytes memory publicInputs = abi.encodePacked(binding, bytes32(0));

        vm.prank(relayer);
        uint256 gasBefore = gasleft();
        hub.submitProofInstant{value: 0.003 ether}(
            proof,
            publicInputs,
            commitment,
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(0) // proof type
        );
        uint256 gasUsed = gasBefore - gasleft();

        results.push(GasResult("submitProofInstant", gasUsed));
        emit log_named_uint("submitProofInstant gas", gasUsed);
        assertLt(gasUsed, 350_000, "submitProofInstant should be < 350k gas");
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: submitBatch (4 proofs)
    // ─────────────────────────────────────────────────────────────

    function test_gas_SubmitBatch() public {
        BatchProofInput[] memory inputs = new BatchProofInput[](4);

        for (uint256 i = 0; i < 4; i++) {
            inputs[i] = BatchProofInput({
                proofHash: keccak256(abi.encode("proof", i)),
                publicInputsHash: keccak256(abi.encode("inputs", i)),
                commitment: keccak256(abi.encode("commitment", i)),
                sourceChainId: uint64(SOURCE_CHAIN),
                destChainId: uint64(DEST_CHAIN)
            });
        }

        bytes32 batchRoot = keccak256(abi.encode(inputs));

        vm.prank(relayer);
        uint256 gasBefore = gasleft();
        hub.submitBatch{value: 0.004 ether}(inputs, batchRoot);
        uint256 gasUsed = gasBefore - gasleft();

        results.push(GasResult("submitBatch(4)", gasUsed));
        emit log_named_uint("submitBatch(4) gas", gasUsed);
        assertLt(gasUsed, 1_000_000, "submitBatch(4) should be < 1M gas");
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: finalizeProof
    // ─────────────────────────────────────────────────────────────

    function test_gas_FinalizeProof() public {
        // Submit a proof first
        bytes memory proof = _mockProof(128);
        bytes memory publicInputs = _mockInputs(64);
        bytes32 commitment = keccak256("commitment-finalize");

        vm.prank(relayer);
        bytes32 proofId = hub.submitProof{value: 0.001 ether}(
            proof,
            publicInputs,
            commitment,
            SOURCE_CHAIN,
            DEST_CHAIN
        );

        // Warp past challenge period
        vm.warp(block.timestamp + 2 hours);

        uint256 gasBefore = gasleft();
        hub.finalizeProof(proofId);
        uint256 gasUsed = gasBefore - gasleft();

        results.push(GasResult("finalizeProof", gasUsed));
        emit log_named_uint("finalizeProof gas", gasUsed);
        assertLt(gasUsed, 150_000, "finalizeProof should be < 150k gas");
    }

    // ─────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────

    function _mockProof(uint256 length) internal pure returns (bytes memory) {
        bytes memory proof = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            proof[i] = bytes1(uint8(i % 256));
        }
        return proof;
    }

    function _mockInputs(uint256 length) internal pure returns (bytes memory) {
        bytes memory inputs = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            inputs[i] = bytes1(uint8((i + 128) % 256));
        }
        return inputs;
    }
}
