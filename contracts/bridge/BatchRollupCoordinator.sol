// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title  IRollupBatchVerifier
 * @notice Verifier produced by the new `noir/rollup_aggregator` circuit.
 *         Accepts a proof plus the batch commitments it aggregates and
 *         returns true iff every constituent proof was sound.
 */
interface IRollupBatchVerifier {
    function verifyBatch(
        bytes calldata proof,
        bytes32 aggregatedRoot,
        bytes32[] calldata batchCommitments
    ) external view returns (bool);
}

/**
 * @title  BatchRollupCoordinator
 * @notice Accepts an aggregated proof over K batch commitments and stores a
 *         single rolling settlement root on L1. Each batch commitment itself
 *         is the Merkle root over a cohort of cross-chain transfers.
 *
 * @dev Security model: a relayer may propose a batch at any time; the
 *      verifier call guarantees soundness of every constituent proof, so the
 *      only trust assumption is that the verifier contract is correct. No
 *      challenge window is required — fraud would require producing a valid
 *      UltraHonk proof, which is computationally infeasible.
 */
contract BatchRollupCoordinator is AccessControl, ReentrancyGuard {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    IRollupBatchVerifier public verifier;

    /// @notice Rolling head: latest aggregated root + the height it was set at.
    bytes32 public head;
    uint64 public headHeight;
    uint64 public headPostedAt;

    /// @notice History of posted roots keyed by height (1-indexed).
    mapping(uint64 => bytes32) public rootAt;

    /// @notice Tracks every batch commitment ever settled to prevent double-counting.
    mapping(bytes32 => bool) public settledBatch;

    event VerifierUpdated(address oldVerifier, address newVerifier);
    event BatchSettled(
        uint64 indexed height,
        bytes32 indexed aggregatedRoot,
        uint256 batchCount
    );

    error ZeroAddress();
    error EmptyBatch();
    error DuplicateBatchCommitment(bytes32 commitment);
    error InvalidProof();

    constructor(address admin, address verifier_) {
        if (admin == address(0) || verifier_ == address(0))
            revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(PROPOSER_ROLE, admin);
        verifier = IRollupBatchVerifier(verifier_);
    }

    // ----- Admin -----

    function setVerifier(address newVerifier) external onlyRole(ADMIN_ROLE) {
        if (newVerifier == address(0)) revert ZeroAddress();
        emit VerifierUpdated(address(verifier), newVerifier);
        verifier = IRollupBatchVerifier(newVerifier);
    }

    // ----- Settlement -----

    /// @notice Verify and record an aggregated batch of batch commitments.
    function settleBatch(
        bytes calldata proof,
        bytes32 aggregatedRoot,
        bytes32[] calldata batchCommitments
    ) external nonReentrant onlyRole(PROPOSER_ROLE) returns (uint64 height) {
        if (batchCommitments.length == 0) revert EmptyBatch();

        // Reject any previously-settled batch commitment, or a duplicate
        // repeated inside the current batch.
        for (uint256 i; i < batchCommitments.length; ++i) {
            bytes32 c = batchCommitments[i];
            if (settledBatch[c]) revert DuplicateBatchCommitment(c);
            for (uint256 j; j < i; ++j) {
                if (batchCommitments[j] == c) {
                    revert DuplicateBatchCommitment(c);
                }
            }
        }

        if (!verifier.verifyBatch(proof, aggregatedRoot, batchCommitments)) {
            revert InvalidProof();
        }

        for (uint256 i; i < batchCommitments.length; ++i) {
            settledBatch[batchCommitments[i]] = true;
        }

        unchecked {
            height = headHeight + 1;
        }
        headHeight = height;
        head = aggregatedRoot;
        headPostedAt = uint64(block.timestamp);
        rootAt[height] = aggregatedRoot;

        emit BatchSettled(height, aggregatedRoot, batchCommitments.length);
    }

    function latest()
        external
        view
        returns (bytes32 root, uint64 height, uint64 postedAt)
    {
        return (head, headHeight, headPostedAt);
    }
}
