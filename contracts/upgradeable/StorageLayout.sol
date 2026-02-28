// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title StorageLayoutChecker
 * @notice Utility for verifying storage layout compatibility during upgrades
 * @dev Used to ensure storage slots don't collide between versions
 */

// Storage slot definitions for Zaseon contracts
// These must remain constant across upgrades

/**
 * @title StorageSlots
 * @author ZASEON Team
 * @notice Storage Slots library
 */
library StorageSlots {
    // PC³ Storage Slots
    bytes32 public constant PC3_CONTAINERS_SLOT =
        keccak256("zaseon.storage.pc3.containers");
    bytes32 public constant PC3_NULLIFIERS_SLOT =
        keccak256("zaseon.storage.pc3.nullifiers");
    bytes32 public constant PC3_TOTAL_CONTAINERS_SLOT =
        keccak256("zaseon.storage.pc3.totalContainers");

    // PBP Storage Slots
    bytes32 public constant PBP_POLICIES_SLOT = keccak256("zaseon.storage.pbp.policies");
    bytes32 public constant PBP_POLICY_COUNT_SLOT =
        keccak256("zaseon.storage.pbp.policyCount");

    // EASC Storage Slots
    bytes32 public constant EASC_COMMITMENTS_SLOT =
        keccak256("zaseon.storage.easc.commitments");
    bytes32 public constant EASC_TRANSITIONS_SLOT =
        keccak256("zaseon.storage.easc.transitions");

    // CDNA Storage Slots
    bytes32 public constant CDNA_DOMAINS_SLOT = keccak256("zaseon.storage.cdna.domains");
    bytes32 public constant CDNA_NULLIFIERS_SLOT =
        keccak256("zaseon.storage.cdna.nullifiers");

    // Orchestrator Storage Slots
    bytes32 public constant ORCH_PRIMITIVES_SLOT =
        keccak256("zaseon.storage.orchestrator.primitives");
    bytes32 public constant ORCH_PAUSED_SLOT =
        keccak256("zaseon.storage.orchestrator.paused");
}

/**
 * @notice Generates storage layout report for verification
 */
contract StorageLayoutReport {
    struct SlotInfo {
        bytes32 slot;
        string name;
        string contractName;
    }

        /**
     * @notice Returns the p c3 slots
     * @return The result value
     */
function getPC3Slots() external pure returns (SlotInfo[] memory) {
        SlotInfo[] memory slots = new SlotInfo[](3);
        slots[0] = SlotInfo(
            StorageSlots.PC3_CONTAINERS_SLOT,
            "containers",
            "ProofCarryingContainer"
        );
        slots[1] = SlotInfo(
            StorageSlots.PC3_NULLIFIERS_SLOT,
            "nullifiers",
            "ProofCarryingContainer"
        );
        slots[2] = SlotInfo(
            StorageSlots.PC3_TOTAL_CONTAINERS_SLOT,
            "totalContainers",
            "ProofCarryingContainer"
        );
        return slots;
    }

        /**
     * @notice Returns the p b p slots
     * @return The result value
     */
function getPBPSlots() external pure returns (SlotInfo[] memory) {
        SlotInfo[] memory slots = new SlotInfo[](2);
        slots[0] = SlotInfo(
            StorageSlots.PBP_POLICIES_SLOT,
            "policies",
            "PolicyBoundProofs"
        );
        slots[1] = SlotInfo(
            StorageSlots.PBP_POLICY_COUNT_SLOT,
            "policyCount",
            "PolicyBoundProofs"
        );
        return slots;
    }

        /**
     * @notice Returns the e a s c slots
     * @return The result value
     */
function getEASCSlots() external pure returns (SlotInfo[] memory) {
        SlotInfo[] memory slots = new SlotInfo[](2);
        slots[0] = SlotInfo(
            StorageSlots.EASC_COMMITMENTS_SLOT,
            "commitments",
            "ExecutionAgnosticStateCommitments"
        );
        slots[1] = SlotInfo(
            StorageSlots.EASC_TRANSITIONS_SLOT,
            "transitions",
            "ExecutionAgnosticStateCommitments"
        );
        return slots;
    }

        /**
     * @notice Returns the c d n a slots
     * @return The result value
     */
function getCDNASlots() external pure returns (SlotInfo[] memory) {
        SlotInfo[] memory slots = new SlotInfo[](2);
        slots[0] = SlotInfo(
            StorageSlots.CDNA_DOMAINS_SLOT,
            "domains",
            "CrossDomainNullifierAlgebra"
        );
        slots[1] = SlotInfo(
            StorageSlots.CDNA_NULLIFIERS_SLOT,
            "nullifiers",
            "CrossDomainNullifierAlgebra"
        );
        return slots;
    }
}
