// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
library StorageSlots {
    bytes32 public constant PC3_CONTAINERS_SLOT = keccak256("pil.storage.pc3.containers");
    bytes32 public constant PC3_NULLIFIERS_SLOT = keccak256("pil.storage.pc3.nullifiers");
    bytes32 public constant PC3_TOTAL_CONTAINERS_SLOT = keccak256("pil.storage.pc3.totalContainers");
    bytes32 public constant PBP_POLICIES_SLOT = keccak256("pil.storage.pbp.policies");
    bytes32 public constant PBP_POLICY_COUNT_SLOT = keccak256("pil.storage.pbp.policyCount");
    bytes32 public constant EASC_COMMITMENTS_SLOT = keccak256("pil.storage.easc.commitments");
    bytes32 public constant EASC_TRANSITIONS_SLOT = keccak256("pil.storage.easc.transitions");
    bytes32 public constant CDNA_DOMAINS_SLOT = keccak256("pil.storage.cdna.domains");
    bytes32 public constant CDNA_NULLIFIERS_SLOT = keccak256("pil.storage.cdna.nullifiers");
    bytes32 public constant ORCH_PRIMITIVES_SLOT = keccak256("pil.storage.orchestrator.primitives");
    bytes32 public constant ORCH_PAUSED_SLOT = keccak256("pil.storage.orchestrator.paused");
}

contract StorageLayoutReport {
    struct SlotInfo { bytes32 slot; string name; string contractName; }
    function getPC3Slots() external pure returns (SlotInfo[] memory) { return new SlotInfo[](0); }
    function getPBPSlots() external pure returns (SlotInfo[] memory) { return new SlotInfo[](0); }
    function getEASCSlots() external pure returns (SlotInfo[] memory) { return new SlotInfo[](0); }
    function getCDNASlots() external pure returns (SlotInfo[] memory) { return new SlotInfo[](0); }
}
