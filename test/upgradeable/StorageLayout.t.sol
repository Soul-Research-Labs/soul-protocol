// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/upgradeable/StorageLayout.sol";

contract StorageLayoutTest is Test {
    StorageLayoutReport report;

    function setUp() public {
        report = new StorageLayoutReport();
    }

    /* ══════════════════════════════════════════════════
              STORAGE SLOTS LIBRARY
       ══════════════════════════════════════════════════ */

    function test_pc3Slots_nonZero() public pure {
        assertNotEq(StorageSlots.PC3_CONTAINERS_SLOT, bytes32(0));
        assertNotEq(StorageSlots.PC3_NULLIFIERS_SLOT, bytes32(0));
        assertNotEq(StorageSlots.PC3_TOTAL_CONTAINERS_SLOT, bytes32(0));
    }

    function test_pbpSlots_nonZero() public pure {
        assertNotEq(StorageSlots.PBP_POLICIES_SLOT, bytes32(0));
        assertNotEq(StorageSlots.PBP_POLICY_COUNT_SLOT, bytes32(0));
    }

    function test_eascSlots_nonZero() public pure {
        assertNotEq(StorageSlots.EASC_COMMITMENTS_SLOT, bytes32(0));
        assertNotEq(StorageSlots.EASC_TRANSITIONS_SLOT, bytes32(0));
    }

    function test_cdnaSlots_nonZero() public pure {
        assertNotEq(StorageSlots.CDNA_DOMAINS_SLOT, bytes32(0));
        assertNotEq(StorageSlots.CDNA_NULLIFIERS_SLOT, bytes32(0));
    }

    function test_orchSlots_nonZero() public pure {
        assertNotEq(StorageSlots.ORCH_PRIMITIVES_SLOT, bytes32(0));
        assertNotEq(StorageSlots.ORCH_PAUSED_SLOT, bytes32(0));
    }

    function test_allSlots_unique() public pure {
        bytes32[12] memory slots = [
            StorageSlots.PC3_CONTAINERS_SLOT,
            StorageSlots.PC3_NULLIFIERS_SLOT,
            StorageSlots.PC3_TOTAL_CONTAINERS_SLOT,
            StorageSlots.PBP_POLICIES_SLOT,
            StorageSlots.PBP_POLICY_COUNT_SLOT,
            StorageSlots.EASC_COMMITMENTS_SLOT,
            StorageSlots.EASC_TRANSITIONS_SLOT,
            StorageSlots.CDNA_DOMAINS_SLOT,
            StorageSlots.CDNA_NULLIFIERS_SLOT,
            StorageSlots.ORCH_PRIMITIVES_SLOT,
            StorageSlots.ORCH_PAUSED_SLOT,
            bytes32(0) // padding
        ];
        for (uint256 i = 0; i < 11; i++) {
            for (uint256 j = i + 1; j < 11; j++) {
                assertNotEq(slots[i], slots[j], "Storage slots must be unique");
            }
        }
    }

    function test_slots_matchKeccak() public pure {
        assertEq(
            StorageSlots.PC3_CONTAINERS_SLOT,
            keccak256("zaseon.storage.pc3.containers")
        );
        assertEq(
            StorageSlots.PC3_NULLIFIERS_SLOT,
            keccak256("zaseon.storage.pc3.nullifiers")
        );
        assertEq(
            StorageSlots.CDNA_DOMAINS_SLOT,
            keccak256("zaseon.storage.cdna.domains")
        );
    }

    /* ══════════════════════════════════════════════════
              STORAGE LAYOUT REPORT
       ══════════════════════════════════════════════════ */

    function test_getPC3Slots_returnsThree() public view {
        StorageLayoutReport.SlotInfo[] memory slots = report.getPC3Slots();
        assertEq(slots.length, 3);
        assertEq(slots[0].slot, StorageSlots.PC3_CONTAINERS_SLOT);
        assertEq(keccak256(bytes(slots[0].name)), keccak256("containers"));
    }

    function test_getPBPSlots_returnsTwo() public view {
        StorageLayoutReport.SlotInfo[] memory slots = report.getPBPSlots();
        assertEq(slots.length, 2);
        assertEq(slots[0].slot, StorageSlots.PBP_POLICIES_SLOT);
    }

    function test_getEASCSlots_returnsTwo() public view {
        StorageLayoutReport.SlotInfo[] memory slots = report.getEASCSlots();
        assertEq(slots.length, 2);
        assertEq(slots[0].slot, StorageSlots.EASC_COMMITMENTS_SLOT);
    }

    function test_getCDNASlots_returnsTwo() public view {
        StorageLayoutReport.SlotInfo[] memory slots = report.getCDNASlots();
        assertEq(slots.length, 2);
        assertEq(slots[0].slot, StorageSlots.CDNA_DOMAINS_SLOT);
    }

    function test_report_contractNameMatches() public view {
        StorageLayoutReport.SlotInfo[] memory pc3 = report.getPC3Slots();
        assertEq(
            keccak256(bytes(pc3[0].contractName)),
            keccak256("ProofCarryingContainer")
        );
        StorageLayoutReport.SlotInfo[] memory pbp = report.getPBPSlots();
        assertEq(
            keccak256(bytes(pbp[0].contractName)),
            keccak256("PolicyBoundProofs")
        );
    }
}
