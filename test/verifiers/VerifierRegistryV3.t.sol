// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {VerifierRegistryV3} from "../../contracts/verifiers/VerifierRegistryV3.sol";
import {MockProofVerifier} from "../../contracts/mocks/MockProofVerifier.sol";

contract VerifierRegistryV3Test is Test {
    VerifierRegistryV3 internal reg;
    MockProofVerifier internal verifierA;
    MockProofVerifier internal adapterA;
    MockProofVerifier internal adapterB;

    address internal admin = address(0xA);
    address internal timelock = address(0xB);
    address internal guardian = address(0xC);
    address internal stranger = address(0xD);

    bytes32 internal constant CID_A = keccak256("private_transfer:v1");
    bytes32 internal constant CID_B = keccak256("state_transfer:v1");

    bytes32 internal constant ACIR_A = keccak256("acir_a");
    bytes32 internal constant VKEY_A = keccak256("vkey_a");

    function setUp() public {
        reg = new VerifierRegistryV3(admin, timelock, guardian);
        verifierA = new MockProofVerifier();
        adapterA = new MockProofVerifier();
        adapterB = new MockProofVerifier();
        verifierA.setVerificationResult(true);
        adapterA.setVerificationResult(true);
        adapterB.setVerificationResult(true);
    }

    function _register(bytes32 cid, address adapter) internal {
        vm.prank(timelock);
        reg.registerCircuit(
            cid,
            address(verifierA),
            adapter,
            ACIR_A,
            VKEY_A,
            300_000,
            1,
            32,
            false,
            false
        );
    }

    /* ------------------------------------------------------------
     * Basic registration
     * ------------------------------------------------------------ */

    function test_register_success_and_views() public {
        _register(CID_A, address(adapterA));
        assertTrue(reg.isRegistered(CID_A));
        assertTrue(reg.isAvailable(CID_A));
        assertEq(address(reg.getAdapter(CID_A)), address(adapterA));
        assertEq(reg.circuitCount(), 1);
        assertEq(reg.adapterToCircuit(address(adapterA)), CID_A);
    }

    function test_register_revertsOnZeroAddresses() public {
        vm.prank(timelock);
        vm.expectRevert(VerifierRegistryV3.InvalidAddress.selector);
        reg.registerCircuit(
            CID_A,
            address(0),
            address(adapterA),
            ACIR_A,
            VKEY_A,
            0,
            1,
            4,
            false,
            false
        );

        vm.prank(timelock);
        vm.expectRevert(VerifierRegistryV3.InvalidAddress.selector);
        reg.registerCircuit(
            CID_A,
            address(verifierA),
            address(0),
            ACIR_A,
            VKEY_A,
            0,
            1,
            4,
            false,
            false
        );
    }

    function test_register_revertsOnZeroHashes() public {
        vm.prank(timelock);
        vm.expectRevert(VerifierRegistryV3.InvalidHash.selector);
        reg.registerCircuit(
            CID_A,
            address(verifierA),
            address(adapterA),
            bytes32(0),
            VKEY_A,
            0,
            1,
            4,
            false,
            false
        );
    }

    function test_register_revertsOnBadBounds() public {
        vm.prank(timelock);
        vm.expectRevert(VerifierRegistryV3.InvalidInputBounds.selector);
        reg.registerCircuit(
            CID_A,
            address(verifierA),
            address(adapterA),
            ACIR_A,
            VKEY_A,
            0,
            5,
            3,
            false,
            false
        );

        vm.prank(timelock);
        vm.expectRevert(VerifierRegistryV3.InvalidInputBounds.selector);
        reg.registerCircuit(
            CID_A,
            address(verifierA),
            address(adapterA),
            ACIR_A,
            VKEY_A,
            0,
            0,
            0,
            false,
            false
        );
    }

    function test_register_onlyTimelock() public {
        vm.prank(stranger);
        vm.expectRevert();
        reg.registerCircuit(
            CID_A,
            address(verifierA),
            address(adapterA),
            ACIR_A,
            VKEY_A,
            0,
            1,
            4,
            false,
            false
        );
    }

    /* ------------------------------------------------------------
     * IMMUTABILITY of acirHash / vkeyHash
     * ------------------------------------------------------------ */

    function test_cannotReregisterSameCircuitId() public {
        _register(CID_A, address(adapterA));

        vm.prank(timelock);
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifierRegistryV3.CircuitAlreadyExists.selector,
                CID_A
            )
        );
        reg.registerCircuit(
            CID_A,
            address(verifierA),
            address(adapterB),
            keccak256("acir_a_v2"),
            keccak256("vkey_a_v2"),
            0,
            1,
            4,
            false,
            false
        );
    }

    function test_newCircuitIdForVkeyRotation() public {
        _register(CID_A, address(adapterA));
        vm.prank(timelock);
        reg.registerCircuit(
            keccak256("private_transfer:v2"),
            address(verifierA),
            address(adapterB),
            keccak256("acir_a_v2"),
            keccak256("vkey_a_v2"),
            0,
            1,
            4,
            false,
            false
        );
        assertEq(reg.circuitCount(), 2);
    }

    /* ------------------------------------------------------------
     * Pause / retire
     * ------------------------------------------------------------ */

    function test_guardianCanPauseCircuit() public {
        _register(CID_A, address(adapterA));
        vm.prank(guardian);
        reg.pauseCircuit(CID_A);
        assertFalse(reg.isAvailable(CID_A));

        vm.prank(timelock);
        reg.unpauseCircuit(CID_A);
        assertTrue(reg.isAvailable(CID_A));
    }

    function test_strangerCannotPause() public {
        _register(CID_A, address(adapterA));
        vm.prank(stranger);
        vm.expectRevert();
        reg.pauseCircuit(CID_A);
    }

    function test_retireIsOneWay() public {
        _register(CID_A, address(adapterA));
        vm.prank(timelock);
        reg.retireCircuit(CID_A);
        assertFalse(reg.isAvailable(CID_A));
        VerifierRegistryV3.Entry memory e = reg.getEntry(CID_A);
        assertEq(e.active, false);
        assertGt(e.deprecatedAt, 0);
    }

    /* ------------------------------------------------------------
     * Tuning (mutable fields)
     * ------------------------------------------------------------ */

    function test_setGasCap() public {
        _register(CID_A, address(adapterA));
        vm.prank(timelock);
        reg.setGasCap(CID_A, 500_000);
        assertEq(reg.getEntry(CID_A).gasCap, 500_000);
    }

    function test_globalPause() public {
        _register(CID_A, address(adapterA));
        vm.prank(guardian);
        reg.pauseRegistry();
        assertFalse(reg.isAvailable(CID_A));
        vm.prank(timelock);
        reg.unpauseRegistry();
        assertTrue(reg.isAvailable(CID_A));
    }
}
