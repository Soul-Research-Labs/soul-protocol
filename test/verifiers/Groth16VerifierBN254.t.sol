// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/verifiers/Groth16VerifierBN254.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract Groth16VerifierBN254Test is Test {
    Groth16VerifierBN254 verifier;

    address owner;
    address user = makeAddr("user");

    // BN254 G1 generator
    uint256 constant G1_X = 1;
    uint256 constant G1_Y = 2;

    // BN254 field modulus
    uint256 constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        owner = address(this);
        verifier = new Groth16VerifierBN254(owner);
    }

    /* ══════════════════════════════════════════════════
                     CONSTRUCTOR
       ══════════════════════════════════════════════════ */

    function test_constructor_setsOwner() public view {
        assertTrue(verifier.hasRole(verifier.DEFAULT_ADMIN_ROLE(), owner));
        assertTrue(verifier.hasRole(verifier.VK_ADMIN_ROLE(), owner));
    }

    function test_constructor_notInitialized() public view {
        assertFalse(verifier.initialized());
    }

    /* ══════════════════════════════════════════════════
                 SET VERIFICATION KEY
       ══════════════════════════════════════════════════ */

    function test_setVerificationKey() public {
        _setDummyVK(2);
        assertTrue(verifier.initialized());
    }

    function test_setVerificationKey_revertsNotOwner() public {
        bytes32 vkAdminRole = verifier.VK_ADMIN_ROLE();
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                user,
                vkAdminRole
            )
        );

        uint256[2] memory alpha = [uint256(1), uint256(2)];
        uint256[4] memory beta = [
            uint256(1),
            uint256(2),
            uint256(3),
            uint256(4)
        ];
        uint256[4] memory gamma = [
            uint256(1),
            uint256(2),
            uint256(3),
            uint256(4)
        ];
        uint256[4] memory delta = [
            uint256(1),
            uint256(2),
            uint256(3),
            uint256(4)
        ];
        uint256[2][] memory ic = new uint256[2][](2);
        ic[0] = [uint256(1), uint256(2)];
        ic[1] = [uint256(1), uint256(2)];

        verifier.setVerificationKey(alpha, beta, gamma, delta, ic);
    }

    function test_setVerificationKey_canRotateKey() public {
        _setDummyVK(2);
        assertTrue(verifier.initialized());

        // Should allow re-setting (key rotation)
        _setDummyVK(3);
        assertTrue(verifier.initialized());
    }

    /* ══════════════════════════════════════════════════
               VERIFY — PRECONDITION CHECKS
       ══════════════════════════════════════════════════ */

    function test_verify_revertsNotInitialized() public {
        bytes memory proof = new bytes(256);
        uint256[] memory inputs = new uint256[](1);

        vm.expectRevert(Groth16VerifierBN254.NotInitialized.selector);
        verifier.verify(proof, inputs);
    }

    function test_verify_revertsInvalidProofSize() public {
        _setDummyVK(2);

        bytes memory proof = new bytes(128); // wrong size
        uint256[] memory inputs = new uint256[](1);

        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidProofSize.selector,
                128
            )
        );
        verifier.verify(proof, inputs);
    }

    function test_verify_revertsInvalidInputCount() public {
        _setDummyVK(2); // IC length 2 → expects 1 public input

        bytes memory proof = new bytes(256);
        uint256[] memory inputs = new uint256[](3); // wrong count

        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidPublicInputCount.selector,
                3,
                1
            )
        );
        verifier.verify(proof, inputs);
    }

    function test_verify_revertsInvalidPublicInput() public {
        _setDummyVK(2);

        bytes memory proof = new bytes(256);
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = FR; // >= field modulus

        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidPublicInput.selector,
                0,
                FR
            )
        );
        verifier.verify(proof, inputs);
    }

    /* ══════════════════════════════════════════════════
              VERIFY SINGLE — PRECONDITIONS
       ══════════════════════════════════════════════════ */

    function test_verifySingle_revertsNotInitialized() public {
        bytes memory proof = new bytes(256);
        vm.expectRevert(Groth16VerifierBN254.NotInitialized.selector);
        verifier.verifySingle(proof, 0);
    }

    function test_verifySingle_revertsInvalidProofSize() public {
        _setDummyVK(2);

        bytes memory proof = new bytes(100);
        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidProofSize.selector,
                100
            )
        );
        verifier.verifySingle(proof, 0);
    }

    function test_verifySingle_revertsInvalidInput() public {
        _setDummyVK(2);

        bytes memory proof = new bytes(256);
        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidPublicInput.selector,
                0,
                FR
            )
        );
        verifier.verifySingle(proof, FR);
    }

    /* ══════════════════════════════════════════════════
                  VERIFY PROOF (bytes)
       ══════════════════════════════════════════════════ */

    function test_verifyProof_revertsNotInitialized() public {
        bytes memory proof = new bytes(256);
        uint256[] memory inputs = new uint256[](1);
        bytes memory encodedInputs = abi.encode(inputs);

        vm.expectRevert(Groth16VerifierBN254.NotInitialized.selector);
        verifier.verifyProof(proof, encodedInputs);
    }

    /* ══════════════════════════════════════════════════
               GET PUBLIC INPUT COUNT
       ══════════════════════════════════════════════════ */

    function test_getPublicInputCount_notInitialized() public view {
        assertEq(verifier.getPublicInputCount(), 0);
    }

    function test_getPublicInputCount_initialized() public {
        _setDummyVK(3); // IC length 3 → 2 public inputs
        assertEq(verifier.getPublicInputCount(), 2);
    }

    /* ══════════════════════════════════════════════════
                     IS READY
       ══════════════════════════════════════════════════ */

    function test_isReady_false() public view {
        assertFalse(verifier.isReady());
    }

    function test_isReady_true() public {
        _setDummyVK(2);
        assertTrue(verifier.isReady());
    }

    /* ══════════════════════════════════════════════════
               ACCESS CONTROL
       ══════════════════════════════════════════════════ */

    function test_grantVKAdminRole() public {
        bytes32 vkAdminRole = verifier.VK_ADMIN_ROLE();
        verifier.grantRole(vkAdminRole, user);
        assertTrue(verifier.hasRole(vkAdminRole, user));
    }

    function test_grantRole_revertsNotAdmin() public {
        bytes32 vkAdminRole = verifier.VK_ADMIN_ROLE();
        bytes32 defaultAdminRole = verifier.DEFAULT_ADMIN_ROLE();
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                user,
                defaultAdminRole
            )
        );
        verifier.grantRole(vkAdminRole, user);
    }

    function test_revokeVKAdminRole() public {
        bytes32 vkAdminRole = verifier.VK_ADMIN_ROLE();
        verifier.grantRole(vkAdminRole, user);
        assertTrue(verifier.hasRole(vkAdminRole, user));
        verifier.revokeRole(vkAdminRole, user);
        assertFalse(verifier.hasRole(vkAdminRole, user));
    }

    /* ══════════════════════════════════════════════════
                     CONSTANTS
       ══════════════════════════════════════════════════ */

    function test_constants() public view {
        // Verify VK alpha not set yet (public array getter takes index)
        assertEq(verifier.vkAlpha(0), 0);
        assertEq(verifier.vkAlpha(1), 0);
    }

    /* ══════════════════════════════════════════════════
                      HELPERS
       ══════════════════════════════════════════════════ */

    function _setDummyVK(uint256 icLength) internal {
        uint256[2] memory alpha = [G1_X, G1_Y];
        uint256[4] memory beta = [
            uint256(1),
            uint256(2),
            uint256(3),
            uint256(4)
        ];
        uint256[4] memory gamma = [
            uint256(1),
            uint256(2),
            uint256(3),
            uint256(4)
        ];
        uint256[4] memory delta = [
            uint256(1),
            uint256(2),
            uint256(3),
            uint256(4)
        ];

        uint256[2][] memory ic = new uint256[2][](icLength);
        for (uint256 i = 0; i < icLength; i++) {
            ic[i] = [G1_X, G1_Y];
        }

        verifier.setVerificationKey(alpha, beta, gamma, delta, ic);
    }
}
