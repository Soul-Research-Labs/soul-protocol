// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/internal/helpers/VerifierProxy.sol";

/// @dev Mock verifier that always returns true
contract MockVerifierTrue {
    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        return true;
    }
}

/// @dev Mock verifier that always returns false
contract MockVerifierFalse {
    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        return false;
    }
}

/// @dev Mock verifier that reverts
contract MockVerifierReverts {
    function verify(bytes calldata, bytes32[] calldata) external pure {
        revert("BOOM");
    }
}

/// @dev Mock verifier that returns invalid data (too short)
contract MockVerifierInvalidReturn {
    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bytes memory) {
        // Return only 16 bytes (less than 32), which will be decoded as invalid
        assembly {
            mstore(0x00, 0x01)
            return(0x00, 16)
        }
    }
}

/// @dev Harness contract to expose VerifierProxy library functions
contract VerifierProxyHarness {
    using VerifierProxy for mapping(bytes32 => address);

    mapping(bytes32 => address) internal _verifiers;

    function register(bytes32 key, address verifier) external {
        _verifiers.register(key, verifier);
    }

    function deregister(bytes32 key) external {
        _verifiers.deregister(key);
    }

    function isRegistered(bytes32 key) external view returns (bool) {
        return _verifiers.isRegistered(key);
    }

    function getVerifier(bytes32 key) external view returns (address) {
        return _verifiers.getVerifier(key);
    }

    function dispatch(
        VerifierProxy.VerifyRequest memory req
    ) external view returns (VerifierProxy.VerifyResult memory) {
        return VerifierProxy.dispatch(_verifiers, req);
    }

    function dispatchAndRequire(
        VerifierProxy.VerifyRequest memory req
    ) external view returns (bytes32) {
        return VerifierProxy.dispatchAndRequire(_verifiers, req);
    }
}

contract VerifierProxyTest is Test {
    VerifierProxyHarness harness;
    MockVerifierTrue verifierTrue;
    MockVerifierFalse verifierFalse;
    MockVerifierReverts verifierReverts;
    MockVerifierInvalidReturn verifierInvalid;

    bytes32 constant KEY_1 = keccak256("groth16-bn254");
    bytes32 constant KEY_2 = keccak256("ultrahonk");

    function setUp() public {
        harness = new VerifierProxyHarness();
        verifierTrue = new MockVerifierTrue();
        verifierFalse = new MockVerifierFalse();
        verifierReverts = new MockVerifierReverts();
        verifierInvalid = new MockVerifierInvalidReturn();
    }

    // ---------------------------------------------------------------
    // Registration Tests
    // ---------------------------------------------------------------

    function test_Register() public {
        harness.register(KEY_1, address(verifierTrue));
        assertTrue(harness.isRegistered(KEY_1));
        assertEq(harness.getVerifier(KEY_1), address(verifierTrue));
    }

    function test_RegisterMultiple() public {
        harness.register(KEY_1, address(verifierTrue));
        harness.register(KEY_2, address(verifierFalse));
        assertTrue(harness.isRegistered(KEY_1));
        assertTrue(harness.isRegistered(KEY_2));
        assertEq(harness.getVerifier(KEY_1), address(verifierTrue));
        assertEq(harness.getVerifier(KEY_2), address(verifierFalse));
    }

    function test_RegisterOverwrite() public {
        harness.register(KEY_1, address(verifierTrue));
        harness.register(KEY_1, address(verifierFalse));
        assertEq(harness.getVerifier(KEY_1), address(verifierFalse));
    }

    function test_RevertRegisterZeroAddress() public {
        vm.expectRevert(VerifierProxy.ZeroAddressVerifier.selector);
        harness.register(KEY_1, address(0));
    }

    function test_Deregister() public {
        harness.register(KEY_1, address(verifierTrue));
        assertTrue(harness.isRegistered(KEY_1));
        harness.deregister(KEY_1);
        assertFalse(harness.isRegistered(KEY_1));
    }

    function test_DeregisterNonexistent() public {
        // Should not revert — just a no-op delete
        harness.deregister(KEY_1);
        assertFalse(harness.isRegistered(KEY_1));
    }

    function test_IsRegistered_False() public view {
        assertFalse(harness.isRegistered(KEY_1));
    }

    function test_GetVerifier_RevertNotRegistered() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifierProxy.VerifierNotRegistered.selector,
                KEY_1
            )
        );
        harness.getVerifier(KEY_1);
    }

    // ---------------------------------------------------------------
    // Dispatch Tests
    // ---------------------------------------------------------------

    function test_DispatchSuccess() public {
        harness.register(KEY_1, address(verifierTrue));

        VerifierProxy.VerifyRequest memory req = VerifierProxy.VerifyRequest({
            verifierKey: KEY_1,
            proof: hex"deadbeef",
            publicInputs: new bytes32[](0)
        });

        VerifierProxy.VerifyResult memory result = harness.dispatch(req);
        assertTrue(result.verified);
        assertEq(result.proofHash, keccak256(hex"deadbeef"));
        assertGt(result.gasUsed, 0);
    }

    function test_DispatchReturnsFalse() public {
        harness.register(KEY_1, address(verifierFalse));

        VerifierProxy.VerifyRequest memory req = VerifierProxy.VerifyRequest({
            verifierKey: KEY_1,
            proof: hex"cafe",
            publicInputs: new bytes32[](0)
        });

        VerifierProxy.VerifyResult memory result = harness.dispatch(req);
        assertFalse(result.verified);
    }

    function test_DispatchRevertNotRegistered() public {
        VerifierProxy.VerifyRequest memory req = VerifierProxy.VerifyRequest({
            verifierKey: KEY_1,
            proof: hex"aa",
            publicInputs: new bytes32[](0)
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifierProxy.VerifierNotRegistered.selector,
                KEY_1
            )
        );
        harness.dispatch(req);
    }

    function test_DispatchRevertOnVerifierRevert() public {
        harness.register(KEY_1, address(verifierReverts));

        VerifierProxy.VerifyRequest memory req = VerifierProxy.VerifyRequest({
            verifierKey: KEY_1,
            proof: hex"bb",
            publicInputs: new bytes32[](0)
        });

        vm.expectRevert(); // VerifierCallReverted
        harness.dispatch(req);
    }

    function test_DispatchWithPublicInputs() public {
        harness.register(KEY_1, address(verifierTrue));

        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = bytes32(uint256(42));
        inputs[1] = bytes32(uint256(99));

        VerifierProxy.VerifyRequest memory req = VerifierProxy.VerifyRequest({
            verifierKey: KEY_1,
            proof: hex"1234",
            publicInputs: inputs
        });

        VerifierProxy.VerifyResult memory result = harness.dispatch(req);
        assertTrue(result.verified);
    }

    // ---------------------------------------------------------------
    // DispatchAndRequire Tests
    // ---------------------------------------------------------------

    function test_DispatchAndRequireSuccess() public {
        harness.register(KEY_1, address(verifierTrue));

        VerifierProxy.VerifyRequest memory req = VerifierProxy.VerifyRequest({
            verifierKey: KEY_1,
            proof: hex"aabb",
            publicInputs: new bytes32[](0)
        });

        bytes32 proofHash = harness.dispatchAndRequire(req);
        assertEq(proofHash, keccak256(hex"aabb"));
    }

    function test_DispatchAndRequireRevertOnFalse() public {
        harness.register(KEY_1, address(verifierFalse));

        VerifierProxy.VerifyRequest memory req = VerifierProxy.VerifyRequest({
            verifierKey: KEY_1,
            proof: hex"cc",
            publicInputs: new bytes32[](0)
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifierProxy.VerifierReturnedInvalid.selector,
                KEY_1
            )
        );
        harness.dispatchAndRequire(req);
    }

    // ---------------------------------------------------------------
    // Fuzz Tests
    // ---------------------------------------------------------------

    function testFuzz_RegisterAndRetrieve(
        bytes32 key,
        address verifier
    ) public {
        vm.assume(verifier != address(0));
        harness.register(key, verifier);
        assertTrue(harness.isRegistered(key));
        assertEq(harness.getVerifier(key), verifier);
    }

    function testFuzz_RegisterRejectZero(bytes32 key) public {
        vm.expectRevert(VerifierProxy.ZeroAddressVerifier.selector);
        harness.register(key, address(0));
    }
}
