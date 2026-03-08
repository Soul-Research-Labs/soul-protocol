// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/verifiers/adapters/UltraHonkAdapter.sol";

/// @dev Mock UltraHonk verifier
contract MockUltraHonkVerifier {
    bool public result;

    constructor(bool _result) {
        result = _result;
    }

    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external view returns (bool) {
        return result;
    }

    function setResult(bool _v) external {
        result = _v;
    }
}

contract UltraHonkAdapterTest is Test {
    UltraHonkAdapter public adapter;
    MockUltraHonkVerifier public honkV;

    bytes32 constant CIRCUIT_ID = keccak256("test_circuit");
    uint256 constant INPUT_COUNT = 2;

    function setUp() public {
        honkV = new MockUltraHonkVerifier(true);
        adapter = new UltraHonkAdapter(address(honkV), INPUT_COUNT, CIRCUIT_ID);
    }

    // ──────── Deployment ────────

    function test_deploy_verifierSet() public view {
        assertTrue(adapter.isReady());
        assertEq(adapter.getPublicInputCount(), INPUT_COUNT);
        assertEq(adapter.circuitId(), CIRCUIT_ID);
    }

    function test_deploy_zeroVerifierReverts() public {
        vm.expectRevert();
        new UltraHonkAdapter(address(0), 2, CIRCUIT_ID);
    }

    // ──────── verify(bytes, uint256[]) ────────

    function test_verify_uint256Array_success() public {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = 100;
        inputs[1] = 200;

        bool valid = adapter.verify(bytes("proof"), inputs);
        assertTrue(valid);
    }

    function test_verify_wrongInputCount() public {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = 1;
        inputs[1] = 2;
        inputs[2] = 3;

        vm.expectRevert(
            abi.encodeWithSelector(
                UltraHonkAdapter.InvalidPublicInputCount.selector,
                INPUT_COUNT,
                3
            )
        );
        adapter.verify(bytes("proof"), inputs);
    }

    function test_verify_verifierRejects() public {
        honkV.setResult(false);

        uint256[] memory inputs = new uint256[](2);
        inputs[0] = 1;
        inputs[1] = 2;

        bool valid = adapter.verify(bytes("proof"), inputs);
        assertFalse(valid);
    }

    // ──────── verifyProof(bytes, bytes) ────────

    function test_verifyProof_success() public {
        uint256[] memory arr = new uint256[](2);
        arr[0] = 10;
        arr[1] = 20;
        bytes memory pubInputs = abi.encode(arr);

        bool valid = adapter.verifyProof(bytes("proof"), pubInputs);
        assertTrue(valid);
    }

    // ──────── verifySingle ────────

    function test_verifySingle_wrongCountReverts() public {
        // adapter expects 2 inputs; verifySingle provides 1
        vm.expectRevert(
            abi.encodeWithSelector(
                UltraHonkAdapter.InvalidPublicInputCount.selector,
                1,
                2
            )
        );
        adapter.verifySingle(bytes("proof"), 42);
    }

    function test_verifySingle_success() public {
        // Deploy adapter with 1 input
        UltraHonkAdapter adapter1 = new UltraHonkAdapter(
            address(honkV),
            1,
            keccak256("single")
        );
        bool valid = adapter1.verifySingle(bytes("proof"), 42);
        assertTrue(valid);
    }

    // ──────── isReady ────────

    function test_isReady() public view {
        assertTrue(adapter.isReady());
    }

    // ──────── Events ────────

    function test_verify_returnsTrue() public view {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = 1;
        inputs[1] = 2;

        // verify is view (staticcall) so cannot emit events
        bool valid = adapter.verify(bytes("proof"), inputs);
        assertTrue(valid);
    }

    // ──────── Fuzz ────────

    function testFuzz_verify_anyInputs(uint256 a, uint256 b) public {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = a;
        inputs[1] = b;

        bool valid = adapter.verify(bytes("proof"), inputs);
        assertTrue(valid);
    }
}
