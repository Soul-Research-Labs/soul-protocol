// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
// NOTE: Each stub verifier declares its own IVerifier interface, so we can
// only import one at a time without identifier collisions. We test them
// via low-level calls instead.
import "../../contracts/verifiers/generated/AccreditedInvestorVerifier.sol";

/// @title GeneratedVerifiers Smoke Tests
/// @notice Tests for stub verifiers (revert with StubVerifierNotDeployed)
///         and full UltraHonk verifiers (deployment only)
contract GeneratedVerifiersTest is Test {
    AccreditedInvestorVerifier public accredited;

    // Deploy other stubs via create bytecode + low-level calls
    address public aggregatorAddr;
    address public balanceAddr;
    address public complianceAddr;
    address public encryptedAddr;
    address public merkleAddr;
    address public pedersenAddr;
    address public policyBoundAddr;
    address public sanctionsAddr;
    address public shieldedAddr;
    address public swapAddr;

    // verify(bytes,bytes32[]) selector
    bytes4 constant VERIFY_SEL = bytes4(keccak256("verify(bytes,bytes32[])"));
    // StubVerifierNotDeployed() error selector
    bytes4 constant STUB_ERROR = bytes4(keccak256("StubVerifierNotDeployed()"));

    function _deployContract(string memory path) internal returns (address addr) {
        bytes memory code = vm.getCode(path);
        assembly {
            addr := create(0, add(code, 0x20), mload(code))
        }
        require(addr != address(0), "Deploy failed");
    }

    function setUp() public {
        accredited = new AccreditedInvestorVerifier();
        aggregatorAddr = _deployContract("AggregatorVerifier.sol:AggregatorVerifier");
        balanceAddr = _deployContract("BalanceProofVerifier.sol:BalanceProofVerifier");
        complianceAddr = _deployContract("ComplianceProofVerifier.sol:ComplianceProofVerifier");
        encryptedAddr = _deployContract("EncryptedTransferVerifier.sol:EncryptedTransferVerifier");
        merkleAddr = _deployContract("MerkleProofVerifier.sol:MerkleProofVerifier");
        pedersenAddr = _deployContract("PedersenCommitmentVerifier.sol:PedersenCommitmentVerifier");
        policyBoundAddr = _deployContract("PolicyBoundProofVerifier.sol:PolicyBoundProofVerifier");
        sanctionsAddr = _deployContract("SanctionsCheckVerifier.sol:SanctionsCheckVerifier");
        shieldedAddr = _deployContract("ShieldedPoolVerifier.sol:ShieldedPoolVerifier");
        swapAddr = _deployContract("SwapProofVerifier.sol:SwapProofVerifier");
    }

    /* ──── Deployment ──── */

    function test_allStubsDeployable() public view {
        assertTrue(address(accredited) != address(0));
        assertTrue(aggregatorAddr != address(0));
        assertTrue(balanceAddr != address(0));
        assertTrue(complianceAddr != address(0));
        assertTrue(encryptedAddr != address(0));
        assertTrue(merkleAddr != address(0));
        assertTrue(pedersenAddr != address(0));
        assertTrue(policyBoundAddr != address(0));
        assertTrue(sanctionsAddr != address(0));
        assertTrue(shieldedAddr != address(0));
        assertTrue(swapAddr != address(0));
    }

    /* ──── Stub Reverts (direct import) ──── */

    function test_accreditedInvestor_stubReverts() public {
        bytes32[] memory inputs = new bytes32[](0);
        vm.expectRevert(AccreditedInvestorVerifier.StubVerifierNotDeployed.selector);
        accredited.verify("", inputs);
    }

    /* ──── Stub Reverts (low-level calls) ──── */

    function _callVerifyAndExpectStubRevert(address target) internal {
        bytes memory callData = abi.encodeWithSelector(
            VERIFY_SEL,
            "", // proof
            new bytes32[](0) // publicInputs
        );
        (bool success, bytes memory returnData) = target.call(callData);
        assertFalse(success, "Should have reverted");
        // Check custom error selector
        assertGe(returnData.length, 4);
        bytes4 errorSel;
        assembly { errorSel := mload(add(returnData, 32)) }
        assertEq(errorSel, STUB_ERROR, "Wrong error selector");
    }

    function test_aggregator_stubReverts() public {
        _callVerifyAndExpectStubRevert(aggregatorAddr);
    }

    function test_balance_stubReverts() public {
        _callVerifyAndExpectStubRevert(balanceAddr);
    }

    function test_compliance_stubReverts() public {
        _callVerifyAndExpectStubRevert(complianceAddr);
    }

    function test_encrypted_stubReverts() public {
        _callVerifyAndExpectStubRevert(encryptedAddr);
    }

    function test_merkle_stubReverts() public {
        _callVerifyAndExpectStubRevert(merkleAddr);
    }

    function test_pedersen_stubReverts() public {
        _callVerifyAndExpectStubRevert(pedersenAddr);
    }

    function test_policyBound_stubReverts() public {
        _callVerifyAndExpectStubRevert(policyBoundAddr);
    }

    function test_sanctions_stubReverts() public {
        _callVerifyAndExpectStubRevert(sanctionsAddr);
    }

    function test_shielded_stubReverts() public {
        _callVerifyAndExpectStubRevert(shieldedAddr);
    }

    function test_swap_stubReverts() public {
        _callVerifyAndExpectStubRevert(swapAddr);
    }

    /* ──── Fuzz: any proof/inputs still revert ──── */

    function testFuzz_stubsAlwaysRevert(bytes calldata proof) public {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = keccak256(proof);

        vm.expectRevert(AccreditedInvestorVerifier.StubVerifierNotDeployed.selector);
        accredited.verify(proof, inputs);
    }
}
