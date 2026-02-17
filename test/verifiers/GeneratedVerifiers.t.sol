// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
// Import AggregatorVerifier directly (still a stub)
import "../../contracts/verifiers/generated/AggregatorVerifier.sol";

/// @title GeneratedVerifiers Smoke Tests
/// @notice Tests for real UltraHonk verifiers (reject invalid proofs)
///         and AggregatorVerifier (still a stub — recursive circuit)
contract GeneratedVerifiersTest is Test {
    // AggregatorVerifier is the only remaining stub
    AggregatorVerifier public aggregator;

    // Real UltraHonk verifiers deployed via vm.getCode to avoid identifier collision
    address public accreditedAddr;
    address public balanceAddr;
    address public complianceAddr;
    address public encryptedAddr;
    address public merkleAddr;
    address public pedersenAddr;
    address public policyBoundAddr;
    address public sanctionsAddr;
    address public shieldedAddr;
    address public swapAddr;
    address public ringSignatureAddr;

    // Previously-deployed full UltraHonk verifiers
    address public privateTransferAddr;
    address public crossDomainNullifierAddr;

    // verify(bytes,bytes32[]) selector
    bytes4 constant VERIFY_SEL = bytes4(keccak256("verify(bytes,bytes32[])"));
    // StubVerifierNotDeployed() error selector (only for AggregatorVerifier)
    bytes4 constant STUB_ERROR = bytes4(keccak256("StubVerifierNotDeployed()"));

    function _deployContract(
        string memory path
    ) internal returns (address addr) {
        bytes memory code = vm.getCode(path);
        assembly {
            addr := create(0, add(code, 0x20), mload(code))
        }
        require(addr != address(0), "Deploy failed");
    }

    function setUp() public {
        aggregator = new AggregatorVerifier();

        // Real UltraHonk verifiers (generated from VK binaries)
        accreditedAddr = _deployContract(
            "AccreditedInvestorVerifier.sol:AccreditedInvestorVerifier"
        );
        balanceAddr = _deployContract(
            "BalanceProofVerifier.sol:BalanceProofVerifier"
        );
        complianceAddr = _deployContract(
            "ComplianceProofVerifier.sol:ComplianceProofVerifier"
        );
        encryptedAddr = _deployContract(
            "EncryptedTransferVerifier.sol:EncryptedTransferVerifier"
        );
        merkleAddr = _deployContract(
            "MerkleProofVerifier.sol:MerkleProofVerifier"
        );
        pedersenAddr = _deployContract(
            "PedersenCommitmentVerifier.sol:PedersenCommitmentVerifier"
        );
        policyBoundAddr = _deployContract(
            "PolicyBoundProofVerifier.sol:PolicyBoundProofVerifier"
        );
        sanctionsAddr = _deployContract(
            "SanctionsCheckVerifier.sol:SanctionsCheckVerifier"
        );
        shieldedAddr = _deployContract(
            "ShieldedPoolVerifier.sol:ShieldedPoolVerifier"
        );
        swapAddr = _deployContract("SwapProofVerifier.sol:SwapProofVerifier");
        ringSignatureAddr = _deployContract(
            "RingSignatureVerifier.sol:RingSignatureVerifier"
        );

        // Previously-deployed full UltraHonk verifiers
        privateTransferAddr = _deployContract(
            "PrivateTransferVerifier.sol:PrivateTransferVerifier"
        );
        crossDomainNullifierAddr = _deployContract(
            "CrossDomainNullifierVerifier.sol:CrossDomainNullifierVerifier"
        );
    }

    /* ──── Deployment ──── */

    function test_allVerifiersDeployable() public view {
        assertTrue(address(aggregator) != address(0), "aggregator");
        assertTrue(accreditedAddr != address(0), "accredited");
        assertTrue(balanceAddr != address(0), "balance");
        assertTrue(complianceAddr != address(0), "compliance");
        assertTrue(encryptedAddr != address(0), "encrypted");
        assertTrue(merkleAddr != address(0), "merkle");
        assertTrue(pedersenAddr != address(0), "pedersen");
        assertTrue(policyBoundAddr != address(0), "policyBound");
        assertTrue(sanctionsAddr != address(0), "sanctions");
        assertTrue(shieldedAddr != address(0), "shielded");
        assertTrue(swapAddr != address(0), "swap");
        assertTrue(ringSignatureAddr != address(0), "ringSignature");
        assertTrue(privateTransferAddr != address(0), "privateTransfer");
        assertTrue(
            crossDomainNullifierAddr != address(0),
            "crossDomainNullifier"
        );
    }

    /* ──── Stub Revert (AggregatorVerifier only — recursive circuit) ──── */

    function test_aggregator_stubReverts() public {
        bytes32[] memory inputs = new bytes32[](0);
        vm.expectRevert(AggregatorVerifier.StubVerifierNotDeployed.selector);
        aggregator.verify("", inputs);
    }

    /* ──── Real UltraHonk verifiers: reject invalid proofs ──── */

    /// @dev Helper: call verify with invalid proof and expect revert or false
    function _callVerifyAndExpectRejection(
        address target,
        uint256 numInputs
    ) internal {
        bytes32[] memory inputs = new bytes32[](numInputs);
        for (uint256 i = 0; i < numInputs; i++) {
            inputs[i] = bytes32(uint256(i + 1));
        }
        // Call with a too-short proof — should revert with ProofLengthWrong or similar
        (bool ok, bytes memory ret) = target.call(
            abi.encodeWithSelector(VERIFY_SEL, hex"dead", inputs)
        );
        if (ok) {
            bool verified = abi.decode(ret, (bool));
            assertFalse(verified, "Should not verify invalid proof");
        }
        // If !ok, it reverted which is acceptable for invalid proofs
    }

    /// @dev Helper: call verify with wrong input count — should revert
    function _callVerifyWrongInputCount(address target) internal {
        bytes32[] memory inputs = new bytes32[](1); // Wrong count for all circuits
        inputs[0] = bytes32(uint256(1));
        (bool ok, ) = target.call(
            abi.encodeWithSelector(VERIFY_SEL, hex"", inputs)
        );
        assertFalse(ok, "Should revert with wrong input count");
    }

    // --- Reject invalid proofs (each circuit) ---

    function test_accredited_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(accreditedAddr, 21);
    }

    function test_balance_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(balanceAddr, 22);
    }

    function test_compliance_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(complianceAddr, 32);
    }

    function test_encrypted_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(encryptedAddr, 24);
    }

    function test_merkle_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(merkleAddr, 19);
    }

    function test_pedersen_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(pedersenAddr, 19);
    }

    function test_policyBound_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(policyBoundAddr, 21);
    }

    function test_sanctions_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(sanctionsAddr, 21);
    }

    function test_shielded_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(shieldedAddr, 23);
    }

    function test_swap_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(swapAddr, 27);
    }

    function test_ringSignature_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(ringSignatureAddr, 36);
    }

    function test_privateTransfer_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(privateTransferAddr, 32);
    }

    function test_crossDomainNullifier_rejectsInvalidProof() public {
        _callVerifyAndExpectRejection(crossDomainNullifierAddr, 26);
    }

    // --- Reject wrong input count ---

    function test_accredited_rejectsWrongInputCount() public {
        _callVerifyWrongInputCount(accreditedAddr);
    }

    function test_balance_rejectsWrongInputCount() public {
        _callVerifyWrongInputCount(balanceAddr);
    }

    function test_compliance_rejectsWrongInputCount() public {
        _callVerifyWrongInputCount(complianceAddr);
    }

    function test_encrypted_rejectsWrongInputCount() public {
        _callVerifyWrongInputCount(encryptedAddr);
    }

    function test_shielded_rejectsWrongInputCount() public {
        _callVerifyWrongInputCount(shieldedAddr);
    }

    function test_swap_rejectsWrongInputCount() public {
        _callVerifyWrongInputCount(swapAddr);
    }

    function test_privateTransfer_rejectsWrongInputCount() public {
        _callVerifyWrongInputCount(privateTransferAddr);
    }

    function test_crossDomainNullifier_rejectsWrongInputCount() public {
        _callVerifyWrongInputCount(crossDomainNullifierAddr);
    }

    /* ──── Fuzz: AggregatorVerifier stub always reverts ──── */

    function testFuzz_aggregatorStubAlwaysReverts(bytes calldata proof) public {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = keccak256(proof);

        vm.expectRevert(AggregatorVerifier.StubVerifierNotDeployed.selector);
        aggregator.verify(proof, inputs);
    }
}
