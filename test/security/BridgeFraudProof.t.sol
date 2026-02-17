// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/security/BridgeFraudProof.sol";
import "../../contracts/security/OptimisticBridgeVerifier.sol";

contract BridgeFraudProofTest is Test {
    BridgeFraudProof public fraudProof;
    OptimisticBridgeVerifier public verifier;
    address public admin = address(this);
    address public submitter = makeAddr("submitter");
    address public challenger = makeAddr("challenger");

    function setUp() public {
        verifier = new OptimisticBridgeVerifier(admin);
        fraudProof = new BridgeFraudProof(address(verifier), admin);
        
        // Grant RESOLVER_ROLE to fraudProof contract
        verifier.grantRole(verifier.RESOLVER_ROLE(), address(fraudProof));
        
        vm.deal(submitter, 100 ether);
        vm.deal(challenger, 100 ether);
    }

    function test_AutomatedFraudResolution() public {
        bytes32 messageHash = keccak256("msg");
        bytes memory proof = hex"123456";
        
        // 1. Submit Transfer
        vm.prank(submitter);
        bytes32 transferId = verifier.submitTransfer{value: 1 ether}(
            messageHash,
            100 ether, // Value > optimistic threshold (10 eth)
            proof,
            bytes32(0),
            bytes32(0)
        );

        // 2. Challenge Transfer
        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.1 ether}(transferId, hex"");
        
        // 3. Submit Fraud Proof (Evidence starts with FRAUD)
        // Anyone can submit fraud proof? Currently public.
        fraudProof.submitFraudProof(
            transferId,
            proof, // Original proof
            bytes("FRAUD_EVIDENCE") // Valid evidence
        );
        
        // 4. Check Resolution
        OptimisticBridgeVerifier.PendingTransfer memory transfer = verifier.getTransfer(transferId);
        
        // Status should be REJECTED (challenger won)
        assertEq(uint(transfer.status), uint(OptimisticBridgeVerifier.TransferStatus.REJECTED));
        
        // Challenger should be rewarded
        // (Check balance or logs)
    }

    function test_InvalidEvidence_Reverts() public {
        bytes32 messageHash = keccak256("msg2");
        bytes memory proof = hex"123456";
        
        vm.prank(submitter);
        bytes32 transferId = verifier.submitTransfer{value: 1 ether}(
            messageHash,
            100 ether, 
            proof,
            bytes32(0),
            bytes32(0)
        );

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.1 ether}(transferId, hex"");
        
        // Submit weak evidence
        vm.expectRevert("Fraud not proven");
        fraudProof.submitFraudProof(
            transferId,
            proof,
            bytes("WEAK")
        );
    }
}
