// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ConfidentialStateContainerV3} from "../../contracts/core/ConfidentialStateContainerV3.sol";
import {IProofVerifier} from "../../contracts/core/ConfidentialStateContainerV3.sol";

contract MockVerifier is IProofVerifier {
    function verifyProof(
        bytes calldata, /* proof */
        bytes calldata /* publicInputs */
    ) external pure returns (bool) {
        return true;
    }
}

contract Handler is Test {
    ConfidentialStateContainerV3 public container;
    MockVerifier public verifier;
    
    address public admin;
    address[] public users;
    
    // Ghost variables for invariant checking
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => bool) public existingCommitments;
    uint256 public activeStateCount;

    constructor(ConfidentialStateContainerV3 _container, address _admin) {
        container = _container;
        admin = _admin;
        verifier = new MockVerifier();
        
        users.push(address(0x1));
        users.push(address(0x2));
        users.push(address(0x3));
    }

    function registerState(
        uint256 ownerIndex,
        uint256 commitmentSeed,
        uint256 nullifierSeed
    ) public {
        address owner = users[ownerIndex % users.length];
        bytes32 commitment = keccak256(abi.encodePacked(commitmentSeed));
        bytes32 nullifier = keccak256(abi.encodePacked(nullifierSeed));
        
        // Pre-conditions to avoid reverts (we want to test valid state transitions mostly, 
        // though reverts are fine, ghost update should track success)
        if (existingCommitments[commitment]) return;
        if (usedNullifiers[nullifier]) return;

        bytes memory encryptedState = new bytes(64);
        bytes memory proof = new bytes(1);
        bytes32 metadata = bytes32(0);

        try container.registerState(
            encryptedState,
            commitment,
            nullifier,
            proof,
            metadata
        ) {
            existingCommitments[commitment] = true;
            usedNullifiers[nullifier] = true;
            activeStateCount++;
        } catch {
            // Expected if some internal check fails (though we tried to avoid it)
        }
    }

    function transferState(
        uint256 commitmentSeed, // To find existing
        uint256 newCommitmentSeed,
        uint256 newNullifierSeed,
        uint256 spendingNullifierSeed,
        uint256 newOwnerIndex
    ) public {
        bytes32 oldCommitment = keccak256(abi.encodePacked(commitmentSeed));
        if (!existingCommitments[oldCommitment]) return;
        
        // We need to be the owner to transfer. 
        // In this simple Handler, we are simulating msg.sender.
        // We need a way to prank as the owner. 
        // But Handlers in foundry are usually called by the fuzzer.
        // We can't prune msg.sender easily inside the handler unless we use library calls or `vm.prank`.
        // `vm.prank` works in handlers!
        
        ConfidentialStateContainerV3.EncryptedState memory state = container.states(oldCommitment);
        if (state.status != ConfidentialStateContainerV3.StateStatus.Active) return;
        
        bytes32 newCommitment = keccak256(abi.encodePacked(newCommitmentSeed));
        bytes32 newNullifier = keccak256(abi.encodePacked(newNullifierSeed));
        bytes32 spendingNullifier = keccak256(abi.encodePacked(spendingNullifierSeed));
        address newOwner = users[newOwnerIndex % users.length];
        
        if (existingCommitments[newCommitment]) return;
        if (usedNullifiers[newNullifier]) return;
        if (usedNullifiers[spendingNullifier]) return;

        bytes memory newEncryptedState = new bytes(64);
        bytes memory proof = new bytes(1);

        vm.prank(state.owner);
        try container.transferState(
            oldCommitment,
            newEncryptedState,
            newCommitment,
            newNullifier,
            spendingNullifier,
            proof,
            newOwner
        ) {
             existingCommitments[newCommitment] = true;
             usedNullifiers[newNullifier] = true;
             usedNullifiers[spendingNullifier] = true;
             // Old state is retired, new is active. Count doesn't change?
             // Actually old becomes Retired, new becomes Active.
             // Net active count change: 0.
             // But Wait, does it?
             // _transferState marks old as Retired. _createNewState creates Active.
             // total counters are incremented in _validateAndRegisterState, but _createNewState does NOT increment packedCounters?
             // Let's check the code. 
             // _createNewState (line 598) does NOT increment _packedCounters.
             // _validateAndRegisterState (line 425) DOES increment _packedCounters (+_COUNTER_INCREMENT + 1).
             // State registered = +1 active, +1 total.
             // Transfer: Old -> Retired. New -> Active.
             // Is active count decremented for Retired?
             // Not in _transferState.
             // So if Old becomes Retired and New becomes Active, Active count should technically imply "Currently Active".
             // But _packedCounters tracks "activeStates".
             // When does it decrement?
             // freezeState decrements.
             // transferState does NOT decrement.
             // So specific Active count logic might be: "Number of active slots occupied"? 
             // Using ghost var to track expected "Active" status.
        } catch {
             // Ignore
        }
    }
}
