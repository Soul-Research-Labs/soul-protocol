// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../verifiers/Groth16VerifierBLS12381.sol";

/// @title ConfidentialStateContainer
/// @notice MVP: Register and transfer confidential stablecoin state with Groth16 proof verification (BLS12-381)
/// @dev Legacy contract - see ConfidentialStateContainerV3 for production use
contract ConfidentialStateContainer {
    Groth16VerifierBLS12381 public verifier;
    address public admin;

    /// @notice Nullifier tracking
    mapping(bytes32 => bool) public nullifiers;

    struct EncryptedState {
        bytes encryptedState;
        bytes32 commitment;
        bytes32 nullifier;
        address owner;
    }

    mapping(bytes32 => EncryptedState) public states;
    event StateRegistered(bytes32 indexed commitment, address indexed owner);
    event StateTransferred(
        bytes32 indexed oldCommitment,
        bytes32 indexed newCommitment,
        address indexed newOwner
    );

    constructor(address _verifier) {
        verifier = Groth16VerifierBLS12381(_verifier);
        admin = msg.sender;
    }

    function registerState(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external {
        require(!nullifiers[nullifier], "Nullifier used");
        require(verifier.verifyProof(proof, publicInputs), "Invalid proof");
        states[commitment] = EncryptedState({
            encryptedState: encryptedState,
            commitment: commitment,
            nullifier: nullifier,
            owner: msg.sender
        });
        nullifiers[nullifier] = true;
        emit StateRegistered(commitment, msg.sender);
    }

    function transferState(
        bytes32 oldCommitment,
        bytes calldata newEncryptedState,
        bytes32 newCommitment,
        bytes32 newNullifier,
        bytes calldata proof,
        bytes calldata publicInputs,
        address newOwner
    ) external {
        EncryptedState storage oldState = states[oldCommitment];
        require(oldState.owner == msg.sender, "Not owner");
        require(!nullifiers[newNullifier], "Nullifier used");
        require(verifier.verifyProof(proof, publicInputs), "Invalid proof");
        states[newCommitment] = EncryptedState({
            encryptedState: newEncryptedState,
            commitment: newCommitment,
            nullifier: newNullifier,
            owner: newOwner
        });
        nullifiers[newNullifier] = true;
        emit StateTransferred(oldCommitment, newCommitment, newOwner);
    }
}
