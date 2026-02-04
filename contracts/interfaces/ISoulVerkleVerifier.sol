// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISoulVerkleVerifier
/// @notice Interface for Verkle tree witness verification
interface ISoulVerkleVerifier {
    struct VerkleProof {
        bytes32 commitment;
        bytes32[] path;
        uint256 pathBits;
        bytes ipaProof;
        bytes32 leafValue;
    }

    struct VerkleWitness {
        bytes32 stateRoot;
        VerkleProof[] proofs;
        bytes32[] accessedKeys;
        bytes32[] accessedValues;
    }

    struct SoulVerklePrivacyProof {
        bytes32 commitmentHash;
        bytes32 nullifier;
        VerkleWitness stateWitness;
        bytes zkProof;
    }

    struct BandersnatchPoint {
        uint256 x;
        uint256 y;
    }

    event VerkleProofVerified(
        bytes32 indexed commitment,
        bytes32 indexed stateRoot,
        uint256 proofCount
    );

    event VerkleStateRootUpdated(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot
    );

    event SoulVerklePrivacyProofVerified(
        bytes32 indexed commitmentHash,
        bytes32 indexed nullifier
    );

    function verifyVerkleProof(
        VerkleProof calldata proof,
        bytes32 stateRoot,
        bytes32 key
    ) external view returns (bool valid);

    function verifyVerkleWitness(
        VerkleWitness calldata witness
    ) external view returns (bool valid);

    function verifySoulVerklePrivacyProof(
        SoulVerklePrivacyProof calldata proof
    ) external returns (bool valid);

    function verifyBandersnatchPoint(
        BandersnatchPoint calldata point
    ) external pure returns (bool valid);

    function createSoulVerkleCommitment(
        bytes32[] calldata keys,
        bytes32[] calldata values
    ) external pure returns (bytes32 commitment);
}
