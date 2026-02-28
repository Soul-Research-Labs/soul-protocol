// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec
// @notice Configurable AggregatorVerifier — delegates to a real bb-generated
//         UltraHonk verifier once set by admin. Until then, reverts with
//         StubVerifierNotDeployed.
//
//         The real verifier is now available at AggregatorHonkVerifier.sol,
//         generated via bb 3.0.0:
//           nargo compile && bb write_vk -b target/aggregator.json -t evm
//           bb write_solidity_verifier -k target/aggregator_vk_new/vk -t evm --optimized
//
//         After deploying AggregatorHonkVerifier, call:
//           setImplementation(deployedHonkVerifierAddress)
//           lockImplementation()
pragma solidity ^0.8.24;

interface IVerifier {
    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external returns (bool);
}

/**
 * @title AggregatorVerifier
 * @author ZASEON Team
 * @notice Configurable wrapper for the recursive 4-proof batch aggregator verifier.
 * @dev This contract acts as a stable entry point. Once a real UltraHonk verifier
 *      is generated from the Noir aggregator circuit (requires bb >= 3.1.0), the admin
 *      can deploy it and call `setImplementation()` to enable real verification.
 *
 *      EXPECTED PUBLIC INPUTS (4 sub-proofs aggregated):
 *        - 4x sub-proof public input hashes (bytes32[4])
 *        - 4x sub-proof verification key hashes (bytes32[4])
 *        - aggregated commitment (bytes32)
 *
 *      CONSTRAINT COUNT: ~45,000 (recursive circuit)
 */
contract AggregatorVerifier is IVerifier {
    error StubVerifierNotDeployed();
    error Unauthorized();
    error ZeroAddress();
    error ImplementationAlreadyLocked();

    /// @notice Admin who can set the implementation verifier
    address public immutable admin;

    /// @notice The real UltraHonk verifier implementation (address(0) when unset)
    IVerifier public implementation;

    /// @notice Whether the implementation has been permanently locked
    bool public locked;

    /// @notice Emitted when a real verifier implementation is set
    event ImplementationSet(address indexed verifier);

    /// @notice Emitted when the implementation is permanently locked
    event ImplementationLocked(address indexed verifier);

    constructor() {
        admin = msg.sender;
    }

    /// @notice Set the real verifier implementation
    /// @param _implementation Address of the deployed bb-generated UltraHonk verifier
    function setImplementation(address _implementation) external {
        if (msg.sender != admin) revert Unauthorized();
        if (locked) revert ImplementationAlreadyLocked();
        if (_implementation == address(0)) revert ZeroAddress();
        implementation = IVerifier(_implementation);
        emit ImplementationSet(_implementation);
    }

    /// @notice Permanently lock the implementation — irreversible
    function lockImplementation() external {
        if (msg.sender != admin) revert Unauthorized();
        if (address(implementation) == address(0))
            revert StubVerifierNotDeployed();
        locked = true;
        emit ImplementationLocked(address(implementation));
    }

    /// @notice Verify a recursive aggregated proof
    /// @dev Delegates to the real verifier if set, otherwise reverts.
    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external override returns (bool) {
        if (address(implementation) == address(0)) {
            revert StubVerifierNotDeployed();
        }
        return implementation.verify(_proof, _publicInputs);
    }
}
