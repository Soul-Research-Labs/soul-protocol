// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VerifierProxy
 * @author ZASEON
 * @notice Thin delegation layer that routes ZK proof verification requests
 *         to the correct verifier contract, reducing stack depth in callers.
 * @dev Designed to be used as a library by contracts that need to dispatch
 *      proofs to different verifier backends (Groth16 BN254, PLONK, UltraHonk,
 *      FRI, etc.) without embedding all dispatch logic inline.
 *
 * RATIONALE:
 * - ZKBoundStateLocks and ConfidentialStateContainerV3 previously inlined
 *   verifier selection + low‐level call + return decoding, pushing them over
 *   the stack limit during coverage instrumentation.
 * - Extracting into a library lets both contracts `using VerifierProxy for ...`
 *   and keeps their top‐level functions ≤ 16 local variables.
 *
 * VERIFIER REGISTRY INTEGRATION:
 * - Callers maintain a mapping(bytes32 ⇒ address) of registered verifiers.
 * - This library reads from that mapping and performs the static‐call.
 */
library VerifierProxy {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error VerifierNotRegistered(bytes32 verifierKey);
    error VerifierCallReverted(bytes32 verifierKey, bytes reason);
    error VerifierReturnedInvalid(bytes32 verifierKey);
    error ZeroAddressVerifier();

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Packaged verification request
     */
    struct VerifyRequest {
        bytes32 verifierKey;
        bytes proof;
        bytes32[] publicInputs;
    }

    /**
     * @notice Verification result
     */
    struct VerifyResult {
        bool verified;
        bytes32 proofHash;
        uint256 gasUsed;
    }

    /*//////////////////////////////////////////////////////////////
                         DISPATCH FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Dispatches a proof to the registered verifier via staticcall
     * @dev The verifier is expected to implement:
     *        `function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool)`
     * @param verifiers Mapping of verifierKey → verifier address
     * @param req       The verification request
     * @return result   The verification result including gas metering
     */
    function dispatch(
        mapping(bytes32 => address) storage verifiers,
        VerifyRequest memory req
    ) internal view returns (VerifyResult memory result) {
        address verifier = verifiers[req.verifierKey];
        if (verifier == address(0)) {
            revert VerifierNotRegistered(req.verifierKey);
        }

        result.proofHash = keccak256(req.proof);
        uint256 gasBefore = gasleft();

        // Encode call to IProofVerifier.verify(bytes, bytes32[])
        bytes memory callData = abi.encodeWithSignature(
            "verify(bytes,bytes32[])",
            req.proof,
            req.publicInputs
        );

        (bool success, bytes memory returnData) = verifier.staticcall(callData);

        result.gasUsed = gasBefore - gasleft();

        if (!success) {
            revert VerifierCallReverted(req.verifierKey, returnData);
        }

        if (returnData.length < 32) {
            revert VerifierReturnedInvalid(req.verifierKey);
        }

        result.verified = abi.decode(returnData, (bool));
    }

    /**
     * @notice Dispatches verification and reverts on failure
     * @dev Convenience wrapper that enforces proof validity
     * @param verifiers Mapping of verifierKey → verifier address
     * @param req       The verification request
     * @return proofHash Hash of the proof for deduplication / caching
     */
    function dispatchAndRequire(
        mapping(bytes32 => address) storage verifiers,
        VerifyRequest memory req
    ) internal view returns (bytes32 proofHash) {
        VerifyResult memory result = dispatch(verifiers, req);
        if (!result.verified) {
            revert VerifierReturnedInvalid(req.verifierKey);
        }
        return result.proofHash;
    }

    /**
     * @notice Validates that a verifier address is registered and non-zero
     * @param verifiers Mapping of verifierKey → verifier address
     * @param verifierKey The key to look up
     * @return verifier The registered verifier address
     */
    function getVerifier(
        mapping(bytes32 => address) storage verifiers,
        bytes32 verifierKey
    ) internal view returns (address verifier) {
        verifier = verifiers[verifierKey];
        if (verifier == address(0)) {
            revert VerifierNotRegistered(verifierKey);
        }
    }

    /**
     * @notice Registers or updates a verifier in the mapping
     * @param verifiers   Mapping of verifierKey → verifier address
     * @param verifierKey The key to register under
     * @param verifier    The verifier contract address
     */
    function register(
        mapping(bytes32 => address) storage verifiers,
        bytes32 verifierKey,
        address verifier
    ) internal {
        if (verifier == address(0)) revert ZeroAddressVerifier();
        verifiers[verifierKey] = verifier;
    }

    /**
     * @notice Removes a verifier from the mapping
     * @param verifiers   Mapping of verifierKey → verifier address
     * @param verifierKey The key to deregister
     */
    function deregister(
        mapping(bytes32 => address) storage verifiers,
        bytes32 verifierKey
    ) internal {
        delete verifiers[verifierKey];
    }

    /**
     * @notice Checks if a verifier is registered (non-zero)
     * @param verifiers   Mapping of verifierKey → verifier address
     * @param verifierKey The key to check
     * @return True if a verifier is registered for this key
     */
    function isRegistered(
        mapping(bytes32 => address) storage verifiers,
        bytes32 verifierKey
    ) internal view returns (bool) {
        return verifiers[verifierKey] != address(0);
    }
}
