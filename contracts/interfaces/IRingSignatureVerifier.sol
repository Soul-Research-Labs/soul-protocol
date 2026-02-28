// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IRingSignatureVerifier
 * @author ZASEON
 * @notice Interface for ring signature verification (CLSAG/MLSAG style)
 * @dev Matches the ABI expected by GasOptimizedRingCT._verifyRingSignature(),
 *      which uses staticcall with: verify(bytes32[],bytes32[],bytes,bytes32)
 *
 * NOTE: This is intentionally different from IRingSignature.verifyRingSignature()
 * in IPrivacyPrimitives.sol, which uses a RingMember[] struct. The GasOptimized
 * variant uses raw bytes32[] arrays for gas efficiency.
 */
interface IRingSignatureVerifier {
    /// @notice Verify a ring signature against a set of public keys
    /// @param ring Array of public keys (ring members) as bytes32
    /// @param keyImages Array of key images proving spend authority
    /// @param signature The ring signature bytes (CLSAG or MLSAG encoded)
    /// @param message The signed message hash (e.g., balance check hash)
    /// @return valid True if the signature is valid
    function verify(
        bytes32[] calldata ring,
        bytes32[] calldata keyImages,
        bytes calldata signature,
        bytes32 message
    ) external view returns (bool valid);

    /// @notice Get the minimum allowed ring size
    /// @return minSize The minimum number of ring members
    function getMinRingSize() external view returns (uint256 minSize);

    /// @notice Get the maximum allowed ring size
    /// @return maxSize The maximum number of ring members
    function getMaxRingSize() external view returns (uint256 maxSize);
}
