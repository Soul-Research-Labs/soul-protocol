// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockTendermintValidatorOracle
 * @notice Mock Tendermint validator oracle for testing
 * @dev Simulates Provenance's Tendermint BFT validator set with attestation verification
 *
 * Provenance Blockchain uses Tendermint BFT with:
 * - ~100 active validators
 * - 2/3+1 supermajority required for consensus
 * - ~6 second block time
 * - Instant BFT finality (no probabilistic finality)
 * - Bech32 addresses (pb1... prefix on-chain)
 */
contract MockTendermintValidatorOracle {
    mapping(address => bool) public isValidator;
    address[] public validators;
    uint256 public validatorCount;
    bool public shouldReturnValid;

    constructor() {
        shouldReturnValid = true;
    }

    function addValidator(address validator) external {
        require(!isValidator[validator], "Already a validator");
        isValidator[validator] = true;
        validators.push(validator);
        validatorCount++;
    }

    function removeValidator(address validator) external {
        require(isValidator[validator], "Not a validator");
        isValidator[validator] = false;
        validatorCount--;
        // Remove from array
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == validator) {
                validators[i] = validators[validators.length - 1];
                validators.pop();
                break;
            }
        }
    }

    function setShouldReturnValid(bool _valid) external {
        shouldReturnValid = _valid;
    }

    /**
     * @notice Verify a validator attestation for a block hash
     * @dev In production, this would verify the actual Ed25519/Secp256k1 signature
     *      against the Tendermint validator set
     * @param blockHash The block hash being attested
     * @param validator The validator address
     * @param signature The signature bytes (ignored in mock)
     * @return valid Whether the attestation is valid
     */
    function verifyAttestation(
        bytes32 blockHash,
        address validator,
        bytes calldata signature
    ) external view returns (bool valid) {
        if (!shouldReturnValid) return false;
        if (!isValidator[validator]) return false;
        if (blockHash == bytes32(0)) return false;
        if (signature.length == 0) return false;
        return true;
    }

    /**
     * @notice Get current active validator set
     * @return The list of active validators
     */
    function getActiveValidators() external view returns (address[] memory) {
        return validators;
    }

    /**
     * @notice Check if supermajority is met
     * @dev Tendermint requires 2/3+1 validators for consensus
     * @param signatoryCount Number of valid signatories
     * @return Whether supermajority is reached
     */
    function isSuperMajority(
        uint256 signatoryCount
    ) external view returns (bool) {
        if (validatorCount == 0) return false;
        // 2/3+1 supermajority
        return signatoryCount * 3 > validatorCount * 2;
    }

    /**
     * @notice Get minimum required signatures for consensus
     * @return The minimum number of validator signatures needed
     */
    function getMinRequiredSignatures() external view returns (uint256) {
        if (validatorCount == 0) return 0;
        return (validatorCount * 2) / 3 + 1;
    }

    /**
     * @notice Batch verify multiple attestations
     * @param blockHash The block hash
     * @param _validators Array of validator addresses
     * @param signatures Array of signatures
     * @return validCount The number of valid attestations
     */
    function batchVerifyAttestations(
        bytes32 blockHash,
        address[] calldata _validators,
        bytes[] calldata signatures
    ) external view returns (uint256 validCount) {
        require(_validators.length == signatures.length, "Length mismatch");

        for (uint256 i = 0; i < _validators.length; i++) {
            if (
                shouldReturnValid &&
                isValidator[_validators[i]] &&
                blockHash != bytes32(0) &&
                signatures[i].length > 0
            ) {
                validCount++;
            }
        }
    }
}
