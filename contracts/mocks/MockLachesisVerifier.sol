// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MockLachesisVerifier
/// @notice Mock verifier for Fantom Lachesis aBFT consensus verification in testing
/// @dev Simulates Lachesis asynchronous BFT DAG-based consensus
contract MockLachesisVerifier {
    struct ValidatorInfo {
        bool active;
        uint256 votingPower;
    }

    mapping(address => ValidatorInfo) public validators;
    mapping(uint256 => bytes32) public blockHashes;
    address[] public validatorList;
    uint256 public totalVotingPower;
    uint256 public currentEpoch;

    event ValidatorAdded(address indexed validator, uint256 votingPower);
    event ValidatorRemoved(address indexed validator);
    event AttestationVerified(
        address indexed validator,
        uint256 indexed blockNumber,
        bytes32 blockHash
    );
    event BlockRecorded(uint256 indexed blockNumber, bytes32 blockHash);
    event EpochAdvanced(uint256 indexed newEpoch);

    /// @notice Add a validator to the set
    /// @param validator Address of the validator
    /// @param votingPower Voting power (stake) of the validator
    function addValidator(address validator, uint256 votingPower) external {
        require(!validators[validator].active, "Already active");
        validators[validator] = ValidatorInfo({
            active: true,
            votingPower: votingPower
        });
        validatorList.push(validator);
        totalVotingPower += votingPower;
        emit ValidatorAdded(validator, votingPower);
    }

    /// @notice Remove a validator from the set
    /// @param validator Address of the validator to remove
    function removeValidator(address validator) external {
        require(validators[validator].active, "Not active");
        totalVotingPower -= validators[validator].votingPower;
        validators[validator].active = false;
        validators[validator].votingPower = 0;
        for (uint256 i = 0; i < validatorList.length; i++) {
            if (validatorList[i] == validator) {
                validatorList[i] = validatorList[validatorList.length - 1];
                validatorList.pop();
                break;
            }
        }
        emit ValidatorRemoved(validator);
    }

    /// @notice Mock verify a Lachesis aBFT attestation
    /// @param validator Address of the attesting validator
    /// @param blockNumber Block number being attested
    /// @param blockHash Hash of the block
    /// @return valid True if the validator is active
    function verifyAttestation(
        address validator,
        uint256 blockNumber,
        bytes32 blockHash
    ) external returns (bool valid) {
        valid = validators[validator].active;
        if (valid) {
            emit AttestationVerified(validator, blockNumber, blockHash);
        }
    }

    /// @notice Record a finalized block hash
    /// @param blockNumber The block number
    /// @param blockHash The block hash
    function recordBlock(uint256 blockNumber, bytes32 blockHash) external {
        blockHashes[blockNumber] = blockHash;
        emit BlockRecorded(blockNumber, blockHash);
    }

    /// @notice Advance the epoch
    function advanceEpoch() external {
        currentEpoch++;
        emit EpochAdvanced(currentEpoch);
    }

    /// @notice Get the number of validators
    /// @return count Number of validators in the set
    function getValidatorCount() external view returns (uint256 count) {
        return validatorList.length;
    }

    /// @notice Check if a validator is active
    /// @param validator Address to check
    /// @return True if the validator is active
    function isActiveValidator(address validator) external view returns (bool) {
        return validators[validator].active;
    }
}
