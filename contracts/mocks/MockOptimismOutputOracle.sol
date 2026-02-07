// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MockOptimismOutputOracle
/// @notice Mock output oracle for Optimism Bedrock fault proof verification in testing
/// @dev Simulates OP Stack output proposals and fault proof dispute resolution
contract MockOptimismOutputOracle {
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
        uint256 indexed l2BlockNumber,
        bytes32 outputRoot
    );
    event BlockRecorded(uint256 indexed l2BlockNumber, bytes32 outputRoot);
    event EpochAdvanced(uint256 indexed newEpoch);

    /// @notice Add a proposer/challenger to the set
    /// @param validator Address of the validator (proposer/challenger)
    /// @param votingPower Voting power of the validator
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

    /// @notice Mock verify an output attestation
    /// @param validator Address of the attesting proposer
    /// @param l2BlockNumber L2 block number being attested
    /// @param outputRoot Output root hash
    /// @return valid True if the validator is active
    function verifyAttestation(
        address validator,
        uint256 l2BlockNumber,
        bytes32 outputRoot
    ) external returns (bool valid) {
        valid = validators[validator].active;
        if (valid) {
            emit AttestationVerified(validator, l2BlockNumber, outputRoot);
        }
    }

    /// @notice Record an L2 output root
    /// @param l2BlockNumber The L2 block number
    /// @param outputRoot The output root hash
    function recordBlock(uint256 l2BlockNumber, bytes32 outputRoot) external {
        blockHashes[l2BlockNumber] = outputRoot;
        emit BlockRecorded(l2BlockNumber, outputRoot);
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
