// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IERC8004ValidationRegistry
 * @author Soul Protocol
 * @notice Interface for ERC-8004 Trustless Agents - Validation Registry
 * @dev On-chain validation request/response system for agent trustworthiness
 *
 * ERC-8004 VALIDATION REGISTRY:
 *
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                  Validation Registry                        │
 *   │  ┌───────────────────────────────────────────────────────┐  │
 *   │  │  Validation Flow                                      │  │
 *   │  │                                                       │  │
 *   │  │  Agent Owner ──► validationRequest() ──► Validator    │  │
 *   │  │                                             │          │  │
 *   │  │                validationResponse() ◄───────┘          │  │
 *   │  │                                                       │  │
 *   │  │  Trust Models:                                         │  │
 *   │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐              │  │
 *   │  │  │ Staked   │ │  zkML    │ │   TEE    │              │  │
 *   │  │  │ Re-exec  │ │ Verifier │ │ Oracle   │              │  │
 *   │  │  └──────────┘ └──────────┘ └──────────┘              │  │
 *   │  │                                                       │  │
 *   │  │  Response: 0-100 (0=failed, 100=passed)               │  │
 *   │  └───────────────────────────────────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────┘
 */
interface IERC8004ValidationRegistry {
    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a validation is requested
    event ValidationRequest(
        address indexed validatorAddress,
        uint256 indexed agentId,
        string requestURI,
        bytes32 indexed requestHash
    );

    /// @notice Emitted when a validator responds
    event ValidationResponse(
        address indexed validatorAddress,
        uint256 indexed agentId,
        bytes32 indexed requestHash,
        uint8 response,
        string responseURI,
        bytes32 responseHash,
        string tag
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error AgentNotRegistered(uint256 agentId);
    error NotAgentOwnerOrOperator(uint256 agentId, address caller);
    error NotDesignatedValidator(bytes32 requestHash, address caller, address expected);
    error RequestNotFound(bytes32 requestHash);
    error InvalidResponse(uint8 response);
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the identity registry address
    function getIdentityRegistry() external view returns (address);

    /// @notice Request validation from a specific validator
    /// @param validatorAddress The validator contract/EOA address
    /// @param agentId The agent requesting validation
    /// @param requestURI URI to off-chain validation data
    /// @param requestHash keccak256 commitment of the request payload
    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external;

    /// @notice Respond to a validation request
    /// @param requestHash The request being responded to
    /// @param response Validation result (0-100, 0=failed, 100=passed)
    /// @param responseURI Optional URI to evidence/audit
    /// @param responseHash Optional keccak256 of responseURI content
    /// @param tag Optional categorization tag
    function validationResponse(
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external;

    /// @notice Get validation status for a request
    function getValidationStatus(
        bytes32 requestHash
    ) external view returns (
        address validatorAddress,
        uint256 agentId,
        uint8 response,
        bytes32 responseHash,
        string memory tag,
        uint256 lastUpdate
    );

    /// @notice Get aggregated validation statistics for an agent
    /// @param agentId The agent ID
    /// @param validatorAddresses Optional validator filter
    /// @param tag Optional tag filter
    /// @return count Number of matching validations
    /// @return averageResponse Weighted average response (0-100)
    function getSummary(
        uint256 agentId,
        address[] calldata validatorAddresses,
        string calldata tag
    ) external view returns (uint64 count, uint8 averageResponse);

    /// @notice Get all validation request hashes for an agent
    function getAgentValidations(
        uint256 agentId
    ) external view returns (bytes32[] memory requestHashes);

    /// @notice Get all request hashes assigned to a validator
    function getValidatorRequests(
        address validatorAddress
    ) external view returns (bytes32[] memory requestHashes);
}
