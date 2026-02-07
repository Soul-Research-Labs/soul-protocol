// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC8004ValidationRegistry} from "../interfaces/IERC8004ValidationRegistry.sol";

/**
 * @title ERC8004ValidationRegistry
 * @author Soul Protocol
 * @notice ERC-8004 Trustless Agents - Validation Registry implementation
 * @dev Request/response validation system for confirming agent capabilities.
 *
 * Flow:
 * 1. Agent owner/operator creates a validationRequest targeting a validator
 * 2. Designated validator submits a validationResponse (0-100 score)
 * 3. Validators may update responses over time
 *
 * Key properties:
 * - Only agent owner/operator can create validation requests
 * - Only the designated validator can respond to a request
 * - Responses are integers 0-100 (0 = failed, 100 = passed)
 * - requestHash uniquely identifies each request
 * - Each response records a tag for categorization
 * - Summaries computed on-chain with tag filtering
 */
contract ERC8004ValidationRegistry is
    IERC8004ValidationRegistry,
    ReentrancyGuard
{
    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Stored validation entry
    struct ValidationEntry {
        address validatorAddress;
        uint256 agentId;
        uint8 response;
        bytes32 responseHash;
        string tag;
        uint256 lastUpdate;
        bool hasResponse;
        bool exists;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Identity registry reference
    address public identityRegistry;

    /// @notice Whether the registry has been initialized
    bool public initialized;

    /// @notice Validation entries: requestHash → ValidationEntry
    mapping(bytes32 => ValidationEntry) private _validations;

    /// @notice Request hashes per agent
    mapping(uint256 => bytes32[]) private _agentValidations;

    /// @notice Request hashes per validator
    mapping(address => bytes32[]) private _validatorRequests;

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize with identity registry address
    function initialize(address identityRegistry_) external {
        require(!initialized, "Already initialized");
        require(identityRegistry_ != address(0), "Zero address");
        identityRegistry = identityRegistry_;
        initialized = true;
    }

    /// @inheritdoc IERC8004ValidationRegistry
    function getIdentityRegistry() external view returns (address) {
        return identityRegistry;
    }

    /*//////////////////////////////////////////////////////////////
                       VALIDATION REQUEST
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004ValidationRegistry
    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external nonReentrant {
        _requireRegisteredAgent(agentId);
        if (validatorAddress == address(0)) revert ZeroAddress();
        _requireAgentOwnerOrOperator(agentId, msg.sender);

        // Ensure request doesn't already exist
        if (_validations[requestHash].exists) {
            // Allow re-creation only if same parameters
            ValidationEntry storage existing = _validations[requestHash];
            require(
                existing.validatorAddress == validatorAddress && existing.agentId == agentId,
                "Duplicate request hash"
            );
            // Update is a no-op for existing identical request
            return;
        }

        _validations[requestHash] = ValidationEntry({
            validatorAddress: validatorAddress,
            agentId: agentId,
            response: 0,
            responseHash: bytes32(0),
            tag: "",
            lastUpdate: block.timestamp,
            hasResponse: false,
            exists: true
        });

        _agentValidations[agentId].push(requestHash);
        _validatorRequests[validatorAddress].push(requestHash);

        emit ValidationRequest(validatorAddress, agentId, requestURI, requestHash);
    }

    /*//////////////////////////////////////////////////////////////
                      VALIDATION RESPONSE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004ValidationRegistry
    function validationResponse(
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external nonReentrant {
        ValidationEntry storage entry = _validations[requestHash];
        if (!entry.exists) revert RequestNotFound(requestHash);
        if (msg.sender != entry.validatorAddress)
            revert NotDesignatedValidator(requestHash, msg.sender, entry.validatorAddress);
        if (response > 100) revert InvalidResponse(response);

        entry.response = response;
        entry.responseHash = responseHash;
        entry.tag = tag;
        entry.lastUpdate = block.timestamp;
        entry.hasResponse = true;

        emit ValidationResponse(
            msg.sender,
            entry.agentId,
            requestHash,
            response,
            responseURI,
            responseHash,
            tag
        );
    }

    /*//////////////////////////////////////////////////////////////
                          READ FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004ValidationRegistry
    function getValidationStatus(
        bytes32 requestHash
    ) external view returns (
        address validatorAddress,
        uint256 agentId,
        uint8 response,
        bytes32 responseHash,
        string memory tag,
        uint256 lastUpdate
    ) {
        ValidationEntry storage entry = _validations[requestHash];
        if (!entry.exists) revert RequestNotFound(requestHash);
        return (
            entry.validatorAddress,
            entry.agentId,
            entry.response,
            entry.responseHash,
            entry.tag,
            entry.lastUpdate
        );
    }

    /// @inheritdoc IERC8004ValidationRegistry
    function getSummary(
        uint256 agentId,
        address[] calldata validatorAddresses,
        string calldata tag
    ) external view returns (uint64 count, uint8 averageResponse) {
        bytes32 tagHash = bytes(tag).length > 0 ? keccak256(abi.encodePacked(tag)) : bytes32(0);

        uint256 totalResponse = 0;

        bytes32[] storage hashes = _agentValidations[agentId];
        for (uint256 i = 0; i < hashes.length; i++) {
            ValidationEntry storage entry = _validations[hashes[i]];
            if (!entry.hasResponse) continue;

            // Apply validator filter if provided
            if (validatorAddresses.length > 0) {
                bool found = false;
                for (uint256 j = 0; j < validatorAddresses.length; j++) {
                    if (entry.validatorAddress == validatorAddresses[j]) {
                        found = true;
                        break;
                    }
                }
                if (!found) continue;
            }

            // Apply tag filter
            if (tagHash != bytes32(0)) {
                if (keccak256(abi.encodePacked(entry.tag)) != tagHash) continue;
            }

            count++;
            totalResponse += entry.response;
        }

        if (count > 0) {
            averageResponse = uint8(totalResponse / count);
        }
    }

    /// @inheritdoc IERC8004ValidationRegistry
    function getAgentValidations(
        uint256 agentId
    ) external view returns (bytes32[] memory) {
        return _agentValidations[agentId];
    }

    /// @inheritdoc IERC8004ValidationRegistry
    function getValidatorRequests(
        address validatorAddress
    ) external view returns (bytes32[] memory) {
        return _validatorRequests[validatorAddress];
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _requireRegisteredAgent(uint256 agentId) internal view {
        try IERC721(identityRegistry).ownerOf(agentId) returns (address) {
            // Agent exists
        } catch {
            revert AgentNotRegistered(agentId);
        }
    }

    function _requireAgentOwnerOrOperator(uint256 agentId, address caller) internal view {
        address owner = IERC721(identityRegistry).ownerOf(agentId);
        if (caller == owner) return;

        try IERC721(identityRegistry).isApprovedForAll(owner, caller) returns (bool isOperator) {
            if (isOperator) return;
        } catch {}

        try IERC721(identityRegistry).getApproved(agentId) returns (address approved) {
            if (caller == approved) return;
        } catch {}

        revert NotAgentOwnerOrOperator(agentId, caller);
    }
}
