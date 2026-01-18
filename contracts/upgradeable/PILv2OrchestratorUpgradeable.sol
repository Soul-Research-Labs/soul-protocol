// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title PILv2OrchestratorUpgradeable
/// @author Soul Protocol - PIL v2
/// @notice Upgradeable orchestrator that coordinates all PIL v2 primitives
contract PILv2OrchestratorUpgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ORCHESTRATOR_ADMIN_ROLE =
        keccak256("ORCHESTRATOR_ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Operation request
    struct OperationRequest {
        bytes32 stateCommitment;
        bytes32 nullifier;
        bytes validityProof;
        bytes policyProof;
        bytes nullifierProof;
        bytes32 proofHash;
        bytes32 policyId;
        address recipient;
        uint256 amount;
        uint256 timestamp;
    }

    /// @notice Operation result
    struct OperationResult {
        bytes32 operationId;
        bool success;
        bytes32 containerId;
        bytes32 newStateCommitment;
        string message;
    }

    /// @notice System status
    struct SystemStatus {
        bool pc3Active;
        bool pbpActive;
        bool eascActive;
        bool cdnaActive;
        uint256 totalOperations;
        uint256 successfulOperations;
        uint256 failedOperations;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice PC³ contract address
    address public proofCarryingContainer;

    /// @notice PBP contract address
    address public policyBoundProofs;

    /// @notice EASC contract address
    address public executionAgnosticStateCommitments;

    /// @notice CDNA contract address
    address public crossDomainNullifierAlgebra;

    /// @notice Total operations executed
    uint256 public totalOperations;

    /// @notice Successful operations
    uint256 public successfulOperations;

    /// @notice Failed operations
    uint256 public failedOperations;

    /// @notice Operation history (operationId => OperationResult)
    mapping(bytes32 => OperationResult) public operationHistory;

    /// @notice User operation count
    mapping(address => uint256) public userOperationCount;

    /// @notice Contract version
    uint256 public contractVersion;

    /// @notice Primitives active status
    mapping(bytes32 => bool) public primitiveActive;

    /*//////////////////////////////////////////////////////////////
                            STORAGE GAP
    //////////////////////////////////////////////////////////////*/

    uint256[50] private __gap;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event OperationExecuted(
        bytes32 indexed operationId,
        address indexed user,
        bool success,
        string message
    );

    event PrimitiveUpdated(
        bytes32 indexed primitiveId,
        address indexed oldAddress,
        address indexed newAddress
    );

    event PrimitiveStatusChanged(bytes32 indexed primitiveId, bool active);
    event ContractUpgraded(
        uint256 indexed oldVersion,
        uint256 indexed newVersion
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error PrimitiveNotActive(bytes32 primitiveId);
    error InvalidOperation();
    error OperationFailed(string reason);

    /*//////////////////////////////////////////////////////////////
                           PRIMITIVE IDs
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant PC3_PRIMITIVE = keccak256("PC3");
    bytes32 public constant PBP_PRIMITIVE = keccak256("PBP");
    bytes32 public constant EASC_PRIMITIVE = keccak256("EASC");
    bytes32 public constant CDNA_PRIMITIVE = keccak256("CDNA");

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the orchestrator
    function initialize(
        address admin,
        address _pc3,
        address _pbp,
        address _easc,
        address _cdna
    ) public initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ORCHESTRATOR_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        proofCarryingContainer = _pc3;
        policyBoundProofs = _pbp;
        executionAgnosticStateCommitments = _easc;
        crossDomainNullifierAlgebra = _cdna;

        // Activate all primitives
        primitiveActive[PC3_PRIMITIVE] = true;
        primitiveActive[PBP_PRIMITIVE] = true;
        primitiveActive[EASC_PRIMITIVE] = true;
        primitiveActive[CDNA_PRIMITIVE] = true;

        contractVersion = 1;
    }

    /*//////////////////////////////////////////////////////////////
                          UPGRADE AUTHORIZATION
    //////////////////////////////////////////////////////////////*/

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {
        uint256 oldVersion = contractVersion;
        contractVersion++;
        emit ContractUpgraded(oldVersion, contractVersion);
    }

    /*//////////////////////////////////////////////////////////////
                          OPERATION EXECUTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Execute a private transfer operation
    function executePrivateTransfer(
        OperationRequest calldata request
    )
        external
        whenNotPaused
        nonReentrant
        returns (OperationResult memory result)
    {
        // Validate primitives are active
        if (!primitiveActive[PC3_PRIMITIVE])
            revert PrimitiveNotActive(PC3_PRIMITIVE);
        if (!primitiveActive[CDNA_PRIMITIVE])
            revert PrimitiveNotActive(CDNA_PRIMITIVE);

        // Generate operation ID
        bytes32 operationId = keccak256(
            abi.encodePacked(
                msg.sender,
                request.stateCommitment,
                request.nullifier,
                block.timestamp,
                totalOperations
            )
        );

        // Track operation
        unchecked {
            ++totalOperations;
            ++userOperationCount[msg.sender];
        }

        // Execute operation (simplified for MVP)
        bool success = _executeOperation(request);

        result = OperationResult({
            operationId: operationId,
            success: success,
            containerId: request.stateCommitment, // Simplified
            newStateCommitment: keccak256(
                abi.encodePacked(request.stateCommitment, block.timestamp)
            ),
            message: success
                ? "Operation executed successfully"
                : "Operation failed"
        });

        // Store result
        operationHistory[operationId] = result;

        if (success) {
            unchecked {
                ++successfulOperations;
            }
        } else {
            unchecked {
                ++failedOperations;
            }
        }

        emit OperationExecuted(
            operationId,
            msg.sender,
            success,
            result.message
        );
    }

    /// @notice Internal operation execution
    function _executeOperation(
        OperationRequest calldata request
    ) internal view returns (bool) {
        // Validate basic request parameters
        if (request.stateCommitment == bytes32(0)) return false;
        if (request.nullifier == bytes32(0)) return false;
        if (request.validityProof.length < 256) return false;
        if (request.recipient == address(0)) return false;

        // In production, this would interact with all primitives
        // For MVP, we validate proof structure
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get system status
    function getSystemStatus() external view returns (SystemStatus memory) {
        return
            SystemStatus({
                pc3Active: primitiveActive[PC3_PRIMITIVE],
                pbpActive: primitiveActive[PBP_PRIMITIVE],
                eascActive: primitiveActive[EASC_PRIMITIVE],
                cdnaActive: primitiveActive[CDNA_PRIMITIVE],
                totalOperations: totalOperations,
                successfulOperations: successfulOperations,
                failedOperations: failedOperations
            });
    }

    /// @notice Get operation result
    function getOperationResult(
        bytes32 operationId
    ) external view returns (OperationResult memory) {
        return operationHistory[operationId];
    }

    /// @notice Get user operation count
    function getUserOperationCount(
        address user
    ) external view returns (uint256) {
        return userOperationCount[user];
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Update a primitive address
    function updatePrimitive(
        bytes32 primitiveId,
        address newAddress
    ) external onlyRole(ORCHESTRATOR_ADMIN_ROLE) {
        address oldAddress;

        if (primitiveId == PC3_PRIMITIVE) {
            oldAddress = proofCarryingContainer;
            proofCarryingContainer = newAddress;
        } else if (primitiveId == PBP_PRIMITIVE) {
            oldAddress = policyBoundProofs;
            policyBoundProofs = newAddress;
        } else if (primitiveId == EASC_PRIMITIVE) {
            oldAddress = executionAgnosticStateCommitments;
            executionAgnosticStateCommitments = newAddress;
        } else if (primitiveId == CDNA_PRIMITIVE) {
            oldAddress = crossDomainNullifierAlgebra;
            crossDomainNullifierAlgebra = newAddress;
        } else {
            revert InvalidOperation();
        }

        emit PrimitiveUpdated(primitiveId, oldAddress, newAddress);
    }

    /// @notice Set primitive active status
    function setPrimitiveActive(
        bytes32 primitiveId,
        bool active
    ) external onlyRole(ORCHESTRATOR_ADMIN_ROLE) {
        primitiveActive[primitiveId] = active;
        emit PrimitiveStatusChanged(primitiveId, active);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Get implementation version
    function getImplementationVersion() external pure returns (string memory) {
        return "1.0.0";
    }
}
