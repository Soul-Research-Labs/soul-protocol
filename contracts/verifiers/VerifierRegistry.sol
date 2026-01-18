// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IProofVerifier.sol";

/**
 * @title VerifierRegistry
 * @author Soul Protocol
 * @notice Central registry for all PIL v2 proof verifiers
 * @dev Manages verifiers for different proof types (validity, policy, nullifier, etc.)
 */
contract VerifierRegistry is AccessControl, IVerifierRegistry {
    /*//////////////////////////////////////////////////////////////
                               ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REGISTRY_ADMIN_ROLE =
        keccak256("REGISTRY_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                          PROOF TYPE CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Standard proof types
    bytes32 public constant VALIDITY_PROOF = keccak256("VALIDITY_PROOF");
    bytes32 public constant POLICY_PROOF = keccak256("POLICY_PROOF");
    bytes32 public constant NULLIFIER_PROOF = keccak256("NULLIFIER_PROOF");
    bytes32 public constant STATE_TRANSITION_PROOF =
        keccak256("STATE_TRANSITION_PROOF");
    bytes32 public constant CROSS_DOMAIN_PROOF =
        keccak256("CROSS_DOMAIN_PROOF");
    bytes32 public constant RANGE_PROOF = keccak256("RANGE_PROOF");
    bytes32 public constant MEMBERSHIP_PROOF = keccak256("MEMBERSHIP_PROOF");

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of proof type to verifier address
    mapping(bytes32 => IProofVerifier) public verifiers;

    /// @notice All registered proof types
    bytes32[] public registeredTypes;

    /// @notice Mapping to check if type is registered
    mapping(bytes32 => bool) public isTypeRegistered;

    /// @notice Total verifiers registered
    uint256 public totalVerifiers;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event VerifierRegistered(
        bytes32 indexed proofType,
        address indexed verifier,
        address indexed registrar
    );

    event VerifierUpdated(
        bytes32 indexed proofType,
        address indexed oldVerifier,
        address indexed newVerifier
    );

    event VerifierRemoved(bytes32 indexed proofType, address indexed verifier);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error VerifierNotFound(bytes32 proofType);
    error VerifierAlreadyRegistered(bytes32 proofType);
    error InvalidVerifier();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                       REGISTRATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new verifier for a proof type
     * @param proofType The proof type identifier
     * @param verifier The verifier contract address
     */
    function registerVerifier(
        bytes32 proofType,
        address verifier
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        if (isTypeRegistered[proofType])
            revert VerifierAlreadyRegistered(proofType);

        // Verify the contract implements the interface
        if (!_isValidVerifier(verifier)) revert InvalidVerifier();

        verifiers[proofType] = IProofVerifier(verifier);
        registeredTypes.push(proofType);
        isTypeRegistered[proofType] = true;

        unchecked {
            ++totalVerifiers;
        }

        emit VerifierRegistered(proofType, verifier, msg.sender);
    }

    /**
     * @notice Update an existing verifier
     * @param proofType The proof type identifier
     * @param newVerifier The new verifier contract address
     */
    function updateVerifier(
        bytes32 proofType,
        address newVerifier
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (newVerifier == address(0)) revert ZeroAddress();
        if (!isTypeRegistered[proofType]) revert VerifierNotFound(proofType);
        if (!_isValidVerifier(newVerifier)) revert InvalidVerifier();

        address oldVerifier = address(verifiers[proofType]);
        verifiers[proofType] = IProofVerifier(newVerifier);

        emit VerifierUpdated(proofType, oldVerifier, newVerifier);
    }

    /**
     * @notice Remove a verifier (emergency use only)
     * @param proofType The proof type identifier
     */
    function removeVerifier(
        bytes32 proofType
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!isTypeRegistered[proofType]) revert VerifierNotFound(proofType);

        address oldVerifier = address(verifiers[proofType]);
        delete verifiers[proofType];
        isTypeRegistered[proofType] = false;

        unchecked {
            --totalVerifiers;
        }

        emit VerifierRemoved(proofType, oldVerifier);
    }

    /*//////////////////////////////////////////////////////////////
                         QUERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IVerifierRegistry
     */
    function getVerifier(
        bytes32 proofType
    ) external view override returns (IProofVerifier) {
        if (!isTypeRegistered[proofType]) revert VerifierNotFound(proofType);
        return verifiers[proofType];
    }

    /**
     * @inheritdoc IVerifierRegistry
     */
    function hasVerifier(
        bytes32 proofType
    ) external view override returns (bool) {
        return isTypeRegistered[proofType];
    }

    /**
     * @notice Get all registered proof types
     * @return types Array of proof type identifiers
     */
    function getAllProofTypes() external view returns (bytes32[] memory) {
        return registeredTypes;
    }

    /**
     * @notice Verify a proof using the registered verifier
     * @param proofType The proof type
     * @param proof The proof bytes
     * @param publicInputs Public inputs for verification
     * @return success True if proof is valid
     */
    function verifyProof(
        bytes32 proofType,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool success) {
        if (!isTypeRegistered[proofType]) revert VerifierNotFound(proofType);

        IProofVerifier verifier = verifiers[proofType];
        if (!verifier.isReady()) return false;

        return verifier.verify(proof, publicInputs);
    }

    /**
     * @notice Verify a single proof with one public input
     * @param proofType The proof type
     * @param proof The proof bytes
     * @param publicInput Single public input for verification
     * @return success True if proof is valid
     */
    function verifySingleInput(
        bytes32 proofType,
        bytes calldata proof,
        uint256 publicInput
    ) external view returns (bool success) {
        if (!isTypeRegistered[proofType]) revert VerifierNotFound(proofType);

        IProofVerifier verifier = verifiers[proofType];
        if (!verifier.isReady()) return false;

        return verifier.verifySingle(proof, publicInput);
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if address is a valid verifier contract
     */
    function _isValidVerifier(address verifier) internal view returns (bool) {
        // Check code exists
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(verifier)
        }
        if (codeSize == 0) return false;

        // Try to call isReady() - if it doesn't revert, consider it valid
        try IProofVerifier(verifier).isReady() returns (bool) {
            return true;
        } catch {
            return false;
        }
    }
}
