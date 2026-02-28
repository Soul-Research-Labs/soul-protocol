// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IProofVerifier.sol";

/**
 * @title VerifierRegistry
 * @author ZASEON
 * @notice Central registry for all Zaseon v2 proof verifiers
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

    /// @notice GKR/Binary field proof types (Hekate-Groestl)
    bytes32 public constant HEKATE_GROESTL_PROOF = keccak256("HEKATE_GROESTL");
    bytes32 public constant GKR_RECURSION_PROOF =
        keccak256("GKR_RECURSION_PROOF");
    bytes32 public constant BINIUS_PROOF = keccak256("BINIUS_PROOF");

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of proof type to verifier address (Legacy version)
    mapping(bytes32 => IProofVerifier) public verifiers;

    /// @notice Mapping of proof type to a specific version of a verifier
    mapping(bytes32 => mapping(uint256 => IProofVerifier))
        public versionedVerifiers;

    /// @notice Current active version for each proof type
    mapping(bytes32 => uint256) public activeVersions;

    /// @notice Mapping of proof type to version count
    mapping(bytes32 => uint256) public versionCounts;

    /// @notice All registered proof types
    bytes32[] public registeredTypes;

    /// @notice Mapping to check if type is registered
    mapping(bytes32 => bool) public isTypeRegistered;

    /// @notice Total verifiers registered (unique types)
    uint256 public totalVerifiers;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event VerifierRegistered(
        bytes32 indexed proofType,
        address indexed verifier,
        address indexed registrar
    );

    event VerifierVersionRegistered(
        bytes32 indexed proofType,
        uint256 indexed version,
        address indexed verifier
    );

    event VerifierUpdated(
        bytes32 indexed proofType,
        address indexed oldVerifier,
        address indexed newVerifier
    );

    event VerifierVersionSwitched(
        bytes32 indexed proofType,
        uint256 oldVersion,
        uint256 newVersion
    );

    event VerifierRemoved(bytes32 indexed proofType, address indexed verifier);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error VerifierNotFound(bytes32 proofType);
    error VerifierAlreadyRegistered(bytes32 proofType);
    error InvalidVerifier();
    error ZeroAddress();
    error VersionNotFound(bytes32 proofType, uint256 version);

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

        // Also register as version 1
        uint256 version = 1;
        versionedVerifiers[proofType][version] = IProofVerifier(verifier);
        activeVersions[proofType] = version;
        versionCounts[proofType] = version;

        registeredTypes.push(proofType);
        isTypeRegistered[proofType] = true;

        unchecked {
            ++totalVerifiers;
        }

        emit VerifierRegistered(proofType, verifier, msg.sender);
        emit VerifierVersionRegistered(proofType, version, verifier);
    }

    /**
     * @notice Register a new version for an existing proof type
     * @param proofType The proof type identifier
     * @param verifier The new verifier version address
     */
    function registerVerifierVersion(
        bytes32 proofType,
        address verifier
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        if (!isTypeRegistered[proofType]) revert VerifierNotFound(proofType);
        if (!_isValidVerifier(verifier)) revert InvalidVerifier();

        uint256 nextVersion = versionCounts[proofType] + 1;
        versionedVerifiers[proofType][nextVersion] = IProofVerifier(verifier);
        versionCounts[proofType] = nextVersion;

        emit VerifierVersionRegistered(proofType, nextVersion, verifier);
    }

    /**
     * @notice Switch the active version for a proof type
     * @param proofType The proof type identifier
     * @param version The version number to make active
     */
    function switchVersion(
        bytes32 proofType,
        uint256 version
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (!isTypeRegistered[proofType]) revert VerifierNotFound(proofType);
        if (address(versionedVerifiers[proofType][version]) == address(0))
            revert VersionNotFound(proofType, version);

        uint256 oldVersion = activeVersions[proofType];
        activeVersions[proofType] = version;

        // Keep legacy mapping in sync for backwards compatibility
        verifiers[proofType] = versionedVerifiers[proofType][version];

        emit VerifierVersionSwitched(proofType, oldVersion, version);
    }

    /**
     * @notice Update an existing verifier (Direct update, equivalent to switching to a new V1)
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

        // Register as a new version automatically
        uint256 nextVersion = versionCounts[proofType] + 1;
        versionedVerifiers[proofType][nextVersion] = IProofVerifier(
            newVerifier
        );
        versionCounts[proofType] = nextVersion;
        activeVersions[proofType] = nextVersion;

        verifiers[proofType] = IProofVerifier(newVerifier);

        emit VerifierUpdated(proofType, oldVerifier, newVerifier);
        emit VerifierVersionRegistered(proofType, nextVersion, newVerifier);
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
        /**
     * @notice Returns the verifier
     * @param proofType The proof type
     * @return The result value
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
        /**
     * @notice Checks if has verifier
     * @param proofType The proof type
     * @return The result value
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

        // Try to call isReady() - verifier must be ready to be valid
        try IProofVerifier(verifier).isReady() returns (bool ready) {
            return ready;
        } catch {
            return false;
        }
    }
}
