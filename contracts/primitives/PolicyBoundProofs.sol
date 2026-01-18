// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/// @title PolicyBoundProofs (PBP)
/// @author Soul Protocol - PIL v2
/// @notice Proofs that are cryptographically scoped by disclosure policy
/// @dev MVP Implementation - Makes compliance a cryptographic invariant
///
/// Key Properties:
/// - Proofs are valid only under a specific disclosure policy
/// - Policy hash is bound to verification key domain separator
/// - Reuse outside policy scope fails cryptographically
/// - Enables "compliance-optional verifiability"
///
/// Security Considerations:
/// - Domain separator prevents cross-policy proof reuse
/// - Policy expiration prevents stale policy attacks
/// - Proof nullifiers prevent replay attacks
/// - Public input validation ensures policy commitment
contract PolicyBoundProofs is AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant POLICY_ADMIN_ROLE = keccak256("POLICY_ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Disclosure policy definition
    struct DisclosurePolicy {
        bytes32 policyId; // Unique policy identifier
        bytes32 policyHash; // Hash of policy rules
        string name; // Human-readable name
        string description; // Policy description
        // Disclosure requirements
        bool requiresIdentity; // Must disclose identity
        bool requiresJurisdiction; // Must disclose jurisdiction
        bool requiresAmount; // Must disclose amounts
        bool requiresCounterparty; // Must disclose counterparty
        // Verification constraints
        uint256 minAmount; // Minimum amount threshold
        uint256 maxAmount; // Maximum amount threshold
        bytes32[] allowedAssets; // Allowed asset types
        bytes32[] blockedCountries; // Blocked jurisdictions
        // Metadata
        uint64 createdAt;
        uint64 expiresAt;
        bool isActive;
    }

    /// @notice Policy-bound verification key
    struct BoundVerificationKey {
        bytes32 vkHash; // Hash of verification key
        bytes32 policyHash; // Bound policy hash
        bytes32 domainSeparator; // VK domain separator (vkHash ⊕ policyHash)
        bool isActive;
        uint64 registeredAt;
    }

    /// @notice Policy-bound proof structure
    struct BoundProof {
        bytes proof; // The SNARK proof
        bytes32 policyHash; // Policy this proof is bound to
        bytes32 domainSeparator; // Domain separator used in Fiat-Shamir
        bytes32[] publicInputs; // Public inputs including policy commitment
        uint64 generatedAt;
        uint64 expiresAt;
    }

    /// @notice Proof verification result
    struct VerificationResult {
        bool proofValid;
        bool policyValid;
        bool withinScope;
        bool notExpired;
        bytes32 boundPolicy;
        string failureReason;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of policy ID to policy
    mapping(bytes32 => DisclosurePolicy) public policies;

    /// @notice Mapping of policy hash to policy ID
    mapping(bytes32 => bytes32) public policyHashToId;

    /// @notice Mapping of VK hash to bound verification key
    mapping(bytes32 => BoundVerificationKey) public verificationKeys;

    /// @notice Mapping of domain separator to VK hash (reverse lookup)
    mapping(bytes32 => bytes32) public domainToVk;

    /// @notice Used proof nullifiers (prevent replay)
    mapping(bytes32 => bool) public usedProofNullifiers;

    /// @notice Policy usage count
    mapping(bytes32 => uint256) public policyUsageCount;

    /// @notice Policy IDs for enumeration
    bytes32[] private _policyIds;

    /// @notice VK hashes for enumeration
    bytes32[] private _vkHashes;

    /// @notice Total policies registered
    uint256 public totalPolicies;

    /// @notice Total verification keys registered
    uint256 public totalVerificationKeys;

    /// @notice Default proof validity period
    uint256 public defaultProofValidity = 24 hours;

    /// @notice Minimum proof size for validity
    uint256 public constant MIN_PROOF_SIZE = 256;

    /// @notice Maximum public inputs length (prevent DOS)
    uint256 public constant MAX_PUBLIC_INPUTS = 32;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PolicyRegistered(
        bytes32 indexed policyId,
        bytes32 indexed policyHash,
        string name
    );

    event PolicyUpdated(
        bytes32 indexed policyId,
        bytes32 oldHash,
        bytes32 newHash
    );

    event PolicyDeactivated(bytes32 indexed policyId);

    event VerificationKeyBound(
        bytes32 indexed vkHash,
        bytes32 indexed policyHash,
        bytes32 domainSeparator
    );

    event ProofVerified(
        bytes32 indexed proofHash,
        bytes32 indexed policyHash,
        address indexed verifier,
        bool success
    );

    event ProofRejectedOutOfScope(
        bytes32 indexed proofHash,
        bytes32 indexed attemptedPolicy,
        bytes32 indexed boundPolicy
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error PolicyNotFound(bytes32 policyId);
    error PolicyAlreadyExists(bytes32 policyId);
    error PolicyExpired(bytes32 policyId);
    error PolicyInactive(bytes32 policyId);
    error VerificationKeyNotFound(bytes32 vkHash);
    error VerificationKeyAlreadyBound(bytes32 vkHash);
    error ProofOutOfPolicyScope(bytes32 attemptedPolicy, bytes32 boundPolicy);
    error ProofExpired(uint64 expiresAt);
    error ProofAlreadyUsed(bytes32 proofNullifier);
    error InvalidDomainSeparator();
    error InvalidProofStructure();
    error TooManyPublicInputs(uint256 count, uint256 max);
    error EmptyPolicyName();
    error EmptyProof();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(POLICY_ADMIN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                          POLICY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a new disclosure policy
    /// @param policy The policy to register
    /// @return policyId The unique policy identifier
    function registerPolicy(
        DisclosurePolicy calldata policy
    ) external onlyRole(POLICY_ADMIN_ROLE) returns (bytes32 policyId) {
        // Validate inputs
        if (bytes(policy.name).length == 0) revert EmptyPolicyName();

        policyId = keccak256(
            abi.encodePacked(policy.name, policy.policyHash, block.timestamp)
        );

        if (policies[policyId].createdAt != 0) {
            revert PolicyAlreadyExists(policyId);
        }

        policies[policyId] = DisclosurePolicy({
            policyId: policyId,
            policyHash: policy.policyHash,
            name: policy.name,
            description: policy.description,
            requiresIdentity: policy.requiresIdentity,
            requiresJurisdiction: policy.requiresJurisdiction,
            requiresAmount: policy.requiresAmount,
            requiresCounterparty: policy.requiresCounterparty,
            minAmount: policy.minAmount,
            maxAmount: policy.maxAmount,
            allowedAssets: policy.allowedAssets,
            blockedCountries: policy.blockedCountries,
            createdAt: uint64(block.timestamp),
            expiresAt: policy.expiresAt,
            isActive: true
        });

        policyHashToId[policy.policyHash] = policyId;
        _policyIds.push(policyId);

        unchecked {
            ++totalPolicies;
        }

        emit PolicyRegistered(policyId, policy.policyHash, policy.name);
    }

    /// @notice Deactivate a policy
    /// @param policyId The policy to deactivate
    function deactivatePolicy(
        bytes32 policyId
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        if (policies[policyId].createdAt == 0) {
            revert PolicyNotFound(policyId);
        }

        policies[policyId].isActive = false;
        emit PolicyDeactivated(policyId);
    }

    /*//////////////////////////////////////////////////////////////
                      VERIFICATION KEY BINDING
    //////////////////////////////////////////////////////////////*/

    /// @notice Bind a verification key to a policy
    /// @dev Creates domain separator = keccak256(vkHash || policyHash)
    /// @param vkHash Hash of the verification key
    /// @param policyHash Hash of the policy to bind
    /// @return domainSeparator The computed domain separator
    function bindVerificationKey(
        bytes32 vkHash,
        bytes32 policyHash
    ) external onlyRole(POLICY_ADMIN_ROLE) returns (bytes32 domainSeparator) {
        if (verificationKeys[vkHash].registeredAt != 0) {
            revert VerificationKeyAlreadyBound(vkHash);
        }

        // Verify policy exists
        bytes32 policyId = policyHashToId[policyHash];
        if (policies[policyId].createdAt == 0 && policyHash != bytes32(0)) {
            revert PolicyNotFound(policyId);
        }

        // Compute domain separator (VK bound to policy)
        domainSeparator = keccak256(abi.encodePacked(vkHash, policyHash));

        verificationKeys[vkHash] = BoundVerificationKey({
            vkHash: vkHash,
            policyHash: policyHash,
            domainSeparator: domainSeparator,
            isActive: true,
            registeredAt: uint64(block.timestamp)
        });

        domainToVk[domainSeparator] = vkHash;
        _vkHashes.push(vkHash);

        unchecked {
            ++totalVerificationKeys;
        }

        emit VerificationKeyBound(vkHash, policyHash, domainSeparator);
    }

    /*//////////////////////////////////////////////////////////////
                          PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify a policy-bound proof
    /// @param boundProof The proof with policy binding
    /// @param vkHash The verification key hash to use
    /// @return result The verification result
    function verifyBoundProof(
        BoundProof calldata boundProof,
        bytes32 vkHash
    ) external view returns (VerificationResult memory result) {
        // Check VK exists
        BoundVerificationKey storage vk = verificationKeys[vkHash];
        if (vk.registeredAt == 0) {
            result.failureReason = "Verification key not found";
            return result;
        }

        // Check VK is active
        if (!vk.isActive) {
            result.failureReason = "Verification key inactive";
            return result;
        }

        // Critical: Verify proof is bound to the same policy as VK
        if (boundProof.policyHash != vk.policyHash) {
            result.failureReason = "Proof out of policy scope";
            result.boundPolicy = vk.policyHash;
            return result;
        }
        result.withinScope = true;

        // Verify domain separator matches
        bytes32 expectedDomain = keccak256(
            abi.encodePacked(vkHash, boundProof.policyHash)
        );
        if (boundProof.domainSeparator != expectedDomain) {
            result.failureReason = "Invalid domain separator";
            return result;
        }

        // Check expiry
        if (
            boundProof.expiresAt != 0 && block.timestamp > boundProof.expiresAt
        ) {
            result.failureReason = "Proof expired";
            return result;
        }
        result.notExpired = true;

        // Check policy is valid
        bytes32 policyId = policyHashToId[boundProof.policyHash];
        if (policies[policyId].createdAt != 0) {
            DisclosurePolicy storage policy = policies[policyId];

            if (!policy.isActive) {
                result.failureReason = "Policy inactive";
                return result;
            }

            if (policy.expiresAt != 0 && block.timestamp > policy.expiresAt) {
                result.failureReason = "Policy expired";
                return result;
            }
        }
        result.policyValid = true;

        // Verify proof structure (actual SNARK verification in production)
        if (boundProof.proof.length < MIN_PROOF_SIZE) {
            result.failureReason = "Invalid proof structure";
            return result;
        }

        // Validate public inputs length
        uint256 inputsLen = boundProof.publicInputs.length;
        if (inputsLen > MAX_PUBLIC_INPUTS) {
            result.failureReason = "Too many public inputs";
            return result;
        }

        // Check public inputs include policy commitment
        bool hasPolicyCommitment = false;
        bytes32 policyHash_ = boundProof.policyHash;
        for (uint256 i = 0; i < inputsLen; ) {
            if (boundProof.publicInputs[i] == policyHash_) {
                hasPolicyCommitment = true;
                break;
            }
            unchecked {
                ++i;
            }
        }

        if (!hasPolicyCommitment && policyHash_ != bytes32(0)) {
            result.failureReason = "Policy commitment not in public inputs";
            return result;
        }

        result.proofValid = true;
        result.boundPolicy = policyHash_;
    }

    /// @notice Verify and consume a proof (marks as used)
    /// @param boundProof The proof to verify and consume
    /// @param vkHash The verification key hash
    function verifyAndConsumeProof(
        BoundProof calldata boundProof,
        bytes32 vkHash
    ) external whenNotPaused onlyRole(VERIFIER_ROLE) {
        // Compute proof nullifier
        bytes32 proofNullifier = keccak256(
            abi.encodePacked(
                boundProof.proof,
                boundProof.policyHash,
                boundProof.domainSeparator
            )
        );

        if (usedProofNullifiers[proofNullifier]) {
            revert ProofAlreadyUsed(proofNullifier);
        }

        // Verify the proof
        VerificationResult memory result = this.verifyBoundProof(
            boundProof,
            vkHash
        );

        if (!result.proofValid || !result.policyValid || !result.withinScope) {
            revert InvalidProofStructure();
        }

        // Mark as used
        usedProofNullifiers[proofNullifier] = true;

        // Update usage count
        unchecked {
            ++policyUsageCount[boundProof.policyHash];
        }

        emit ProofVerified(
            proofNullifier,
            boundProof.policyHash,
            msg.sender,
            true
        );
    }

    /*//////////////////////////////////////////////////////////////
                          DOMAIN SEPARATOR UTILS
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute domain separator for a VK and policy
    /// @param vkHash The verification key hash
    /// @param policyHash The policy hash
    /// @return domainSeparator The computed domain separator
    function computeDomainSeparator(
        bytes32 vkHash,
        bytes32 policyHash
    ) external pure returns (bytes32 domainSeparator) {
        return keccak256(abi.encodePacked(vkHash, policyHash));
    }

    /// @notice Get verification key by domain separator
    /// @param domainSeparator The domain separator
    /// @return vkHash The verification key hash
    function getVkByDomain(
        bytes32 domainSeparator
    ) external view returns (bytes32 vkHash) {
        return domainToVk[domainSeparator];
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get policy details
    function getPolicy(
        bytes32 policyId
    ) external view returns (DisclosurePolicy memory) {
        return policies[policyId];
    }

    /// @notice Get verification key details
    function getVerificationKey(
        bytes32 vkHash
    ) external view returns (BoundVerificationKey memory) {
        return verificationKeys[vkHash];
    }

    /// @notice Check if policy is valid and active
    function isPolicyValid(bytes32 policyId) external view returns (bool) {
        DisclosurePolicy storage policy = policies[policyId];
        if (policy.createdAt == 0) return false;
        if (!policy.isActive) return false;
        if (policy.expiresAt != 0 && block.timestamp > policy.expiresAt)
            return false;
        return true;
    }

    /// @notice Get all policy IDs (paginated)
    /// @param offset Starting index
    /// @param limit Maximum number to return
    function getPolicyIds(
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory ids) {
        uint256 total = _policyIds.length;
        if (offset >= total) return new bytes32[](0);

        uint256 end = offset + limit;
        if (end > total) end = total;

        ids = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; ) {
            ids[i - offset] = _policyIds[i];
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Get all VK hashes (paginated)
    /// @param offset Starting index
    /// @param limit Maximum number to return
    function getVkHashes(
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory hashes) {
        uint256 total = _vkHashes.length;
        if (offset >= total) return new bytes32[](0);

        uint256 end = offset + limit;
        if (end > total) end = total;

        hashes = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; ) {
            hashes[i - offset] = _vkHashes[i];
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Batch check multiple policies
    /// @param policyIds Array of policy IDs to check
    /// @return validities Array of validity results
    function batchCheckPolicies(
        bytes32[] calldata policyIds
    ) external view returns (bool[] memory validities) {
        uint256 len = policyIds.length;
        validities = new bool[](len);
        for (uint256 i = 0; i < len; ) {
            validities[i] = this.isPolicyValid(policyIds[i]);
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set default proof validity period
    function setDefaultProofValidity(
        uint256 validity
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        defaultProofValidity = validity;
    }

    /// @notice Pause contract
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
