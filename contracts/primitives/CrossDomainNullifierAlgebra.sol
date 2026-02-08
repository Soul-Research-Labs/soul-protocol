// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IProofVerifier.sol";

/// @title CrossDomainNullifierAlgebra (CDNA)
/// @author Soul Protocol - Soul v2
/// @notice Domain-separated nullifiers that compose across chains, epochs, and applications
/// @dev MVP Implementation - Enables cross-chain double-spend prevention without global state
///
/// Key Properties:
/// - Nullifiers are domain-separated: N = H(secret, app_id, chain_id, epoch, transition_id)
/// - Provable relations between nullifiers across domains
/// - Enables parallel execution without global locks
/// - Directly addresses replay and double-spend threats
///
/// Security Considerations:
/// - Domain separation prevents cross-domain replay
/// - Epoch finalization creates immutable audit trail
/// - Parent-child linking enables cross-chain verification
/// - Nullifier consumption is atomic and irreversible
contract CrossDomainNullifierAlgebra is AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("NULLIFIER_REGISTRAR_ROLE")
    bytes32 public constant NULLIFIER_REGISTRAR_ROLE =
        0x5505d4e1c339d2da96b423eae372f08e27c4388c7bee6502a760802a80405236;
    /// @dev keccak256("DOMAIN_ADMIN_ROLE")
    bytes32 public constant DOMAIN_ADMIN_ROLE =
        0x7792e66be7e1c65b630a8198da6bf1636e24cd26934ca652e146dd12060d06fb;
    /// @dev keccak256("BRIDGE_ROLE")
    bytes32 public constant BRIDGE_ROLE =
        0x52ba824bfabc2bcfcdf7f0edbb486ebb05e1836c90e78047efeb949990f72e5f;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain definition for nullifier separation
    struct Domain {
        bytes32 domainId;
        uint64 chainId; // Chain identifier
        bytes32 appId; // Application identifier
        uint64 epochStart; // Epoch start timestamp
        uint64 epochEnd; // Epoch end timestamp (0 = infinite)
        bytes32 domainSeparator; // Precomputed domain separator
        bool isActive;
        uint64 registeredAt;
    }

    /// @notice Domain-separated nullifier structure
    struct DomainNullifier {
        bytes32 nullifier; // The nullifier value
        bytes32 domainId; // Domain this nullifier belongs to
        bytes32 commitmentHash; // Associated commitment
        bytes32 transitionId; // State transition identifier
        // Cross-domain linking
        bytes32 parentNullifier; // Nullifier this was derived from (if any)
        bytes32[] childNullifiers; // Nullifiers derived from this
        // Metadata
        address registrar;
        uint64 registeredAt;
        uint64 epochId;
        bool isConsumed;
    }

    /// @notice Cross-domain nullifier proof
    struct CrossDomainProof {
        bytes32 sourceNullifier;
        bytes32 targetNullifier;
        bytes32 sourceDomainId;
        bytes32 targetDomainId;
        bytes proof; // ZK proof of valid derivation
        bytes32 proofHash;
    }

    /// @notice Epoch configuration
    struct Epoch {
        uint64 epochId;
        uint64 startTime;
        uint64 endTime;
        bytes32 merkleRoot; // Merkle root of all nullifiers in epoch
        uint256 nullifierCount;
        bool isFinalized;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of domain ID to domain
    mapping(bytes32 => Domain) public domains;

    /// @notice Mapping of nullifier to domain nullifier data
    mapping(bytes32 => DomainNullifier) public nullifiers;

    /// @notice Mapping of domain separator to domain ID
    mapping(bytes32 => bytes32) public separatorToDomain;

    /// @notice Quick check for nullifier existence
    mapping(bytes32 => bool) public nullifierExists;

    /// @notice Nullifiers by domain
    mapping(bytes32 => bytes32[]) public nullifiersByDomain;

    /// @notice Epoch data
    mapping(uint64 => Epoch) public epochs;

    /// @notice Current epoch ID
    uint64 public currentEpochId;

    /// @notice Epoch duration
    uint64 public epochDuration = 1 hours;

    /// @notice Chain ID
    uint256 public immutable CHAIN_ID;

    /// @notice Total domains
    uint256 public totalDomains;

    /// @notice Total nullifiers
    uint256 public totalNullifiers;

    /// @notice Cross-domain link count
    uint256 public totalCrossLinks;

    /// @notice Storage for domain IDs (for enumeration)
    bytes32[] private _domainIds;

    /// @notice Minimum derivation proof size
    uint256 public constant MIN_DERIVATION_PROOF_SIZE = 256;

    /// @notice Minimum cross-domain proof size
    uint256 public constant MIN_CROSS_DOMAIN_PROOF_SIZE = 256;

    /// @notice ZK verifier for nullifier derivation proofs
    /// @dev Phase 3: Replaces length-check placeholder verification
    IProofVerifier public derivationVerifier;

    /// @notice Maximum child nullifiers per parent (prevent DOS)
    uint256 public constant MAX_CHILD_NULLIFIERS = 100;

    /// @notice Maximum epoch duration (prevent stale epochs)
    uint64 public constant MAX_EPOCH_DURATION = 7 days;

    /// @notice Minimum epoch duration
    uint64 public constant MIN_EPOCH_DURATION = 1 minutes;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event DomainRegistered(
        bytes32 indexed domainId,
        uint64 indexed chainId,
        bytes32 indexed appId,
        bytes32 domainSeparator
    );

    event DomainDeactivated(bytes32 indexed domainId);

    event NullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed domainId,
        bytes32 indexed commitmentHash,
        uint64 epochId
    );

    event NullifierConsumed(
        bytes32 indexed nullifier,
        bytes32 indexed domainId,
        address indexed consumer
    );

    event CrossDomainLink(
        bytes32 indexed parentNullifier,
        bytes32 indexed childNullifier,
        bytes32 indexed sourceDomainId,
        bytes32 targetDomainId
    );

    event EpochFinalized(
        uint64 indexed epochId,
        bytes32 merkleRoot,
        uint256 nullifierCount
    );

    event CrossDomainProofVerified(
        bytes32 indexed sourceNullifier,
        bytes32 indexed targetNullifier,
        bytes32 proofHash
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error DomainNotFound(bytes32 domainId);
    error DomainAlreadyExists(bytes32 domainId);
    error DomainInactive(bytes32 domainId);
    error NullifierAlreadyExists(bytes32 nullifier);
    error NullifierNotFound(bytes32 nullifier);
    error NullifierAlreadyConsumed(bytes32 nullifier);
    error InvalidDomainSeparator();
    error InvalidCrossDomainProof();
    error EpochNotFinalized(uint64 epochId);
    error EpochAlreadyFinalized(uint64 epochId);
    error NullifierDomainMismatch(bytes32 nullifier, bytes32 expectedDomain);
    error ParentNullifierNotFound(bytes32 parentNullifier);
    error CircularNullifierLink();
    error TooManyChildNullifiers(bytes32 parent, uint256 count);
    error InvalidEpochDuration(uint64 duration);
    error ZeroAppId();
    error InvalidChainId();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DOMAIN_ADMIN_ROLE, msg.sender);
        _grantRole(NULLIFIER_REGISTRAR_ROLE, msg.sender);

        CHAIN_ID = block.chainid;

        // Initialize first epoch
        currentEpochId = 1;
        epochs[1] = Epoch({
            epochId: 1,
            startTime: uint64(block.timestamp),
            endTime: uint64(block.timestamp) + epochDuration,
            merkleRoot: bytes32(0),
            nullifierCount: 0,
            isFinalized: false
        });
    }

    /*//////////////////////////////////////////////////////////////
                          DOMAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a new domain for nullifier separation
    /// @param chainId Chain identifier
    /// @param appId Application identifier
    /// @param epochEnd Optional epoch end time (0 = infinite)
    /// @return domainId The unique domain identifier
    function registerDomain(
        uint64 chainId,
        bytes32 appId,
        uint64 epochEnd
    ) external onlyRole(DOMAIN_ADMIN_ROLE) returns (bytes32 domainId) {
        // Validate inputs
        if (chainId == 0) revert InvalidChainId();
        if (appId == bytes32(0)) revert ZeroAppId();

        // Compute domain separator
        bytes32 domainSeparator = computeDomainSeparator(
            chainId,
            appId,
            currentEpochId
        );

        // Compute domain ID
        domainId = keccak256(abi.encodePacked(chainId, appId, domainSeparator));

        if (domains[domainId].registeredAt != 0) {
            revert DomainAlreadyExists(domainId);
        }

        domains[domainId] = Domain({
            domainId: domainId,
            chainId: chainId,
            appId: appId,
            epochStart: uint64(block.timestamp),
            epochEnd: epochEnd,
            domainSeparator: domainSeparator,
            isActive: true,
            registeredAt: uint64(block.timestamp)
        });

        separatorToDomain[domainSeparator] = domainId;

        // Add to domain IDs array for enumeration
        _domainIds.push(domainId);

        unchecked {
            ++totalDomains;
        }

        emit DomainRegistered(domainId, chainId, appId, domainSeparator);
    }

    /// @notice Deactivate a domain
    function deactivateDomain(
        bytes32 domainId
    ) external onlyRole(DOMAIN_ADMIN_ROLE) {
        if (domains[domainId].registeredAt == 0) {
            revert DomainNotFound(domainId);
        }

        domains[domainId].isActive = false;
        emit DomainDeactivated(domainId);
    }

    /*//////////////////////////////////////////////////////////////
                       NULLIFIER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a domain-separated nullifier
    /// @param domainId The domain for this nullifier
    /// @param nullifierValue The computed nullifier
    /// @param commitmentHash Associated commitment
    /// @param transitionId State transition identifier
    /// @return nullifier The registered nullifier
    function registerNullifier(
        bytes32 domainId,
        bytes32 nullifierValue,
        bytes32 commitmentHash,
        bytes32 transitionId
    )
        public
        whenNotPaused
        onlyRole(NULLIFIER_REGISTRAR_ROLE)
        returns (bytes32 nullifier)
    {
        Domain storage domain = domains[domainId];

        if (domain.registeredAt == 0) {
            revert DomainNotFound(domainId);
        }

        if (!domain.isActive) {
            revert DomainInactive(domainId);
        }

        // Compute full nullifier with domain separation
        nullifier = computeNullifier(
            nullifierValue,
            domain.domainSeparator,
            transitionId
        );

        if (nullifierExists[nullifier]) {
            revert NullifierAlreadyExists(nullifier);
        }

        // Check epoch
        _checkAndAdvanceEpoch();

        nullifiers[nullifier] = DomainNullifier({
            nullifier: nullifier,
            domainId: domainId,
            commitmentHash: commitmentHash,
            transitionId: transitionId,
            parentNullifier: bytes32(0),
            childNullifiers: new bytes32[](0),
            registrar: msg.sender,
            registeredAt: uint64(block.timestamp),
            epochId: currentEpochId,
            isConsumed: false
        });

        nullifierExists[nullifier] = true;
        nullifiersByDomain[domainId].push(nullifier);

        // Update epoch
        unchecked {
            ++epochs[currentEpochId].nullifierCount;
            ++totalNullifiers;
        }

        emit NullifierRegistered(
            nullifier,
            domainId,
            commitmentHash,
            currentEpochId
        );
    }

    /// @notice Register a cross-domain derived nullifier
    /// @param parentNullifier The parent nullifier in source domain
    /// @param targetDomainId The target domain for the new nullifier
    /// @param transitionId New transition identifier
    /// @param derivationProof ZK proof of valid derivation
    /// @return childNullifier The derived nullifier
    function registerDerivedNullifier(
        bytes32 parentNullifier,
        bytes32 targetDomainId,
        bytes32 transitionId,
        bytes calldata derivationProof
    )
        external
        whenNotPaused
        onlyRole(BRIDGE_ROLE)
        returns (bytes32 childNullifier)
    {
        // Validate parent exists
        DomainNullifier storage parent = nullifiers[parentNullifier];
        if (!nullifierExists[parentNullifier]) {
            revert ParentNullifierNotFound(parentNullifier);
        }

        // Validate target domain
        Domain storage targetDomain = domains[targetDomainId];
        if (targetDomain.registeredAt == 0) {
            revert DomainNotFound(targetDomainId);
        }
        if (!targetDomain.isActive) {
            revert DomainInactive(targetDomainId);
        }

        // Verify derivation proof via real SNARK verifier (Phase 3)
        require(
            address(derivationVerifier) != address(0),
            "Derivation verifier not configured"
        );
        {
            uint256[] memory inputs = new uint256[](4);
            inputs[0] = uint256(parentNullifier);
            inputs[1] = uint256(targetDomainId);
            inputs[2] = uint256(transitionId);
            inputs[3] = uint256(targetDomain.domainSeparator);

            bool proofValid = derivationVerifier.verify(
                derivationProof,
                inputs
            );
            if (!proofValid) {
                revert InvalidCrossDomainProof();
            }
        }

        // Compute child nullifier
        childNullifier = computeNullifier(
            keccak256(abi.encodePacked(parentNullifier, transitionId)),
            targetDomain.domainSeparator,
            transitionId
        );

        if (nullifierExists[childNullifier]) {
            revert NullifierAlreadyExists(childNullifier);
        }

        // Prevent circular links
        if (childNullifier == parentNullifier) {
            revert CircularNullifierLink();
        }

        // Check child nullifier limit
        if (parent.childNullifiers.length >= MAX_CHILD_NULLIFIERS) {
            revert TooManyChildNullifiers(
                parentNullifier,
                MAX_CHILD_NULLIFIERS
            );
        }

        _checkAndAdvanceEpoch();

        // Create derived nullifier
        nullifiers[childNullifier] = DomainNullifier({
            nullifier: childNullifier,
            domainId: targetDomainId,
            commitmentHash: parent.commitmentHash,
            transitionId: transitionId,
            parentNullifier: parentNullifier,
            childNullifiers: new bytes32[](0),
            registrar: msg.sender,
            registeredAt: uint64(block.timestamp),
            epochId: currentEpochId,
            isConsumed: false
        });

        nullifierExists[childNullifier] = true;
        nullifiersByDomain[targetDomainId].push(childNullifier);

        // Link to parent
        parent.childNullifiers.push(childNullifier);

        unchecked {
            ++epochs[currentEpochId].nullifierCount;
            ++totalNullifiers;
            ++totalCrossLinks;
        }

        emit CrossDomainLink(
            parentNullifier,
            childNullifier,
            parent.domainId,
            targetDomainId
        );
    }

    /// @notice Consume a nullifier (mark as used)
    function consumeNullifier(
        bytes32 nullifier
    ) external whenNotPaused onlyRole(NULLIFIER_REGISTRAR_ROLE) {
        if (!nullifierExists[nullifier]) {
            revert NullifierNotFound(nullifier);
        }

        DomainNullifier storage n = nullifiers[nullifier];
        if (n.isConsumed) {
            revert NullifierAlreadyConsumed(nullifier);
        }

        n.isConsumed = true;

        emit NullifierConsumed(nullifier, n.domainId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                       CROSS-DOMAIN VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify a cross-domain nullifier proof
    /// @param proof The cross-domain proof
    /// @return valid Whether the proof is valid
    function verifyCrossDomainProof(
        CrossDomainProof calldata proof
    ) external view returns (bool valid) {
        // Verify source nullifier exists
        if (!nullifierExists[proof.sourceNullifier]) {
            return false;
        }

        // Verify target nullifier exists
        if (!nullifierExists[proof.targetNullifier]) {
            return false;
        }

        // Verify domains exist
        if (domains[proof.sourceDomainId].registeredAt == 0) {
            return false;
        }
        if (domains[proof.targetDomainId].registeredAt == 0) {
            return false;
        }

        // Verify nullifiers belong to correct domains
        if (
            nullifiers[proof.sourceNullifier].domainId != proof.sourceDomainId
        ) {
            return false;
        }
        if (
            nullifiers[proof.targetNullifier].domainId != proof.targetDomainId
        ) {
            return false;
        }

        // Verify proof via real SNARK verifier (Phase 3)
        if (address(derivationVerifier) == address(0)) {
            return false;
        }
        {
            uint256[] memory inputs = new uint256[](4);
            inputs[0] = uint256(proof.sourceNullifier);
            inputs[1] = uint256(proof.targetNullifier);
            inputs[2] = uint256(proof.sourceDomainId);
            inputs[3] = uint256(proof.targetDomainId);

            try derivationVerifier.verify(proof.proof, inputs) returns (
                bool proofValid
            ) {
                if (!proofValid) return false;
            } catch {
                return false;
            }
        }

        // Verify proof hash
        bytes32 computedHash = keccak256(proof.proof);
        if (computedHash != proof.proofHash) {
            return false;
        }

        // Verify link exists
        DomainNullifier storage source = nullifiers[proof.sourceNullifier];
        bytes32[] storage children = source.childNullifiers;
        uint256 childLen = children.length;
        bool isChild = false;

        for (uint256 i = 0; i < childLen; ) {
            if (children[i] == proof.targetNullifier) {
                isChild = true;
                break;
            }
            unchecked {
                ++i;
            }
        }

        return
            isChild ||
            nullifiers[proof.targetNullifier].parentNullifier ==
            proof.sourceNullifier;
    }

    /*//////////////////////////////////////////////////////////////
                          EPOCH MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Finalize current epoch
    /// @param merkleRoot Merkle root of all nullifiers in epoch
    function finalizeEpoch(
        bytes32 merkleRoot
    ) external onlyRole(DOMAIN_ADMIN_ROLE) {
        Epoch storage epoch = epochs[currentEpochId];

        if (epoch.isFinalized) {
            revert EpochAlreadyFinalized(currentEpochId);
        }

        epoch.merkleRoot = merkleRoot;
        epoch.isFinalized = true;

        emit EpochFinalized(currentEpochId, merkleRoot, epoch.nullifierCount);

        // Start new epoch
        _startNewEpoch();
    }

    /// @notice Check and auto-advance epoch if needed
    function _checkAndAdvanceEpoch() internal {
        Epoch storage epoch = epochs[currentEpochId];

        if (block.timestamp > epoch.endTime && !epoch.isFinalized) {
            // Auto-finalize with zero root (can be updated later)
            epoch.merkleRoot = bytes32(0);
            epoch.isFinalized = true;
            _startNewEpoch();
        }
    }

    /// @notice Start a new epoch
    function _startNewEpoch() internal {
        unchecked {
            ++currentEpochId;
        }

        epochs[currentEpochId] = Epoch({
            epochId: currentEpochId,
            startTime: uint64(block.timestamp),
            endTime: uint64(block.timestamp) + epochDuration,
            merkleRoot: bytes32(0),
            nullifierCount: 0,
            isFinalized: false
        });
    }

    /*//////////////////////////////////////////////////////////////
                          COMPUTATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute domain separator
    /// @param chainId Chain identifier
    /// @param appId Application identifier
    /// @param epochId Epoch identifier
    /// @return separator The domain separator
    function computeDomainSeparator(
        uint64 chainId,
        bytes32 appId,
        uint64 epochId
    ) public pure returns (bytes32 separator) {
        return keccak256(abi.encodePacked("CDNA_v1", chainId, appId, epochId));
    }

    /// @notice Compute a domain-separated nullifier
    /// @param secret The secret/base value
    /// @param domainSeparator The domain separator
    /// @param transitionId The transition identifier
    /// @return nullifier The computed nullifier
    function computeNullifier(
        bytes32 secret,
        bytes32 domainSeparator,
        bytes32 transitionId
    ) public pure returns (bytes32 nullifier) {
        return
            keccak256(abi.encodePacked(secret, domainSeparator, transitionId));
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get nullifier details
    function getNullifier(
        bytes32 nullifier
    )
        external
        view
        returns (
            bytes32 domainId,
            bytes32 commitmentHash,
            bytes32 transitionId,
            bytes32 parentNullifier,
            uint64 registeredAt,
            uint64 epochId,
            bool isConsumed
        )
    {
        DomainNullifier storage n = nullifiers[nullifier];
        return (
            n.domainId,
            n.commitmentHash,
            n.transitionId,
            n.parentNullifier,
            n.registeredAt,
            n.epochId,
            n.isConsumed
        );
    }

    /// @notice Get child nullifiers
    function getChildNullifiers(
        bytes32 nullifier
    ) external view returns (bytes32[] memory) {
        return nullifiers[nullifier].childNullifiers;
    }

    /// @notice Get domain details
    function getDomain(bytes32 domainId) external view returns (Domain memory) {
        return domains[domainId];
    }

    /// @notice Get all active domain IDs
    function getActiveDomains() external view returns (bytes32[] memory) {
        uint256 domainLen = _domainIds.length;
        uint256 activeCount = 0;

        // Count active domains
        for (uint256 i = 0; i < domainLen; ) {
            if (domains[_domainIds[i]].isActive) {
                unchecked {
                    ++activeCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        // Collect active domain IDs
        bytes32[] memory result = new bytes32[](activeCount);
        uint256 index = 0;
        for (uint256 i = 0; i < domainLen && index < activeCount; ) {
            bytes32 did = _domainIds[i];
            if (domains[did].isActive) {
                result[index] = did;
                unchecked {
                    ++index;
                }
            }
            unchecked {
                ++i;
            }
        }

        return result;
    }

    /// @notice Get nullifiers in a domain
    function getNullifiersByDomain(
        bytes32 domainId
    ) external view returns (bytes32[] memory) {
        return nullifiersByDomain[domainId];
    }

    /// @notice Get epoch details
    function getEpoch(uint64 epochId) external view returns (Epoch memory) {
        return epochs[epochId];
    }

    /// @notice Check if nullifier is valid (exists and not consumed)
    function isNullifierValid(bytes32 nullifier) external view returns (bool) {
        return nullifierExists[nullifier] && !nullifiers[nullifier].isConsumed;
    }

    /// @notice Batch check nullifier validity
    /// @param nullifierList Array of nullifiers to check
    /// @return validities Array of validity results
    function batchCheckNullifiers(
        bytes32[] calldata nullifierList
    ) external view returns (bool[] memory validities) {
        uint256 len = nullifierList.length;
        validities = new bool[](len);
        for (uint256 i = 0; i < len; ) {
            bytes32 n = nullifierList[i];
            validities[i] = nullifierExists[n] && !nullifiers[n].isConsumed;
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Batch consume multiple nullifiers
    /// @param nullifierList Array of nullifiers to consume
    function batchConsumeNullifiers(
        bytes32[] calldata nullifierList
    ) external whenNotPaused onlyRole(NULLIFIER_REGISTRAR_ROLE) {
        uint256 len = nullifierList.length;
        for (uint256 i = 0; i < len; ) {
            bytes32 n = nullifierList[i];
            if (!nullifierExists[n]) revert NullifierNotFound(n);

            DomainNullifier storage nullifierData = nullifiers[n];
            if (nullifierData.isConsumed) revert NullifierAlreadyConsumed(n);

            nullifierData.isConsumed = true;
            emit NullifierConsumed(n, nullifierData.domainId, msg.sender);

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Get protocol stats
    /// @return domains_ Total domains
    /// @return nullifiers_ Total nullifiers
    /// @return crossLinks Total cross-domain links
    /// @return currentEpoch Current epoch ID
    function getStats()
        external
        view
        returns (
            uint256 domains_,
            uint256 nullifiers_,
            uint256 crossLinks,
            uint64 currentEpoch
        )
    {
        return (totalDomains, totalNullifiers, totalCrossLinks, currentEpochId);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set epoch duration with validation
    function setEpochDuration(
        uint64 duration
    ) external onlyRole(DOMAIN_ADMIN_ROLE) {
        if (duration < MIN_EPOCH_DURATION || duration > MAX_EPOCH_DURATION) {
            revert InvalidEpochDuration(duration);
        }
        epochDuration = duration;
    }

    /// @notice Set the ZK verifier for nullifier derivation proofs
    /// @dev Phase 3: Required for real SNARK verification of cross-domain nullifiers
    /// @param _verifier Address of the IProofVerifier-compatible contract
    function setDerivationVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_verifier != address(0), "Zero verifier address");
        derivationVerifier = IProofVerifier(_verifier);
        emit DerivationVerifierUpdated(_verifier);
    }

    event DerivationVerifierUpdated(address indexed newVerifier);

    /// @notice Pause contract
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
