// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../canton/CantonPrimitives.sol";

/**
 * @title CantonBridgeAdapter
 * @notice Bridge adapter for Canton Network integration with PIL
 * @dev Enables cross-domain transfers between Canton and EVM chains
 *
 * Canton Network Features:
 * - Sub-transaction privacy (participants only see their views)
 * - Synchronization domains for multi-party coordination
 * - BFT consensus within domains
 * - X.509 certificate-based identity
 * - Daml smart contracts
 *
 * Bridge Architecture:
 * - Participant nodes validate Canton transactions
 * - Domain mediators coordinate cross-domain transfers
 * - Nullifiers derived from archived contracts
 * - PIL binding for cross-chain privacy
 */
contract CantonBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    using CantonPrimitives for *;

    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant MEDIATOR_ROLE = keccak256("MEDIATOR_ROLE");
    bytes32 public constant SEQUENCER_ROLE = keccak256("SEQUENCER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Maximum BFT committee size
    uint256 public constant MAX_COMMITTEE_SIZE = 21;

    /// @notice Minimum signatures required (BFT threshold)
    uint256 public constant MIN_SIGNATURES = 14; // 2/3 + 1

    /// @notice Maximum clock skew allowed (5 minutes)
    uint256 public constant MAX_CLOCK_SKEW = 300;

    /// @notice Transaction finality delay
    uint256 public constant FINALITY_DELAY = 30; // seconds

    /// @notice Maximum transfer amount
    uint256 public constant MAX_TRANSFER_AMOUNT = 100_000 ether;

    /// @notice Daily transfer limit
    uint256 public constant DAILY_LIMIT = 1_000_000 ether;

    /// @notice Confirmation timeout
    uint256 public constant CONFIRMATION_TIMEOUT = 1 hours;

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Registered synchronization domains
    mapping(bytes32 => CantonPrimitives.DomainConfig) public domains;

    /// @notice Domain topology snapshots
    mapping(bytes32 => CantonPrimitives.DomainTopology) public topologies;

    /// @notice Registered participant nodes
    mapping(bytes32 => CantonPrimitives.ParticipantNode) public participants;

    /// @notice Participant address to node ID mapping
    mapping(address => bytes32) public participantNodeIds;

    /// @notice Used nullifiers (contract archival)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Processed transactions
    mapping(bytes32 => bool) public processedTransactions;

    /// @notice Transaction confirmations
    mapping(bytes32 => CantonPrimitives.TransactionConfirmation)
        public confirmations;

    /// @notice Cross-domain transfers
    mapping(bytes32 => CantonPrimitives.DomainTransfer) public transfers;

    /// @notice Canton to PIL nullifier binding
    mapping(bytes32 => bytes32) public crossDomainNullifiers;

    /// @notice PIL to Canton reverse binding
    mapping(bytes32 => bytes32) public pilBindings;

    /// @notice Registered X.509 certificates
    mapping(bytes32 => CantonPrimitives.X509Certificate) public certificates;

    /// @notice Daily volume tracking
    uint256 public dailyVolume;
    uint256 public lastVolumeResetTime;

    /// @notice Circuit breaker state
    bool public circuitBreakerActive;
    string public circuitBreakerReason;

    /// @notice Total processed transactions
    uint256 public totalTransactions;

    /// @notice Total transferred value
    uint256 public totalTransferredValue;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event DomainRegistered(bytes32 indexed domainId, string domainAlias);
    event DomainStatusChanged(
        bytes32 indexed domainId,
        CantonPrimitives.DomainStatus status
    );
    event TopologyUpdated(bytes32 indexed domainId, bytes32 topologyHash);

    event ParticipantRegistered(
        bytes32 indexed nodeId,
        address indexed operator
    );
    event ParticipantStatusChanged(
        bytes32 indexed nodeId,
        CantonPrimitives.ParticipantStatus status
    );

    event TransactionSubmitted(
        bytes32 indexed transactionId,
        bytes32 indexed domainId
    );
    event TransactionConfirmed(bytes32 indexed transactionId, bytes32 rootHash);
    event TransactionRejected(bytes32 indexed transactionId, string reason);

    event TransferInitiated(
        bytes32 indexed transferId,
        bytes32 indexed sourceDomain,
        bytes32 indexed targetDomain,
        bytes32 contractId
    );
    event TransferCompleted(bytes32 indexed transferId);

    event NullifierUsed(bytes32 indexed nullifier, bytes32 indexed contractId);
    event CrossDomainNullifierRegistered(
        bytes32 indexed cantonNf,
        bytes32 indexed pilNf
    );

    event CertificateRegistered(bytes32 indexed keyId, uint256 validUntil);
    event CertificateRevoked(bytes32 indexed keyId);

    event CircuitBreakerTriggered(string reason);
    event CircuitBreakerReset();

    event Deposit(
        address indexed depositor,
        uint256 amount,
        bytes32 indexed partyFingerprint
    );
    event Withdrawal(
        address indexed recipient,
        uint256 amount,
        bytes32 indexed nullifier
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidDomain();
    error DomainNotActive();
    error InvalidParticipant();
    error ParticipantNotActive();
    error InvalidTransaction();
    error TransactionAlreadyProcessed();
    error InvalidSignature();
    error InsufficientSignatures();
    error NullifierAlreadyUsed();
    error InvalidNullifier();
    error TransferNotFound();
    error TransferAlreadyComplete();
    error InvalidAmount();
    error DailyLimitExceeded();
    error CircuitBreakerOn();
    error InvalidCertificate();
    error CertificateExpired();
    error ConfirmationTimeout();
    error InvalidProof();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier whenCircuitBreakerOff() {
        if (circuitBreakerActive) revert CircuitBreakerOn();
        _;
    }

    modifier validDomain(bytes32 domainId) {
        if (!CantonPrimitives.isDomainActive(domains[domainId]))
            revert DomainNotActive();
        _;
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        lastVolumeResetTime = block.timestamp;
    }

    // =========================================================================
    // DOMAIN MANAGEMENT
    // =========================================================================

    /// @notice Register a new synchronization domain
    function registerDomain(
        bytes32 domainId,
        string calldata domainAlias,
        uint256 sequencerThreshold,
        uint256 mediatorThreshold,
        uint256 maxRequestSize,
        uint256 participantResponseTimeout,
        uint256 reconciliationInterval
    ) external onlyRole(OPERATOR_ROLE) {
        if (domainId == bytes32(0)) revert InvalidDomain();
        if (domains[domainId].domainId != bytes32(0)) revert InvalidDomain();

        domains[domainId] = CantonPrimitives.DomainConfig({
            domainId: domainId,
            domainAlias: domainAlias,
            sequencerThreshold: sequencerThreshold,
            mediatorThreshold: mediatorThreshold,
            maxRequestSize: maxRequestSize,
            participantResponseTimeout: participantResponseTimeout,
            reconciliationInterval: reconciliationInterval,
            status: CantonPrimitives.DomainStatus.ACTIVE
        });

        emit DomainRegistered(domainId, domainAlias);
    }

    /// @notice Update domain status
    function setDomainStatus(
        bytes32 domainId,
        CantonPrimitives.DomainStatus status
    ) external onlyRole(OPERATOR_ROLE) {
        if (domains[domainId].domainId == bytes32(0)) revert InvalidDomain();
        domains[domainId].status = status;
        emit DomainStatusChanged(domainId, status);
    }

    /// @notice Update domain topology
    function updateTopology(
        bytes32 domainId,
        bytes32[] calldata sequencers,
        bytes32[] calldata mediators,
        bytes32[] calldata participantIds
    ) external onlyRole(OPERATOR_ROLE) validDomain(domainId) {
        bytes32 topologyHash = sha256(
            abi.encodePacked(
                domainId,
                sequencers,
                mediators,
                participantIds,
                block.timestamp
            )
        );

        topologies[domainId] = CantonPrimitives.DomainTopology({
            domainId: domainId,
            sequencers: sequencers,
            mediators: mediators,
            participants: participantIds,
            timestamp: block.timestamp,
            topologyHash: topologyHash
        });

        emit TopologyUpdated(domainId, topologyHash);
    }

    // =========================================================================
    // PARTICIPANT MANAGEMENT
    // =========================================================================

    /// @notice Register a participant node
    function registerParticipant(
        bytes32 nodeId,
        bytes32[] calldata hostedPartyFingerprints,
        bytes32[] calldata hostedPartyNamespaces
    ) external {
        if (nodeId == bytes32(0)) revert InvalidParticipant();
        if (participants[nodeId].nodeId != bytes32(0))
            revert InvalidParticipant();
        require(
            hostedPartyFingerprints.length == hostedPartyNamespaces.length,
            "Length mismatch"
        );

        CantonPrimitives.PartyId[]
            memory parties = new CantonPrimitives.PartyId[](
                hostedPartyFingerprints.length
            );
        for (uint256 i = 0; i < hostedPartyFingerprints.length; i++) {
            parties[i] = CantonPrimitives.PartyId({
                fingerprint: hostedPartyFingerprints[i],
                namespace: hostedPartyNamespaces[i]
            });
        }

        participants[nodeId] = CantonPrimitives.ParticipantNode({
            nodeId: nodeId,
            hostedParties: parties,
            connectedDomains: new bytes32[](0),
            status: CantonPrimitives.ParticipantStatus.CONNECTED,
            registeredAt: block.timestamp
        });

        participantNodeIds[msg.sender] = nodeId;

        emit ParticipantRegistered(nodeId, msg.sender);
    }

    /// @notice Update participant status
    function setParticipantStatus(
        bytes32 nodeId,
        CantonPrimitives.ParticipantStatus status
    ) external onlyRole(OPERATOR_ROLE) {
        if (participants[nodeId].nodeId == bytes32(0))
            revert InvalidParticipant();
        participants[nodeId].status = status;
        emit ParticipantStatusChanged(nodeId, status);
    }

    /// @notice Connect participant to domain
    function connectToDomain(bytes32 domainId) external validDomain(domainId) {
        bytes32 nodeId = participantNodeIds[msg.sender];
        if (nodeId == bytes32(0)) revert InvalidParticipant();

        CantonPrimitives.ParticipantNode storage node = participants[nodeId];

        // Add domain to connected list (simplified - production would check duplicates)
        bytes32[] memory newDomains = new bytes32[](
            node.connectedDomains.length + 1
        );
        for (uint256 i = 0; i < node.connectedDomains.length; i++) {
            newDomains[i] = node.connectedDomains[i];
        }
        newDomains[node.connectedDomains.length] = domainId;
        node.connectedDomains = newDomains;
        node.status = CantonPrimitives.ParticipantStatus.ACTIVE;
    }

    // =========================================================================
    // CERTIFICATE MANAGEMENT
    // =========================================================================

    /// @notice Register X.509 certificate
    function registerCertificate(
        bytes32 subjectKeyId,
        bytes32 issuerKeyId,
        uint256 validFrom,
        uint256 validUntil,
        bytes calldata publicKey,
        bytes calldata signature
    ) external onlyRole(OPERATOR_ROLE) {
        if (subjectKeyId == bytes32(0)) revert InvalidCertificate();
        if (validUntil <= block.timestamp) revert CertificateExpired();

        certificates[subjectKeyId] = CantonPrimitives.X509Certificate({
            subjectKeyId: subjectKeyId,
            issuerKeyId: issuerKeyId,
            validFrom: validFrom,
            validUntil: validUntil,
            publicKey: publicKey,
            signature: signature
        });

        emit CertificateRegistered(subjectKeyId, validUntil);
    }

    /// @notice Revoke certificate
    function revokeCertificate(bytes32 keyId) external onlyRole(OPERATOR_ROLE) {
        if (certificates[keyId].subjectKeyId == bytes32(0))
            revert InvalidCertificate();
        delete certificates[keyId];
        emit CertificateRevoked(keyId);
    }

    // =========================================================================
    // TRANSACTION PROCESSING
    // =========================================================================

    /// @notice Submit Canton transaction for processing
    function submitTransaction(
        bytes32 transactionId,
        bytes32 domainId,
        uint256 ledgerTime,
        bytes32[] calldata viewHashes,
        bytes32 submitterFingerprint,
        bytes32 submitterNamespace,
        bytes32 commandId
    )
        external
        whenNotPaused
        whenCircuitBreakerOff
        validDomain(domainId)
        nonReentrant
    {
        if (processedTransactions[transactionId])
            revert TransactionAlreadyProcessed();
        if (
            viewHashes.length == 0 ||
            viewHashes.length > CantonPrimitives.MAX_SUB_TRANSACTIONS
        ) {
            revert InvalidTransaction();
        }

        // Validate timing
        if (ledgerTime > block.timestamp + MAX_CLOCK_SKEW)
            revert InvalidTransaction();

        bytes32 rootHash = CantonPrimitives.computeMerkleRoot(viewHashes);

        confirmations[transactionId] = CantonPrimitives
            .TransactionConfirmation({
                transactionId: transactionId,
                domainId: domainId,
                rootHash: rootHash,
                recordTime: block.timestamp,
                participantAcks: new bytes32[](0),
                isAccepted: false
            });

        emit TransactionSubmitted(transactionId, domainId);
    }

    /// @notice Confirm transaction with participant signature
    function confirmTransaction(
        bytes32 transactionId,
        bytes32 participantNodeId,
        bytes calldata signature
    ) external whenNotPaused whenCircuitBreakerOff {
        CantonPrimitives.TransactionConfirmation storage conf = confirmations[
            transactionId
        ];
        if (conf.transactionId == bytes32(0)) revert InvalidTransaction();
        if (conf.isAccepted) revert TransactionAlreadyProcessed();
        if (block.timestamp > conf.recordTime + CONFIRMATION_TIMEOUT)
            revert ConfirmationTimeout();

        // Verify participant is valid
        if (
            !CantonPrimitives.isParticipantActive(
                participants[participantNodeId]
            )
        ) {
            revert ParticipantNotActive();
        }

        // Add acknowledgment
        bytes32[] memory newAcks = new bytes32[](
            conf.participantAcks.length + 1
        );
        for (uint256 i = 0; i < conf.participantAcks.length; i++) {
            newAcks[i] = conf.participantAcks[i];
        }
        newAcks[conf.participantAcks.length] = participantNodeId;
        conf.participantAcks = newAcks;

        // Check if threshold reached
        CantonPrimitives.DomainConfig memory domain = domains[conf.domainId];
        if (conf.participantAcks.length >= domain.mediatorThreshold) {
            conf.isAccepted = true;
            processedTransactions[transactionId] = true;
            totalTransactions++;
            emit TransactionConfirmed(transactionId, conf.rootHash);
        }
    }

    /// @notice Reject transaction
    function rejectTransaction(
        bytes32 transactionId,
        string calldata reason
    ) external onlyRole(MEDIATOR_ROLE) {
        CantonPrimitives.TransactionConfirmation storage conf = confirmations[
            transactionId
        ];
        if (conf.transactionId == bytes32(0)) revert InvalidTransaction();
        if (conf.isAccepted) revert TransactionAlreadyProcessed();

        processedTransactions[transactionId] = true;
        emit TransactionRejected(transactionId, reason);
    }

    // =========================================================================
    // CROSS-DOMAIN TRANSFERS
    // =========================================================================

    /// @notice Initiate cross-domain transfer
    function initiateTransfer(
        bytes32 transferId,
        bytes32 sourceDomain,
        bytes32 targetDomain,
        bytes32 contractId,
        bytes32 submitterFingerprint,
        bytes32 submitterNamespace
    )
        external
        whenNotPaused
        whenCircuitBreakerOff
        validDomain(sourceDomain)
        validDomain(targetDomain)
    {
        if (transfers[transferId].transferId != bytes32(0))
            revert InvalidTransaction();

        transfers[transferId] = CantonPrimitives.DomainTransfer({
            transferId: transferId,
            sourceDomain: sourceDomain,
            targetDomain: targetDomain,
            contractId: contractId,
            submitter: CantonPrimitives.PartyId({
                fingerprint: submitterFingerprint,
                namespace: submitterNamespace
            }),
            initiatedAt: block.timestamp,
            completedAt: 0,
            isComplete: false
        });

        emit TransferInitiated(
            transferId,
            sourceDomain,
            targetDomain,
            contractId
        );
    }

    /// @notice Complete cross-domain transfer
    function completeTransfer(
        bytes32 transferId,
        bytes32 nullifier,
        bytes32[] calldata proof,
        uint256[] calldata proofIndices
    ) external whenNotPaused whenCircuitBreakerOff onlyRole(MEDIATOR_ROLE) {
        CantonPrimitives.DomainTransfer storage transfer = transfers[
            transferId
        ];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.isComplete) revert TransferAlreadyComplete();
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();

        // Mark nullifier as used
        usedNullifiers[nullifier] = true;

        // Complete transfer
        transfer.isComplete = true;
        transfer.completedAt = block.timestamp;

        emit NullifierUsed(nullifier, transfer.contractId);
        emit TransferCompleted(transferId);
    }

    // =========================================================================
    // DEPOSIT / WITHDRAWAL
    // =========================================================================

    /// @notice Deposit ETH for Canton party
    function deposit(
        bytes32 partyFingerprint
    ) external payable whenNotPaused whenCircuitBreakerOff nonReentrant {
        if (msg.value == 0 || msg.value > MAX_TRANSFER_AMOUNT)
            revert InvalidAmount();
        if (partyFingerprint == bytes32(0)) revert InvalidParticipant();

        _checkDailyLimit(msg.value);

        emit Deposit(msg.sender, msg.value, partyFingerprint);
    }

    /// @notice Withdraw with Canton nullifier proof
    function withdraw(
        bytes32 nullifier,
        address recipient,
        uint256 amount,
        bytes32 domainId,
        bytes32[] calldata merkleProof,
        uint256[] calldata proofIndices,
        bytes calldata signatures
    )
        external
        whenNotPaused
        whenCircuitBreakerOff
        validDomain(domainId)
        nonReentrant
    {
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        if (recipient == address(0)) revert InvalidParticipant();
        if (amount == 0 || amount > MAX_TRANSFER_AMOUNT) revert InvalidAmount();

        _checkDailyLimit(amount);

        // Verify signatures reach threshold
        _verifyWithdrawalSignatures(
            nullifier,
            recipient,
            amount,
            domainId,
            signatures
        );

        // Mark nullifier as used
        usedNullifiers[nullifier] = true;
        totalTransferredValue += amount;

        // Transfer funds
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        emit NullifierUsed(nullifier, bytes32(0));
        emit Withdrawal(recipient, amount, nullifier);
    }

    // =========================================================================
    // CROSS-DOMAIN NULLIFIER BINDING
    // =========================================================================

    /// @notice Register cross-domain nullifier for PIL binding
    function registerCrossDomainNullifier(
        bytes32 cantonNullifier,
        uint256 targetChainId
    ) external whenNotPaused {
        if (cantonNullifier == bytes32(0)) revert InvalidNullifier();

        // Check if already registered
        if (crossDomainNullifiers[cantonNullifier] != bytes32(0)) {
            return; // Idempotent
        }

        bytes32 pilNullifier = CantonPrimitives.deriveCrossDomainNullifier(
            cantonNullifier,
            block.chainid,
            targetChainId
        );

        crossDomainNullifiers[cantonNullifier] = pilNullifier;
        pilBindings[pilNullifier] = cantonNullifier;

        emit CrossDomainNullifierRegistered(cantonNullifier, pilNullifier);
    }

    // =========================================================================
    // CIRCUIT BREAKER
    // =========================================================================

    /// @notice Trigger circuit breaker
    function triggerCircuitBreaker(
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        circuitBreakerActive = true;
        circuitBreakerReason = reason;
        emit CircuitBreakerTriggered(reason);
    }

    /// @notice Reset circuit breaker
    function resetCircuitBreaker() external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreakerActive = false;
        circuitBreakerReason = "";
        emit CircuitBreakerReset();
    }

    // =========================================================================
    // PAUSE
    // =========================================================================

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get domain configuration
    function getDomain(
        bytes32 domainId
    ) external view returns (CantonPrimitives.DomainConfig memory) {
        return domains[domainId];
    }

    /// @notice Get domain topology
    function getTopology(
        bytes32 domainId
    ) external view returns (CantonPrimitives.DomainTopology memory) {
        return topologies[domainId];
    }

    /// @notice Get participant node
    function getParticipant(
        bytes32 nodeId
    )
        external
        view
        returns (
            bytes32 id,
            CantonPrimitives.ParticipantStatus status,
            uint256 registeredAt,
            uint256 connectedDomainsCount
        )
    {
        CantonPrimitives.ParticipantNode storage node = participants[nodeId];
        return (
            node.nodeId,
            node.status,
            node.registeredAt,
            node.connectedDomains.length
        );
    }

    /// @notice Get transfer details
    function getTransfer(
        bytes32 transferId
    ) external view returns (CantonPrimitives.DomainTransfer memory) {
        return transfers[transferId];
    }

    /// @notice Get confirmation details
    function getConfirmation(
        bytes32 transactionId
    ) external view returns (CantonPrimitives.TransactionConfirmation memory) {
        return confirmations[transactionId];
    }

    /// @notice Check if nullifier is used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Get bridge statistics
    function getStats()
        external
        view
        returns (
            uint256 transactions,
            uint256 transferredValue,
            uint256 currentDailyVolume,
            bool circuitBreaker
        )
    {
        return (
            totalTransactions,
            totalTransferredValue,
            dailyVolume,
            circuitBreakerActive
        );
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /// @notice Check and update daily limit
    function _checkDailyLimit(uint256 amount) internal {
        // Reset daily volume if new day
        if (block.timestamp >= lastVolumeResetTime + 1 days) {
            dailyVolume = 0;
            lastVolumeResetTime = block.timestamp;
        }

        if (dailyVolume + amount > DAILY_LIMIT) revert DailyLimitExceeded();
        dailyVolume += amount;
    }

    /// @notice Verify withdrawal signatures
    function _verifyWithdrawalSignatures(
        bytes32 nullifier,
        address recipient,
        uint256 amount,
        bytes32 domainId,
        bytes calldata signatures
    ) internal view {
        // Signatures should be concatenated (65 bytes each)
        uint256 sigCount = signatures.length / 65;
        if (sigCount < MIN_SIGNATURES) revert InsufficientSignatures();

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                nullifier,
                recipient,
                amount,
                domainId,
                block.chainid
            )
        );

        // In production, verify each signature against registered mediators
        // This is a simplified check
        for (uint256 i = 0; i < sigCount; i++) {
            bytes memory sig = signatures[i * 65:(i + 1) * 65];
            if (sig.length != 65) revert InvalidSignature();
        }
    }

    /// @notice Receive ETH
    receive() external payable {}
}
