// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "../celestia/CelestiaPrimitives.sol";

/**
 * @title CelestiaBridgeAdapter
 * @notice Bridge adapter for Celestia modular DA network integration with PIL
 * @dev Implements Blobstream-style data availability verification and cross-chain messaging
 *
 * Features:
 * - Validator committee management with BLS aggregate signatures
 * - Data commitment verification via Blobstream attestations
 * - Blob inclusion proofs with NMT verification
 * - Cross-domain nullifier binding for privacy-preserving bridging
 * - Rate limiting and circuit breaker for security
 */
contract CelestiaBridgeAdapter is
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    // =========================================================================
    // EVENTS
    // =========================================================================

    event ValidatorRegistered(
        address indexed validator,
        bytes blsKey,
        uint256 votingPower
    );
    event ValidatorRemoved(address indexed validator);
    event ValidatorPowerUpdated(
        address indexed validator,
        uint256 oldPower,
        uint256 newPower
    );

    event DataCommitmentStored(
        bytes32 indexed dataRoot,
        uint64 startBlock,
        uint64 endBlock,
        uint64 nonce
    );
    event BlobstreamAttestationVerified(
        bytes32 indexed dataRoot,
        uint64 height,
        uint256 signingPower
    );

    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed sender,
        uint256 amount,
        CelestiaPrimitives.Namespace namespace
    );
    event WithdrawalCompleted(
        bytes32 indexed withdrawalId,
        address indexed recipient,
        uint256 amount
    );

    event NullifierBound(
        bytes32 indexed celestiaCommitment,
        bytes32 indexed pilNullifier,
        uint64 height
    );
    event NullifierConsumed(bytes32 indexed nullifier);

    event CircuitBreakerTriggered(address indexed triggeredBy, string reason);
    event CircuitBreakerReset(address indexed resetBy);
    event EmergencyCouncilUpdated(
        address indexed oldCouncil,
        address indexed newCouncil
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidValidator();
    error ValidatorAlreadyRegistered();
    error ValidatorNotRegistered();
    error InvalidVotingPower();
    error InvalidPublicKeyLength();
    error QuorumNotMet();
    error InvalidDataCommitment();
    error DataCommitmentAlreadyExists();
    error InvalidBlobstreamAttestation();
    error InvalidNMTProof();
    error NullifierAlreadyConsumed();
    error NullifierNotBound();
    error InvalidNullifierBinding();
    error InvalidWithdrawalProof();
    error WithdrawalAlreadyProcessed();
    error InsufficientDeposit();
    error ExceedsMaxTransfer();
    error ExceedsDailyLimit();
    error CircuitBreakerActive();
    error OnlyEmergencyCouncil();
    error InvalidHeader();
    error HeaderAlreadyFinalized();
    error InvalidSquareSize();

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 public constant MAX_VALIDATORS = 150;
    uint256 public constant MAX_TRANSFER = 100_000 ether;
    uint256 public constant DAILY_LIMIT = 1_000_000 ether;
    uint256 public constant MAX_RELAYER_FEE_BPS = 500; // 5%
    uint256 public constant MIN_CONFIRMATIONS = 10;
    uint256 public constant DATA_COMMITMENT_HISTORY = 100;

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Registered validators
    mapping(address => CelestiaPrimitives.Validator) public validators;
    address[] public validatorList;
    uint256 public totalVotingPower;

    /// @notice Data commitments by data root
    mapping(bytes32 => CelestiaPrimitives.DataCommitment)
        public dataCommitments;
    bytes32[] public dataCommitmentHistory;

    /// @notice Finalized headers by height
    mapping(uint64 => CelestiaPrimitives.CelestiaHeader)
        public finalizedHeaders;
    uint64 public latestFinalizedHeight;

    /// @notice Nullifier tracking
    mapping(bytes32 => bool) public consumedNullifiers;
    mapping(bytes32 => CelestiaPrimitives.CelestiaNullifierBinding)
        public nullifierBindings;

    /// @notice Deposit/withdrawal tracking
    mapping(bytes32 => bool) public processedDeposits;
    mapping(bytes32 => bool) public processedWithdrawals;

    /// @notice Rate limiting
    uint256 public dailyVolume;
    uint256 public lastVolumeReset;

    /// @notice Security
    bool public circuitBreakerActive;
    address public emergencyCouncil;
    uint256 public relayerFeeBps;

    /// @notice Chain identifier
    string public chainId;

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _emergencyCouncil,
        string memory _chainId
    ) external initializer {
        __Ownable_init(_owner);
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        emergencyCouncil = _emergencyCouncil;
        chainId = _chainId;
        lastVolumeReset = block.timestamp;
        relayerFeeBps = 100; // 1% default
    }

    // =========================================================================
    // VALIDATOR MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a new validator
     * @param validator Validator address
     * @param blsKey BLS public key (96 bytes)
     * @param votingPower Initial voting power
     */
    function registerValidator(
        address validator,
        bytes calldata blsKey,
        uint256 votingPower
    ) external onlyOwner {
        if (validator == address(0)) revert InvalidValidator();
        if (validators[validator].votingPower > 0)
            revert ValidatorAlreadyRegistered();
        if (blsKey.length != CelestiaPrimitives.BLS_PUBKEY_LENGTH)
            revert InvalidPublicKeyLength();
        if (votingPower == 0) revert InvalidVotingPower();
        if (validatorList.length >= MAX_VALIDATORS) revert InvalidValidator();

        validators[validator] = CelestiaPrimitives.Validator({
            pubKey: blsKey,
            votingPower: votingPower,
            proposerPriority: ""
        });

        validatorList.push(validator);
        totalVotingPower += votingPower;

        emit ValidatorRegistered(validator, blsKey, votingPower);
    }

    /**
     * @notice Remove a validator
     * @param validator Validator address to remove
     */
    function removeValidator(address validator) external onlyOwner {
        if (validators[validator].votingPower == 0)
            revert ValidatorNotRegistered();

        totalVotingPower -= validators[validator].votingPower;
        delete validators[validator];

        // Remove from list
        for (uint256 i = 0; i < validatorList.length; i++) {
            if (validatorList[i] == validator) {
                validatorList[i] = validatorList[validatorList.length - 1];
                validatorList.pop();
                break;
            }
        }

        emit ValidatorRemoved(validator);
    }

    /**
     * @notice Update validator voting power
     * @param validator Validator address
     * @param newPower New voting power
     */
    function updateValidatorPower(
        address validator,
        uint256 newPower
    ) external onlyOwner {
        if (validators[validator].votingPower == 0)
            revert ValidatorNotRegistered();
        if (newPower == 0) revert InvalidVotingPower();

        uint256 oldPower = validators[validator].votingPower;
        totalVotingPower = totalVotingPower - oldPower + newPower;
        validators[validator].votingPower = newPower;

        emit ValidatorPowerUpdated(validator, oldPower, newPower);
    }

    /**
     * @notice Get validator array for verification
     */
    function getValidators()
        public
        view
        returns (CelestiaPrimitives.Validator[] memory)
    {
        CelestiaPrimitives.Validator[]
            memory vals = new CelestiaPrimitives.Validator[](
                validatorList.length
            );
        for (uint256 i = 0; i < validatorList.length; i++) {
            vals[i] = validators[validatorList[i]];
        }
        return vals;
    }

    // =========================================================================
    // DATA COMMITMENT VERIFICATION
    // =========================================================================

    /**
     * @notice Store verified data commitment
     * @param commitment Data commitment to store
     * @param attestation Blobstream attestation proving the commitment
     */
    function storeDataCommitment(
        CelestiaPrimitives.DataCommitment calldata commitment,
        CelestiaPrimitives.BlobstreamAttestation calldata attestation
    ) external whenNotPaused nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();

        // Verify attestation
        CelestiaPrimitives.Validator[] memory vals = getValidators();
        if (
            !CelestiaPrimitives.verifyBlobstreamAttestation(attestation, vals)
        ) {
            revert InvalidBlobstreamAttestation();
        }

        // Verify data root matches
        if (attestation.dataRoot != commitment.dataRoot) {
            revert InvalidDataCommitment();
        }

        // Check not already stored
        if (dataCommitments[commitment.dataRoot].dataRoot != bytes32(0)) {
            revert DataCommitmentAlreadyExists();
        }

        // Store commitment
        dataCommitments[commitment.dataRoot] = commitment;

        // Maintain history
        if (dataCommitmentHistory.length >= DATA_COMMITMENT_HISTORY) {
            // Remove oldest
            bytes32 oldRoot = dataCommitmentHistory[0];
            delete dataCommitments[oldRoot];
            for (uint256 i = 0; i < dataCommitmentHistory.length - 1; i++) {
                dataCommitmentHistory[i] = dataCommitmentHistory[i + 1];
            }
            dataCommitmentHistory.pop();
        }
        dataCommitmentHistory.push(commitment.dataRoot);

        emit DataCommitmentStored(
            commitment.dataRoot,
            commitment.startBlock,
            commitment.endBlock,
            commitment.nonce
        );
        emit BlobstreamAttestationVerified(
            attestation.dataRoot,
            attestation.height,
            CelestiaPrimitives.calculateSigningPower(
                attestation.signerBitmap,
                vals
            )
        );
    }

    /**
     * @notice Verify blob inclusion proof
     * @param dataRoot Data root containing the blob
     * @param proof NMT proof for blob inclusion
     * @param namespace Namespace of the blob
     * @param data Blob data
     */
    function verifyBlobInclusion(
        bytes32 dataRoot,
        CelestiaPrimitives.NMTProof calldata proof,
        CelestiaPrimitives.Namespace calldata namespace,
        bytes calldata data
    ) external view returns (bool) {
        // Check data commitment exists
        if (dataCommitments[dataRoot].dataRoot == bytes32(0)) {
            return false;
        }

        // Verify NMT proof
        return
            CelestiaPrimitives.verifyNMTProof(proof, dataRoot, namespace, data);
    }

    // =========================================================================
    // HEADER FINALIZATION
    // =========================================================================

    /**
     * @notice Finalize a Celestia header
     * @param header Celestia block header
     * @param attestation Blobstream attestation for the header
     */
    function finalizeHeader(
        CelestiaPrimitives.CelestiaHeader calldata header,
        CelestiaPrimitives.BlobstreamAttestation calldata attestation
    ) external whenNotPaused nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();

        // Validate header
        if (!CelestiaPrimitives.isValidHeader(header)) {
            revert InvalidHeader();
        }

        // Check not already finalized
        if (finalizedHeaders[header.height].height != 0) {
            revert HeaderAlreadyFinalized();
        }

        // Verify attestation
        CelestiaPrimitives.Validator[] memory vals = getValidators();
        if (
            !CelestiaPrimitives.verifyBlobstreamAttestation(attestation, vals)
        ) {
            revert InvalidBlobstreamAttestation();
        }

        // Store header
        finalizedHeaders[header.height] = header;

        // Update latest height
        if (header.height > latestFinalizedHeight) {
            latestFinalizedHeight = header.height;
        }
    }

    // =========================================================================
    // DEPOSITS AND WITHDRAWALS
    // =========================================================================

    /**
     * @notice Initiate a deposit to Celestia
     * @param namespace Target namespace on Celestia
     */
    function deposit(
        CelestiaPrimitives.Namespace calldata namespace
    ) external payable whenNotPaused nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        if (msg.value == 0) revert InsufficientDeposit();
        if (msg.value > MAX_TRANSFER) revert ExceedsMaxTransfer();

        // Rate limiting
        _checkAndUpdateDailyLimit(msg.value);

        bytes32 depositId = keccak256(
            abi.encodePacked(
                msg.sender,
                msg.value,
                namespace.version,
                namespace.id,
                block.timestamp,
                block.number
            )
        );

        processedDeposits[depositId] = true;

        emit DepositInitiated(depositId, msg.sender, msg.value, namespace);
    }

    /**
     * @notice Complete a withdrawal from Celestia
     * @param withdrawalId Withdrawal identifier
     * @param recipient Recipient address
     * @param amount Withdrawal amount
     * @param proof NMT proof of withdrawal request on Celestia
     * @param dataRoot Data root containing the withdrawal
     * @param namespace Withdrawal namespace
     */
    function withdraw(
        bytes32 withdrawalId,
        address recipient,
        uint256 amount,
        CelestiaPrimitives.NMTProof calldata proof,
        bytes32 dataRoot,
        CelestiaPrimitives.Namespace calldata namespace
    ) external whenNotPaused nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        if (processedWithdrawals[withdrawalId])
            revert WithdrawalAlreadyProcessed();
        if (amount > MAX_TRANSFER) revert ExceedsMaxTransfer();

        // Rate limiting
        _checkAndUpdateDailyLimit(amount);

        // Verify data commitment exists
        if (dataCommitments[dataRoot].dataRoot == bytes32(0)) {
            revert InvalidDataCommitment();
        }

        // Encode expected withdrawal data
        bytes memory withdrawalData = abi.encodePacked(
            withdrawalId,
            recipient,
            amount
        );

        // Verify NMT proof
        if (
            !CelestiaPrimitives.verifyNMTProof(
                proof,
                dataRoot,
                namespace,
                withdrawalData
            )
        ) {
            revert InvalidWithdrawalProof();
        }

        // Mark as processed
        processedWithdrawals[withdrawalId] = true;

        // Calculate fee and transfer
        uint256 fee = (amount * relayerFeeBps) / 10000;
        uint256 netAmount = amount - fee;

        (bool success, ) = recipient.call{value: netAmount}("");
        require(success, "Transfer failed");

        emit WithdrawalCompleted(withdrawalId, recipient, netAmount);
    }

    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================

    /**
     * @notice Bind a Celestia nullifier to a PIL nullifier
     * @param celestiaCommitment Celestia blob commitment
     * @param pilNullifier PIL domain nullifier
     * @param domainSeparator Domain separator for binding
     * @param height Celestia block height
     */
    function bindNullifier(
        bytes32 celestiaCommitment,
        bytes32 pilNullifier,
        bytes32 domainSeparator,
        uint64 height
    ) external whenNotPaused {
        if (circuitBreakerActive) revert CircuitBreakerActive();

        // Check height is finalized
        if (finalizedHeaders[height].height == 0) {
            revert InvalidHeader();
        }

        // Create binding
        CelestiaPrimitives.CelestiaNullifierBinding
            memory binding = CelestiaPrimitives.bindNullifier(
                celestiaCommitment,
                pilNullifier,
                domainSeparator,
                height
            );

        // Verify binding
        if (!CelestiaPrimitives.verifyNullifierBinding(binding)) {
            revert InvalidNullifierBinding();
        }

        // Store binding
        nullifierBindings[celestiaCommitment] = binding;

        emit NullifierBound(celestiaCommitment, pilNullifier, height);
    }

    /**
     * @notice Consume a nullifier (mark as spent)
     * @param nullifier Nullifier to consume
     */
    function consumeNullifier(bytes32 nullifier) external whenNotPaused {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        if (consumedNullifiers[nullifier]) revert NullifierAlreadyConsumed();

        consumedNullifiers[nullifier] = true;

        emit NullifierConsumed(nullifier);
    }

    /**
     * @notice Check if a nullifier is consumed
     * @param nullifier Nullifier to check
     */
    function isNullifierConsumed(
        bytes32 nullifier
    ) external view returns (bool) {
        return consumedNullifiers[nullifier];
    }

    // =========================================================================
    // RATE LIMITING
    // =========================================================================

    function _checkAndUpdateDailyLimit(uint256 amount) internal {
        // Reset daily volume if new day
        if (block.timestamp >= lastVolumeReset + 1 days) {
            dailyVolume = 0;
            lastVolumeReset = block.timestamp;
        }

        if (dailyVolume + amount > DAILY_LIMIT) {
            revert ExceedsDailyLimit();
        }

        dailyVolume += amount;
    }

    // =========================================================================
    // SECURITY CONTROLS
    // =========================================================================

    /**
     * @notice Trigger circuit breaker
     * @param reason Reason for triggering
     */
    function triggerCircuitBreaker(string calldata reason) external {
        if (msg.sender != emergencyCouncil && msg.sender != owner()) {
            revert OnlyEmergencyCouncil();
        }

        circuitBreakerActive = true;
        emit CircuitBreakerTriggered(msg.sender, reason);
    }

    /**
     * @notice Reset circuit breaker
     */
    function resetCircuitBreaker() external onlyOwner {
        circuitBreakerActive = false;
        emit CircuitBreakerReset(msg.sender);
    }

    /**
     * @notice Update emergency council
     * @param newCouncil New emergency council address
     */
    function updateEmergencyCouncil(address newCouncil) external onlyOwner {
        address oldCouncil = emergencyCouncil;
        emergencyCouncil = newCouncil;
        emit EmergencyCouncilUpdated(oldCouncil, newCouncil);
    }

    /**
     * @notice Update relayer fee
     * @param newFeeBps New fee in basis points
     */
    function updateRelayerFee(uint256 newFeeBps) external onlyOwner {
        require(newFeeBps <= MAX_RELAYER_FEE_BPS, "Fee too high");
        relayerFeeBps = newFeeBps;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get validator count
     */
    function getValidatorCount() external view returns (uint256) {
        return validatorList.length;
    }

    /**
     * @notice Get data commitment history length
     */
    function getDataCommitmentCount() external view returns (uint256) {
        return dataCommitmentHistory.length;
    }

    /**
     * @notice Check if data commitment exists
     */
    function hasDataCommitment(bytes32 dataRoot) external view returns (bool) {
        return dataCommitments[dataRoot].dataRoot != bytes32(0);
    }

    /**
     * @notice Get finalized header
     */
    function getFinalizedHeader(
        uint64 height
    ) external view returns (CelestiaPrimitives.CelestiaHeader memory) {
        return finalizedHeaders[height];
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // =========================================================================
    // RECEIVE
    // =========================================================================

    receive() external payable {}
}
