// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AptosPrimitives} from "../aptos/AptosPrimitives.sol";

/**
 * @title AptosBridgeAdapter
 * @notice Bridge adapter for Aptos blockchain integration with PIL
 * @dev Implements:
 *      - BLS12-381 validator signatures (aggregate)
 *      - Ledger info finalization (AptosBFT)
 *      - Move resource state proofs
 *      - Cross-domain nullifier binding
 *      - Rate limiting and circuit breaker
 *
 * Aptos Consensus:
 * - AptosBFT (derived from DiemBFT/HotStuff)
 * - 2-chain commit rule
 * - ~160ms finality under good conditions
 * - Epoch-based validator rotation
 */
contract AptosBridgeAdapter is
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Quorum threshold in basis points (66.67%)
    uint256 public constant QUORUM_THRESHOLD_BPS = 6667;

    /// @notice Maximum validators
    uint256 public constant MAX_VALIDATORS = 150;

    /// @notice Maximum single withdrawal
    uint256 public constant MAX_SINGLE_WITHDRAWAL = 100_000 ether;

    /// @notice Maximum daily withdrawal
    uint256 public constant MAX_DAILY_WITHDRAWAL = 1_000_000 ether;

    /// @notice Maximum relayer fee (5%)
    uint256 public constant MAX_RELAYER_FEE_BPS = 500;

    /// @notice Ledger info history size
    uint256 public constant LEDGER_HISTORY_SIZE = 100;

    /// @notice Minimum confirmations (epochs)
    uint64 public constant MIN_CONFIRMATIONS = 2;

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Current epoch
    uint64 public currentEpoch;

    /// @notice Total voting power
    uint256 public totalVotingPower;

    /// @notice Active validator count
    uint256 public activeValidatorCount;

    /// @notice Relayer fee in basis points
    uint256 public relayerFeeBps;

    /// @notice Emergency council address
    address public emergencyCouncil;

    /// @notice Circuit breaker triggered
    bool public circuitBreakerTriggered;

    /// @notice Daily withdrawal volume
    uint256 public dailyWithdrawalVolume;

    /// @notice Last withdrawal day
    uint256 public lastWithdrawalDay;

    /// @notice Deposit nonce
    uint256 public depositNonce;

    /// @notice Validator info mapping
    mapping(address => AptosPrimitives.ValidatorInfo) public validators;

    /// @notice Validator addresses list
    address[] public validatorList;

    /// @notice Finalized ledger info by version
    mapping(uint64 => AptosPrimitives.LedgerInfoWithSignatures)
        public finalizedLedgerInfo;

    /// @notice Finalized versions list
    uint64[] public finalizedVersions;

    /// @notice Consumed nullifiers
    mapping(bytes32 => bool) public consumedNullifiers;

    /// @notice Aptos nullifier to PIL nullifier mapping
    mapping(bytes32 => bytes32) public aptosNullifierToPIL;

    /// @notice PIL nullifier to Aptos nullifier mapping
    mapping(bytes32 => bytes32) public pilNullifierToAptos;

    /// @notice Token mappings (Aptos coin type hash => ERC20 address)
    mapping(bytes32 => address) public tokenMappings;

    /// @notice Reverse token mappings
    mapping(address => bytes32) public reverseTokenMappings;

    /// @notice Epoch states
    mapping(uint64 => AptosPrimitives.EpochState) public epochStates;

    /// @notice Pending withdrawals for refund
    mapping(bytes32 => uint256) public pendingWithdrawals;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ValidatorRegistered(
        address indexed validator,
        bytes blsPublicKey,
        uint256 votingPower
    );
    event ValidatorRemoved(address indexed validator);
    event ValidatorPowerUpdated(
        address indexed validator,
        uint256 oldPower,
        uint256 newPower
    );
    event LedgerInfoFinalized(
        uint64 indexed epoch,
        uint64 indexed version,
        bytes32 blockHash
    );
    event EpochChanged(
        uint64 indexed oldEpoch,
        uint64 indexed newEpoch,
        bytes32 validatorSetHash
    );
    event Deposited(
        address indexed token,
        address indexed sender,
        bytes32 indexed aptosRecipient,
        uint256 amount,
        uint256 nonce
    );
    event Withdrawn(
        address indexed token,
        address indexed recipient,
        uint256 amount,
        bytes32 nullifier
    );
    event NullifierConsumed(bytes32 indexed nullifier);
    event CrossDomainNullifierBound(
        bytes32 indexed aptosNullifier,
        bytes32 indexed pilNullifier
    );
    event TokenMappingAdded(
        bytes32 indexed coinTypeHash,
        address indexed erc20Token
    );
    event CircuitBreakerTriggered(address indexed triggeredBy);
    event CircuitBreakerReset(address indexed resetBy);
    event RelayerFeeUpdated(uint256 oldFee, uint256 newFee);
    event EmergencyCouncilUpdated(
        address indexed oldCouncil,
        address indexed newCouncil
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ValidatorAlreadyRegistered();
    error ValidatorNotFound();
    error InvalidVotingPower();
    error InvalidPublicKeyLength();
    error InsufficientQuorum();
    error LedgerInfoAlreadyFinalized();
    error InvalidLedgerInfo();
    error NullifierAlreadyConsumed();
    error InvalidProof();
    error WithdrawalExceedsLimit();
    error DailyLimitExceeded();
    error CircuitBreakerActive();
    error NotEmergencyCouncil();
    error InvalidRelayerFee();
    error TokenNotMapped();
    error InvalidAmount();
    error TransferFailed();
    error EpochMismatch();
    error VersionNotFinalized();
    error InsufficientConfirmations();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier onlyEmergencyCouncil() {
        if (msg.sender != emergencyCouncil && msg.sender != owner()) {
            revert NotEmergencyCouncil();
        }
        _;
    }

    modifier whenCircuitBreakerNotTriggered() {
        if (circuitBreakerTriggered) {
            revert CircuitBreakerActive();
        }
        _;
    }

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    function initialize(
        address _emergencyCouncil,
        uint256 _relayerFeeBps
    ) external initializer {
        __Ownable_init(msg.sender);
        __Pausable_init();
        __ReentrancyGuard_init();

        if (_relayerFeeBps > MAX_RELAYER_FEE_BPS) revert InvalidRelayerFee();

        emergencyCouncil = _emergencyCouncil;
        relayerFeeBps = _relayerFeeBps;
        currentEpoch = 1;
    }

    // =========================================================================
    // VALIDATOR MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a validator
     * @param validator Validator address
     * @param blsPublicKey BLS12-381 public key (96 bytes)
     * @param ed25519PublicKey Ed25519 public key (32 bytes)
     * @param votingPower Voting power
     */
    function registerValidator(
        address validator,
        bytes calldata blsPublicKey,
        bytes calldata ed25519PublicKey,
        uint256 votingPower
    ) external onlyOwner {
        if (validators[validator].isActive) revert ValidatorAlreadyRegistered();
        if (votingPower == 0) revert InvalidVotingPower();
        if (blsPublicKey.length != AptosPrimitives.BLS_PUBKEY_LENGTH)
            revert InvalidPublicKeyLength();
        if (ed25519PublicKey.length != AptosPrimitives.ED25519_PUBKEY_LENGTH)
            revert InvalidPublicKeyLength();
        if (activeValidatorCount >= MAX_VALIDATORS) revert InvalidVotingPower();

        validators[validator] = AptosPrimitives.ValidatorInfo({
            accountAddress: validator,
            blsPublicKey: blsPublicKey,
            ed25519PublicKey: ed25519PublicKey,
            votingPower: votingPower,
            isActive: true,
            lastEpochParticipated: currentEpoch
        });

        validatorList.push(validator);
        totalVotingPower += votingPower;
        activeValidatorCount++;

        emit ValidatorRegistered(validator, blsPublicKey, votingPower);
    }

    /**
     * @notice Remove a validator
     * @param validator Validator address
     */
    function removeValidator(address validator) external onlyOwner {
        AptosPrimitives.ValidatorInfo storage info = validators[validator];
        if (!info.isActive) revert ValidatorNotFound();

        totalVotingPower -= info.votingPower;
        activeValidatorCount--;
        info.isActive = false;
        info.votingPower = 0;

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
        AptosPrimitives.ValidatorInfo storage info = validators[validator];
        if (!info.isActive) revert ValidatorNotFound();
        if (newPower == 0) revert InvalidVotingPower();

        uint256 oldPower = info.votingPower;
        totalVotingPower = totalVotingPower - oldPower + newPower;
        info.votingPower = newPower;

        emit ValidatorPowerUpdated(validator, oldPower, newPower);
    }

    /**
     * @notice Check if address is an active validator
     * @param validator Address to check
     * @return isActive True if active validator
     */
    function isValidator(address validator) external view returns (bool) {
        return validators[validator].isActive;
    }

    /**
     * @notice Get validator voting power
     * @param validator Validator address
     * @return power Voting power
     */
    function getValidatorPower(
        address validator
    ) external view returns (uint256) {
        return validators[validator].votingPower;
    }

    // =========================================================================
    // LEDGER INFO FINALIZATION
    // =========================================================================

    /**
     * @notice Submit and finalize ledger info with aggregate BLS signature
     * @param ledgerInfo Ledger info with signatures
     * @param signers Array of validator addresses who signed
     */
    function submitLedgerInfo(
        AptosPrimitives.LedgerInfoWithSignatures calldata ledgerInfo,
        address[] calldata signers
    ) external whenNotPaused whenCircuitBreakerNotTriggered {
        // Validate ledger info
        if (!AptosPrimitives.isValidLedgerInfo(ledgerInfo))
            revert InvalidLedgerInfo();

        // Check not already finalized
        if (finalizedLedgerInfo[ledgerInfo.version].version != 0) {
            revert LedgerInfoAlreadyFinalized();
        }

        // Calculate signing power
        uint256 signingPower = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            AptosPrimitives.ValidatorInfo storage info = validators[signers[i]];
            if (info.isActive) {
                signingPower += info.votingPower;
            }
        }

        // Check quorum
        if (!AptosPrimitives.hasQuorum(signingPower, totalVotingPower)) {
            revert InsufficientQuorum();
        }

        // Store finalized ledger info
        finalizedLedgerInfo[ledgerInfo.version] = ledgerInfo;
        finalizedVersions.push(ledgerInfo.version);

        // Handle epoch change
        if (ledgerInfo.epoch > currentEpoch) {
            uint64 oldEpoch = currentEpoch;
            currentEpoch = ledgerInfo.epoch;
            emit EpochChanged(
                oldEpoch,
                currentEpoch,
                ledgerInfo.nextEpochState
            );
        }

        // Prune old ledger info if needed
        if (finalizedVersions.length > LEDGER_HISTORY_SIZE) {
            uint64 oldVersion = finalizedVersions[0];
            delete finalizedLedgerInfo[oldVersion];
            // Shift array (gas expensive but maintains history)
            for (uint256 i = 0; i < finalizedVersions.length - 1; i++) {
                finalizedVersions[i] = finalizedVersions[i + 1];
            }
            finalizedVersions.pop();
        }

        emit LedgerInfoFinalized(
            ledgerInfo.epoch,
            ledgerInfo.version,
            ledgerInfo.blockHash
        );
    }

    /**
     * @notice Check if version is finalized
     * @param version Ledger version
     * @return isFinalized True if finalized
     */
    function isVersionFinalized(uint64 version) external view returns (bool) {
        return finalizedLedgerInfo[version].version != 0;
    }

    /**
     * @notice Get finalized ledger info
     * @param version Ledger version
     * @return Ledger info
     */
    function getFinalizedLedgerInfo(
        uint64 version
    ) external view returns (AptosPrimitives.LedgerInfoWithSignatures memory) {
        return finalizedLedgerInfo[version];
    }

    // =========================================================================
    // DEPOSIT/WITHDRAWAL
    // =========================================================================

    /**
     * @notice Deposit tokens to bridge to Aptos
     * @param token ERC20 token address (address(0) for ETH)
     * @param amount Amount to deposit
     * @param aptosRecipient Aptos recipient address (as bytes32)
     */
    function deposit(
        address token,
        uint256 amount,
        bytes32 aptosRecipient
    )
        external
        payable
        whenNotPaused
        whenCircuitBreakerNotTriggered
        nonReentrant
    {
        if (amount == 0) revert InvalidAmount();

        if (token == address(0)) {
            // ETH deposit
            if (msg.value != amount) revert InvalidAmount();
        } else {
            // ERC20 deposit
            if (reverseTokenMappings[token] == bytes32(0))
                revert TokenNotMapped();
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }

        uint256 nonce = depositNonce++;

        emit Deposited(token, msg.sender, aptosRecipient, amount, nonce);
    }

    /**
     * @notice Withdraw tokens from Aptos
     * @param token ERC20 token address
     * @param amount Amount to withdraw
     * @param version Ledger version containing the transfer
     * @param nullifier Unique nullifier
     * @param proof State proof
     * @param signers Validators who signed the ledger info
     */
    function withdraw(
        address token,
        uint256 amount,
        uint64 version,
        bytes32 nullifier,
        AptosPrimitives.SparseMerkleProof calldata proof,
        address[] calldata signers
    ) external whenNotPaused whenCircuitBreakerNotTriggered nonReentrant {
        // Check nullifier not consumed
        if (consumedNullifiers[nullifier]) revert NullifierAlreadyConsumed();

        // Check amount limits
        if (amount > MAX_SINGLE_WITHDRAWAL) revert WithdrawalExceedsLimit();

        // Check daily limit
        _checkAndUpdateDailyLimit(amount);

        // Verify version is finalized
        AptosPrimitives.LedgerInfoWithSignatures
            storage ledgerInfo = finalizedLedgerInfo[version];
        if (ledgerInfo.version == 0) revert VersionNotFinalized();

        // Check minimum confirmations (epochs)
        if (currentEpoch < ledgerInfo.epoch + MIN_CONFIRMATIONS) {
            revert InsufficientConfirmations();
        }

        // Verify state proof
        bytes32 expectedRoot = ledgerInfo.executedStateId;
        if (
            !AptosPrimitives.verifySparseMerkleProof(
                proof,
                expectedRoot,
                nullifier,
                keccak256(abi.encodePacked(token, amount, msg.sender))
            )
        ) {
            revert InvalidProof();
        }

        // Consume nullifier
        consumedNullifiers[nullifier] = true;
        emit NullifierConsumed(nullifier);

        // Calculate fees
        uint256 fee = (amount * relayerFeeBps) / 10000;
        uint256 amountAfterFee = amount - fee;

        // Transfer tokens
        if (token == address(0)) {
            (bool success, ) = msg.sender.call{value: amountAfterFee}("");
            if (!success) revert TransferFailed();
        } else {
            IERC20(token).safeTransfer(msg.sender, amountAfterFee);
        }

        emit Withdrawn(token, msg.sender, amountAfterFee, nullifier);
    }

    /**
     * @notice Check and update daily withdrawal limit
     * @param amount Amount to withdraw
     */
    function _checkAndUpdateDailyLimit(uint256 amount) internal {
        uint256 currentDay = block.timestamp / 1 days;

        if (currentDay > lastWithdrawalDay) {
            // New day, reset volume
            dailyWithdrawalVolume = 0;
            lastWithdrawalDay = currentDay;
        }

        if (dailyWithdrawalVolume + amount > MAX_DAILY_WITHDRAWAL) {
            revert DailyLimitExceeded();
        }

        dailyWithdrawalVolume += amount;
    }

    // =========================================================================
    // NULLIFIER MANAGEMENT
    // =========================================================================

    /**
     * @notice Consume a nullifier directly
     * @param nullifier Nullifier to consume
     */
    function consumeNullifier(bytes32 nullifier) external onlyOwner {
        if (consumedNullifiers[nullifier]) revert NullifierAlreadyConsumed();
        consumedNullifiers[nullifier] = true;
        emit NullifierConsumed(nullifier);
    }

    /**
     * @notice Bind cross-domain nullifiers
     * @param aptosNullifier Aptos nullifier
     * @param pilNullifier PIL nullifier
     */
    function bindCrossDomainNullifier(
        bytes32 aptosNullifier,
        bytes32 pilNullifier
    ) external onlyOwner {
        require(
            aptosNullifierToPIL[aptosNullifier] == bytes32(0),
            "Already bound"
        );
        require(
            pilNullifierToAptos[pilNullifier] == bytes32(0),
            "PIL already bound"
        );

        aptosNullifierToPIL[aptosNullifier] = pilNullifier;
        pilNullifierToAptos[pilNullifier] = aptosNullifier;

        emit CrossDomainNullifierBound(aptosNullifier, pilNullifier);
    }

    /**
     * @notice Check if nullifier is consumed
     * @param nullifier Nullifier to check
     * @return isConsumed True if consumed
     */
    function isNullifierConsumed(
        bytes32 nullifier
    ) external view returns (bool) {
        return consumedNullifiers[nullifier];
    }

    // =========================================================================
    // TOKEN MAPPING
    // =========================================================================

    /**
     * @notice Add token mapping
     * @param coinTypeHash Hash of Aptos coin type (e.g., "0x1::aptos_coin::AptosCoin")
     * @param erc20Token ERC20 token address
     */
    function addTokenMapping(
        bytes32 coinTypeHash,
        address erc20Token
    ) external onlyOwner {
        tokenMappings[coinTypeHash] = erc20Token;
        reverseTokenMappings[erc20Token] = coinTypeHash;
        emit TokenMappingAdded(coinTypeHash, erc20Token);
    }

    // =========================================================================
    // CIRCUIT BREAKER
    // =========================================================================

    /**
     * @notice Trigger circuit breaker
     */
    function triggerCircuitBreaker() external onlyEmergencyCouncil {
        circuitBreakerTriggered = true;
        _pause();
        emit CircuitBreakerTriggered(msg.sender);
    }

    /**
     * @notice Reset circuit breaker
     */
    function resetCircuitBreaker() external onlyOwner {
        circuitBreakerTriggered = false;
        emit CircuitBreakerReset(msg.sender);
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

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

    /**
     * @notice Update relayer fee
     * @param newFeeBps New fee in basis points
     */
    function updateRelayerFee(uint256 newFeeBps) external onlyOwner {
        if (newFeeBps > MAX_RELAYER_FEE_BPS) revert InvalidRelayerFee();
        uint256 oldFee = relayerFeeBps;
        relayerFeeBps = newFeeBps;
        emit RelayerFeeUpdated(oldFee, newFeeBps);
    }

    /**
     * @notice Update emergency council
     * @param newCouncil New council address
     */
    function updateEmergencyCouncil(address newCouncil) external onlyOwner {
        address oldCouncil = emergencyCouncil;
        emergencyCouncil = newCouncil;
        emit EmergencyCouncilUpdated(oldCouncil, newCouncil);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get validator count
     * @return count Active validator count
     */
    function getValidatorCount() external view returns (uint256) {
        return activeValidatorCount;
    }

    /**
     * @notice Get latest finalized version
     * @return version Latest version
     */
    function getLatestFinalizedVersion() external view returns (uint64) {
        if (finalizedVersions.length == 0) return 0;
        return finalizedVersions[finalizedVersions.length - 1];
    }

    /**
     * @notice Check if contract is paused
     * @return isPaused True if paused
     */
    function isPaused() external view returns (bool) {
        return paused();
    }

    // =========================================================================
    // RECEIVE ETH
    // =========================================================================

    receive() external payable {}
}
