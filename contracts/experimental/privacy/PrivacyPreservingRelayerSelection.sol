// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ExperimentalFeatureGated} from "../ExperimentalFeatureGated.sol";
import {ExperimentalFeatureRegistry} from "../../security/ExperimentalFeatureRegistry.sol";

/// @title PrivacyPreservingRelayerSelection
/// @notice Enables privacy-preserving selection of relayers for transaction submission
/// @dev Uses commitment schemes and VRF for unbiased, private relayer selection
/// @custom:experimental This contract is research-tier and NOT production-ready. See contracts/experimental/README.md for promotion criteria.
/// @custom:security-contact security@zaseonprotocol.io
/**
 * @title PrivacyPreservingRelayerSelection
 * @author ZASEON Team
 * @notice Privacy Preserving Relayer Selection contract
 */
contract PrivacyPreservingRelayerSelection is
    AccessControl,
    ReentrancyGuard,
    ExperimentalFeatureGated
{
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    /// @notice Domain separator
    bytes32 public constant DOMAIN = keccak256("Zaseon_PRIVATE_RELAYER_V1");

    /// @notice Minimum stake required for relayers
    uint256 public constant MIN_STAKE = 1 ether;

    /// @notice Maximum relayers in selection pool
    uint256 public constant MAX_POOL_SIZE = 100;

    /// @notice Commitment reveal window (blocks)
    uint256 public constant REVEAL_WINDOW = 10;

    /// @notice Selection validity period
    uint256 public constant SELECTION_VALIDITY = 100; // blocks

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Relayer information
    struct Relayer {
        address relayerAddress;
        bytes32 publicKeyHash; // Hash of encryption public key
        uint256 stake;
        uint256 reputation; // 0-10000 (basis points)
        uint256 successfulRelays;
        uint256 failedRelays;
        bool active;
        uint256 registrationBlock;
    }

    /// @notice Selection request
    struct SelectionRequest {
        bytes32 requestId;
        bytes32 commitmentHash; // H(sender, randomness, preferences)
        bytes32 vrfSeed; // Seed for VRF selection
        uint256 requestBlock;
        uint256 numRelayers; // How many relayers to select
        bool revealed;
        bool fulfilled;
        address[] selectedRelayers;
    }

    /// @notice Private preferences (revealed later)
    struct SelectionPreferences {
        uint256 minReputation; // Minimum reputation required
        uint256 maxLatency; // Maximum acceptable latency
        bytes32[] excludedRelayers; // Relayers to exclude (hashed)
        uint256 feeBudget; // Maximum fee willing to pay
    }

    /// @notice VRF proof for verifiable randomness
    struct VRFProof {
        bytes32 gamma;
        bytes32 c;
        bytes32 s;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Registered relayers
    mapping(address => Relayer) public relayers;

    /// @notice Active relayer list
    address[] public activeRelayers;

    /// @notice Index of relayer in activeRelayers array (1-indexed to distinguish from 0 = not in list)
    mapping(address => uint256) private relayerIndex;

    /// @notice Selection requests
    mapping(bytes32 => SelectionRequest) public selectionRequests;

    /// @notice Relayer commitments for each round
    mapping(bytes32 => mapping(address => bytes32)) public relayerCommitments;

    /// @notice VRF public key
    bytes32 public vrfPublicKey;

    /// @notice Total stake in system
    uint256 public totalStake;

    /// @notice Request count
    uint256 public requestCount;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event RelayerRegistered(
        address indexed relayer,
        uint256 stake,
        bytes32 publicKeyHash
    );

    event RelayerDeactivated(address indexed relayer, uint256 stake);

    event SelectionRequested(
        bytes32 indexed requestId,
        bytes32 commitmentHash,
        uint256 numRelayers
    );

    event SelectionRevealed(bytes32 indexed requestId, address requester);

    event RelayersSelected(
        bytes32 indexed requestId,
        address[] selectedRelayers
    );

    event RelayCompleted(
        address indexed relayer,
        bytes32 indexed requestId,
        bool success
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InsufficientStake();
    error RelayerNotActive();
    error InvalidCommitment();
    error RequestNotFound();
    error RevealWindowClosed();
    error AlreadyRevealed();
    error InvalidVRFProof();
    error NoActiveRelayers();
    error TooManyRelayers();
    error TransferFailed();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(bytes32 _vrfPublicKey, address _featureRegistry) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        vrfPublicKey = _vrfPublicKey;

        // Wire to ExperimentalFeatureRegistry
        _setFeatureRegistry(
            _featureRegistry,
            ExperimentalFeatureRegistry(_featureRegistry)
                .PRIVACY_PRESERVING_RELAYER_SELECTION()
        );
    }

    // =========================================================================
    // RELAYER MANAGEMENT
    // =========================================================================

    /// @notice Register as a relayer
    /// @param publicKeyHash Hash of encryption public key for private communication
        /**
     * @notice Registers relayer
     * @param publicKeyHash The publicKeyHash hash value
     */
function registerRelayer(bytes32 publicKeyHash) external payable {
        if (msg.value < MIN_STAKE) revert InsufficientStake();

        Relayer storage relayer = relayers[msg.sender];

        if (!relayer.active) {
            activeRelayers.push(msg.sender);
            // Store 1-indexed position (0 means not in list)
            relayerIndex[msg.sender] = activeRelayers.length;
        }

        relayer.relayerAddress = msg.sender;
        relayer.publicKeyHash = publicKeyHash;
        relayer.stake += msg.value;
        relayer.reputation = 5000; // Start at 50%
        relayer.active = true;
        relayer.registrationBlock = block.number;

        totalStake += msg.value;

        _grantRole(RELAYER_ROLE, msg.sender);

        emit RelayerRegistered(msg.sender, msg.value, publicKeyHash);
    }

    /// @notice Add stake to existing registration
        /**
     * @notice Adds stake
     */
function addStake() external payable onlyRole(RELAYER_ROLE) {
        Relayer storage relayer = relayers[msg.sender];
        relayer.stake += msg.value;
        totalStake += msg.value;
    }

    /// @notice Deactivate and withdraw stake
        /**
     * @notice Deactivate relayer
     */
function deactivateRelayer() external nonReentrant onlyRole(RELAYER_ROLE) {
        Relayer storage relayer = relayers[msg.sender];
        if (!relayer.active) revert RelayerNotActive();

        uint256 stake = relayer.stake;
        relayer.stake = 0;
        relayer.active = false;

        totalStake -= stake;

        // Remove from active list
        _removeFromActiveList(msg.sender);

        _revokeRole(RELAYER_ROLE, msg.sender);

        // Transfer stake back
        (bool success, ) = payable(msg.sender).call{value: stake}("");
        if (!success) revert TransferFailed();

        emit RelayerDeactivated(msg.sender, stake);
    }

    // =========================================================================
    // PRIVATE SELECTION
    // =========================================================================

    /// @notice Request private relayer selection (commit phase)
    /// @param commitmentHash H(sender, randomness, preferences)
    /// @param numRelayers Number of relayers to select
    /// @return requestId The selection request ID
        /**
     * @notice Requests selection
     * @param commitmentHash The commitmentHash hash value
     * @param numRelayers The num relayers
     * @return requestId The request id
     */
function requestSelection(
        bytes32 commitmentHash,
        uint256 numRelayers
    ) external returns (bytes32 requestId) {
        if (activeRelayers.length == 0) revert NoActiveRelayers();
        if (numRelayers > activeRelayers.length) revert TooManyRelayers();

        requestId = keccak256(
            abi.encodePacked(
                DOMAIN,
                msg.sender,
                commitmentHash,
                block.number,
                requestCount++
            )
        );

        selectionRequests[requestId] = SelectionRequest({
            requestId: requestId,
            commitmentHash: commitmentHash,
            vrfSeed: bytes32(0),
            requestBlock: block.number,
            numRelayers: numRelayers,
            revealed: false,
            fulfilled: false,
            selectedRelayers: new address[](0)
        });

        emit SelectionRequested(requestId, commitmentHash, numRelayers);
    }

    /// @notice Reveal selection preferences (reveal phase)
    /// @param requestId The request ID
    /// @param randomness The randomness used in commitment
    /// @param preferences The selection preferences
        /**
     * @notice Reveal selection
     * @param requestId The requestId identifier
     * @param randomness The randomness
     * @param preferences The preferences
     */
function revealSelection(
        bytes32 requestId,
        bytes32 randomness,
        SelectionPreferences calldata preferences
    ) external {
        SelectionRequest storage request = selectionRequests[requestId];
        if (request.requestId == bytes32(0)) revert RequestNotFound();
        if (request.revealed) revert AlreadyRevealed();
        if (block.number > request.requestBlock + REVEAL_WINDOW)
            revert RevealWindowClosed();

        // Verify commitment
        bytes32 expectedCommitment = keccak256(
            abi.encodePacked(
                msg.sender,
                randomness,
                preferences.minReputation,
                preferences.maxLatency,
                keccak256(abi.encodePacked(preferences.excludedRelayers)),
                preferences.feeBudget
            )
        );

        if (expectedCommitment != request.commitmentHash)
            revert InvalidCommitment();

        request.revealed = true;
        request.vrfSeed = keccak256(
            abi.encodePacked(randomness, blockhash(request.requestBlock))
        );

        emit SelectionRevealed(requestId, msg.sender);
    }

    /// @notice Complete selection using VRF (oracle fulfills)
    /// @param requestId The request ID
    /// @param vrfProof VRF proof for verifiable randomness
        /**
     * @notice Fulfill selection
     * @param requestId The requestId identifier
     * @param vrfProof The vrf proof
     */
function fulfillSelection(
        bytes32 requestId,
        VRFProof calldata vrfProof
    ) external onlyRole(ORACLE_ROLE) {
        SelectionRequest storage request = selectionRequests[requestId];
        if (request.requestId == bytes32(0)) revert RequestNotFound();
        if (!request.revealed) revert InvalidCommitment();
        if (request.fulfilled) return;

        // Verify VRF proof
        if (!_verifyVRF(request.vrfSeed, vrfProof)) revert InvalidVRFProof();

        // Select relayers using VRF output
        bytes32 vrfOutput = keccak256(abi.encodePacked(vrfProof.gamma));
        address[] memory selected = _selectRelayers(
            vrfOutput,
            request.numRelayers
        );

        request.selectedRelayers = selected;
        request.fulfilled = true;

        emit RelayersSelected(requestId, selected);
    }

    /// @notice Verify VRF proof
    /// @dev In production, use actual VRF verification (e.g., Chainlink VRF)
    /// @param seed The VRF seed
    /// @param proof The VRF proof containing gamma, c, s
    /// @return True if the VRF proof is valid
    function _verifyVRF(
        bytes32 seed,
        VRFProof calldata proof
    ) internal view returns (bool) {
        // Verify gamma is non-zero (basic sanity check)
        if (proof.gamma == bytes32(0)) {
            return false;
        }

        // Compute expected gamma from VRF public key and seed
        // Note: In production, implement full ECVRF verification or use Chainlink VRF
        bytes32 expectedGamma = keccak256(
            abi.encodePacked(vrfPublicKey, seed, proof.c, proof.s)
        );

        return proof.gamma == expectedGamma;
    }

    /// @notice Select relayers using VRF output
    function _selectRelayers(
        bytes32 vrfOutput,
        uint256 numToSelect
    ) internal view returns (address[] memory selected) {
        selected = new address[](numToSelect);
        uint256 poolSize = activeRelayers.length;

        // Weighted selection based on stake and reputation
        uint256[] memory weights = new uint256[](poolSize);
        uint256 totalWeight = 0;

        for (uint256 i = 0; i < poolSize; ) {
            Relayer storage r = relayers[activeRelayers[i]];
            // Weight = stake * reputation / 10000
            weights[i] = (r.stake * r.reputation) / 10000;
            totalWeight += weights[i];
            unchecked {
                ++i;
            }
        }

        // Select without replacement
        bool[] memory chosen = new bool[](poolSize);
        uint256 selectedCount = 0;

        while (selectedCount < numToSelect) {
            // Generate index from VRF output
            uint256 rand = uint256(
                keccak256(abi.encodePacked(vrfOutput, selectedCount))
            );
            uint256 target = rand % totalWeight;

            uint256 cumulative = 0;
            for (uint256 i = 0; i < poolSize; i++) {
                if (chosen[i]) continue;
                cumulative += weights[i];
                if (cumulative > target) {
                    selected[selectedCount++] = activeRelayers[i];
                    chosen[i] = true;
                    totalWeight -= weights[i];
                    break;
                }
            }
        }
    }

    /// @notice Remove relayer from active list (O(1) using index mapping)
    /// @param relayer The relayer address to remove
    function _removeFromActiveList(address relayer) internal {
        uint256 idx = relayerIndex[relayer];
        if (idx == 0) return; // Not in list

        uint256 arrayIndex = idx - 1; // Convert from 1-indexed to 0-indexed
        uint256 lastIndex = activeRelayers.length - 1;

        if (arrayIndex != lastIndex) {
            // Move last element to the removed position
            address lastRelayer = activeRelayers[lastIndex];
            activeRelayers[arrayIndex] = lastRelayer;
            relayerIndex[lastRelayer] = idx; // Update index for moved element
        }

        activeRelayers.pop();
        delete relayerIndex[relayer];
    }

    // =========================================================================
    // REPUTATION MANAGEMENT
    // =========================================================================

    /// @notice Report relay completion
    /// @param relayer The relayer address
    /// @param requestId The request ID
    /// @param success Whether relay was successful
        /**
     * @notice Reports relay completion
     * @param relayer The relayer address
     * @param requestId The requestId identifier
     * @param success The success
     */
function reportRelayCompletion(
        address relayer,
        bytes32 requestId,
        bool success
    ) external onlyRole(ORACLE_ROLE) {
        Relayer storage r = relayers[relayer];
        if (!r.active) revert RelayerNotActive();

        if (success) {
            r.successfulRelays++;
            // Increase reputation (max 10000)
            r.reputation = r.reputation + 100 > 10000
                ? 10000
                : r.reputation + 100;
        } else {
            r.failedRelays++;
            // Decrease reputation (min 0)
            r.reputation = r.reputation > 200 ? r.reputation - 200 : 0;
        }

        emit RelayCompleted(relayer, requestId, success);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get selected relayers for a request
        /**
     * @notice Returns the selected relayers
     * @param requestId The requestId identifier
     * @return The result value
     */
function getSelectedRelayers(
        bytes32 requestId
    ) external view returns (address[] memory) {
        return selectionRequests[requestId].selectedRelayers;
    }

    /// @notice Get relayer info
        /**
     * @notice Returns the relayer info
     * @param relayer The relayer address
     * @return The result value
     */
function getRelayerInfo(
        address relayer
    ) external view returns (Relayer memory) {
        return relayers[relayer];
    }

    /// @notice Get active relayer count
        /**
     * @notice Returns the active relayer count
     * @return The result value
     */
function getActiveRelayerCount() external view returns (uint256) {
        return activeRelayers.length;
    }

    /// @notice Get all active relayers
        /**
     * @notice Returns the active relayers
     * @return The result value
     */
function getActiveRelayers() external view returns (address[] memory) {
        return activeRelayers;
    }

    /// @notice Check if selection is valid
        /**
     * @notice Checks if selection valid
     * @param requestId The requestId identifier
     * @return The result value
     */
function isSelectionValid(bytes32 requestId) external view returns (bool) {
        SelectionRequest storage request = selectionRequests[requestId];
        return
            request.fulfilled &&
            block.number <= request.requestBlock + SELECTION_VALIDITY;
    }

    /// @notice Get system statistics
        /**
     * @notice Returns the stats
     * @return relayerCount The relayer count
     * @return totalStakeAmount The total stake amount
     * @return requests The requests
     */
function getStats()
        external
        view
        returns (
            uint256 relayerCount,
            uint256 totalStakeAmount,
            uint256 requests
        )
    {
        relayerCount = activeRelayers.length;
        totalStakeAmount = totalStake;
        requests = requestCount;
    }
}
