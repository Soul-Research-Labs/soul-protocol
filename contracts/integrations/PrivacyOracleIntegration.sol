// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title PrivacyOracleIntegration
 * @author Soul Protocol
 * @notice Privacy-preserving oracle for encrypted data feeds implementing IPrivacyOracle
 * @dev Provides encrypted price data and ZK proof verification for private DeFi
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                      PrivacyOracleIntegration                                │
 * │                                                                              │
 * │   ┌─────────────────────────────────────────────────────────────────────┐   │
 * │   │  Data Sources                                                        │   │
 * │   │  ├─ Chainlink Price Feeds (encrypted)                               │   │
 * │   │  ├─ Pyth Network (encrypted)                                        │   │
 * │   │  ├─ Chronicle Labs (encrypted)                                      │   │
 * │   │  └─ Private Oracles (TEE-based)                                     │   │
 * │   └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │   ┌─────────────────────────────────────────────────────────────────────┐   │
 * │   │  Privacy Layer                                                       │   │
 * │   │  ├─ ECIES encryption for recipient-specific data                    │   │
 * │   │  ├─ Pedersen commitments for price hiding                           │   │
 * │   │  └─ ZK range proofs for price validation                            │   │
 * │   └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │   ┌─────────────────────────────────────────────────────────────────────┐   │
 * │   │  Verification Layer                                                  │   │
 * │   │  ├─ Price proof verification                                        │   │
 * │   │  ├─ Threshold signature validation                                  │   │
 * │   │  └─ Freshness checks                                                │   │
 * │   └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * USE CASES:
 * - Private DEX: Verify swap prices without revealing trade details
 * - Private Lending: Verify collateral ratios privately
 * - Private Options: Verify strike prices without revealing positions
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract PrivacyOracleIntegration is ReentrancyGuard, AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error InvalidPairId();
    error InvalidPublicKey();
    error PairNotSupported();
    error StalePrice();
    error InvalidProof();
    error InvalidCommitment();
    error OracleNotActive();
    error InsufficientSignatures();
    error InvalidSignature();
    error PriceOutOfRange();
    error UpdateTooFrequent();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event EncryptedPriceRequested(
        bytes32 indexed pairId,
        bytes32 indexed recipientPubKey,
        address indexed requester,
        uint256 timestamp
    );

    event PriceUpdated(
        bytes32 indexed pairId,
        bytes32 indexed commitment,
        uint256 timestamp
    );

    event PriceProofVerified(
        bytes32 indexed pairId,
        bytes32 indexed commitment,
        bool valid
    );

    event PairAdded(bytes32 indexed pairId, string symbol, uint8 decimals);

    event OracleNodeRegistered(address indexed node, bytes32 pubKey);

    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);

    /*//////////////////////////////////////////////////////////////
                                 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /// @notice Domain separator
    bytes32 public constant PRIVACY_ORACLE_DOMAIN =
        keccak256("Soul_PRIVACY_ORACLE_V1");

    /// @notice Maximum price staleness (1 hour)
    uint256 public constant MAX_PRICE_STALENESS = 1 hours;

    /// @notice Minimum update interval (10 seconds)
    uint256 public constant MIN_UPDATE_INTERVAL = 10 seconds;

    /// @notice Maximum oracle nodes
    uint256 public constant MAX_ORACLE_NODES = 100;

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Trading pair configuration
     */
    struct PairConfig {
        bytes32 pairId;
        string symbol; // e.g., "ETH/USD"
        uint8 decimals;
        bool isActive;
        uint256 heartbeat; // Update frequency
        uint256 deviationThreshold; // Price deviation threshold (bps)
        address baseToken;
        address quoteToken;
    }

    /**
     * @notice Encrypted price data
     */
    struct EncryptedPrice {
        bytes ciphertext; // Encrypted price data
        bytes32 ephemeralPubKey; // Sender's ephemeral public key
        bytes32 commitment; // Pedersen commitment to price
        uint256 timestamp;
        uint256 roundId;
    }

    /**
     * @notice Price update with signatures
     */
    struct SignedPriceUpdate {
        bytes32 pairId;
        bytes32 commitment; // Pedersen commitment
        uint256 timestamp;
        bytes32[] signerPubKeys;
        bytes[] signatures;
    }

    /**
     * @notice Oracle node registration
     */
    struct OracleNode {
        address nodeAddress;
        bytes32 publicKey; // For encryption
        bool isActive;
        uint256 reputation;
        uint256 lastUpdate;
    }

    /**
     * @notice Price commitment record
     */
    struct PriceCommitment {
        bytes32 commitment;
        uint256 timestamp;
        uint256 roundId;
        uint256 signatureCount;
    }

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Pair configurations
    mapping(bytes32 => PairConfig) public pairs;

    /// @notice All pair IDs
    bytes32[] public allPairs;

    /// @notice Latest price commitments per pair
    mapping(bytes32 => PriceCommitment) public latestPriceCommitments;

    /// @notice Historical price commitments
    mapping(bytes32 => mapping(uint256 => PriceCommitment)) public priceHistory;

    /// @notice Encrypted prices per pair per recipient
    mapping(bytes32 => mapping(bytes32 => EncryptedPrice))
        public encryptedPrices;

    /// @notice Oracle nodes
    mapping(address => OracleNode) public oracleNodes;

    /// @notice Oracle node addresses
    address[] public oracleNodeList;

    /// @notice Required signatures threshold
    uint256 public signatureThreshold;

    /// @notice Price proof verifier contract
    address public priceProofVerifier;

    /// @notice Range proof verifier contract
    address public rangeProofVerifier;

    /// @notice Round counter per pair
    mapping(bytes32 => uint256) public roundCounter;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _priceProofVerifier,
        address _rangeProofVerifier,
        uint256 _signatureThreshold
    ) {
        if (_priceProofVerifier == address(0)) revert ZeroAddress();
        if (_rangeProofVerifier == address(0)) revert ZeroAddress();

        priceProofVerifier = _priceProofVerifier;
        rangeProofVerifier = _rangeProofVerifier;
        signatureThreshold = _signatureThreshold;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         PAIR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a new trading pair
     * @param pairId Unique pair identifier
     * @param symbol Human-readable symbol
     * @param decimals Price decimals
     * @param heartbeat Update frequency
     * @param deviationThreshold Price deviation threshold in bps
     * @param baseToken Base token address
     * @param quoteToken Quote token address
     */
    function addPair(
        bytes32 pairId,
        string calldata symbol,
        uint8 decimals,
        uint256 heartbeat,
        uint256 deviationThreshold,
        address baseToken,
        address quoteToken
    ) external onlyRole(OPERATOR_ROLE) {
        if (pairId == bytes32(0)) revert InvalidPairId();
        if (pairs[pairId].isActive) revert InvalidPairId();

        pairs[pairId] = PairConfig({
            pairId: pairId,
            symbol: symbol,
            decimals: decimals,
            isActive: true,
            heartbeat: heartbeat,
            deviationThreshold: deviationThreshold,
            baseToken: baseToken,
            quoteToken: quoteToken
        });

        allPairs.push(pairId);

        emit PairAdded(pairId, symbol, decimals);
    }

    /**
     * @notice Register oracle node
     */
    function registerOracleNode(
        address nodeAddress,
        bytes32 publicKey
    ) external onlyRole(OPERATOR_ROLE) {
        if (nodeAddress == address(0)) revert ZeroAddress();
        if (publicKey == bytes32(0)) revert InvalidPublicKey();
        if (oracleNodeList.length >= MAX_ORACLE_NODES) revert OracleNotActive();

        oracleNodes[nodeAddress] = OracleNode({
            nodeAddress: nodeAddress,
            publicKey: publicKey,
            isActive: true,
            reputation: 100,
            lastUpdate: 0
        });

        oracleNodeList.push(nodeAddress);
        _grantRole(ORACLE_ROLE, nodeAddress);

        emit OracleNodeRegistered(nodeAddress, publicKey);
    }

    /*//////////////////////////////////////////////////////////////
                        GET ENCRYPTED PRICE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get encrypted price data for a recipient
     * @param pairId The trading pair identifier
     * @param recipientPubKey Recipient's public key for ECIES encryption
     * @return encryptedPrice Encrypted price data
     */
    function getEncryptedPrice(
        bytes32 pairId,
        bytes32 recipientPubKey
    ) external view returns (bytes memory encryptedPrice) {
        if (!pairs[pairId].isActive) revert PairNotSupported();
        if (recipientPubKey == bytes32(0)) revert InvalidPublicKey();

        EncryptedPrice storage price = encryptedPrices[pairId][recipientPubKey];

        // Check staleness
        if (block.timestamp - price.timestamp > MAX_PRICE_STALENESS) {
            revert StalePrice();
        }

        return price.ciphertext;
    }

    /**
     * @notice Request encrypted price (triggers oracle update)
     * @param pairId Trading pair
     * @param recipientPubKey Recipient's public key
     */
    function requestEncryptedPrice(
        bytes32 pairId,
        bytes32 recipientPubKey
    ) external nonReentrant whenNotPaused {
        if (!pairs[pairId].isActive) revert PairNotSupported();
        if (recipientPubKey == bytes32(0)) revert InvalidPublicKey();

        emit EncryptedPriceRequested(
            pairId,
            recipientPubKey,
            msg.sender,
            block.timestamp
        );

        // Off-chain oracles will pick up this event and submit encrypted price
    }

    /*//////////////////////////////////////////////////////////////
                       PRICE PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a price proof without revealing the price
     * @param pairId The trading pair
     * @param commitment Pedersen commitment to the price
     * @param proof ZK proof of price validity
     * @return valid True if proof is valid
     */
    function verifyPriceProof(
        bytes32 pairId,
        bytes32 commitment,
        bytes calldata proof
    ) external view returns (bool valid) {
        if (!pairs[pairId].isActive) revert PairNotSupported();
        if (commitment == bytes32(0)) revert InvalidCommitment();

        // Get latest price commitment
        PriceCommitment storage latestCommitment = latestPriceCommitments[
            pairId
        ];

        // Check freshness
        if (
            block.timestamp - latestCommitment.timestamp > MAX_PRICE_STALENESS
        ) {
            revert StalePrice();
        }

        // Verify proof against committed price
        bool isValid = _verifyPriceProof(
            pairId,
            commitment,
            latestCommitment.commitment,
            proof
        );

        return isValid;
    }

    /**
     * @notice Verify price is within a range without revealing exact price
     * @param pairId Trading pair
     * @param commitment Price commitment
     * @param minPrice Minimum price (committed)
     * @param maxPrice Maximum price (committed)
     * @param proof Range proof
     */
    function verifyPriceInRange(
        bytes32 pairId,
        bytes32 commitment,
        bytes32 minPrice,
        bytes32 maxPrice,
        bytes calldata proof
    ) external view returns (bool valid) {
        if (!pairs[pairId].isActive) revert PairNotSupported();

        return _verifyRangeProof(commitment, minPrice, maxPrice, proof);
    }

    /*//////////////////////////////////////////////////////////////
                        ORACLE PRICE UPDATES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit price update with threshold signatures
     * @param update Signed price update
     */
    function submitPriceUpdate(
        SignedPriceUpdate calldata update
    ) external onlyRole(ORACLE_ROLE) nonReentrant whenNotPaused {
        if (!pairs[update.pairId].isActive) revert PairNotSupported();
        if (update.commitment == bytes32(0)) revert InvalidCommitment();

        PriceCommitment storage latest = latestPriceCommitments[update.pairId];

        // Check update frequency
        if (block.timestamp - latest.timestamp < MIN_UPDATE_INTERVAL) {
            revert UpdateTooFrequent();
        }

        // Verify threshold signatures
        if (update.signatures.length < signatureThreshold) {
            revert InsufficientSignatures();
        }

        uint256 validSignatures = 0;
        for (uint256 i = 0; i < update.signatures.length; i++) {
            if (
                _verifyOracleSignature(
                    update.pairId,
                    update.commitment,
                    update.timestamp,
                    update.signerPubKeys[i],
                    update.signatures[i]
                )
            ) {
                validSignatures++;
            }
        }

        if (validSignatures < signatureThreshold) {
            revert InsufficientSignatures();
        }

        // Update round counter
        roundCounter[update.pairId]++;
        uint256 newRoundId = roundCounter[update.pairId];

        // Store price commitment
        PriceCommitment memory newCommitment = PriceCommitment({
            commitment: update.commitment,
            timestamp: update.timestamp,
            roundId: newRoundId,
            signatureCount: validSignatures
        });

        latestPriceCommitments[update.pairId] = newCommitment;
        priceHistory[update.pairId][newRoundId] = newCommitment;

        emit PriceUpdated(update.pairId, update.commitment, update.timestamp);
    }

    /**
     * @notice Submit encrypted price for specific recipient
     * @param pairId Trading pair
     * @param recipientPubKey Recipient's public key
     * @param ciphertext Encrypted price data
     * @param ephemeralPubKey Ephemeral public key for ECIES
     * @param commitment Price commitment
     */
    function submitEncryptedPrice(
        bytes32 pairId,
        bytes32 recipientPubKey,
        bytes calldata ciphertext,
        bytes32 ephemeralPubKey,
        bytes32 commitment
    ) external onlyRole(ORACLE_ROLE) whenNotPaused {
        if (!pairs[pairId].isActive) revert PairNotSupported();
        if (recipientPubKey == bytes32(0)) revert InvalidPublicKey();

        uint256 roundId = roundCounter[pairId];

        encryptedPrices[pairId][recipientPubKey] = EncryptedPrice({
            ciphertext: ciphertext,
            ephemeralPubKey: ephemeralPubKey,
            commitment: commitment,
            timestamp: block.timestamp,
            roundId: roundId
        });
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify price proof
     */
    function _verifyPriceProof(
        bytes32 pairId,
        bytes32 userCommitment,
        bytes32 oracleCommitment,
        bytes calldata proof
    ) internal view returns (bool) {
        (bool success, bytes memory result) = priceProofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyPriceProof(bytes32,bytes32,bytes32,bytes)",
                pairId,
                userCommitment,
                oracleCommitment,
                proof
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Verify range proof
     */
    function _verifyRangeProof(
        bytes32 commitment,
        bytes32 minPrice,
        bytes32 maxPrice,
        bytes calldata proof
    ) internal view returns (bool) {
        (bool success, bytes memory result) = rangeProofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyRangeProof(bytes32,bytes32,bytes32,bytes)",
                commitment,
                minPrice,
                maxPrice,
                proof
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Verify oracle signature
     */
    function _verifyOracleSignature(
        bytes32 pairId,
        bytes32 commitment,
        uint256 timestamp,
        bytes32 signerPubKey,
        bytes calldata signature
    ) internal view returns (bool) {
        // Find oracle node by public key
        for (uint256 i = 0; i < oracleNodeList.length; i++) {
            OracleNode storage node = oracleNodes[oracleNodeList[i]];
            if (node.publicKey == signerPubKey && node.isActive) {
                // Verify signature
                bytes32 messageHash = keccak256(
                    abi.encodePacked(
                        PRIVACY_ORACLE_DOMAIN,
                        pairId,
                        commitment,
                        timestamp
                    )
                );

                // Recover signer using OpenZeppelin ECDSA
                (address recovered, ECDSA.RecoverError err, ) = ECDSA
                    .tryRecover(messageHash, signature);
                if (
                    err == ECDSA.RecoverError.NoError &&
                    recovered == oracleNodeList[i]
                ) {
                    return true;
                }
            }
        }
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get pair configuration
     */
    function getPair(bytes32 pairId) external view returns (PairConfig memory) {
        return pairs[pairId];
    }

    /**
     * @notice Get all pairs
     */
    function getAllPairs() external view returns (bytes32[] memory) {
        return allPairs;
    }

    /**
     * @notice Get latest price commitment
     */
    function getLatestPriceCommitment(
        bytes32 pairId
    ) external view returns (PriceCommitment memory) {
        return latestPriceCommitments[pairId];
    }

    /**
     * @notice Get historical price commitment
     */
    function getHistoricalPriceCommitment(
        bytes32 pairId,
        uint256 roundId
    ) external view returns (PriceCommitment memory) {
        return priceHistory[pairId][roundId];
    }

    /**
     * @notice Get oracle node info
     */
    function getOracleNode(
        address nodeAddress
    ) external view returns (OracleNode memory) {
        return oracleNodes[nodeAddress];
    }

    /**
     * @notice Get all oracle nodes
     */
    function getAllOracleNodes() external view returns (address[] memory) {
        return oracleNodeList;
    }

    /**
     * @notice Check if price is fresh
     */
    function isPriceFresh(bytes32 pairId) external view returns (bool) {
        PriceCommitment storage commitment = latestPriceCommitments[pairId];
        return block.timestamp - commitment.timestamp <= MAX_PRICE_STALENESS;
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update signature threshold
     */
    function setSignatureThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldThreshold = signatureThreshold;
        signatureThreshold = newThreshold;
        emit ThresholdUpdated(oldThreshold, newThreshold);
    }

    /**
     * @notice Update verifiers
     */
    function setVerifiers(
        address _priceProofVerifier,
        address _rangeProofVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_priceProofVerifier == address(0)) revert ZeroAddress();
        if (_rangeProofVerifier == address(0)) revert ZeroAddress();

        priceProofVerifier = _priceProofVerifier;
        rangeProofVerifier = _rangeProofVerifier;
    }

    /**
     * @notice Deactivate oracle node
     */
    function deactivateOracleNode(
        address nodeAddress
    ) external onlyRole(OPERATOR_ROLE) {
        oracleNodes[nodeAddress].isActive = false;
        _revokeRole(ORACLE_ROLE, nodeAddress);
    }

    /**
     * @notice Deactivate pair
     */
    function deactivatePair(bytes32 pairId) external onlyRole(OPERATOR_ROLE) {
        pairs[pairId].isActive = false;
    }

    /**
     * @notice Pause oracle
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause oracle
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
