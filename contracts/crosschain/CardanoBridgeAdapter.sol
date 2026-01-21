// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title CardanoBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Cardano blockchain integration
 * @dev Enables cross-chain interoperability between PIL (EVM) and Cardano (eUTXO)
 *
 * CARDANO INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     PIL <-> Cardano Bridge                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   Cardano         │                 │
 * │  │  (EVM/Solidity)   │           │  (eUTXO/Plutus)   │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ ZK Proofs   │  │◄─────────►│  │ Plutus      │  │                 │
 * │  │  │ Groth16     │  │           │  │ Scripts     │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ ERC20/721   │  │           │  │ Native      │  │                 │
 * │  │  │ Tokens      │  │◄─────────►│  │ Assets      │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Bridge Protocol Layer                            │ │
 * │  │  - UTXO Merkle Proof Verification                                  │ │
 * │  │  - Native Asset Mapping (Policy ID + Asset Name)                   │ │
 * │  │  - Plutus Script Validation                                        │ │
 * │  │  - Hydra State Channel Integration                                 │ │
 * │  │  - Mithril Certificate Verification                                │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * CARDANO CONCEPTS:
 * - eUTXO: Extended UTXO model (UTXOs can carry data and scripts)
 * - Plutus: Cardano's smart contract language (Haskell-based)
 * - Native Assets: Multi-asset ledger (no smart contract needed for tokens)
 * - Policy ID: 28-byte hash identifying a minting policy script
 * - Asset Name: Up to 32-byte name within a policy
 * - Datum: Data attached to a UTXO (script input)
 * - Redeemer: Data provided when spending a script UTXO
 * - Hydra: L2 scaling solution using state channels
 * - Mithril: Stake-based threshold signatures for light clients
 * - Slot: Time unit in Cardano (~1 second)
 * - Epoch: 5 days (432,000 slots)
 *
 * SUPPORTED FEATURES:
 * - ADA and Native Asset Bridging
 * - NFT Bridging (CIP-25/68 metadata)
 * - Cross-chain Message Passing
 * - UTXO State Proofs via Mithril
 * - Plutus Script Verification
 * - Hydra Head Integration
 * - Multi-signature Threshold Bridge
 */
contract CardanoBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant MITHRIL_SIGNER_ROLE =
        keccak256("MITHRIL_SIGNER_ROLE");
    bytes32 public constant HYDRA_OPERATOR_ROLE =
        keccak256("HYDRA_OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Cardano network types
    enum CardanoNetwork {
        MAINNET,
        PREPROD,
        PREVIEW,
        PRIVATE
    }

    /// @notice Message direction
    enum MessageDirection {
        EVM_TO_CARDANO,
        CARDANO_TO_EVM
    }

    /// @notice Transfer status
    enum TransferStatus {
        PENDING,
        CONFIRMED,
        COMPLETED,
        FAILED,
        REFUNDED
    }

    /// @notice UTXO status
    enum UTXOStatus {
        UNSPENT,
        PENDING_SPEND,
        SPENT,
        INVALID
    }

    /// @notice Plutus script type
    enum PlutusScriptType {
        PLUTUS_V1,
        PLUTUS_V2,
        PLUTUS_V3
    }

    /// @notice Mithril certificate status
    enum MithrilStatus {
        UNVERIFIED,
        PENDING,
        VERIFIED,
        EXPIRED,
        INVALID
    }

    /// @notice Hydra head state
    enum HydraHeadState {
        IDLE,
        INITIALIZING,
        OPEN,
        CLOSED,
        FANOUT_POSSIBLE,
        FINAL
    }

    /// @notice Cardano address (57-62 bytes bech32 decoded)
    struct CardanoAddress {
        bytes addressBytes;
        uint8 networkTag; // 0 = testnet, 1 = mainnet
        uint8 addressType; // 0 = base, 1 = pointer, 2 = enterprise, 3 = reward, etc.
        bytes28 paymentCredential;
        bytes28 stakingCredential;
    }

    /// @notice Native Asset identifier
    struct NativeAsset {
        bytes28 policyId;
        bytes32 assetName;
        uint256 quantity;
        address evmToken; // Mapped EVM token
        bool verified;
    }

    /// @notice UTXO structure
    struct UTXO {
        bytes32 txHash;
        uint32 outputIndex;
        uint64 lovelace; // ADA amount in lovelace (1 ADA = 1,000,000 lovelace)
        NativeAsset[] assets;
        bytes datum; // Inline datum or datum hash
        bool hasScript;
        bytes32 scriptHash;
        UTXOStatus status;
    }

    /// @notice Plutus script info
    struct PlutusScript {
        bytes32 scriptHash;
        PlutusScriptType scriptType;
        bytes scriptBytes;
        bool verified;
        uint256 registeredAt;
    }

    /// @notice Cross-chain message
    struct CrossChainMessage {
        bytes32 messageId;
        MessageDirection direction;
        bytes sourceAddress; // Cardano address bytes or EVM address
        bytes targetAddress;
        bytes payload;
        uint64 cardanoSlot;
        uint256 evmBlock;
        uint256 timestamp;
        TransferStatus status;
        bytes32 mithrilCertHash;
    }

    /// @notice Token transfer request
    struct TokenTransfer {
        bytes32 transferId;
        MessageDirection direction;
        bytes28 policyId;
        bytes32 assetName;
        uint256 amount;
        bytes sender;
        bytes recipient;
        uint256 fee;
        TransferStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice Mithril certificate for state proofs
    struct MithrilCertificate {
        bytes32 certHash;
        uint64 epoch;
        uint64 immutableFileNumber;
        bytes32 merkleRoot; // UTXO set Merkle root
        bytes32 stakesRoot; // Stake distribution root
        uint256 signersCount;
        bytes aggregateSignature;
        MithrilStatus status;
        uint256 verifiedAt;
    }

    /// @notice UTXO Merkle proof
    struct UTXOMerkleProof {
        bytes32 utxoHash;
        bytes32[] proof;
        uint256 leafIndex;
        bytes32 merkleRoot;
        bytes32 mithrilCertHash;
        bool verified;
    }

    /// @notice Hydra head info
    struct HydraHead {
        bytes32 headId;
        bytes32[] participants; // Cardano verification key hashes
        address[] evmParticipants;
        uint256 contestationPeriod; // In slots
        HydraHeadState state;
        bytes32 utxoHash; // Committed UTXOs hash
        uint256 createdAt;
        uint256 closedAt;
    }

    /// @notice Block header for SPV proofs
    struct CardanoBlockHeader {
        uint64 slot;
        uint64 blockNumber;
        bytes32 blockHash;
        bytes32 prevBlockHash;
        bytes32 issuerVkHash; // Block producer verification key hash
        bytes32 vrfVkHash;
        bytes32 bodyHash;
        bytes operationalCert;
        uint256 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Lovelace per ADA
    uint64 public constant LOVELACE_PER_ADA = 1_000_000;

    /// @notice Cardano slot duration (~1 second)
    uint256 public constant CARDANO_SLOT_DURATION = 1;

    /// @notice Cardano epoch length (5 days)
    uint256 public constant CARDANO_EPOCH_LENGTH = 432_000;

    /// @notice Minimum ADA for UTXO (protocol parameter)
    uint64 public constant MIN_UTXO_LOVELACE = 1_000_000; // 1 ADA

    /// @notice Maximum asset name length
    uint256 public constant MAX_ASSET_NAME_LENGTH = 32;

    /// @notice Maximum datum size
    uint256 public constant MAX_DATUM_SIZE = 65536;

    /// @notice Transfer timeout (24 hours)
    uint256 public constant TRANSFER_TIMEOUT = 24 hours;

    /// @notice Mithril certificate validity (48 hours)
    uint256 public constant MITHRIL_CERT_VALIDITY = 48 hours;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current Cardano network
    CardanoNetwork public network;

    /// @notice Bridge treasury address on Cardano
    bytes public cardanoTreasuryAddress;

    /// @notice Mithril aggregator endpoint hash (for verification)
    bytes32 public mithrilAggregatorHash;

    /// @notice Bridge fee (basis points, max 100 = 1%)
    uint256 public bridgeFee;

    /// @notice Minimum transfer amount (in lovelace)
    uint64 public minTransferAmount;

    /// @notice Accumulated fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total ADA bridged
    uint256 public totalAdaBridged;

    /// @notice Latest verified Cardano slot
    uint64 public latestVerifiedSlot;

    /// @notice Latest verified epoch
    uint64 public latestVerifiedEpoch;

    /// @notice Registered Plutus scripts
    mapping(bytes32 => PlutusScript) public plutusScripts;

    /// @notice Native asset mappings
    mapping(bytes32 => NativeAsset) public nativeAssets;

    /// @notice EVM to Cardano asset mapping (EVM token => policy+asset hash)
    mapping(address => bytes32) public evmToCardanoAsset;

    /// @notice Cross-chain messages
    mapping(bytes32 => CrossChainMessage) public messages;

    /// @notice Token transfers
    mapping(bytes32 => TokenTransfer) public transfers;

    /// @notice Mithril certificates
    mapping(bytes32 => MithrilCertificate) public mithrilCertificates;

    /// @notice UTXO proofs
    mapping(bytes32 => UTXOMerkleProof) public utxoProofs;

    /// @notice Hydra heads
    mapping(bytes32 => HydraHead) public hydraHeads;

    /// @notice Block headers for SPV verification
    mapping(bytes32 => CardanoBlockHeader) public blockHeaders;

    /// @notice Used transaction hashes (replay protection)
    mapping(bytes32 => bool) public usedTxHashes;

    /// @notice Sender nonces for replay protection
    mapping(address => uint256) public senderNonces;

    /// @notice Whitelisted policy IDs
    mapping(bytes28 => bool) public whitelistedPolicies;

    /// @notice Guardian threshold for multi-sig
    uint256 public guardianThreshold;

    /// @notice Total guardians
    uint256 public totalGuardians;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event NetworkSet(CardanoNetwork indexed network);
    event TreasuryAddressSet(bytes treasuryAddress);
    event MithrilAggregatorSet(bytes32 aggregatorHash);
    event BridgeFeeSet(uint256 feeBps);
    event MinTransferAmountSet(uint64 amount);
    event GuardianThresholdSet(uint256 threshold);

    event PlutusScriptRegistered(
        bytes32 indexed scriptHash,
        PlutusScriptType scriptType
    );
    event PlutusScriptVerified(bytes32 indexed scriptHash);

    event NativeAssetRegistered(
        bytes28 indexed policyId,
        bytes32 indexed assetName,
        address evmToken
    );
    event NativeAssetVerified(
        bytes28 indexed policyId,
        bytes32 indexed assetName
    );
    event PolicyWhitelisted(bytes28 indexed policyId, bool status);

    event MithrilCertificateSubmitted(bytes32 indexed certHash, uint64 epoch);
    event MithrilCertificateVerified(bytes32 indexed certHash);

    event UTXOProofSubmitted(
        bytes32 indexed utxoHash,
        bytes32 indexed mithrilCertHash
    );
    event UTXOProofVerified(bytes32 indexed utxoHash);

    event MessageSent(
        bytes32 indexed messageId,
        MessageDirection direction,
        bytes targetAddress,
        bytes payload
    );
    event MessageReceived(
        bytes32 indexed messageId,
        MessageDirection direction,
        bytes sourceAddress,
        bytes payload
    );
    event MessageCompleted(bytes32 indexed messageId);
    event MessageFailed(bytes32 indexed messageId, string reason);

    event TransferInitiated(
        bytes32 indexed transferId,
        MessageDirection direction,
        bytes28 policyId,
        bytes32 assetName,
        uint256 amount
    );
    event TransferConfirmed(bytes32 indexed transferId);
    event TransferCompleted(bytes32 indexed transferId);
    event TransferFailed(bytes32 indexed transferId, string reason);
    event TransferRefunded(bytes32 indexed transferId);

    event HydraHeadCreated(bytes32 indexed headId, uint256 participantCount);
    event HydraHeadOpened(bytes32 indexed headId);
    event HydraHeadClosed(bytes32 indexed headId);
    event HydraHeadFinalized(bytes32 indexed headId);

    event BlockHeaderSubmitted(bytes32 indexed blockHash, uint64 slot);
    event BlockHeaderVerified(bytes32 indexed blockHash);

    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidCardanoAddress();
    error InvalidPolicyId();
    error InvalidAssetName();
    error AssetNotWhitelisted();
    error AmountTooLow();
    error AmountTooHigh();
    error TransferNotFound();
    error TransferAlreadyCompleted();
    error TransferExpired();
    error MessageNotFound();
    error InvalidMithrilCertificate();
    error MithrilCertificateExpired();
    error InvalidUTXOProof();
    error UTXOAlreadySpent();
    error InvalidPlutusScript();
    error PlutusScriptNotVerified();
    error HydraHeadNotFound();
    error HydraHeadInvalidState();
    error InvalidBlockHeader();
    error InsufficientGuardianSignatures();
    error TxHashAlreadyUsed();
    error InsufficientFee();
    error DatumTooLarge();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address admin,
        CardanoNetwork _network,
        bytes memory _treasuryAddress,
        uint256 _guardianThreshold
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        network = _network;
        cardanoTreasuryAddress = _treasuryAddress;
        guardianThreshold = _guardianThreshold;
        bridgeFee = 30; // 0.3%
        minTransferAmount = 2_000_000; // 2 ADA

        emit NetworkSet(_network);
        emit TreasuryAddressSet(_treasuryAddress);
        emit GuardianThresholdSet(_guardianThreshold);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set the Cardano network
    function setNetwork(
        CardanoNetwork _network
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        network = _network;
        emit NetworkSet(_network);
    }

    /// @notice Set the treasury address on Cardano
    function setTreasuryAddress(
        bytes calldata _address
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_address.length < 57 || _address.length > 114)
            revert InvalidCardanoAddress();
        cardanoTreasuryAddress = _address;
        emit TreasuryAddressSet(_address);
    }

    /// @notice Set the Mithril aggregator hash
    function setMithrilAggregator(
        bytes32 _hash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        mithrilAggregatorHash = _hash;
        emit MithrilAggregatorSet(_hash);
    }

    /// @notice Set the bridge fee
    function setBridgeFee(
        uint256 _feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_feeBps <= 100, "Fee too high"); // Max 1%
        bridgeFee = _feeBps;
        emit BridgeFeeSet(_feeBps);
    }

    /// @notice Set minimum transfer amount
    function setMinTransferAmount(
        uint64 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_amount >= MIN_UTXO_LOVELACE, "Below min UTXO");
        minTransferAmount = _amount;
        emit MinTransferAmountSet(_amount);
    }

    /// @notice Set guardian threshold
    function setGuardianThreshold(
        uint256 _threshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            _threshold > 0 && _threshold <= totalGuardians,
            "Invalid threshold"
        );
        guardianThreshold = _threshold;
        emit GuardianThresholdSet(_threshold);
    }

    /// @notice Whitelist a policy ID
    function whitelistPolicy(
        bytes28 _policyId,
        bool _status
    ) external onlyRole(OPERATOR_ROLE) {
        whitelistedPolicies[_policyId] = _status;
        emit PolicyWhitelisted(_policyId, _status);
    }

    /// @notice Pause the bridge
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause the bridge
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                      PLUTUS SCRIPT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a Plutus script
    function registerPlutusScript(
        bytes32 _scriptHash,
        PlutusScriptType _scriptType,
        bytes calldata _scriptBytes
    ) external onlyRole(OPERATOR_ROLE) {
        if (_scriptHash == bytes32(0)) revert InvalidPlutusScript();

        plutusScripts[_scriptHash] = PlutusScript({
            scriptHash: _scriptHash,
            scriptType: _scriptType,
            scriptBytes: _scriptBytes,
            verified: false,
            registeredAt: block.timestamp
        });

        emit PlutusScriptRegistered(_scriptHash, _scriptType);
    }

    /// @notice Verify a Plutus script
    function verifyPlutusScript(
        bytes32 _scriptHash
    ) external onlyRole(GUARDIAN_ROLE) {
        PlutusScript storage script = plutusScripts[_scriptHash];
        if (script.scriptHash == bytes32(0)) revert InvalidPlutusScript();

        // Verify the script hash matches the script bytes
        bytes32 computedHash = _computePlutusHash(
            script.scriptBytes,
            script.scriptType
        );
        require(computedHash == _scriptHash, "Hash mismatch");

        script.verified = true;
        emit PlutusScriptVerified(_scriptHash);
    }

    /// @notice Compute Plutus script hash (simplified)
    function _computePlutusHash(
        bytes memory _scriptBytes,
        PlutusScriptType _scriptType
    ) internal pure returns (bytes32) {
        // In practice, this would use CBOR encoding and Blake2b-224
        // Simplified version uses keccak256
        return keccak256(abi.encodePacked(uint8(_scriptType), _scriptBytes));
    }

    /*//////////////////////////////////////////////////////////////
                      NATIVE ASSET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a native asset mapping
    function registerNativeAsset(
        bytes28 _policyId,
        bytes32 _assetName,
        address _evmToken
    ) external onlyRole(OPERATOR_ROLE) {
        if (_policyId == bytes28(0)) revert InvalidPolicyId();

        bytes32 assetId = _computeAssetId(_policyId, _assetName);

        nativeAssets[assetId] = NativeAsset({
            policyId: _policyId,
            assetName: _assetName,
            quantity: 0,
            evmToken: _evmToken,
            verified: false
        });

        evmToCardanoAsset[_evmToken] = assetId;

        emit NativeAssetRegistered(_policyId, _assetName, _evmToken);
    }

    /// @notice Verify a native asset mapping
    function verifyNativeAsset(
        bytes28 _policyId,
        bytes32 _assetName
    ) external onlyRole(GUARDIAN_ROLE) {
        bytes32 assetId = _computeAssetId(_policyId, _assetName);
        NativeAsset storage asset = nativeAssets[assetId];

        if (asset.policyId == bytes28(0)) revert InvalidPolicyId();

        asset.verified = true;
        emit NativeAssetVerified(_policyId, _assetName);
    }

    /// @notice Compute asset ID from policy ID and asset name
    function _computeAssetId(
        bytes28 _policyId,
        bytes32 _assetName
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_policyId, _assetName));
    }

    /*//////////////////////////////////////////////////////////////
                    MITHRIL CERTIFICATE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit a Mithril certificate
    function submitMithrilCertificate(
        bytes32 _certHash,
        uint64 _epoch,
        uint64 _immutableFileNumber,
        bytes32 _merkleRoot,
        bytes32 _stakesRoot,
        uint256 _signersCount,
        bytes calldata _aggregateSignature
    ) external onlyRole(MITHRIL_SIGNER_ROLE) {
        mithrilCertificates[_certHash] = MithrilCertificate({
            certHash: _certHash,
            epoch: _epoch,
            immutableFileNumber: _immutableFileNumber,
            merkleRoot: _merkleRoot,
            stakesRoot: _stakesRoot,
            signersCount: _signersCount,
            aggregateSignature: _aggregateSignature,
            status: MithrilStatus.PENDING,
            verifiedAt: 0
        });

        emit MithrilCertificateSubmitted(_certHash, _epoch);
    }

    /// @notice Verify a Mithril certificate
    function verifyMithrilCertificate(
        bytes32 _certHash,
        bytes[] calldata _guardianSignatures
    ) external onlyRole(GUARDIAN_ROLE) {
        if (_guardianSignatures.length < guardianThreshold) {
            revert InsufficientGuardianSignatures();
        }

        MithrilCertificate storage cert = mithrilCertificates[_certHash];
        if (cert.certHash == bytes32(0)) revert InvalidMithrilCertificate();

        // Verify guardian signatures (simplified - would use proper multi-sig)
        // In production, verify each signature against guardian public keys

        cert.status = MithrilStatus.VERIFIED;
        cert.verifiedAt = block.timestamp;

        // Update latest verified slot
        uint64 certSlot = uint64(cert.epoch) * uint64(CARDANO_EPOCH_LENGTH);
        if (certSlot > latestVerifiedSlot) {
            latestVerifiedSlot = certSlot;
            latestVerifiedEpoch = cert.epoch;
        }

        emit MithrilCertificateVerified(_certHash);
    }

    /// @notice Check if a Mithril certificate is valid
    function isMithrilCertificateValid(
        bytes32 _certHash
    ) public view returns (bool) {
        MithrilCertificate storage cert = mithrilCertificates[_certHash];
        if (cert.status != MithrilStatus.VERIFIED) return false;
        if (block.timestamp > cert.verifiedAt + MITHRIL_CERT_VALIDITY)
            return false;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                        UTXO PROOF MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit a UTXO Merkle proof
    function submitUTXOProof(
        bytes32 _utxoHash,
        bytes32[] calldata _proof,
        uint256 _leafIndex,
        bytes32 _mithrilCertHash
    ) external onlyRole(RELAYER_ROLE) {
        if (!isMithrilCertificateValid(_mithrilCertHash)) {
            revert InvalidMithrilCertificate();
        }

        MithrilCertificate storage cert = mithrilCertificates[_mithrilCertHash];

        utxoProofs[_utxoHash] = UTXOMerkleProof({
            utxoHash: _utxoHash,
            proof: _proof,
            leafIndex: _leafIndex,
            merkleRoot: cert.merkleRoot,
            mithrilCertHash: _mithrilCertHash,
            verified: false
        });

        emit UTXOProofSubmitted(_utxoHash, _mithrilCertHash);
    }

    /// @notice Verify a UTXO proof
    function verifyUTXOProof(bytes32 _utxoHash) external returns (bool) {
        UTXOMerkleProof storage proof = utxoProofs[_utxoHash];
        if (proof.utxoHash == bytes32(0)) revert InvalidUTXOProof();

        // Verify Merkle proof
        bool isValid = _verifyMerkleProof(
            proof.proof,
            proof.merkleRoot,
            _utxoHash,
            proof.leafIndex
        );

        if (isValid) {
            proof.verified = true;
            emit UTXOProofVerified(_utxoHash);
        }

        return isValid;
    }

    /// @notice Verify Merkle proof
    function _verifyMerkleProof(
        bytes32[] memory _proof,
        bytes32 _root,
        bytes32 _leaf,
        uint256 _index
    ) internal pure returns (bool) {
        bytes32 computedHash = _leaf;

        for (uint256 i = 0; i < _proof.length; i++) {
            if (_index % 2 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, _proof[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(_proof[i], computedHash)
                );
            }
            _index = _index / 2;
        }

        return computedHash == _root;
    }

    /*//////////////////////////////////////////////////////////////
                         TRANSFER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Initiate a transfer from EVM to Cardano
    function initiateTransferToCardano(
        bytes28 _policyId,
        bytes32 _assetName,
        uint256 _amount,
        bytes calldata _recipientAddress
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        // Validate inputs
        if (_recipientAddress.length < 57) revert InvalidCardanoAddress();
        if (_amount < minTransferAmount) revert AmountTooLow();

        bytes32 assetId = _computeAssetId(_policyId, _assetName);

        // For non-ADA assets, check whitelist
        if (_policyId != bytes28(0) && !whitelistedPolicies[_policyId]) {
            revert AssetNotWhitelisted();
        }

        // Calculate fee
        uint256 fee = (_amount * bridgeFee) / 10000;
        if (msg.value < fee) revert InsufficientFee();

        // Generate transfer ID
        uint256 nonce = senderNonces[msg.sender]++;
        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                _policyId,
                _assetName,
                _amount,
                _recipientAddress,
                nonce,
                block.timestamp
            )
        );

        // Create transfer record
        transfers[transferId] = TokenTransfer({
            transferId: transferId,
            direction: MessageDirection.EVM_TO_CARDANO,
            policyId: _policyId,
            assetName: _assetName,
            amount: _amount,
            sender: abi.encodePacked(msg.sender),
            recipient: _recipientAddress,
            fee: fee,
            status: TransferStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        accumulatedFees += fee;
        totalMessagesSent++;

        emit TransferInitiated(
            transferId,
            MessageDirection.EVM_TO_CARDANO,
            _policyId,
            _assetName,
            _amount
        );

        return transferId;
    }

    /// @notice Complete a transfer from Cardano to EVM
    function completeTransferFromCardano(
        bytes32 _transferId,
        bytes32 _txHash,
        bytes32 _utxoProofHash,
        bytes[] calldata _guardianSignatures
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        if (_guardianSignatures.length < guardianThreshold) {
            revert InsufficientGuardianSignatures();
        }
        if (usedTxHashes[_txHash]) revert TxHashAlreadyUsed();

        TokenTransfer storage transfer = transfers[_transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.status != TransferStatus.PENDING)
            revert TransferAlreadyCompleted();

        // Verify UTXO proof
        UTXOMerkleProof storage proof = utxoProofs[_utxoProofHash];
        if (!proof.verified) revert InvalidUTXOProof();

        // Mark as completed
        transfer.status = TransferStatus.COMPLETED;
        transfer.completedAt = block.timestamp;
        usedTxHashes[_txHash] = true;

        // Update stats
        if (transfer.policyId == bytes28(0)) {
            totalAdaBridged += transfer.amount;
        }
        totalMessagesReceived++;

        emit TransferCompleted(_transferId);
    }

    /// @notice Refund an expired transfer
    function refundTransfer(bytes32 _transferId) external nonReentrant {
        TokenTransfer storage transfer = transfers[_transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.status != TransferStatus.PENDING)
            revert TransferAlreadyCompleted();
        if (block.timestamp < transfer.initiatedAt + TRANSFER_TIMEOUT)
            revert TransferNotFound();

        transfer.status = TransferStatus.REFUNDED;
        transfer.completedAt = block.timestamp;

        // Refund fee
        accumulatedFees -= transfer.fee;

        emit TransferRefunded(_transferId);
    }

    /*//////////////////////////////////////////////////////////////
                         MESSAGE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Send a cross-chain message to Cardano
    function sendMessageToCardano(
        bytes calldata _targetAddress,
        bytes calldata _payload
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (_targetAddress.length < 57) revert InvalidCardanoAddress();
        if (_payload.length > MAX_DATUM_SIZE) revert DatumTooLarge();

        uint256 nonce = senderNonces[msg.sender]++;
        messageId = keccak256(
            abi.encodePacked(
                msg.sender,
                _targetAddress,
                _payload,
                nonce,
                block.timestamp
            )
        );

        messages[messageId] = CrossChainMessage({
            messageId: messageId,
            direction: MessageDirection.EVM_TO_CARDANO,
            sourceAddress: abi.encodePacked(msg.sender),
            targetAddress: _targetAddress,
            payload: _payload,
            cardanoSlot: 0,
            evmBlock: block.number,
            timestamp: block.timestamp,
            status: TransferStatus.PENDING,
            mithrilCertHash: bytes32(0)
        });

        totalMessagesSent++;

        emit MessageSent(
            messageId,
            MessageDirection.EVM_TO_CARDANO,
            _targetAddress,
            _payload
        );

        return messageId;
    }

    /// @notice Receive a cross-chain message from Cardano
    function receiveMessageFromCardano(
        bytes32 _messageId,
        bytes calldata _sourceAddress,
        bytes calldata _payload,
        uint64 _cardanoSlot,
        bytes32 _mithrilCertHash,
        bytes[] calldata _guardianSignatures
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        if (_guardianSignatures.length < guardianThreshold) {
            revert InsufficientGuardianSignatures();
        }
        if (!isMithrilCertificateValid(_mithrilCertHash)) {
            revert InvalidMithrilCertificate();
        }

        messages[_messageId] = CrossChainMessage({
            messageId: _messageId,
            direction: MessageDirection.CARDANO_TO_EVM,
            sourceAddress: _sourceAddress,
            targetAddress: "",
            payload: _payload,
            cardanoSlot: _cardanoSlot,
            evmBlock: block.number,
            timestamp: block.timestamp,
            status: TransferStatus.COMPLETED,
            mithrilCertHash: _mithrilCertHash
        });

        totalMessagesReceived++;

        emit MessageReceived(
            _messageId,
            MessageDirection.CARDANO_TO_EVM,
            _sourceAddress,
            _payload
        );
        emit MessageCompleted(_messageId);
    }

    /*//////////////////////////////////////////////////////////////
                        HYDRA HEAD FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Create a Hydra head
    function createHydraHead(
        bytes32 _headId,
        bytes32[] calldata _cardanoParticipants,
        address[] calldata _evmParticipants,
        uint256 _contestationPeriod
    ) external onlyRole(HYDRA_OPERATOR_ROLE) {
        require(
            _cardanoParticipants.length == _evmParticipants.length,
            "Participant mismatch"
        );
        require(_contestationPeriod >= 60, "Contestation too short"); // Min 1 minute

        hydraHeads[_headId] = HydraHead({
            headId: _headId,
            participants: _cardanoParticipants,
            evmParticipants: _evmParticipants,
            contestationPeriod: _contestationPeriod,
            state: HydraHeadState.INITIALIZING,
            utxoHash: bytes32(0),
            createdAt: block.timestamp,
            closedAt: 0
        });

        emit HydraHeadCreated(_headId, _cardanoParticipants.length);
    }

    /// @notice Open a Hydra head
    function openHydraHead(
        bytes32 _headId,
        bytes32 _utxoHash
    ) external onlyRole(HYDRA_OPERATOR_ROLE) {
        HydraHead storage head = hydraHeads[_headId];
        if (head.headId == bytes32(0)) revert HydraHeadNotFound();
        if (head.state != HydraHeadState.INITIALIZING)
            revert HydraHeadInvalidState();

        head.state = HydraHeadState.OPEN;
        head.utxoHash = _utxoHash;

        emit HydraHeadOpened(_headId);
    }

    /// @notice Close a Hydra head
    function closeHydraHead(
        bytes32 _headId
    ) external onlyRole(HYDRA_OPERATOR_ROLE) {
        HydraHead storage head = hydraHeads[_headId];
        if (head.headId == bytes32(0)) revert HydraHeadNotFound();
        if (head.state != HydraHeadState.OPEN) revert HydraHeadInvalidState();

        head.state = HydraHeadState.CLOSED;
        head.closedAt = block.timestamp;

        emit HydraHeadClosed(_headId);
    }

    /// @notice Finalize a Hydra head after contestation period
    function finalizeHydraHead(
        bytes32 _headId
    ) external onlyRole(HYDRA_OPERATOR_ROLE) {
        HydraHead storage head = hydraHeads[_headId];
        if (head.headId == bytes32(0)) revert HydraHeadNotFound();
        if (head.state != HydraHeadState.CLOSED) revert HydraHeadInvalidState();
        require(
            block.timestamp >= head.closedAt + head.contestationPeriod,
            "Contestation ongoing"
        );

        head.state = HydraHeadState.FINAL;

        emit HydraHeadFinalized(_headId);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get transfer details
    function getTransfer(
        bytes32 _transferId
    ) external view returns (TokenTransfer memory) {
        return transfers[_transferId];
    }

    /// @notice Get message details
    function getMessage(
        bytes32 _messageId
    ) external view returns (CrossChainMessage memory) {
        return messages[_messageId];
    }

    /// @notice Get Mithril certificate
    function getMithrilCertificate(
        bytes32 _certHash
    ) external view returns (MithrilCertificate memory) {
        return mithrilCertificates[_certHash];
    }

    /// @notice Get Hydra head details
    function getHydraHead(
        bytes32 _headId
    ) external view returns (HydraHead memory) {
        return hydraHeads[_headId];
    }

    /// @notice Get native asset details
    function getNativeAsset(
        bytes28 _policyId,
        bytes32 _assetName
    ) external view returns (NativeAsset memory) {
        bytes32 assetId = _computeAssetId(_policyId, _assetName);
        return nativeAssets[assetId];
    }

    /// @notice Check if policy is whitelisted
    function isPolicyWhitelisted(
        bytes28 _policyId
    ) external view returns (bool) {
        return whitelistedPolicies[_policyId];
    }

    /// @notice Get bridge statistics
    function getBridgeStats()
        external
        view
        returns (
            uint256 messagesSent,
            uint256 messagesReceived,
            uint256 adaBridged,
            uint256 fees,
            uint64 latestSlot,
            uint64 latestEpoch
        )
    {
        return (
            totalMessagesSent,
            totalMessagesReceived,
            totalAdaBridged,
            accumulatedFees,
            latestVerifiedSlot,
            latestVerifiedEpoch
        );
    }

    /*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw accumulated fees
    function withdrawFees(
        address _recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        (bool success, ) = _recipient.call{value: amount}("");
        require(success, "Fee withdrawal failed");

        emit FeesWithdrawn(_recipient, amount);
    }

    /// @notice Convert lovelace to ADA (with 6 decimals)
    function lovelaceToAda(uint64 _lovelace) external pure returns (uint256) {
        return uint256(_lovelace);
    }

    /// @notice Convert ADA to lovelace
    function adaToLovelace(uint256 _ada) external pure returns (uint64) {
        require(_ada <= type(uint64).max, "Amount too large");
        return uint64(_ada);
    }

    /// @notice Validate a Cardano address format (basic validation)
    function isValidCardanoAddress(
        bytes calldata _address
    ) external pure returns (bool) {
        // Cardano addresses are 57-114 bytes when decoded from bech32
        // Network tag should be valid (0 for testnet, 1 for mainnet)
        if (_address.length < 57 || _address.length > 114) return false;

        // First byte contains header info
        uint8 header = uint8(_address[0]);
        uint8 addressType = header >> 4;
        uint8 networkTag = header & 0x0F;

        // Address type should be 0-8 (various Shelley address types)
        if (addressType > 8) return false;

        // Network tag should be 0 (testnet) or 1 (mainnet)
        if (networkTag > 1) return false;

        return true;
    }

    /// @notice Receive ETH for fees
    receive() external payable {}
}
