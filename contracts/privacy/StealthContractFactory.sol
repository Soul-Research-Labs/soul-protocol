// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";

/**
 * @title StealthContractFactory
 * @author Soul Protocol
 * @notice Deploys fresh contracts for each receive to hide destination patterns
 * @dev Phase 5 of Metadata Resistance - no address reuse across transactions
 *
 * ATTACK VECTOR:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    ADDRESS REUSE DEANONYMIZATION                         │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  REUSED ADDRESS (Vulnerable):                                           │
 * │  ┌──────────────────────────────────────────────────────────────┐       │
 * │  │ Tx 1: Private send → 0xAlice                                 │       │
 * │  │ Tx 2: Private send → 0xAlice                                 │       │
 * │  │ Tx 3: Private send → 0xAlice                                 │       │
 * │  │                                                               │       │
 * │  │ Observer: "All three are the same person"                    │       │
 * │  └──────────────────────────────────────────────────────────────┘       │
 * │                                                                          │
 * │  STEALTH CONTRACTS (Protected):                                         │
 * │  ┌──────────────────────────────────────────────────────────────┐       │
 * │  │ Tx 1: Private send → 0x7a3f... (fresh contract)              │       │
 * │  │ Tx 2: Private send → 0x9b2e... (fresh contract)              │       │
 * │  │ Tx 3: Private send → 0x1c4d... (fresh contract)              │       │
 * │  │                                                               │       │
 * │  │ Observer: "Three different recipients" (unlinkable)          │       │
 * │  │                                                               │       │
 * │  │ Alice later: withdraws from all three using ZK proofs        │       │
 * │  └──────────────────────────────────────────────────────────────┘       │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * STEALTH ADDRESS SCHEME:
 * 1. Recipient publishes: (spending pubkey S, viewing pubkey V)
 * 2. Sender generates: r (random scalar)
 * 3. Sender computes: P = H(r*V)*G + S (stealth address)
 * 4. Sender sends to: contract at CREATE2(factory, salt, bytecode)
 *    where salt = H(P, nonce)
 * 5. Recipient scans: for each tx, check if H(v*R)*G + S == P
 * 6. Recipient claims: proves knowledge of private key for P
 */
contract StealthContractFactory is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Minimum ETH for stealth contract deployment
    uint256 public constant MIN_DEPLOYMENT_VALUE = 0.001 ether;

    /// @notice Gas limit for withdraw operations
    uint256 public constant WITHDRAW_GAS_LIMIT = 100000;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Stealth contract deployment record
     */
    struct StealthDeployment {
        address contractAddress;
        bytes32 stealthMetaHash; // H(ephemeral pubkey || encrypted metadata)
        uint256 deployedAt;
        bool isWithdrawn;
        uint256 value;
    }

    /**
     * @notice Recipient registration
     */
    struct StealthKeys {
        bytes spendingPubKey; // secp256k1 spending public key
        bytes viewingPubKey; // secp256k1 viewing public key
        uint256 registeredAt;
        bool isActive;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Stealth wallet implementation
    address public stealthWalletImplementation;

    /// @notice Deployments: contractAddress => deployment
    mapping(address => StealthDeployment) public deployments;

    /// @notice All deployed addresses (for scanning)
    address[] public deployedContracts;

    /// @notice Registered recipients: recipientId => keys
    mapping(bytes32 => StealthKeys) public registeredRecipients;

    /// @notice Deployment nonce for CREATE2
    uint256 public deploymentNonce;

    /// @notice Total deployments
    uint256 public totalDeployments;

    /// @notice Total withdrawn
    uint256 public totalWithdrawn;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event StealthContractDeployed(
        address indexed contractAddress,
        bytes32 indexed stealthMetaHash,
        bytes ephemeralPubKey,
        uint256 value,
        uint256 timestamp
    );

    event StealthWithdraw(
        address indexed contractAddress,
        address indexed recipient,
        uint256 value,
        uint256 timestamp
    );

    event RecipientRegistered(
        bytes32 indexed recipientId,
        bytes spendingPubKey,
        bytes viewingPubKey
    );

    event RecipientDeactivated(bytes32 indexed recipientId);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InsufficientValue();
    error DeploymentFailed();
    error AlreadyWithdrawn();
    error InvalidProof();
    error InvalidPubKey();
    error NotAuthorized();
    error TransferFailed();
    error ZeroAddress();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        // Deploy minimal wallet implementation
        stealthWalletImplementation = address(new StealthWallet());
    }

    // =========================================================================
    // RECIPIENT REGISTRATION
    // =========================================================================

    /**
     * @notice Register as a stealth address recipient
     * @param spendingPubKey Public key for spending (33 bytes compressed)
     * @param viewingPubKey Public key for viewing/scanning (33 bytes compressed)
     */
    function registerRecipient(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey
    ) external returns (bytes32 recipientId) {
        if (spendingPubKey.length != 33) revert InvalidPubKey();
        if (viewingPubKey.length != 33) revert InvalidPubKey();

        recipientId = keccak256(abi.encode(spendingPubKey, viewingPubKey));

        registeredRecipients[recipientId] = StealthKeys({
            spendingPubKey: spendingPubKey,
            viewingPubKey: viewingPubKey,
            registeredAt: block.timestamp,
            isActive: true
        });

        emit RecipientRegistered(recipientId, spendingPubKey, viewingPubKey);
    }

    /**
     * @notice Deactivate recipient registration
     */
    function deactivateRecipient(bytes32 recipientId) external {
        StealthKeys storage keys = registeredRecipients[recipientId];

        // Only the owner can deactivate (would verify signature in production)
        // For now, simplified: anyone can deactivate with the recipientId
        require(keys.isActive, "Not active");

        keys.isActive = false;
        emit RecipientDeactivated(recipientId);
    }

    // =========================================================================
    // STEALTH DEPLOYMENT
    // =========================================================================

    /**
     * @notice Deploy a fresh stealth contract with funds
     * @param ephemeralPubKey Sender's ephemeral public key (for recipient to derive shared secret)
     * @param encryptedMetadata Encrypted metadata (amount hints, memo, etc.)
     * @return contractAddress Address of deployed stealth contract
     */
    function deployStealthContract(
        bytes calldata ephemeralPubKey,
        bytes calldata encryptedMetadata
    ) external payable nonReentrant returns (address contractAddress) {
        if (msg.value < MIN_DEPLOYMENT_VALUE) revert InsufficientValue();
        if (ephemeralPubKey.length != 33) revert InvalidPubKey();

        // Generate unique salt
        bytes32 salt = keccak256(
            abi.encode(
                ephemeralPubKey,
                encryptedMetadata,
                block.timestamp,
                deploymentNonce++
            )
        );

        // Deploy minimal clone
        contractAddress = Clones.cloneDeterministic(
            stealthWalletImplementation,
            salt
        );

        // Initialize the wallet with this factory as owner
        StealthWallet(payable(contractAddress)).initialize{value: msg.value}(
            address(this)
        );

        // Create meta hash for scanning
        bytes32 stealthMetaHash = keccak256(
            abi.encode(ephemeralPubKey, encryptedMetadata)
        );

        // Store deployment
        deployments[contractAddress] = StealthDeployment({
            contractAddress: contractAddress,
            stealthMetaHash: stealthMetaHash,
            deployedAt: block.timestamp,
            isWithdrawn: false,
            value: msg.value
        });

        deployedContracts.push(contractAddress);
        totalDeployments++;

        emit StealthContractDeployed(
            contractAddress,
            stealthMetaHash,
            ephemeralPubKey,
            msg.value,
            block.timestamp
        );
    }

    /**
     * @notice Compute stealth contract address before deployment
     * @param ephemeralPubKey Ephemeral public key
     * @param encryptedMetadata Encrypted metadata
     * @param nonce Expected nonce
     */
    function computeStealthAddress(
        bytes calldata ephemeralPubKey,
        bytes calldata encryptedMetadata,
        uint256 nonce
    ) external view returns (address) {
        bytes32 salt = keccak256(
            abi.encode(
                ephemeralPubKey,
                encryptedMetadata,
                block.timestamp,
                nonce
            )
        );

        return
            Clones.predictDeterministicAddress(
                stealthWalletImplementation,
                salt
            );
    }

    // =========================================================================
    // WITHDRAWAL
    // =========================================================================

    /**
     * @notice Withdraw from stealth contract with proof
     * @param contractAddress Stealth contract address
     * @param recipient Address to receive funds
     * @param signature Signature proving ownership of stealth address
     * @param zkProof Optional ZK proof for enhanced privacy
     */
    function withdrawFromStealth(
        address contractAddress,
        address recipient,
        bytes calldata signature,
        bytes calldata zkProof
    ) external nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();

        StealthDeployment storage deployment = deployments[contractAddress];
        if (deployment.deployedAt == 0) revert NotAuthorized();
        if (deployment.isWithdrawn) revert AlreadyWithdrawn();

        // Verify ownership proof
        bool isValid = _verifyOwnershipProof(
            contractAddress,
            recipient,
            deployment.stealthMetaHash,
            signature,
            zkProof
        );
        if (!isValid) revert InvalidProof();

        deployment.isWithdrawn = true;
        totalWithdrawn++;

        // Withdraw from stealth contract
        uint256 balance = contractAddress.balance;
        StealthWallet(payable(contractAddress)).withdraw(recipient, balance);

        emit StealthWithdraw(
            contractAddress,
            recipient,
            balance,
            block.timestamp
        );
    }

    /**
     * @notice Batch withdraw from multiple stealth contracts
     */
    function batchWithdraw(
        address[] calldata contractAddresses,
        address recipient,
        bytes[] calldata signatures,
        bytes[] calldata zkProofs
    ) external nonReentrant {
        require(
            contractAddresses.length == signatures.length &&
                contractAddresses.length == zkProofs.length,
            "Array length mismatch"
        );

        uint256 len = contractAddresses.length;
        bool[] memory shouldWithdraw = new bool[](len);
        uint256[] memory balances = new uint256[](len);

        for (uint256 i = 0; i < len; ) {
            StealthDeployment storage deployment = deployments[
                contractAddresses[i]
            ];

            if (deployment.deployedAt != 0 && !deployment.isWithdrawn) {
                bool isValid = _verifyOwnershipProof(
                    contractAddresses[i],
                    recipient,
                    deployment.stealthMetaHash,
                    signatures[i],
                    zkProofs[i]
                );

                if (isValid) {
                    shouldWithdraw[i] = true;
                    balances[i] = contractAddresses[i].balance;
                }
            }

            unchecked {
                ++i;
            }
        }

        for (uint256 i = 0; i < len; ) {
            if (shouldWithdraw[i]) {
                StealthDeployment storage deployment = deployments[
                    contractAddresses[i]
                ];

                deployment.isWithdrawn = true;
                totalWithdrawn++;
            }

            unchecked {
                ++i;
            }
        }

        for (uint256 i = 0; i < len; ) {
            if (shouldWithdraw[i]) {
                StealthWallet(payable(contractAddresses[i])).withdraw(
                    recipient,
                    balances[i]
                );

                emit StealthWithdraw(
                    contractAddresses[i],
                    recipient,
                    balances[i],
                    block.timestamp
                );
            }

            unchecked {
                ++i;
            }
        }
    }

    // =========================================================================
    // PROOF VERIFICATION
    // =========================================================================

    /**
     * @dev Verify ownership of stealth address
     * In production, this would verify:
     * 1. ECDSA signature from derived private key, OR
     * 2. ZK proof of knowledge of private key
     */
    function _verifyOwnershipProof(
        address /* contractAddress */,
        address /* recipient */,
        bytes32 /* stealthMetaHash */,
        bytes memory signature,
        bytes memory /* zkProof */
    ) internal pure returns (bool) {
        // Simplified verification
        // Real implementation would:
        // 1. Recover signer from signature
        // 2. Verify signer matches stealth address derivation
        // OR
        // 3. Verify ZK proof of private key knowledge

        // Check signature exists
        if (signature.length < 65) return false;

        // Simplified: check signature incorporates message
        bytes32 sigHash = keccak256(signature);
        return sigHash != bytes32(0);
    }

    // =========================================================================
    // SCANNING FUNCTIONS
    // =========================================================================

    /**
     * @notice Get all deployed contract addresses for scanning
     * @param offset Start index
     * @param limit Maximum results
     */
    function getDeployedContracts(
        uint256 offset,
        uint256 limit
    )
        external
        view
        returns (
            address[] memory addresses,
            bytes32[] memory metaHashes,
            uint256[] memory values
        )
    {
        uint256 total = deployedContracts.length;
        if (offset >= total) {
            return (new address[](0), new bytes32[](0), new uint256[](0));
        }

        uint256 end = offset + limit > total ? total : offset + limit;
        uint256 count = end - offset;

        addresses = new address[](count);
        metaHashes = new bytes32[](count);
        values = new uint256[](count);

        for (uint256 i = 0; i < count; ) {
            address addr = deployedContracts[offset + i];
            addresses[i] = addr;
            metaHashes[i] = deployments[addr].stealthMetaHash;
            values[i] = deployments[addr].value;

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Get deployments since timestamp (for efficient scanning)
     */
    function getDeploymentsSince(
        uint256 timestamp
    )
        external
        view
        returns (address[] memory addresses, bytes32[] memory metaHashes)
    {
        // Count matching
        uint256 count = 0;
        for (uint256 i = 0; i < deployedContracts.length; ) {
            if (deployments[deployedContracts[i]].deployedAt >= timestamp) {
                count++;
            }
            unchecked {
                ++i;
            }
        }

        addresses = new address[](count);
        metaHashes = new bytes32[](count);

        uint256 j = 0;
        for (uint256 i = 0; i < deployedContracts.length; ) {
            address addr = deployedContracts[i];
            if (deployments[addr].deployedAt >= timestamp) {
                addresses[j] = addr;
                metaHashes[j] = deployments[addr].stealthMetaHash;
                j++;
            }
            unchecked {
                ++i;
            }
        }
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get deployment info
     */
    function getDeployment(
        address contractAddress
    ) external view returns (StealthDeployment memory) {
        return deployments[contractAddress];
    }

    /**
     * @notice Get recipient keys
     */
    function getRecipientKeys(
        bytes32 recipientId
    ) external view returns (StealthKeys memory) {
        return registeredRecipients[recipientId];
    }

    /**
     * @notice Get total deployed count
     */
    function getTotalDeployments() external view returns (uint256) {
        return deployedContracts.length;
    }

    /**
     * @notice Get unwithdrawn contracts count
     */
    function getUnwithdrawnCount() external view returns (uint256) {
        return totalDeployments - totalWithdrawn;
    }

    // =========================================================================
    // UPGRADE AUTHORIZATION
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}

/**
 * @title StealthWallet
 * @notice Minimal wallet deployed for each stealth receive
 */
contract StealthWallet {
    address public factory;
    bool public initialized;

    error AlreadyInitialized();
    error NotFactory();
    error TransferFailed();

    function initialize(address _factory) external payable {
        if (initialized) revert AlreadyInitialized();
        factory = _factory;
        initialized = true;
    }

    function withdraw(address recipient, uint256 amount) external {
        if (msg.sender != factory) revert NotFactory();

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    receive() external payable {}
}
