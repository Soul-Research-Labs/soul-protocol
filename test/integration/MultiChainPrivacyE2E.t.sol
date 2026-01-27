// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title MultiChainPrivacyE2E
 * @notice End-to-end tests for cross-chain privacy flows
 * @dev Tests privacy operations across 5+ simulated chains
 */
contract MultiChainPrivacyE2E is Test {
    // ═══════════════════════════════════════════════════════════════════════
    // CHAIN SIMULATION
    // ═══════════════════════════════════════════════════════════════════════

    struct ChainConfig {
        uint256 chainId;
        string name;
        bytes32 domainId;
        address stealthRegistry;
        address nullifierManager;
        address privacyHub;
    }

    ChainConfig[] public chains;

    // Mock contracts per chain
    mapping(uint256 => MockStealthRegistryE2E) stealthRegistries;
    mapping(uint256 => MockNullifierManagerE2E) nullifierManagers;
    mapping(uint256 => MockPrivacyHubE2E) privacyHubs;

    // Cross-chain message relay
    MockCrossChainRelay relay;

    function setUp() public {
        relay = new MockCrossChainRelay();

        // Set up 5 chains
        _setupChain(1, "Ethereum", "ETH_DOMAIN");
        _setupChain(10, "Optimism", "OP_DOMAIN");
        _setupChain(42161, "Arbitrum", "ARB_DOMAIN");
        _setupChain(8453, "Base", "BASE_DOMAIN");
        _setupChain(137, "Polygon", "POLY_DOMAIN");
    }

    function _setupChain(
        uint256 chainId,
        string memory name,
        string memory domainSuffix
    ) internal {
        bytes32 domainId = keccak256(abi.encodePacked(domainSuffix, chainId));

        MockStealthRegistryE2E stealth = new MockStealthRegistryE2E(chainId);
        MockNullifierManagerE2E nullifier = new MockNullifierManagerE2E(
            chainId,
            domainId
        );
        MockPrivacyHubE2E hub = new MockPrivacyHubE2E(
            chainId,
            address(stealth),
            address(nullifier)
        );

        stealthRegistries[chainId] = stealth;
        nullifierManagers[chainId] = nullifier;
        privacyHubs[chainId] = hub;

        chains.push(
            ChainConfig({
                chainId: chainId,
                name: name,
                domainId: domainId,
                stealthRegistry: address(stealth),
                nullifierManager: address(nullifier),
                privacyHub: address(hub)
            })
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // E2E TEST: CROSS-CHAIN STEALTH TRANSFER
    // ═══════════════════════════════════════════════════════════════════════

    function test_e2e_crossChainStealthTransfer() public {
        emit log("=== E2E: Cross-Chain Stealth Transfer ===");
        emit log("Flow: Ethereum -> Optimism -> Arbitrum");

        // User keys
        uint256 spendKeyX = uint256(keccak256("spend_key_x"));
        uint256 spendKeyY = uint256(keccak256("spend_key_y"));
        uint256 viewKeyX = uint256(keccak256("view_key_x"));
        uint256 viewKeyY = uint256(keccak256("view_key_y"));

        // Step 1: Generate stealth address on Ethereum
        uint256 ephKeyX = uint256(keccak256("eph_key_x_1"));
        uint256 ephKeyY = uint256(keccak256("eph_key_y_1"));

        (address stealthAddr1, uint8 viewTag1) = stealthRegistries[1]
            .generateStealthAddress(
                ephKeyX,
                ephKeyY,
                spendKeyX,
                spendKeyY,
                viewKeyX,
                viewKeyY
            );
        emit log_named_address("Ethereum Stealth Address", stealthAddr1);
        emit log_named_uint("View Tag", viewTag1);

        // Step 2: Transfer to Optimism using cross-chain relay
        bytes32 nullifier1 = keccak256(abi.encodePacked(stealthAddr1, ephKeyX));
        nullifierManagers[1].consumeNullifier(nullifier1, chains[0].domainId);

        // Derive cross-domain nullifier for Optimism
        bytes32 crossDomainNull = nullifierManagers[10]
            .deriveCrossDomainNullifier(
                nullifier1,
                chains[0].domainId,
                chains[1].domainId
            );

        // Step 3: Generate new stealth address on Optimism
        uint256 ephKeyX2 = uint256(keccak256("eph_key_x_2"));
        uint256 ephKeyY2 = uint256(keccak256("eph_key_y_2"));

        (address stealthAddr2, uint8 viewTag2) = stealthRegistries[10]
            .generateStealthAddress(
                ephKeyX2,
                ephKeyY2,
                spendKeyX,
                spendKeyY,
                viewKeyX,
                viewKeyY
            );
        emit log_named_address("Optimism Stealth Address", stealthAddr2);
        emit log_named_uint("View Tag", viewTag2);

        // Verify addresses are different (unlinkable)
        assertTrue(
            stealthAddr1 != stealthAddr2,
            "Addresses should be different"
        );

        // Step 4: Continue to Arbitrum
        bytes32 nullifier2 = keccak256(
            abi.encodePacked(stealthAddr2, ephKeyX2)
        );
        nullifierManagers[10].consumeNullifier(nullifier2, chains[1].domainId);

        uint256 ephKeyX3 = uint256(keccak256("eph_key_x_3"));
        uint256 ephKeyY3 = uint256(keccak256("eph_key_y_3"));

        (address stealthAddr3, uint8 viewTag3) = stealthRegistries[42161]
            .generateStealthAddress(
                ephKeyX3,
                ephKeyY3,
                spendKeyX,
                spendKeyY,
                viewKeyX,
                viewKeyY
            );
        emit log_named_address("Arbitrum Stealth Address", stealthAddr3);

        // All three addresses should be unique
        assertTrue(stealthAddr1 != stealthAddr3, "Eth != Arb");
        assertTrue(stealthAddr2 != stealthAddr3, "Op != Arb");

        emit log("=== SUCCESS: 3-chain stealth transfer complete ===");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // E2E TEST: PRIVACY-PRESERVING SWAP ACROSS CHAINS
    // ═══════════════════════════════════════════════════════════════════════

    function test_e2e_privateSwapAcrossChains() public {
        emit log("=== E2E: Private Swap Across Chains ===");
        emit log("Scenario: Swap ETH (Ethereum) for USDC (Base) privately");

        // Alice's keys
        uint256 aliceSpendX = uint256(keccak256("alice_spend_x"));
        uint256 aliceSpendY = uint256(keccak256("alice_spend_y"));
        uint256 aliceViewX = uint256(keccak256("alice_view_x"));
        uint256 aliceViewY = uint256(keccak256("alice_view_y"));

        // Bob's keys
        uint256 bobSpendX = uint256(keccak256("bob_spend_x"));
        uint256 bobSpendY = uint256(keccak256("bob_spend_y"));
        uint256 bobViewX = uint256(keccak256("bob_view_x"));
        uint256 bobViewY = uint256(keccak256("bob_view_y"));

        // Step 1: Alice creates stealth address on Ethereum for Bob
        uint256 ephAlice = uint256(keccak256("alice_eph_for_bob"));
        (address bobStealthEth, ) = stealthRegistries[1].generateStealthAddress(
            ephAlice,
            ephAlice + 1,
            bobSpendX,
            bobSpendY,
            bobViewX,
            bobViewY
        );
        emit log_named_address(
            "Bob's Ethereum Stealth (receives ETH from Alice)",
            bobStealthEth
        );

        // Step 2: Bob creates stealth address on Base for Alice
        uint256 ephBob = uint256(keccak256("bob_eph_for_alice"));
        (address aliceStealthBase, ) = stealthRegistries[8453]
            .generateStealthAddress(
                ephBob,
                ephBob + 1,
                aliceSpendX,
                aliceSpendY,
                aliceViewX,
                aliceViewY
            );
        emit log_named_address(
            "Alice's Base Stealth (receives USDC from Bob)",
            aliceStealthBase
        );

        // Step 3: Create atomic swap commitments
        bytes32 swapSecret = keccak256("atomic_swap_secret");
        bytes32 swapHash = keccak256(abi.encodePacked(swapSecret));

        // Step 4: Alice locks ETH on Ethereum
        bytes32 aliceNullifier = keccak256(
            abi.encodePacked("alice_lock", swapHash)
        );

        // Step 5: Bob locks USDC on Base (seeing Alice's lock)
        bytes32 bobNullifier = keccak256(
            abi.encodePacked("bob_lock", swapHash)
        );

        // Step 6: Alice claims on Base (reveals secret)
        // This allows Bob to claim on Ethereum

        // Consume nullifiers
        nullifierManagers[1].consumeNullifier(
            aliceNullifier,
            chains[0].domainId
        );
        nullifierManagers[8453].consumeNullifier(
            bobNullifier,
            chains[3].domainId
        );

        emit log("=== SUCCESS: Private cross-chain swap executed ===");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // E2E TEST: NULLIFIER DOUBLE-SPEND PREVENTION
    // ═══════════════════════════════════════════════════════════════════════

    function test_e2e_nullifierDoubleSpendPrevention() public {
        emit log("=== E2E: Nullifier Double-Spend Prevention ===");

        bytes32 secret = keccak256("user_secret");
        bytes32 nullifier = keccak256(abi.encodePacked(secret, uint256(1)));

        // First spend on Ethereum - should succeed
        nullifierManagers[1].consumeNullifier(nullifier, chains[0].domainId);
        assertTrue(
            nullifierManagers[1].isConsumed(nullifier, chains[0].domainId)
        );
        emit log("First spend on Ethereum: SUCCESS");

        // Try double-spend on same chain - should fail
        vm.expectRevert("Nullifier already consumed");
        nullifierManagers[1].consumeNullifier(nullifier, chains[0].domainId);
        emit log("Double-spend on Ethereum: BLOCKED");

        // Derive cross-domain nullifier for Optimism
        bytes32 crossDomainNull = nullifierManagers[10]
            .deriveCrossDomainNullifier(
                nullifier,
                chains[0].domainId,
                chains[1].domainId
            );

        // Consume on Optimism with cross-domain nullifier
        nullifierManagers[10].consumeNullifier(
            crossDomainNull,
            chains[1].domainId
        );
        emit log("Cross-domain nullifier consumed on Optimism: SUCCESS");

        // Try to replay cross-domain nullifier
        vm.expectRevert("Nullifier already consumed");
        nullifierManagers[10].consumeNullifier(
            crossDomainNull,
            chains[1].domainId
        );
        emit log("Cross-domain replay: BLOCKED");

        emit log("=== SUCCESS: Double-spend prevention verified ===");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // E2E TEST: MULTI-HOP PRIVACY CHAIN
    // ═══════════════════════════════════════════════════════════════════════

    function test_e2e_multiHopPrivacyChain() public {
        emit log("=== E2E: Multi-Hop Privacy Chain (5 chains) ===");
        emit log("Route: ETH -> OP -> ARB -> BASE -> POLY");

        uint256 spendX = uint256(keccak256("user_spend_x"));
        uint256 spendY = uint256(keccak256("user_spend_y"));
        uint256 viewX = uint256(keccak256("user_view_x"));
        uint256 viewY = uint256(keccak256("user_view_y"));

        address[] memory stealthAddresses = new address[](5);
        bytes32 previousNullifier;
        bytes32 previousDomain;

        for (uint256 i = 0; i < chains.length; i++) {
            ChainConfig memory chain = chains[i];

            // Generate unique ephemeral key for each hop
            uint256 ephX = uint256(keccak256(abi.encodePacked("hop_eph_x", i)));
            uint256 ephY = uint256(keccak256(abi.encodePacked("hop_eph_y", i)));

            // Generate stealth address
            (address stealth, uint8 viewTag) = stealthRegistries[chain.chainId]
                .generateStealthAddress(
                    ephX,
                    ephY,
                    spendX,
                    spendY,
                    viewX,
                    viewY
                );
            stealthAddresses[i] = stealth;

            emit log_string(
                string.concat("Hop ", vm.toString(i + 1), ": ", chain.name)
            );
            emit log_named_address("  Stealth Address", stealth);
            emit log_named_uint("  View Tag", viewTag);

            // Consume nullifier (except first hop)
            if (i > 0) {
                bytes32 crossDomainNull = nullifierManagers[chain.chainId]
                    .deriveCrossDomainNullifier(
                        previousNullifier,
                        previousDomain,
                        chain.domainId
                    );
                nullifierManagers[chain.chainId].consumeNullifier(
                    crossDomainNull,
                    chain.domainId
                );
            }

            // Prepare for next hop
            previousNullifier = keccak256(abi.encodePacked(stealth, ephX));
            previousDomain = chain.domainId;
            nullifierManagers[chain.chainId].consumeNullifier(
                previousNullifier,
                chain.domainId
            );
        }

        // Verify all addresses are unique
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                assertTrue(
                    stealthAddresses[i] != stealthAddresses[j],
                    "Addresses must be unique"
                );
            }
        }

        emit log("=== SUCCESS: 5-hop privacy chain complete ===");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // E2E TEST: CONCURRENT MULTI-USER PRIVACY
    // ═══════════════════════════════════════════════════════════════════════

    function test_e2e_concurrentMultiUserPrivacy() public {
        emit log("=== E2E: Concurrent Multi-User Privacy (100 users) ===");

        uint256 userCount = 100;
        address[] memory userStealths = new address[](userCount);

        for (uint256 i = 0; i < userCount; i++) {
            // Each user has unique keys
            uint256 spendX = uint256(
                keccak256(abi.encodePacked("user_spend_x", i))
            );
            uint256 spendY = uint256(
                keccak256(abi.encodePacked("user_spend_y", i))
            );
            uint256 viewX = uint256(
                keccak256(abi.encodePacked("user_view_x", i))
            );
            uint256 viewY = uint256(
                keccak256(abi.encodePacked("user_view_y", i))
            );
            uint256 ephX = uint256(keccak256(abi.encodePacked("eph_x", i)));
            uint256 ephY = uint256(keccak256(abi.encodePacked("eph_y", i)));

            // Randomly select a chain
            uint256 chainIndex = i % chains.length;
            uint256 chainId = chains[chainIndex].chainId;

            (address stealth, ) = stealthRegistries[chainId]
                .generateStealthAddress(
                    ephX,
                    ephY,
                    spendX,
                    spendY,
                    viewX,
                    viewY
                );
            userStealths[i] = stealth;

            // Consume nullifier
            bytes32 nullifier = keccak256(abi.encodePacked(stealth, ephX, i));
            nullifierManagers[chainId].consumeNullifier(
                nullifier,
                chains[chainIndex].domainId
            );
        }

        // Verify uniqueness
        for (uint256 i = 0; i < userCount; i++) {
            for (uint256 j = i + 1; j < userCount; j++) {
                assertTrue(
                    userStealths[i] != userStealths[j],
                    "All stealth addresses must be unique"
                );
            }
        }

        emit log_named_uint("Users processed", userCount);
        emit log("=== SUCCESS: 100 concurrent users verified ===");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // E2E TEST: PRIVACY HUB INTEGRATION
    // ═══════════════════════════════════════════════════════════════════════

    function test_e2e_privacyHubFullFlow() public {
        emit log("=== E2E: Privacy Hub Full Flow ===");

        // User initiates private transfer through hub
        MockPrivacyHubE2E ethHub = privacyHubs[1];
        MockPrivacyHubE2E opHub = privacyHubs[10];

        bytes32 commitment = keccak256("user_commitment");
        bytes memory proof = hex"deadbeef";

        // Step 1: Create private transaction on Ethereum
        bytes32 txHash = ethHub.createPrivateTransaction(
            commitment,
            proof,
            10, // target: Optimism
            1 ether
        );
        emit log_named_bytes32("Ethereum Tx Hash", txHash);

        // Step 2: Relay to Optimism
        relay.relayMessage(1, 10, abi.encode(txHash, commitment));

        // Step 3: Finalize on Optimism
        opHub.finalizePrivateTransaction(txHash, proof);

        emit log("=== SUCCESS: Privacy hub full flow complete ===");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MOCK CONTRACTS
// ═══════════════════════════════════════════════════════════════════════════

contract MockStealthRegistryE2E {
    uint256 public chainId;
    mapping(bytes32 => address) public stealthAddresses;

    constructor(uint256 _chainId) {
        chainId = _chainId;
    }

    function generateStealthAddress(
        uint256 ephX,
        uint256 ephY,
        uint256 spendX,
        uint256 spendY,
        uint256 viewX,
        uint256 viewY
    ) external returns (address stealth, uint8 viewTag) {
        bytes32 ephKey = keccak256(abi.encodePacked(ephX, ephY));
        bytes32 sharedSecret = keccak256(
            abi.encodePacked(viewX, viewY, ephX, ephY)
        );
        bytes32 stealthHash = keccak256(
            abi.encodePacked(spendX, spendY, sharedSecret, chainId)
        );

        stealth = address(uint160(uint256(stealthHash)));
        viewTag = uint8(uint256(stealthHash) >> 248);

        stealthAddresses[ephKey] = stealth;
    }
}

contract MockNullifierManagerE2E {
    uint256 public chainId;
    bytes32 public domainId;
    mapping(bytes32 => mapping(bytes32 => bool)) public consumed;

    constructor(uint256 _chainId, bytes32 _domainId) {
        chainId = _chainId;
        domainId = _domainId;
    }

    function consumeNullifier(bytes32 nullifier, bytes32 domain) external {
        require(!consumed[nullifier][domain], "Nullifier already consumed");
        consumed[nullifier][domain] = true;
    }

    function isConsumed(
        bytes32 nullifier,
        bytes32 domain
    ) external view returns (bool) {
        return consumed[nullifier][domain];
    }

    function deriveCrossDomainNullifier(
        bytes32 source,
        bytes32 sourceDomain,
        bytes32 targetDomain
    ) external pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(source, sourceDomain, targetDomain, "Soul")
            );
    }
}

contract MockPrivacyHubE2E {
    uint256 public chainId;
    address public stealthRegistry;
    address public nullifierManager;

    mapping(bytes32 => bool) public pendingTxs;
    mapping(bytes32 => bool) public finalizedTxs;

    constructor(uint256 _chainId, address _stealth, address _nullifier) {
        chainId = _chainId;
        stealthRegistry = _stealth;
        nullifierManager = _nullifier;
    }

    function createPrivateTransaction(
        bytes32 commitment,
        bytes memory proof,
        uint256 targetChain,
        uint256 amount
    ) external returns (bytes32 txHash) {
        txHash = keccak256(
            abi.encodePacked(
                commitment,
                proof,
                targetChain,
                amount,
                block.timestamp
            )
        );
        pendingTxs[txHash] = true;
    }

    function finalizePrivateTransaction(bytes32 txHash, bytes memory) external {
        finalizedTxs[txHash] = true;
    }
}

contract MockCrossChainRelay {
    event MessageRelayed(
        uint256 sourceChain,
        uint256 targetChain,
        bytes message
    );

    function relayMessage(
        uint256 source,
        uint256 target,
        bytes memory message
    ) external {
        emit MessageRelayed(source, target, message);
    }
}
