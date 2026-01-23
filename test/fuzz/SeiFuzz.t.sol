// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/sei/SeiPrimitives.sol";
import "../../contracts/crosschain/SeiBridgeAdapter.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title SeiFuzz
 * @notice Comprehensive fuzz tests for Sei integration
 * @dev Tests primitives, bridge adapter, validator set, and nullifier operations
 */
contract SeiFuzz is Test {
    using SeiPrimitives for *;

    SeiBridgeAdapter public bridge;

    address public admin = address(0x1);
    address public relayer = address(0x2);
    address public user = address(0x3);

    function setUp() public {
        vm.startPrank(admin);

        // Deploy implementation
        SeiBridgeAdapter implementation = new SeiBridgeAdapter();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            SeiBridgeAdapter.initialize.selector,
            admin
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        bridge = SeiBridgeAdapter(payable(address(proxy)));

        // Setup roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Register initial validator
        bytes memory pubKey = new bytes(33);
        for (uint i = 0; i < 33; i++) {
            pubKey[i] = bytes1(uint8(i + 1));
        }

        bridge.registerValidator(bytes32(uint256(1)), pubKey, 1000 ether);

        // Add token mapping
        bridge.addTokenMapping("usei", address(0));

        vm.stopPrank();
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test SHA256 hash determinism
    function testFuzz_Sha256Determinism(bytes memory data) public pure {
        bytes32 hash1 = SeiPrimitives.sha256Hash(data);
        bytes32 hash2 = SeiPrimitives.sha256Hash(data);
        assertEq(hash1, hash2, "SHA256 should be deterministic");
    }

    /// @notice Fuzz test SHA256 collision resistance
    function testFuzz_Sha256CollisionResistance(
        bytes memory data1,
        bytes memory data2
    ) public pure {
        vm.assume(keccak256(data1) != keccak256(data2));
        bytes32 hash1 = SeiPrimitives.sha256Hash(data1);
        bytes32 hash2 = SeiPrimitives.sha256Hash(data2);
        assertNotEq(
            hash1,
            hash2,
            "Different inputs should produce different hashes"
        );
    }

    /// @notice Fuzz test hash2 properties
    function testFuzz_Hash2Properties(bytes32 a, bytes32 b) public pure {
        bytes32 result1 = SeiPrimitives.hash2(a, b);
        bytes32 result2 = SeiPrimitives.hash2(a, b);
        assertEq(result1, result2, "hash2 should be deterministic");

        // Order matters
        if (a != b) {
            bytes32 ab = SeiPrimitives.hash2(a, b);
            bytes32 ba = SeiPrimitives.hash2(b, a);
            assertNotEq(ab, ba, "hash2 should not be commutative");
        }
    }

    /// @notice Fuzz test hashN with varying inputs
    function testFuzz_HashN(bytes32[] memory inputs) public pure {
        vm.assume(inputs.length > 0 && inputs.length < 100);

        bytes32 result1 = SeiPrimitives.hashN(inputs);
        bytes32 result2 = SeiPrimitives.hashN(inputs);
        assertEq(result1, result2, "hashN should be deterministic");
    }

    // =========================================================================
    // NULLIFIER FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test nullifier derivation
    function testFuzz_DeriveNullifier(
        bytes32 txHash,
        int64 height,
        uint64 index
    ) public pure {
        vm.assume(height > 0);

        bytes32 nf1 = SeiPrimitives.deriveNullifier(txHash, height, index);
        bytes32 nf2 = SeiPrimitives.deriveNullifier(txHash, height, index);
        assertEq(nf1, nf2, "Nullifier derivation should be deterministic");

        // Different tx should give different nullifier
        bytes32 nfDifferent = SeiPrimitives.deriveNullifier(
            bytes32(uint256(txHash) ^ 1),
            height,
            index
        );
        if (txHash != bytes32(uint256(txHash) ^ 1)) {
            assertNotEq(
                nf1,
                nfDifferent,
                "Different txHash should have different nullifiers"
            );
        }
    }

    /// @notice Fuzz test cross-domain nullifier
    function testFuzz_CrossDomainNullifier(
        bytes32 seiNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) public pure {
        vm.assume(sourceChain != targetChain);

        bytes32 crossNf = SeiPrimitives.deriveCrossDomainNullifier(
            seiNullifier,
            sourceChain,
            targetChain
        );

        bytes32 crossNf2 = SeiPrimitives.deriveCrossDomainNullifier(
            seiNullifier,
            sourceChain,
            targetChain
        );
        assertEq(
            crossNf,
            crossNf2,
            "Cross-domain nullifier should be deterministic"
        );

        // Different chains should give different nullifiers
        bytes32 crossNfReverse = SeiPrimitives.deriveCrossDomainNullifier(
            seiNullifier,
            targetChain,
            sourceChain
        );
        assertNotEq(crossNf, crossNfReverse, "Direction should matter");
    }

    /// @notice Fuzz test PIL binding derivation
    function testFuzz_PILBinding(bytes32 seiNullifier) public pure {
        bytes32 binding1 = SeiPrimitives.derivePILBinding(seiNullifier);
        bytes32 binding2 = SeiPrimitives.derivePILBinding(seiNullifier);
        assertEq(binding1, binding2, "PIL binding should be deterministic");

        // Different nullifier = different binding
        bytes32 differentNullifier = bytes32(uint256(seiNullifier) ^ 1);
        bytes32 bindingDiff = SeiPrimitives.derivePILBinding(
            differentNullifier
        );
        if (seiNullifier != differentNullifier) {
            assertNotEq(
                binding1,
                bindingDiff,
                "Different nullifiers should have different bindings"
            );
        }
    }

    // =========================================================================
    // FINALITY FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test finality calculation
    function testFuzz_HasFinality(
        uint256 signingPower,
        uint256 totalPower
    ) public pure {
        vm.assume(totalPower > 0);
        vm.assume(totalPower < type(uint128).max);
        vm.assume(signingPower <= totalPower);
        vm.assume(signingPower > 0);

        bool finality = SeiPrimitives.hasFinality(signingPower, totalPower);

        // Manual check: 2/3 + 1 threshold
        bool expected = signingPower * 10000 >= totalPower * 6667;

        assertEq(finality, expected, "Finality calculation mismatch");
    }

    /// @notice Fuzz test zero total power
    function testFuzz_ZeroTotalPower(uint256 signingPower) public pure {
        bool finality = SeiPrimitives.hasFinality(signingPower, 0);
        assertFalse(finality, "Zero total power should not have finality");
    }

    // =========================================================================
    // IBC FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test IBC packet commitment
    function testFuzz_PacketCommitment(
        uint64 sequence,
        bytes memory data
    ) public pure {
        vm.assume(data.length < 1000);

        SeiPrimitives.IBCPacket memory packet = SeiPrimitives.IBCPacket({
            sequence: sequence,
            sourcePort: "transfer",
            sourceChannel: "channel-0",
            destPort: "transfer",
            destChannel: "channel-1",
            data: data,
            timeoutHeight: 0,
            timeoutTimestamp: uint64(600) // Use fixed value for pure function
        });

        bytes32 commitment1 = SeiPrimitives.computePacketCommitment(packet);
        bytes32 commitment2 = SeiPrimitives.computePacketCommitment(packet);
        assertEq(
            commitment1,
            commitment2,
            "Packet commitment should be deterministic"
        );
    }

    /// @notice Fuzz test IBC channel validation
    function testFuzz_ChannelState(uint8 state) public pure {
        SeiPrimitives.IBCChannel memory channel = SeiPrimitives.IBCChannel({
            channelId: "channel-0",
            portId: "transfer",
            counterpartyChannelId: "channel-1",
            counterpartyPortId: "transfer",
            connectionId: "connection-0",
            state: state,
            ordering: 1
        });

        bool isOpen = SeiPrimitives.isChannelOpen(channel);
        assertEq(
            isOpen,
            state == 3,
            "Channel should be open only when state is 3"
        );
    }

    // =========================================================================
    // CHAIN VALIDATION FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test Sei chain ID validation
    function testFuzz_IsSeiChain(uint256 chainId) public pure {
        bool isSei = SeiPrimitives.isSeiChain(chainId);
        bool expected = chainId == 1329 || chainId == 1328;
        assertEq(isSei, expected, "Chain validation mismatch");
    }

    /// @notice Fuzz test height validation
    function testFuzz_IsValidHeight(int64 height) public pure {
        bool valid = SeiPrimitives.isValidHeight(height);
        assertEq(valid, height > 0, "Height validation mismatch");
    }

    // =========================================================================
    // MESSAGE FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test message ID computation
    function testFuzz_MessageId(
        uint256 sourceChain,
        uint256 targetChain,
        bytes32 sender,
        address recipient,
        bytes memory payload,
        uint64 nonce
    ) public pure {
        vm.assume(payload.length < 1000);

        SeiPrimitives.SeiMessage memory message = SeiPrimitives.SeiMessage({
            messageId: bytes32(0),
            sourceChainId: sourceChain,
            targetChainId: targetChain,
            sender: sender,
            recipient: recipient,
            payload: payload,
            nonce: nonce,
            timestamp: 0,
            execMode: SeiPrimitives.ExecutionMode.EVM_PARALLEL
        });

        bytes32 id1 = SeiPrimitives.computeMessageId(message);
        bytes32 id2 = SeiPrimitives.computeMessageId(message);
        assertEq(id1, id2, "Message ID should be deterministic");
    }

    /// @notice Fuzz test transfer ID computation
    function testFuzz_TransferId(
        uint256 amount,
        bytes32 sender,
        address recipient,
        int64 sourceHeight,
        bytes32 txHash
    ) public pure {
        vm.assume(sourceHeight > 0);

        SeiPrimitives.SeiBridgeTransfer memory transfer = SeiPrimitives
            .SeiBridgeTransfer({
                transferId: bytes32(0),
                denom: "usei",
                amount: amount,
                sender: sender,
                recipient: recipient,
                sourceHeight: sourceHeight,
                txHash: txHash
            });

        bytes32 id1 = SeiPrimitives.computeTransferId(transfer);
        bytes32 id2 = SeiPrimitives.computeTransferId(transfer);
        assertEq(id1, id2, "Transfer ID should be deterministic");
    }

    // =========================================================================
    // MERKLE FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test Merkle root computation
    function testFuzz_MerkleRoot(bytes32[] memory leaves) public pure {
        vm.assume(leaves.length > 0 && leaves.length <= 64);

        bytes32 root1 = SeiPrimitives.computeMerkleRoot(leaves);
        bytes32 root2 = SeiPrimitives.computeMerkleRoot(leaves);
        assertEq(root1, root2, "Merkle root should be deterministic");
    }

    /// @notice Fuzz test single leaf Merkle root
    function testFuzz_SingleLeafMerkle(bytes32 leaf) public pure {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = leaf;

        bytes32 root = SeiPrimitives.computeMerkleRoot(leaves);
        assertEq(root, leaf, "Single leaf should be root");
    }

    // =========================================================================
    // DEX FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test order ID computation
    function testFuzz_OrderId(bytes32 creator, uint64 nonce) public pure {
        bytes32 orderId1 = SeiPrimitives.computeOrderId(
            creator,
            "sei1market",
            nonce
        );
        bytes32 orderId2 = SeiPrimitives.computeOrderId(
            creator,
            "sei1market",
            nonce
        );
        assertEq(orderId1, orderId2, "Order ID should be deterministic");
    }

    /// @notice Fuzz test pair ID computation
    function testFuzz_PairId(
        string memory baseAsset,
        string memory quoteAsset
    ) public pure {
        vm.assume(bytes(baseAsset).length > 0 && bytes(baseAsset).length < 50);
        vm.assume(
            bytes(quoteAsset).length > 0 && bytes(quoteAsset).length < 50
        );

        bytes32 pairId1 = SeiPrimitives.computePairId(baseAsset, quoteAsset);
        bytes32 pairId2 = SeiPrimitives.computePairId(baseAsset, quoteAsset);
        assertEq(pairId1, pairId2, "Pair ID should be deterministic");
    }

    // =========================================================================
    // SIGNATURE FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test signature recovery
    function testFuzz_SignatureRecovery(
        uint256 privateKey,
        bytes32 messageHash
    ) public pure {
        vm.assume(privateKey > 0);
        vm.assume(
            privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );

        address signer = vm.addr(privateKey);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        address recovered = SeiPrimitives.recoverSigner(messageHash, signature);
        assertEq(recovered, signer, "Signature recovery should match signer");
    }

    /// @notice Fuzz test signature verification
    function testFuzz_SignatureVerification(
        uint256 privateKey,
        bytes32 messageHash
    ) public pure {
        vm.assume(privateKey > 0);
        vm.assume(
            privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );

        address signer = vm.addr(privateKey);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool valid = SeiPrimitives.verifySignature(
            messageHash,
            signature,
            signer
        );
        assertTrue(valid, "Valid signature should verify");
    }

    /// @notice Fuzz test invalid signature length
    function testFuzz_InvalidSignatureLength(
        bytes memory signature
    ) public pure {
        vm.assume(signature.length != 65);

        address recovered = SeiPrimitives.recoverSigner(bytes32(0), signature);
        assertEq(
            recovered,
            address(0),
            "Invalid signature length should return zero address"
        );
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test deposit initiation
    function testFuzz_Deposit(uint256 amount, bytes32 seiRecipient) public {
        vm.assume(amount > 0 && amount <= 100_000 ether);
        vm.assume(seiRecipient != bytes32(0));

        vm.deal(user, amount);
        vm.prank(user);

        bridge.deposit{value: amount}(address(0), amount, seiRecipient);

        uint256 todayVolume = bridge.getTodayVolume();
        assertEq(todayVolume, amount, "Daily volume should be updated");
    }

    /// @notice Fuzz test deposit with valid recipient only
    function testFuzz_DepositRecipientValidation(bytes32 recipient) public {
        uint256 amount = 1 ether;
        vm.deal(user, amount);
        vm.prank(user);

        if (recipient == bytes32(0)) {
            vm.expectRevert(SeiBridgeAdapter.InvalidRecipient.selector);
            bridge.deposit{value: amount}(address(0), amount, recipient);
        } else {
            bridge.deposit{value: amount}(address(0), amount, recipient);
        }
    }

    /// @notice Fuzz test validator registration
    function testFuzz_ValidatorRegistration(
        bytes32 operatorAddress,
        uint256 votingPower
    ) public {
        vm.assume(votingPower > 0 && votingPower < type(uint128).max);
        vm.assume(operatorAddress != bytes32(uint256(1))); // Avoid existing validator

        bytes memory pubKey = new bytes(33);
        for (uint i = 0; i < 33; i++) {
            pubKey[i] = bytes1(uint8(i + 1));
        }

        vm.prank(admin);
        bridge.registerValidator(operatorAddress, pubKey, votingPower);
    }

    /// @notice Fuzz test invalid pubkey length
    function testFuzz_InvalidPubKeyLength(uint8 keyLength) public {
        vm.assume(keyLength != 33);
        vm.assume(keyLength < 200);

        bytes memory pubKey = new bytes(keyLength);

        vm.prank(admin);
        vm.expectRevert(SeiBridgeAdapter.InvalidValidator.selector);
        bridge.registerValidator(bytes32(uint256(999)), pubKey, 1000 ether);
    }

    /// @notice Fuzz test daily limit enforcement
    function testFuzz_DailyLimitEnforcement(uint256 amount) public {
        amount = bound(amount, 100_001 ether, 1_000_000 ether);

        vm.deal(user, amount);
        vm.prank(user);

        vm.expectRevert(SeiBridgeAdapter.TransferTooLarge.selector);
        bridge.deposit{value: amount}(
            address(0),
            amount,
            bytes32(uint256(123))
        );
    }

    /// @notice Fuzz test nullifier consumption check
    function testFuzz_NullifierConsumption(bytes32 nullifier) public view {
        bool consumed = bridge.isNullifierConsumed(nullifier);
        assertFalse(consumed, "New nullifier should not be consumed");
    }

    /// @notice Fuzz test circuit breaker trigger
    function testFuzz_CircuitBreakerTrigger() public {
        vm.prank(admin);
        bridge.triggerCircuitBreaker();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(SeiBridgeAdapter.CircuitBreakerActive.selector);
        bridge.deposit{value: 1 ether}(
            address(0),
            1 ether,
            bytes32(uint256(123))
        );
    }

    /// @notice Fuzz test relayer registration
    function testFuzz_RelayerRegistration(
        address relayerAddr,
        uint256 feeBps
    ) public {
        vm.assume(relayerAddr != address(0));
        vm.assume(feeBps <= 500); // Max 5%

        vm.prank(admin);
        bridge.registerRelayer(relayerAddr, feeBps);

        (bool isActive, uint256 fee, , ) = bridge.relayers(relayerAddr);
        assertTrue(isActive, "Relayer should be active");
        assertEq(fee, feeBps, "Fee should match");
    }

    /// @notice Fuzz test invalid relayer fee
    function testFuzz_InvalidRelayerFee(uint256 feeBps) public {
        vm.assume(feeBps > 500);

        vm.prank(admin);
        vm.expectRevert(SeiBridgeAdapter.InvalidRelayerFee.selector);
        bridge.registerRelayer(address(0x999), feeBps);
    }

    /// @notice Fuzz test IBC channel registration
    function testFuzz_IBCChannelRegistration() public {
        vm.prank(admin);
        bridge.registerIBCChannel(
            "channel-0",
            "transfer",
            "channel-100",
            "transfer",
            "connection-0"
        );

        uint256 channelCount = bridge.getIBCChannelCount();
        assertEq(channelCount, 1, "Should have 1 channel");
    }

    /// @notice Fuzz test user daily limit
    function testFuzz_UserDailyLimit(address userAddr, uint256 limit) public {
        vm.assume(userAddr != address(0));
        vm.assume(limit > 0);

        vm.prank(admin);
        bridge.setUserDailyLimit(userAddr, limit);

        assertEq(bridge.userDailyLimit(userAddr), limit, "Limit should be set");
    }

    /// @notice Fuzz test pause/unpause
    function testFuzz_PauseUnpause() public {
        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.deposit{value: 1 ether}(
            address(0),
            1 ether,
            bytes32(uint256(123))
        );

        vm.prank(admin);
        bridge.unpause();

        vm.prank(user);
        bridge.deposit{value: 1 ether}(
            address(0),
            1 ether,
            bytes32(uint256(123))
        );
    }

    // =========================================================================
    // INVARIANT PROPERTIES
    // =========================================================================

    /// @notice Invariant: daily volume should not exceed max
    function invariant_DailyVolumeLimit() public view {
        uint256 todayVolume = bridge.getTodayVolume();
        assertTrue(
            todayVolume <= 1_000_000 ether,
            "Daily volume should not exceed max"
        );
    }
}
