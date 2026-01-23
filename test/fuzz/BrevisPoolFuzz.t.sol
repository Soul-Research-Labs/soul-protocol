// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/brevis/BrevisPrimitives.sol";
import "../../contracts/crosschain/BrevisPrivacyPoolAdapter.sol";

/**
 * @title BrevisPoolFuzz
 * @notice Fuzz tests for Brevis Privacy Pool on BNB Chain
 * @dev Tests primitives, pool operations, and cross-domain functionality
 */
contract BrevisPoolFuzz is Test {
    using BrevisPrimitives for *;

    BrevisPrivacyPoolAdapter public pool;
    address public admin;
    address public user1;
    address public user2;
    address public relayer;
    address public brevisProver;

    bytes32 constant ZERO_VALUE = keccak256("brevis.privacy.pool");

    function setUp() public {
        admin = makeAddr("admin");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        relayer = makeAddr("relayer");
        brevisProver = makeAddr("brevisProver");

        vm.prank(admin);
        pool = new BrevisPrivacyPoolAdapter(admin, brevisProver, ZERO_VALUE);

        vm.deal(user1, 10000 ether);
        vm.deal(user2, 10000 ether);
        vm.deal(relayer, 100 ether);

        vm.prank(relayer);
        pool.registerRelayer();
    }

    // =========================================================================
    // PRIMITIVES TESTS
    // =========================================================================

    function testFuzz_Hash2Determinism(
        bytes32 left,
        bytes32 right
    ) public pure {
        bytes32 hash1 = BrevisPrimitives.hash2(left, right);
        bytes32 hash2 = BrevisPrimitives.hash2(left, right);
        assertEq(hash1, hash2, "Hash2 not deterministic");
    }

    function testFuzz_Hash2Uniqueness(
        bytes32 left1,
        bytes32 right1,
        bytes32 left2,
        bytes32 right2
    ) public pure {
        vm.assume(left1 != left2 || right1 != right2);

        bytes32 hash1 = BrevisPrimitives.hash2(left1, right1);
        bytes32 hash2 = BrevisPrimitives.hash2(left2, right2);

        assertNotEq(hash1, hash2, "Different inputs produced same hash");
    }

    function testFuzz_HashNDeterminism(bytes32[] memory inputs) public pure {
        vm.assume(inputs.length > 0 && inputs.length <= 10);

        bytes32 hash1 = BrevisPrimitives.hashN(inputs);
        bytes32 hash2 = BrevisPrimitives.hashN(inputs);

        assertEq(hash1, hash2, "HashN not deterministic");
    }

    function testFuzz_CommitmentComputation(
        uint256 amount,
        address token,
        bytes32 blinding
    ) public pure {
        amount = bound(amount, 1, type(uint128).max);

        bytes32 c1 = BrevisPrimitives.computeCommitment(
            amount,
            token,
            blinding
        );
        bytes32 c2 = BrevisPrimitives.computeCommitment(
            amount,
            token,
            blinding
        );

        assertEq(c1, c2, "Commitment not deterministic");
        assertNotEq(c1, bytes32(0), "Commitment should not be zero");
    }

    function testFuzz_CommitmentUniqueness(
        uint256 amount1,
        uint256 amount2,
        address token,
        bytes32 blinding
    ) public pure {
        amount1 = bound(amount1, 1, type(uint128).max);
        amount2 = bound(amount2, 1, type(uint128).max);
        vm.assume(amount1 != amount2);

        bytes32 c1 = BrevisPrimitives.computeCommitment(
            amount1,
            token,
            blinding
        );
        bytes32 c2 = BrevisPrimitives.computeCommitment(
            amount2,
            token,
            blinding
        );

        assertNotEq(c1, c2, "Different amounts produced same commitment");
    }

    function testFuzz_NullifierDerivation(
        bytes32 secret,
        bytes32 commitment,
        uint256 leafIndex
    ) public pure {
        leafIndex = bound(leafIndex, 0, (1 << 20) - 1);

        bytes32 nf1 = BrevisPrimitives.deriveNullifier(
            secret,
            commitment,
            leafIndex
        );
        bytes32 nf2 = BrevisPrimitives.deriveNullifier(
            secret,
            commitment,
            leafIndex
        );

        assertEq(nf1, nf2, "Nullifier not deterministic");
    }

    function testFuzz_NullifierUniqueness(
        bytes32 secret1,
        bytes32 secret2,
        bytes32 commitment,
        uint256 leafIndex
    ) public pure {
        vm.assume(secret1 != secret2);
        leafIndex = bound(leafIndex, 0, (1 << 20) - 1);

        bytes32 nf1 = BrevisPrimitives.deriveNullifier(
            secret1,
            commitment,
            leafIndex
        );
        bytes32 nf2 = BrevisPrimitives.deriveNullifier(
            secret2,
            commitment,
            leafIndex
        );

        assertNotEq(nf1, nf2, "Different secrets produced same nullifier");
    }

    // =========================================================================
    // QUERY TESTS
    // =========================================================================

    function testFuzz_QueryHashComputation(
        uint8 queryType,
        bytes memory data
    ) public pure {
        queryType = uint8(bound(queryType, 0, 4));
        vm.assume(data.length > 0 && data.length <= 1000);

        bytes32 hash1 = BrevisPrimitives.computeQueryHash(
            BrevisPrimitives.QueryType(queryType),
            data
        );
        bytes32 hash2 = BrevisPrimitives.computeQueryHash(
            BrevisPrimitives.QueryType(queryType),
            data
        );

        assertEq(hash1, hash2, "Query hash not deterministic");
    }

    function testFuzz_ReceiptQueryEncoding(
        bytes32 txHash,
        uint64 logIndex,
        uint64 blockNumber,
        address contractAddr
    ) public pure {
        BrevisPrimitives.ReceiptQuery memory query = BrevisPrimitives
            .ReceiptQuery({
                txHash: txHash,
                logIndex: logIndex,
                blockNumber: blockNumber,
                contractAddr: contractAddr,
                topics: new bytes32[](0),
                data: ""
            });

        bytes memory encoded = BrevisPrimitives.encodeReceiptQuery(query);
        assertGt(encoded.length, 0, "Encoded query should not be empty");
    }

    function testFuzz_StorageQueryEncoding(
        address contractAddr,
        bytes32 slot,
        uint64 blockNumber,
        bytes32 value
    ) public pure {
        BrevisPrimitives.StorageQuery memory query = BrevisPrimitives
            .StorageQuery({
                contractAddr: contractAddr,
                slot: slot,
                blockNumber: blockNumber,
                value: value
            });

        bytes memory encoded = BrevisPrimitives.encodeStorageQuery(query);
        assertGt(encoded.length, 0, "Encoded query should not be empty");
    }

    // =========================================================================
    // MERKLE TREE TESTS
    // =========================================================================

    function testFuzz_MerkleRootComputation(
        bytes32 leaf,
        bytes32[20] memory pathElements,
        uint256 pathBits
    ) public pure {
        pathBits = bound(pathBits, 0, (1 << 20) - 1);

        bytes32[] memory path = new bytes32[](20);
        uint256[] memory indices = new uint256[](20);

        for (uint256 i = 0; i < 20; i++) {
            path[i] = pathElements[i];
            indices[i] = (pathBits >> i) & 1;
        }

        bytes32 root1 = BrevisPrimitives.computeMerkleRoot(leaf, path, indices);
        bytes32 root2 = BrevisPrimitives.computeMerkleRoot(leaf, path, indices);

        assertEq(root1, root2, "Merkle root not deterministic");
    }

    function testFuzz_MerkleRootLeafBinding(
        bytes32 leaf1,
        bytes32 leaf2,
        bytes32[20] memory pathElements,
        uint256 pathBits
    ) public pure {
        vm.assume(leaf1 != leaf2);
        pathBits = bound(pathBits, 0, (1 << 20) - 1);

        bytes32[] memory path = new bytes32[](20);
        uint256[] memory indices = new uint256[](20);

        for (uint256 i = 0; i < 20; i++) {
            path[i] = pathElements[i];
            indices[i] = (pathBits >> i) & 1;
        }

        bytes32 root1 = BrevisPrimitives.computeMerkleRoot(
            leaf1,
            path,
            indices
        );
        bytes32 root2 = BrevisPrimitives.computeMerkleRoot(
            leaf2,
            path,
            indices
        );

        assertNotEq(root1, root2, "Different leaves produced same root");
    }

    function testFuzz_ZeroHashComputation(uint256 level) public pure {
        level = bound(level, 0, 19);
        bytes32 zeroValue = keccak256("test");

        bytes32 hash1 = BrevisPrimitives.computeZeroHash(level, zeroValue);
        bytes32 hash2 = BrevisPrimitives.computeZeroHash(level, zeroValue);

        assertEq(hash1, hash2, "Zero hash not deterministic");
    }

    // =========================================================================
    // CROSS-DOMAIN TESTS
    // =========================================================================

    function testFuzz_CrossDomainNullifierDerivation(
        bytes32 brevisNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) public pure {
        sourceChain = bound(sourceChain, 1, type(uint64).max);
        targetChain = bound(targetChain, 1, type(uint64).max);

        bytes32 cdn1 = BrevisPrimitives.deriveCrossDomainNullifier(
            brevisNullifier,
            sourceChain,
            targetChain
        );
        bytes32 cdn2 = BrevisPrimitives.deriveCrossDomainNullifier(
            brevisNullifier,
            sourceChain,
            targetChain
        );

        assertEq(cdn1, cdn2, "Cross-domain nullifier not deterministic");
    }

    function testFuzz_CrossDomainNullifierUniqueness(
        bytes32 nf1,
        bytes32 nf2,
        uint256 sourceChain,
        uint256 targetChain
    ) public pure {
        vm.assume(nf1 != nf2);
        sourceChain = bound(sourceChain, 1, type(uint64).max);
        targetChain = bound(targetChain, 1, type(uint64).max);

        bytes32 cdn1 = BrevisPrimitives.deriveCrossDomainNullifier(
            nf1,
            sourceChain,
            targetChain
        );
        bytes32 cdn2 = BrevisPrimitives.deriveCrossDomainNullifier(
            nf2,
            sourceChain,
            targetChain
        );

        assertNotEq(
            cdn1,
            cdn2,
            "Different nullifiers produced same cross-domain"
        );
    }

    function testFuzz_PILBindingDerivation(
        bytes32 brevisNullifier
    ) public pure {
        bytes32 binding1 = BrevisPrimitives.derivePILBinding(brevisNullifier);
        bytes32 binding2 = BrevisPrimitives.derivePILBinding(brevisNullifier);

        assertEq(binding1, binding2, "PIL binding not deterministic");
        assertNotEq(binding1, bytes32(0), "PIL binding should not be zero");
    }

    // =========================================================================
    // VALIDATION TESTS
    // =========================================================================

    function testFuzz_BNBChainDetection(uint256 chainId) public pure {
        bool isBNB = BrevisPrimitives.isBNBChain(chainId);
        bool expected = chainId == 56 || chainId == 97;
        assertEq(isBNB, expected, "BNB chain detection mismatch");
    }

    function test_KnownBNBChains() public pure {
        assertTrue(BrevisPrimitives.isBNBChain(56), "Mainnet should be BNB");
        assertTrue(BrevisPrimitives.isBNBChain(97), "Testnet should be BNB");
        assertFalse(BrevisPrimitives.isBNBChain(1), "Ethereum is not BNB");
    }

    function testFuzz_CommitmentValidation(bytes32 commitment) public pure {
        bool valid = BrevisPrimitives.isValidCommitment(commitment);
        bool expected = commitment != bytes32(0);
        assertEq(valid, expected, "Commitment validation mismatch");
    }

    function testFuzz_NullifierValidation(bytes32 nullifier) public pure {
        bool valid = BrevisPrimitives.isValidNullifier(nullifier);
        bool expected = nullifier != bytes32(0);
        assertEq(valid, expected, "Nullifier validation mismatch");
    }

    function testFuzz_ProofValidation(
        uint256 proofTimestamp,
        uint256 currentTimestamp
    ) public pure {
        proofTimestamp = bound(proofTimestamp, 0, type(uint128).max);
        currentTimestamp = bound(
            currentTimestamp,
            proofTimestamp,
            type(uint128).max
        );

        bool valid = BrevisPrimitives.isProofValid(
            proofTimestamp,
            currentTimestamp
        );
        bool expected = (currentTimestamp - proofTimestamp) <= 24 hours;

        assertEq(valid, expected, "Proof validation mismatch");
    }

    function testFuzz_ConfirmationValidation(
        uint64 queryBlock,
        uint64 currentBlock
    ) public pure {
        queryBlock = uint64(bound(queryBlock, 0, type(uint64).max - 100));
        currentBlock = uint64(
            bound(currentBlock, queryBlock, type(uint64).max)
        );

        bool valid = BrevisPrimitives.hasEnoughConfirmations(
            queryBlock,
            currentBlock
        );
        bool expected = currentBlock >= queryBlock + 15;

        assertEq(valid, expected, "Confirmation validation mismatch");
    }

    // =========================================================================
    // POOL DEPOSIT TESTS
    // =========================================================================

    function testFuzz_DepositBNB(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 10000 ether);

        bytes32 commitment = _generateCommitment(amount);

        vm.prank(user1);
        pool.depositBNB{value: amount}(commitment);

        (uint256 totalDeposits, , uint32 nextIndex) = pool.getPoolStats();
        assertEq(totalDeposits, 1, "Deposit count should be 1");
        assertEq(nextIndex, 1, "Next index should be 1");

        BrevisPrimitives.DepositData memory data = pool.getDeposit(commitment);
        assertEq(data.amount, amount, "Amount mismatch");
        assertEq(data.depositor, user1, "Depositor mismatch");
    }

    function testFuzz_DepositMultiple(uint256 count) public {
        count = bound(count, 1, 20);
        uint256 amount = 1 ether;

        for (uint256 i = 0; i < count; i++) {
            bytes32 commitment = _generateCommitment(i);
            vm.prank(user1);
            pool.depositBNB{value: amount}(commitment);
        }

        (uint256 totalDeposits, , uint32 nextIndex) = pool.getPoolStats();
        assertEq(totalDeposits, count, "Deposit count mismatch");
        assertEq(nextIndex, count, "Next index mismatch");
    }

    function testFuzz_DepositRevertsInvalidAmount(uint256 amount) public {
        vm.assume(amount < 0.01 ether || amount > 10000 ether);

        bytes32 commitment = _generateCommitment(amount);

        vm.prank(user1);
        vm.expectRevert(BrevisPrivacyPoolAdapter.InvalidAmount.selector);
        pool.depositBNB{value: amount}(commitment);
    }

    function testFuzz_DepositRevertsZeroCommitment() public {
        vm.prank(user1);
        vm.expectRevert(BrevisPrivacyPoolAdapter.InvalidCommitment.selector);
        pool.depositBNB{value: 1 ether}(bytes32(0));
    }

    function testFuzz_DepositRevertsDuplicate() public {
        bytes32 commitment = _generateCommitment(1);

        vm.prank(user1);
        pool.depositBNB{value: 1 ether}(commitment);

        vm.prank(user2);
        vm.expectRevert(BrevisPrivacyPoolAdapter.CommitmentExists.selector);
        pool.depositBNB{value: 1 ether}(commitment);
    }

    // =========================================================================
    // POOL RELAYER TESTS
    // =========================================================================

    function testFuzz_RelayerRegistration(address newRelayer) public {
        vm.assume(newRelayer != address(0) && newRelayer != relayer);

        assertFalse(
            pool.registeredRelayers(newRelayer),
            "Should not be registered"
        );

        vm.prank(newRelayer);
        pool.registerRelayer();

        assertTrue(pool.registeredRelayers(newRelayer), "Should be registered");
    }

    function testFuzz_RelayerUnregistration(address newRelayer) public {
        vm.assume(newRelayer != address(0));

        vm.startPrank(newRelayer);
        pool.registerRelayer();
        assertTrue(pool.registeredRelayers(newRelayer), "Should be registered");

        pool.unregisterRelayer();
        assertFalse(
            pool.registeredRelayers(newRelayer),
            "Should be unregistered"
        );
        vm.stopPrank();
    }

    // =========================================================================
    // CROSS-DOMAIN POOL TESTS
    // =========================================================================

    function testFuzz_PoolCrossDomainRegistration(
        bytes32 brevisNullifier,
        uint256 targetChainId
    ) public {
        vm.assume(brevisNullifier != bytes32(0));
        targetChainId = bound(targetChainId, 1, type(uint64).max);

        vm.prank(user1);
        pool.registerCrossDomainNullifier(brevisNullifier, targetChainId);

        bytes32 pilNullifier = pool.crossDomainNullifiers(brevisNullifier);
        assertNotEq(pilNullifier, bytes32(0), "PIL nullifier should be set");

        bytes32 reverse = pool.pilBindings(pilNullifier);
        assertEq(reverse, brevisNullifier, "Reverse mapping should match");
    }

    // =========================================================================
    // CIRCUIT BREAKER TESTS
    // =========================================================================

    function test_CircuitBreakerBlocksDeposits() public {
        vm.prank(admin);
        pool.triggerCircuitBreaker("Test");

        assertTrue(
            pool.circuitBreakerActive(),
            "Circuit breaker should be active"
        );

        bytes32 commitment = _generateCommitment(1);
        vm.prank(user1);
        vm.expectRevert(BrevisPrivacyPoolAdapter.CircuitBreakerOn.selector);
        pool.depositBNB{value: 1 ether}(commitment);
    }

    function test_CircuitBreakerReset() public {
        vm.prank(admin);
        pool.triggerCircuitBreaker("Test");

        vm.prank(admin);
        pool.resetCircuitBreaker();

        assertFalse(
            pool.circuitBreakerActive(),
            "Circuit breaker should be reset"
        );

        bytes32 commitment = _generateCommitment(1);
        vm.prank(user1);
        pool.depositBNB{value: 1 ether}(commitment);
    }

    // =========================================================================
    // PAUSE TESTS
    // =========================================================================

    function test_PauseBlocksDeposits() public {
        vm.prank(admin);
        pool.pause();

        bytes32 commitment = _generateCommitment(1);
        vm.prank(user1);
        vm.expectRevert();
        pool.depositBNB{value: 1 ether}(commitment);
    }

    function test_UnpauseAllowsDeposits() public {
        vm.prank(admin);
        pool.pause();

        vm.prank(admin);
        pool.unpause();

        bytes32 commitment = _generateCommitment(1);
        vm.prank(user1);
        pool.depositBNB{value: 1 ether}(commitment);
    }

    // =========================================================================
    // ACCESS CONTROL TESTS
    // =========================================================================

    function testFuzz_OnlyGuardianCanTriggerBreaker(address attacker) public {
        vm.assume(attacker != admin);
        vm.assume(!pool.hasRole(pool.GUARDIAN_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        pool.triggerCircuitBreaker("Attack");
    }

    function testFuzz_OnlyAdminCanResetBreaker(address attacker) public {
        vm.assume(attacker != admin);
        vm.assume(!pool.hasRole(pool.DEFAULT_ADMIN_ROLE(), attacker));

        vm.prank(admin);
        pool.triggerCircuitBreaker("Test");

        vm.prank(attacker);
        vm.expectRevert();
        pool.resetCircuitBreaker();
    }

    // =========================================================================
    // PROOF STRUCTURE TESTS
    // =========================================================================

    function testFuzz_Groth16StructureValidation(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c
    ) public pure {
        BrevisPrimitives.Groth16Proof memory proof = BrevisPrimitives
            .Groth16Proof({a: a, b: b, c: c});

        bool valid = BrevisPrimitives.verifyGroth16Structure(proof);
        bool expected = proof.a[0] != 0 || proof.a[1] != 0;

        assertEq(valid, expected, "Groth16 structure validation mismatch");
    }

    function testFuzz_AggregateProofValidation(
        bytes32[] memory queryHashes
    ) public pure {
        vm.assume(queryHashes.length > 0 && queryHashes.length <= 32);

        bytes32 aggregateHash = BrevisPrimitives.hashN(queryHashes);

        BrevisPrimitives.AggregateProof memory proof = BrevisPrimitives
            .AggregateProof({
                queryHashes: queryHashes,
                aggregateHash: aggregateHash,
                proof: "",
                batchSize: queryHashes.length
            });

        bool valid = BrevisPrimitives.verifyAggregateProof(proof);
        assertTrue(valid, "Valid aggregate proof should pass");
    }

    // =========================================================================
    // ROOT HISTORY TESTS
    // =========================================================================

    function testFuzz_RootHistoryTracking(uint256 depositCount) public {
        depositCount = bound(depositCount, 1, 50);

        for (uint256 i = 0; i < depositCount; i++) {
            bytes32 commitment = _generateCommitment(i);
            vm.prank(user1);
            pool.depositBNB{value: 1 ether}(commitment);
        }

        bytes32 lastRoot = pool.getLastRoot();
        assertTrue(pool.isKnownRoot(lastRoot), "Last root should be known");
    }

    // =========================================================================
    // TOKEN SUPPORT TESTS
    // =========================================================================

    function testFuzz_TokenSupport(address token) public {
        vm.assume(token != address(0));

        assertFalse(
            pool.supportedTokens(token),
            "Token should not be supported"
        );

        vm.prank(admin);
        pool.addSupportedToken(token);

        assertTrue(pool.supportedTokens(token), "Token should be supported");

        vm.prank(admin);
        pool.removeSupportedToken(token);

        assertFalse(
            pool.supportedTokens(token),
            "Token should not be supported"
        );
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    uint256 private _nonce;

    function _generateCommitment(uint256 seed) internal returns (bytes32) {
        _nonce++;
        return
            keccak256(
                abi.encodePacked("commitment", seed, _nonce, block.timestamp)
            );
    }
}
