// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/canton/CantonPrimitives.sol";
import "../../contracts/crosschain/CantonBridgeAdapter.sol";

/**
 * @title CantonFuzz
 * @notice Fuzz tests for Canton Network primitives and bridge
 * @dev Tests Daml contract handling, sub-transaction privacy, and domain sync
 */
contract CantonFuzz is Test {
    using CantonPrimitives for *;

    CantonBridgeAdapter public bridge;
    address public admin;
    address public operator;
    address public mediator;
    address public participant1;
    address public participant2;

    bytes32 constant DOMAIN_ID_1 = keccak256("domain.canton.network.1");
    bytes32 constant DOMAIN_ID_2 = keccak256("domain.canton.network.2");

    function setUp() public {
        admin = makeAddr("admin");
        operator = makeAddr("operator");
        mediator = makeAddr("mediator");
        participant1 = makeAddr("participant1");
        participant2 = makeAddr("participant2");

        vm.prank(admin);
        bridge = new CantonBridgeAdapter(admin);

        // Grant roles
        vm.startPrank(admin);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.MEDIATOR_ROLE(), mediator);
        vm.stopPrank();

        // Register domains
        vm.startPrank(operator);
        bridge.registerDomain(
            DOMAIN_ID_1,
            "domain1.canton.network",
            3, // sequencer threshold
            2, // mediator threshold
            1024 * 1024, // max request size
            30, // participant response timeout
            60 // reconciliation interval
        );
        bridge.registerDomain(
            DOMAIN_ID_2,
            "domain2.canton.network",
            3,
            2,
            1024 * 1024,
            30,
            60
        );
        vm.stopPrank();

        // Fund participants
        vm.deal(participant1, 10000 ether);
        vm.deal(participant2, 10000 ether);
        vm.deal(address(bridge), 100000 ether);
    }

    // =========================================================================
    // PRIMITIVES TESTS - HASH FUNCTIONS
    // =========================================================================

    function testFuzz_Hash2Determinism(
        bytes32 left,
        bytes32 right
    ) public pure {
        bytes32 hash1 = CantonPrimitives.hash2(left, right);
        bytes32 hash2 = CantonPrimitives.hash2(left, right);
        assertEq(hash1, hash2, "Hash2 not deterministic");
    }

    function testFuzz_Hash2Uniqueness(
        bytes32 left1,
        bytes32 right1,
        bytes32 left2,
        bytes32 right2
    ) public pure {
        vm.assume(left1 != left2 || right1 != right2);

        bytes32 hash1 = CantonPrimitives.hash2(left1, right1);
        bytes32 hash2 = CantonPrimitives.hash2(left2, right2);

        assertNotEq(hash1, hash2, "Different inputs produced same hash");
    }

    function testFuzz_HashNDeterminism(bytes32[] memory inputs) public pure {
        vm.assume(inputs.length > 0 && inputs.length <= 10);

        bytes32 hash1 = CantonPrimitives.hashN(inputs);
        bytes32 hash2 = CantonPrimitives.hashN(inputs);

        assertEq(hash1, hash2, "HashN not deterministic");
    }

    function testFuzz_HashNEmpty() public pure {
        bytes32[] memory empty = new bytes32[](0);
        bytes32 result = CantonPrimitives.hashN(empty);
        assertEq(result, bytes32(0), "Empty hash should be zero");
    }

    function testFuzz_HashNSingle(bytes32 input) public pure {
        bytes32[] memory single = new bytes32[](1);
        single[0] = input;
        bytes32 result = CantonPrimitives.hashN(single);
        assertEq(result, input, "Single element should return itself");
    }

    // =========================================================================
    // PRIMITIVES TESTS - PARTY ID
    // =========================================================================

    function testFuzz_ComputePartyId(
        bytes memory publicKey,
        bytes32 namespace
    ) public pure {
        vm.assume(publicKey.length > 0 && publicKey.length <= 256);

        CantonPrimitives.PartyId memory party1 = CantonPrimitives
            .computePartyId(publicKey, namespace);
        CantonPrimitives.PartyId memory party2 = CantonPrimitives
            .computePartyId(publicKey, namespace);

        assertEq(
            party1.fingerprint,
            party2.fingerprint,
            "Fingerprint not deterministic"
        );
        assertEq(party1.namespace, namespace, "Namespace mismatch");
    }

    function testFuzz_PartyIdUniqueness(
        bytes memory pk1,
        bytes memory pk2,
        bytes32 namespace
    ) public pure {
        vm.assume(pk1.length > 0 && pk1.length <= 256);
        vm.assume(pk2.length > 0 && pk2.length <= 256);
        vm.assume(keccak256(pk1) != keccak256(pk2));

        CantonPrimitives.PartyId memory party1 = CantonPrimitives
            .computePartyId(pk1, namespace);
        CantonPrimitives.PartyId memory party2 = CantonPrimitives
            .computePartyId(pk2, namespace);

        assertNotEq(
            party1.fingerprint,
            party2.fingerprint,
            "Different keys should produce different fingerprints"
        );
    }

    // =========================================================================
    // PRIMITIVES TESTS - CONTRACT ID
    // =========================================================================

    function testFuzz_ComputeContractId(
        bytes32 discriminator,
        bytes32 suffix
    ) public pure {
        bytes32 id1 = CantonPrimitives.computeContractId(discriminator, suffix);
        bytes32 id2 = CantonPrimitives.computeContractId(discriminator, suffix);

        assertEq(id1, id2, "Contract ID not deterministic");
        assertNotEq(id1, bytes32(0), "Contract ID should not be zero");
    }

    function testFuzz_ContractIdUniqueness(
        bytes32 disc1,
        bytes32 disc2,
        bytes32 suffix
    ) public pure {
        vm.assume(disc1 != disc2);

        bytes32 id1 = CantonPrimitives.computeContractId(disc1, suffix);
        bytes32 id2 = CantonPrimitives.computeContractId(disc2, suffix);

        assertNotEq(
            id1,
            id2,
            "Different discriminators should produce different IDs"
        );
    }

    // =========================================================================
    // PRIMITIVES TESTS - BLINDED COMMITMENT
    // =========================================================================

    function testFuzz_BlindedCommitment(
        bytes32 viewHash,
        bytes32 salt
    ) public pure {
        bytes32 c1 = CantonPrimitives.computeBlindedCommitment(viewHash, salt);
        bytes32 c2 = CantonPrimitives.computeBlindedCommitment(viewHash, salt);

        assertEq(c1, c2, "Blinded commitment not deterministic");
    }

    function testFuzz_VerifyBlindedOpening(
        bytes32 viewHash,
        bytes32 salt
    ) public pure {
        bytes32 commitment = CantonPrimitives.computeBlindedCommitment(
            viewHash,
            salt
        );
        bool valid = CantonPrimitives.verifyBlindedOpening(
            commitment,
            viewHash,
            salt
        );

        assertTrue(valid, "Valid opening should verify");
    }

    function testFuzz_BlindedOpeningInvalid(
        bytes32 viewHash,
        bytes32 salt,
        bytes32 wrongSalt
    ) public pure {
        vm.assume(salt != wrongSalt);

        bytes32 commitment = CantonPrimitives.computeBlindedCommitment(
            viewHash,
            salt
        );
        bool valid = CantonPrimitives.verifyBlindedOpening(
            commitment,
            viewHash,
            wrongSalt
        );

        assertFalse(valid, "Invalid opening should not verify");
    }

    // =========================================================================
    // PRIMITIVES TESTS - MERKLE TREE
    // =========================================================================

    function testFuzz_MerkleRootDeterminism(
        bytes32[] memory leaves
    ) public pure {
        vm.assume(leaves.length > 0 && leaves.length <= 20);

        bytes32 root1 = CantonPrimitives.computeMerkleRoot(leaves);
        bytes32 root2 = CantonPrimitives.computeMerkleRoot(leaves);

        assertEq(root1, root2, "Merkle root not deterministic");
    }

    function testFuzz_MerkleRootSingleLeaf(bytes32 leaf) public pure {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = leaf;

        bytes32 root = CantonPrimitives.computeMerkleRoot(leaves);
        assertEq(root, leaf, "Single leaf should be root");
    }

    function testFuzz_MerkleRootTwoLeaves(
        bytes32 leaf1,
        bytes32 leaf2
    ) public pure {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = leaf1;
        leaves[1] = leaf2;

        bytes32 root = CantonPrimitives.computeMerkleRoot(leaves);
        bytes32 expected = CantonPrimitives.hash2(leaf1, leaf2);

        assertEq(root, expected, "Two leaves should hash together");
    }

    function testFuzz_MerkleProofVerification(
        bytes32 leaf,
        bytes32[5] memory proofElements,
        uint8 pathBits
    ) public pure {
        bytes32[] memory proof = new bytes32[](5);
        uint256[] memory indices = new uint256[](5);

        for (uint256 i = 0; i < 5; i++) {
            proof[i] = proofElements[i];
            indices[i] = (pathBits >> i) & 1;
        }

        // Compute root
        bytes32 computed = leaf;
        for (uint256 i = 0; i < 5; i++) {
            if (indices[i] == 0) {
                computed = CantonPrimitives.hash2(computed, proof[i]);
            } else {
                computed = CantonPrimitives.hash2(proof[i], computed);
            }
        }

        // Verify
        bool valid = CantonPrimitives.verifyMerkleProof(
            leaf,
            proof,
            indices,
            computed
        );
        assertTrue(valid, "Valid proof should verify");
    }

    // =========================================================================
    // PRIMITIVES TESTS - NULLIFIER
    // =========================================================================

    function testFuzz_NullifierDerivation(
        bytes32 contractId,
        bytes32 domainId,
        bytes32 actionHash
    ) public pure {
        bytes32 nf1 = CantonPrimitives.deriveNullifier(
            contractId,
            domainId,
            actionHash
        );
        bytes32 nf2 = CantonPrimitives.deriveNullifier(
            contractId,
            domainId,
            actionHash
        );

        assertEq(nf1, nf2, "Nullifier not deterministic");
    }

    function testFuzz_NullifierUniqueness(
        bytes32 contractId1,
        bytes32 contractId2,
        bytes32 domainId,
        bytes32 actionHash
    ) public pure {
        vm.assume(contractId1 != contractId2);

        bytes32 nf1 = CantonPrimitives.deriveNullifier(
            contractId1,
            domainId,
            actionHash
        );
        bytes32 nf2 = CantonPrimitives.deriveNullifier(
            contractId2,
            domainId,
            actionHash
        );

        assertNotEq(
            nf1,
            nf2,
            "Different contracts should produce different nullifiers"
        );
    }

    function testFuzz_CrossDomainNullifier(
        bytes32 cantonNf,
        uint256 sourceChain,
        uint256 targetChain
    ) public pure {
        sourceChain = bound(sourceChain, 1, type(uint64).max);
        targetChain = bound(targetChain, 1, type(uint64).max);

        bytes32 cdn1 = CantonPrimitives.deriveCrossDomainNullifier(
            cantonNf,
            sourceChain,
            targetChain
        );
        bytes32 cdn2 = CantonPrimitives.deriveCrossDomainNullifier(
            cantonNf,
            sourceChain,
            targetChain
        );

        assertEq(cdn1, cdn2, "Cross-domain nullifier not deterministic");
    }

    function testFuzz_PILBinding(bytes32 cantonNf) public pure {
        bytes32 binding1 = CantonPrimitives.derivePILBinding(cantonNf);
        bytes32 binding2 = CantonPrimitives.derivePILBinding(cantonNf);

        assertEq(binding1, binding2, "PIL binding not deterministic");
    }

    // =========================================================================
    // PRIMITIVES TESTS - VALIDATION
    // =========================================================================

    function testFuzz_DomainConfigValidation(
        bytes32 domainId,
        uint256 seqThreshold,
        uint256 medThreshold,
        uint256 maxSize,
        uint256 timeout
    ) public pure {
        seqThreshold = bound(seqThreshold, 0, 100);
        medThreshold = bound(medThreshold, 0, 100);
        maxSize = bound(maxSize, 0, type(uint128).max);
        timeout = bound(timeout, 0, type(uint64).max);

        CantonPrimitives.DomainConfig memory config = CantonPrimitives
            .DomainConfig({
                domainId: domainId,
                domainAlias: "test",
                sequencerThreshold: seqThreshold,
                mediatorThreshold: medThreshold,
                maxRequestSize: maxSize,
                participantResponseTimeout: timeout,
                reconciliationInterval: 60,
                status: CantonPrimitives.DomainStatus.ACTIVE
            });

        bool valid = CantonPrimitives.isValidDomainConfig(config);
        bool expected = domainId != bytes32(0) &&
            seqThreshold > 0 &&
            medThreshold > 0 &&
            maxSize > 0 &&
            timeout > 0;

        assertEq(valid, expected, "Domain validation mismatch");
    }

    function testFuzz_CertificateValidation(
        bytes32 keyId,
        uint256 validFrom,
        uint256 validUntil,
        uint256 currentTime
    ) public pure {
        validFrom = bound(validFrom, 0, type(uint128).max);
        validUntil = bound(validUntil, validFrom, type(uint128).max);
        currentTime = bound(currentTime, 0, type(uint128).max);

        CantonPrimitives.X509Certificate memory cert = CantonPrimitives
            .X509Certificate({
                subjectKeyId: keyId,
                issuerKeyId: bytes32(0),
                validFrom: validFrom,
                validUntil: validUntil,
                publicKey: "",
                signature: ""
            });

        bool valid = CantonPrimitives.isCertificateValid(cert, currentTime);
        bool expected = currentTime >= validFrom &&
            currentTime <= validUntil &&
            keyId != bytes32(0);

        assertEq(valid, expected, "Certificate validation mismatch");
    }

    // =========================================================================
    // BRIDGE TESTS - DOMAIN MANAGEMENT
    // =========================================================================

    function testFuzz_DomainRegistration(
        bytes32 domainId,
        string memory domainAlias
    ) public {
        vm.assume(domainId != bytes32(0));
        vm.assume(domainId != DOMAIN_ID_1 && domainId != DOMAIN_ID_2);

        vm.prank(operator);
        bridge.registerDomain(domainId, domainAlias, 3, 2, 1024, 30, 60);

        CantonPrimitives.DomainConfig memory config = bridge.getDomain(
            domainId
        );
        assertEq(config.domainId, domainId, "Domain ID mismatch");
        assertTrue(
            config.status == CantonPrimitives.DomainStatus.ACTIVE,
            "Should be active"
        );
    }

    function testFuzz_DomainStatusChange(uint8 statusVal) public {
        statusVal = uint8(bound(statusVal, 0, 3));
        CantonPrimitives.DomainStatus status = CantonPrimitives.DomainStatus(
            statusVal
        );

        vm.prank(operator);
        bridge.setDomainStatus(DOMAIN_ID_1, status);

        CantonPrimitives.DomainConfig memory config = bridge.getDomain(
            DOMAIN_ID_1
        );
        assertTrue(config.status == status, "Status mismatch");
    }

    // =========================================================================
    // BRIDGE TESTS - PARTICIPANT MANAGEMENT
    // =========================================================================

    function testFuzz_ParticipantRegistration(bytes32 nodeId) public {
        vm.assume(nodeId != bytes32(0));

        bytes32[] memory fingerprints = new bytes32[](1);
        bytes32[] memory namespaces = new bytes32[](1);
        fingerprints[0] = keccak256("party1");
        namespaces[0] = keccak256("namespace1");

        vm.prank(participant1);
        bridge.registerParticipant(nodeId, fingerprints, namespaces);

        (bytes32 id, CantonPrimitives.ParticipantStatus status, , ) = bridge
            .getParticipant(nodeId);
        assertEq(id, nodeId, "Node ID mismatch");
        assertTrue(
            status == CantonPrimitives.ParticipantStatus.CONNECTED,
            "Should be connected"
        );
    }

    function testFuzz_ParticipantDomainConnection(bytes32 nodeId) public {
        vm.assume(nodeId != bytes32(0));

        bytes32[] memory fingerprints = new bytes32[](1);
        bytes32[] memory namespaces = new bytes32[](1);
        fingerprints[0] = keccak256("party1");
        namespaces[0] = keccak256("namespace1");

        vm.prank(participant1);
        bridge.registerParticipant(nodeId, fingerprints, namespaces);

        vm.prank(participant1);
        bridge.connectToDomain(DOMAIN_ID_1);

        (
            ,
            CantonPrimitives.ParticipantStatus status,
            ,
            uint256 domains
        ) = bridge.getParticipant(nodeId);
        assertTrue(
            status == CantonPrimitives.ParticipantStatus.ACTIVE,
            "Should be active"
        );
        assertEq(domains, 1, "Should have 1 domain");
    }

    // =========================================================================
    // BRIDGE TESTS - DEPOSIT
    // =========================================================================

    function testFuzz_Deposit(uint256 amount, bytes32 partyFingerprint) public {
        amount = bound(amount, 1, bridge.MAX_TRANSFER_AMOUNT());
        vm.assume(partyFingerprint != bytes32(0));

        vm.prank(participant1);
        bridge.deposit{value: amount}(partyFingerprint);
    }

    function testFuzz_DepositRevertsZeroAmount(
        bytes32 partyFingerprint
    ) public {
        vm.assume(partyFingerprint != bytes32(0));

        vm.prank(participant1);
        vm.expectRevert(CantonBridgeAdapter.InvalidAmount.selector);
        bridge.deposit{value: 0}(partyFingerprint);
    }

    function testFuzz_DepositRevertsExceedsMax(
        bytes32 partyFingerprint
    ) public {
        vm.assume(partyFingerprint != bytes32(0));
        uint256 amount = bridge.MAX_TRANSFER_AMOUNT() + 1;

        vm.deal(participant1, amount);
        vm.prank(participant1);
        vm.expectRevert(CantonBridgeAdapter.InvalidAmount.selector);
        bridge.deposit{value: amount}(partyFingerprint);
    }

    function testFuzz_DepositRevertsInvalidParty() public {
        vm.prank(participant1);
        vm.expectRevert(CantonBridgeAdapter.InvalidParticipant.selector);
        bridge.deposit{value: 1 ether}(bytes32(0));
    }

    // =========================================================================
    // BRIDGE TESTS - CROSS-DOMAIN NULLIFIER
    // =========================================================================

    function testFuzz_CrossDomainRegistration(
        bytes32 cantonNf,
        uint256 targetChain
    ) public {
        vm.assume(cantonNf != bytes32(0));
        targetChain = bound(targetChain, 1, type(uint64).max);

        vm.prank(participant1);
        bridge.registerCrossDomainNullifier(cantonNf, targetChain);

        bytes32 pilNf = bridge.crossDomainNullifiers(cantonNf);
        assertNotEq(pilNf, bytes32(0), "PIL nullifier should be set");

        bytes32 reverse = bridge.pilBindings(pilNf);
        assertEq(reverse, cantonNf, "Reverse mapping should match");
    }

    function testFuzz_CrossDomainIdempotent(
        bytes32 cantonNf,
        uint256 targetChain
    ) public {
        vm.assume(cantonNf != bytes32(0));
        targetChain = bound(targetChain, 1, type(uint64).max);

        vm.prank(participant1);
        bridge.registerCrossDomainNullifier(cantonNf, targetChain);
        bytes32 pilNf1 = bridge.crossDomainNullifiers(cantonNf);

        vm.prank(participant1);
        bridge.registerCrossDomainNullifier(cantonNf, targetChain);
        bytes32 pilNf2 = bridge.crossDomainNullifiers(cantonNf);

        assertEq(pilNf1, pilNf2, "Should be idempotent");
    }

    // =========================================================================
    // BRIDGE TESTS - CIRCUIT BREAKER
    // =========================================================================

    function test_CircuitBreakerBlocksDeposits() public {
        vm.prank(admin);
        bridge.triggerCircuitBreaker("Test");

        assertTrue(bridge.circuitBreakerActive(), "Should be active");

        vm.prank(participant1);
        vm.expectRevert(CantonBridgeAdapter.CircuitBreakerOn.selector);
        bridge.deposit{value: 1 ether}(keccak256("party"));
    }

    function test_CircuitBreakerReset() public {
        vm.prank(admin);
        bridge.triggerCircuitBreaker("Test");

        vm.prank(admin);
        bridge.resetCircuitBreaker();

        assertFalse(bridge.circuitBreakerActive(), "Should be reset");

        vm.prank(participant1);
        bridge.deposit{value: 1 ether}(keccak256("party"));
    }

    // =========================================================================
    // BRIDGE TESTS - PAUSE
    // =========================================================================

    function test_PauseBlocksDeposits() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(participant1);
        vm.expectRevert();
        bridge.deposit{value: 1 ether}(keccak256("party"));
    }

    function test_UnpauseAllowsDeposits() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(admin);
        bridge.unpause();

        vm.prank(participant1);
        bridge.deposit{value: 1 ether}(keccak256("party"));
    }

    // =========================================================================
    // BRIDGE TESTS - ACCESS CONTROL
    // =========================================================================

    function testFuzz_OnlyOperatorCanRegisterDomain(address attacker) public {
        vm.assume(attacker != operator && attacker != admin);
        vm.assume(!bridge.hasRole(bridge.OPERATOR_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        bridge.registerDomain(
            keccak256("new"),
            "new.domain",
            3,
            2,
            1024,
            30,
            60
        );
    }

    function testFuzz_OnlyGuardianCanTriggerBreaker(address attacker) public {
        vm.assume(attacker != admin);
        vm.assume(!bridge.hasRole(bridge.GUARDIAN_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        bridge.triggerCircuitBreaker("Attack");
    }

    // =========================================================================
    // BRIDGE TESTS - TRANSACTION SUBMISSION
    // =========================================================================

    function testFuzz_TransactionSubmission(
        bytes32 txId,
        bytes32[] memory viewHashes
    ) public {
        vm.assume(txId != bytes32(0));
        vm.assume(viewHashes.length > 0 && viewHashes.length <= 50);

        uint256 ledgerTime = block.timestamp;

        vm.prank(participant1);
        bridge.submitTransaction(
            txId,
            DOMAIN_ID_1,
            ledgerTime,
            viewHashes,
            keccak256("submitter"),
            keccak256("namespace"),
            keccak256("command")
        );

        CantonPrimitives.TransactionConfirmation memory conf = bridge
            .getConfirmation(txId);
        assertEq(conf.transactionId, txId, "Transaction ID mismatch");
        assertEq(conf.domainId, DOMAIN_ID_1, "Domain ID mismatch");
    }

    function testFuzz_TransactionSubmissionRevertsEmpty(bytes32 txId) public {
        vm.assume(txId != bytes32(0));
        bytes32[] memory empty = new bytes32[](0);

        vm.prank(participant1);
        vm.expectRevert(CantonBridgeAdapter.InvalidTransaction.selector);
        bridge.submitTransaction(
            txId,
            DOMAIN_ID_1,
            block.timestamp,
            empty,
            keccak256("submitter"),
            keccak256("namespace"),
            keccak256("command")
        );
    }

    // =========================================================================
    // BRIDGE TESTS - TRANSFER
    // =========================================================================

    function testFuzz_TransferInitiation(
        bytes32 transferId,
        bytes32 contractId
    ) public {
        vm.assume(transferId != bytes32(0));
        vm.assume(contractId != bytes32(0));

        vm.prank(participant1);
        bridge.initiateTransfer(
            transferId,
            DOMAIN_ID_1,
            DOMAIN_ID_2,
            contractId,
            keccak256("submitter"),
            keccak256("namespace")
        );

        CantonPrimitives.DomainTransfer memory transfer = bridge.getTransfer(
            transferId
        );
        assertEq(transfer.transferId, transferId, "Transfer ID mismatch");
        assertEq(transfer.sourceDomain, DOMAIN_ID_1, "Source domain mismatch");
        assertEq(transfer.targetDomain, DOMAIN_ID_2, "Target domain mismatch");
        assertFalse(transfer.isComplete, "Should not be complete");
    }

    // =========================================================================
    // BRIDGE TESTS - STATISTICS
    // =========================================================================

    function test_GetStats() public {
        (
            uint256 transactions,
            uint256 transferredValue,
            uint256 dailyVol,
            bool circuitBreaker
        ) = bridge.getStats();

        assertEq(transactions, 0, "Should start at 0");
        assertEq(transferredValue, 0, "Should start at 0");
        assertEq(dailyVol, 0, "Should start at 0");
        assertFalse(circuitBreaker, "Should be off");
    }
}
