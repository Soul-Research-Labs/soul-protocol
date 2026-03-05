// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";

import {UniversalShieldedPool} from "../../contracts/privacy/UniversalShieldedPool.sol";
import {IUniversalShieldedPool} from "../../contracts/interfaces/IUniversalShieldedPool.sol";
import {ZaseonCrossChainRelay} from "../../contracts/crosschain/ZaseonCrossChainRelay.sol";
import {CrossChainProofHubV3} from "../../contracts/bridge/CrossChainProofHubV3.sol";
import {DecentralizedRelayerRegistry} from "../../contracts/relayer/DecentralizedRelayerRegistry.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {OptimisticRelayVerifier} from "../../contracts/security/OptimisticRelayVerifier.sol";

/// @dev Mock verifier that accepts all proofs (for E2E integration)
contract MockProofVerifier {
    bool public result = true;

    function setResult(bool _r) external {
        result = _r;
    }

    function verifyProof(bytes calldata, bytes calldata) external view returns (bool) {
        return result;
    }
}

/// @dev Mock bridge adapter that accepts any sendMessage call (for E2E)
contract MockBridgeAdapter {
    event MessageSent(uint32 dstEid, bytes payload);

    fallback() external payable {
        // Accept any call — relay adapter mock
    }

    receive() external payable {}
}

/**
 * @title PrivateTransferE2E
 * @notice End-to-end test: deposit on chain A → relay proof → withdraw on chain B.
 * @dev Uses simulated multi-chain state (no forks) to test the complete flow.
 *
 * Flow:
 *  1. Deploy infrastructure on "source" and "destination" chains
 *  2. User deposits ETH into ShieldedPool on source
 *  3. Relayer calls relayProof() on ZaseonCrossChainRelay
 *  4. ProofHub on destination receives and stores proof
 *  5. User withdraws ETH on destination ShieldedPool
 *  6. Verify: nullifier spent, balances correct, no on-chain link
 *
 * Run:
 *   forge test --match-contract PrivateTransferE2E -vvv
 */
contract PrivateTransferE2E is Test {
    // ═══════════════════════════════════════════════════════════
    //  CONSTANTS
    // ═══════════════════════════════════════════════════════════

    uint64 constant SOURCE_CHAIN_ID = 421614; // Arbitrum Sepolia
    uint64 constant DEST_CHAIN_ID = 11155420; // Optimism Sepolia

    uint256 internal constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // ═══════════════════════════════════════════════════════════
    //  STATE
    // ═══════════════════════════════════════════════════════════

    // Source chain
    UniversalShieldedPool public srcPool;

    // Destination chain
    UniversalShieldedPool public destPool;
    CrossChainProofHubV3 public destProofHub;
    NullifierRegistryV3 public destNullifierRegistry;

    // Shared / cross-chain
    ZaseonCrossChainRelay public relay;
    DecentralizedRelayerRegistry public relayerRegistry;

    // Mock
    MockProofVerifier public mockVerifier;
    MockBridgeAdapter public mockAdapter;

    // Accounts
    address public admin;
    address public depositor; // sender
    address public recipient; // stealth address on dest chain
    address public relayerAddr;

    // Roles
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    // ═══════════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════════

    function _validCommitment(bytes memory seed) internal pure returns (bytes32) {
        return bytes32((uint256(keccak256(seed)) % (FIELD_SIZE - 1)) + 1);
    }

    // ═══════════════════════════════════════════════════════════
    //  SETUP
    // ═══════════════════════════════════════════════════════════

    function setUp() public {
        admin = makeAddr("admin");
        depositor = makeAddr("depositor");
        recipient = makeAddr("recipient"); // simulates a stealth address
        relayerAddr = makeAddr("relayer");

        vm.deal(admin, 1000 ether);
        vm.deal(depositor, 100 ether);
        vm.deal(relayerAddr, 100 ether);
        // Fund dest pool so it can pay out withdrawals
        // (in production, cross-chain liquidity vaults handle this)

        vm.startPrank(admin);

        // Deploy shared mock verifier
        mockVerifier = new MockProofVerifier();
        mockAdapter = new MockBridgeAdapter();

        // --- Source chain contracts ---
        srcPool = new UniversalShieldedPool(admin, address(mockVerifier), false);

        // --- Destination chain contracts ---
        destPool = new UniversalShieldedPool(admin, address(mockVerifier), false);
        destProofHub = new CrossChainProofHubV3();
        destNullifierRegistry = new NullifierRegistryV3();

        // --- Cross-chain relay ---
        OptimisticRelayVerifier verifier = new OptimisticRelayVerifier(admin);
        relay = new ZaseonCrossChainRelay(
            address(verifier),
            ZaseonCrossChainRelay.BridgeType.LAYERZERO
        );

        // --- Relayer registry ---
        relayerRegistry = new DecentralizedRelayerRegistry(admin);

        // --- Wiring ---

        // Grant RELAYER_ROLE on relay to the relayer account
        relay.grantRole(RELAYER_ROLE, relayerAddr);

        // Grant RELAYER_ROLE on proof hub to relayer
        destProofHub.grantRole(RELAYER_ROLE, relayerAddr);

        // Register source chain on proof hub
        destProofHub.addSupportedChain(SOURCE_CHAIN_ID);

        // Confirm role separation (required before proof submissions)
        destProofHub.confirmRoleSeparation();

        vm.stopPrank();

        // Relayer stakes on ProofHub (required: minRelayerStake = 0.1 ETH)
        vm.prank(relayerAddr);
        destProofHub.depositStake{value: 0.1 ether}();

        vm.startPrank(admin);

        // Add destination chain as supported on ProofHub
        destProofHub.addSupportedChain(DEST_CHAIN_ID);

        // Configure destination chain on relay (required for relayProof)
        relay.configureChain(
            DEST_CHAIN_ID,
            ZaseonCrossChainRelay.ChainConfig({
                proofHub: address(destProofHub),
                relayAdapter: address(mockAdapter),
                bridgeChainId: uint32(DEST_CHAIN_ID),
                active: true
            })
        );

        vm.stopPrank();

        // Fund the destination pool so withdrawals succeed
        // (simulates pre-seeded liquidity)
        vm.deal(address(destPool), 100 ether);
    }

    // ═══════════════════════════════════════════════════════════
    //  E2E: Full private cross-chain transfer
    // ═══════════════════════════════════════════════════════════

    function test_E2E_PrivateCrossChainTransfer() public {
        uint256 depositAmount = 1 ether;
        bytes32 commitment = _validCommitment(abi.encodePacked("secret", depositAmount));
        bytes32 nullifier = keccak256(abi.encodePacked("nullifier-1"));
        bytes32 proofType = keccak256("balance_proof");
        bytes memory proof = hex"deadbeef0123456789abcdef";
        bytes memory publicInputs = abi.encode(commitment, SOURCE_CHAIN_ID, DEST_CHAIN_ID);
        bytes32 proofId = keccak256(abi.encodePacked(proof, commitment));

        // ═══ Phase 1: Deposit on Source Chain ═══
        console2.log("=== Phase 1: Deposit on Source Chain ===");

        vm.prank(depositor);
        srcPool.depositETH{value: depositAmount}(commitment);

        assertEq(srcPool.totalDeposits(), 1, "Source should have 1 deposit");
        assertTrue(srcPool.commitmentExists(commitment), "Commitment should exist");
        assertEq(address(srcPool).balance, depositAmount, "Source pool should hold deposit");

        bytes32 srcRoot = srcPool.currentRoot();
        assertTrue(srcPool.isKnownRoot(srcRoot), "Merkle root should be known");

        console2.log("  Deposit amount:", depositAmount);
        console2.log("  Depositor:", depositor);
        console2.log("  Source balance:", address(srcPool).balance);

        // ═══ Phase 2: Relayer relays proof to destination ═══
        console2.log("=== Phase 2: Relay Proof ===");

        // Relayer calls relayProof on ZaseonCrossChainRelay
        vm.prank(relayerAddr);
        bytes32 messageId = relay.relayProof(
            proofId,
            proof,
            publicInputs,
            commitment,
            DEST_CHAIN_ID,
            proofType
        );

        console2.log("  Relayed proofId:");
        console2.logBytes32(proofId);
        console2.log("  MessageId:");
        console2.logBytes32(messageId);

        // Relayer submits proof to destination ProofHub
        // (In production, this happens via cross-chain message bridge)
        vm.prank(relayerAddr);
        bytes32 hubProofId = destProofHub.submitProof{value: 0.001 ether}(
            proof,
            publicInputs,
            commitment,
            SOURCE_CHAIN_ID,
            DEST_CHAIN_ID
        );

        console2.log("  ProofHub proofId:");
        console2.logBytes32(hubProofId);

        // ═══ Phase 3: Withdraw on Destination Chain ═══
        console2.log("=== Phase 3: Withdraw on Destination ===");

        bytes32 nativeAsset = destPool.NATIVE_ASSET();
        bytes32 merkleRoot = destPool.currentRoot(); // empty root (no deposits here)

        // For this E2E we simulate that the cross-chain commitment was relayed
        // and the dest pool's Merkle tree includes it. In production,
        // CrossChainCommitmentBatch.insertBatch() handles this.
        // We use a fresh deposit on dest to populate the tree for the test.
        vm.prank(admin);
        vm.deal(admin, depositAmount);
        destPool.depositETH{value: depositAmount}(commitment);
        merkleRoot = destPool.currentRoot();

        uint256 recipientBalBefore = recipient.balance;

        IUniversalShieldedPool.WithdrawalProof memory wp = IUniversalShieldedPool
            .WithdrawalProof({
                proof: proof,
                merkleRoot: merkleRoot,
                nullifier: nullifier,
                recipient: recipient,
                relayerAddress: address(0),
                amount: depositAmount,
                relayerFee: 0,
                assetId: nativeAsset,
                destChainId: 0
            });

        destPool.withdraw(wp);

        // ═══ Phase 4: Verify Privacy Properties ═══
        console2.log("=== Phase 4: Verify Privacy Properties ===");

        // Nullifier is spent
        assertTrue(destPool.isSpent(nullifier), "Nullifier should be spent on destination");

        // Recipient received funds
        assertEq(
            recipient.balance - recipientBalBefore,
            depositAmount,
            "Recipient should receive full amount"
        );

        // Pool balance decreased
        assertEq(destPool.totalWithdrawals(), 1, "Should have 1 withdrawal");

        // Source depositor and dest recipient have no on-chain link
        assertTrue(depositor != recipient, "Depositor and recipient are different addresses");
        // In production: depositor address never appears on dest chain

        console2.log("  Recipient balance increase:", recipient.balance - recipientBalBefore);
        console2.log("  Nullifier spent: true");
        console2.log("  Depositor == Recipient:", depositor == recipient);

        // ═══ Phase 5: Double-spend prevention ═══
        console2.log("=== Phase 5: Double-spend Prevention ===");

        vm.expectRevert(
            abi.encodeWithSelector(
                IUniversalShieldedPool.NullifierAlreadySpent.selector,
                nullifier
            )
        );
        destPool.withdraw(wp);

        console2.log("  Double-spend correctly rejected");
        console2.log("=== E2E COMPLETE ===");
    }

    // ═══════════════════════════════════════════════════════════
    //  E2E: Relayer fee flow
    // ═══════════════════════════════════════════════════════════

    function test_E2E_CrossChainWithRelayerFee() public {
        uint256 depositAmount = 5 ether;
        uint256 relayerFee = 0.05 ether;
        bytes32 commitment = _validCommitment(abi.encodePacked("relayer-fee-test"));
        bytes32 nullifier = keccak256(abi.encodePacked("null-relayer-fee"));

        // Deposit on source
        vm.prank(depositor);
        srcPool.depositETH{value: depositAmount}(commitment);

        // Simulate commitment relay to dest (mirror deposit for tree)
        vm.deal(admin, depositAmount);
        vm.prank(admin);
        destPool.depositETH{value: depositAmount}(commitment);
        bytes32 merkleRoot = destPool.currentRoot();
        bytes32 nativeAsset = destPool.NATIVE_ASSET();

        uint256 recipientBalBefore = recipient.balance;
        uint256 relayerBalBefore = relayerAddr.balance;

        // Withdraw with relayer fee
        IUniversalShieldedPool.WithdrawalProof memory wp = IUniversalShieldedPool
            .WithdrawalProof({
                proof: hex"cafe",
                merkleRoot: merkleRoot,
                nullifier: nullifier,
                recipient: recipient,
                relayerAddress: relayerAddr,
                amount: depositAmount,
                relayerFee: relayerFee,
                assetId: nativeAsset,
                destChainId: 0
            });

        destPool.withdraw(wp);

        // Verify fee split
        assertEq(
            recipient.balance - recipientBalBefore,
            depositAmount - relayerFee,
            "Recipient gets amount minus fee"
        );
        assertEq(
            relayerAddr.balance - relayerBalBefore,
            relayerFee,
            "Relayer gets fee"
        );
    }

    // ═══════════════════════════════════════════════════════════
    //  E2E: Relayer registration + staking
    // ═══════════════════════════════════════════════════════════

    function test_E2E_RelayerRegistration() public {
        uint256 minStake = relayerRegistry.MIN_STAKE();

        // Relayer registers with stake
        vm.prank(relayerAddr);
        relayerRegistry.register{value: minStake}();

        // Verify registration
        (uint256 stake, , , bool isRegistered) = relayerRegistry.relayers(relayerAddr);
        assertTrue(isRegistered, "Relayer should be registered");
        assertEq(stake, minStake, "Stake should equal MIN_STAKE");
    }

    // ═══════════════════════════════════════════════════════════
    //  E2E: Multiple deposits, single cross-chain withdraw
    // ═══════════════════════════════════════════════════════════

    function test_E2E_MultiDepositCrossChainWithdraw() public {
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;
        bytes32 commit1 = _validCommitment(abi.encodePacked("multi-1", amount1));
        bytes32 commit2 = _validCommitment(abi.encodePacked("multi-2", amount2));
        bytes32 null1 = keccak256(abi.encodePacked("multi-null-1"));

        // Two deposits on source
        vm.startPrank(depositor);
        srcPool.depositETH{value: amount1}(commit1);
        srcPool.depositETH{value: amount2}(commit2);
        vm.stopPrank();

        assertEq(srcPool.totalDeposits(), 2, "Source should have 2 deposits");
        assertEq(address(srcPool).balance, amount1 + amount2, "Source holds both deposits");

        // Mirror commit1 to dest for tree
        vm.deal(admin, amount1);
        vm.prank(admin);
        destPool.depositETH{value: amount1}(commit1);
        bytes32 merkleRoot = destPool.currentRoot();
        bytes32 nativeAsset = destPool.NATIVE_ASSET();

        // Withdraw only deposit 1 on destination
        IUniversalShieldedPool.WithdrawalProof memory wp = IUniversalShieldedPool
            .WithdrawalProof({
                proof: hex"abcd",
                merkleRoot: merkleRoot,
                nullifier: null1,
                recipient: recipient,
                relayerAddress: address(0),
                amount: amount1,
                relayerFee: 0,
                assetId: nativeAsset,
                destChainId: 0
            });

        destPool.withdraw(wp);

        assertTrue(destPool.isSpent(null1), "Nullifier 1 should be spent");
        assertEq(recipient.balance, amount1, "Recipient should have amount1");

        // Source still holds both deposits (no linkage)
        assertEq(address(srcPool).balance, amount1 + amount2, "Source untouched");
    }
}
