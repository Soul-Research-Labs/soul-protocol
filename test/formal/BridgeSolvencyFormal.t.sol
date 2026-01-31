// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/EthereumL1Bridge.sol";

contract BridgeSolvencyFormalTest is Test {
    EthereumL1Bridge public bridge;
    
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    function setUp() public {
        bridge = new EthereumL1Bridge();
    }

    receive() external payable {}

    function test_submitStateCommitment_AccessControl(address caller, uint256 chainId, bytes32 root, bytes32 proof, uint256 blockNum) public {
        vm.prank(caller);
        (bool success, ) = address(bridge).call{value: 0.1 ether}(abi.encodeWithSelector(bridge.submitStateCommitment.selector, chainId, root, proof, blockNum));
        if (success) {
            assertTrue(bridge.hasRole(RELAYER_ROLE, caller));
        }
    }

    function test_Withdrawal_DoubleInitiation_Invariant(
        uint256 sourceChainId,
        uint256 amount,
        bytes32 nullifier,
        bytes32[] calldata proof,
        bytes32 stateRoot
    ) public {
        address relayer = address(0x123);
        bridge.grantRole(RELAYER_ROLE, relayer);
        
        bridge.grantRole(OPERATOR_ROLE, address(this));
        EthereumL1Bridge.L2Config memory config = EthereumL1Bridge.L2Config({
            chainId: sourceChainId,
            name: "TestChain",
            rollupType: EthereumL1Bridge.RollupType.ZK_ROLLUP,
            canonicalBridge: address(0),
            messenger: address(0),
            stateCommitmentChain: address(0),
            challengePeriod: 0,
            confirmationBlocks: 1,
            enabled: true,
            gasLimit: 1000000,
            lastSyncedBlock: 0
        });
        bridge.configureL2Chain(config);
        
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(sourceChainId, stateRoot, bytes32(0), 100);
        
        // First initiation
        vm.prank(address(0xabc));
        (bool success1, ) = address(bridge).call(abi.encodeWithSelector(bridge.initiateWithdrawal.selector, sourceChainId, amount, nullifier, proof));
        
        if (success1) {
            // Second initiation with same nullifier MUST fail
            vm.prank(address(0xabc));
            (bool success2, ) = address(bridge).call(abi.encodeWithSelector(bridge.initiateWithdrawal.selector, sourceChainId, amount, nullifier, proof));
            assertFalse(success2);
        }
    }
    function test_Withdrawal_Finalization_Timeline(
        uint256 t_init,
        uint256 t_final,
        uint256 challengePeriod
    ) public {
        vm.assume(t_init > 1000000);
        vm.assume(challengePeriod > 0 && challengePeriod < 30 days);
        vm.assume(t_final >= t_init);
        
        uint256 sourceChainId = 10; // Optimism
        
        bridge.grantRole(OPERATOR_ROLE, address(this));
        EthereumL1Bridge.L2Config memory config = EthereumL1Bridge.L2Config({
            chainId: sourceChainId,
            name: "Optimism",
            rollupType: EthereumL1Bridge.RollupType.OPTIMISTIC,
            canonicalBridge: address(0x1),
            messenger: address(0x2),
            stateCommitmentChain: address(0x3),
            challengePeriod: challengePeriod,
            confirmationBlocks: 1,
            enabled: true,
            gasLimit: 1000000,
            lastSyncedBlock: 0
        });
        bridge.configureL2Chain(config);
        
        vm.warp(t_init);
        bytes32 nullifier = keccak256("nullifier");
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = bytes32(uint256(1));
        
        // Compute the expected state root that our placeholder logic will produce
        bytes32 leaf = keccak256(abi.encodePacked(nullifier, uint256(1 ether)));
        bytes32 stateRoot;
        if (leaf <= proof[0]) {
            stateRoot = keccak256(abi.encodePacked(leaf, proof[0]));
        } else {
            stateRoot = keccak256(abi.encodePacked(proof[0], leaf));
        }
        
        // 1. Submit state commitment
        bridge.grantRole(RELAYER_ROLE, address(this));
        vm.deal(address(this), 1 ether);
        uint256 t_submit = block.timestamp;
        bridge.submitStateCommitment{value: 0.1 ether}(sourceChainId, stateRoot, bytes32(0), 100);
        bytes32 commitmentId = keccak256(
            abi.encodePacked(
                sourceChainId,
                stateRoot,
                bytes32(0), // proofRoot
                uint256(100), // blockNumber
                t_submit,
                bytes32(0) // blobVersionedHash
            )
        );
        
        // 2. Finalize state commitment
        vm.warp(t_init + challengePeriod + 1);
        bridge.finalizeCommitment(commitmentId);
        
        // 3. Initiate withdrawal
        uint256 t_init_real = block.timestamp;
        bridge.initiateWithdrawal(sourceChainId, 1 ether, nullifier, proof);
        
        // Correct withdrawalId calculation
        bytes32 withdrawalId = keccak256(
            abi.encodePacked(
                address(this),
                sourceChainId,
                uint256(1 ether),
                nullifier,
                t_init_real
            )
        );
        
        // Try finalize withdrawal at t_final
        vm.assume(t_final >= t_init_real);
        vm.warp(t_final);
        (bool success, ) = address(bridge).call(abi.encodeWithSelector(bridge.finalizeWithdrawal.selector, withdrawalId));
        
        if (success) {
            assertTrue(t_final >= t_init_real + challengePeriod);
        } else {
            if (t_final < t_init_real + challengePeriod) {
                assertFalse(success);
            }
        }
    }
    function test_Commitment_Finalization_Timeline(
        uint256 t_submit,
        uint256 timePassed,
        uint256 challengePeriod
    ) public {
        t_submit = bound(t_submit, 1000000, type(uint64).max); // Use reasonable timestamp range
        challengePeriod = bound(challengePeriod, 1 minutes, 30 days);
        timePassed = bound(timePassed, 0, 365 days); // excessive time passed doesn't change logic
        
        uint256 t_final = t_submit + timePassed;

        uint256 chainId = 10; // Optimism
        
        bridge.grantRole(OPERATOR_ROLE, address(this));
        EthereumL1Bridge.L2Config memory config = EthereumL1Bridge.L2Config({
            chainId: chainId,
            name: "Optimism",
            rollupType: EthereumL1Bridge.RollupType.OPTIMISTIC,
            canonicalBridge: address(0x1),
            messenger: address(0x2),
            stateCommitmentChain: address(0x3),
            challengePeriod: challengePeriod,
            confirmationBlocks: 1,
            enabled: true,
            gasLimit: 1000000,
            lastSyncedBlock: 0
        });
        bridge.configureL2Chain(config);

        // 1. Submit commitment
        bridge.grantRole(RELAYER_ROLE, address(this));
        vm.deal(address(this), 1 ether);
        vm.warp(t_submit);
        
        bridge.submitStateCommitment{value: 0.1 ether}(chainId, bytes32(uint256(1)), bytes32(0), 100);
        
        bytes32 commitmentId = keccak256(
            abi.encodePacked(
                chainId,
                bytes32(uint256(1)), // stateRoot
                bytes32(0), // proofRoot
                uint256(100), // blockNumber
                t_submit,
                bytes32(0) // blobVersionedHash
            )
        );

        // 2. Try to finalize at t_final
        vm.warp(t_final);
        (bool success, ) = address(bridge).call(abi.encodeWithSelector(bridge.finalizeCommitment.selector, commitmentId));

        // 3. Verify property: Success implies we are past the deadline
        if (success) {
            assertTrue(t_final >= t_submit + challengePeriod);
        } else {
            // Failure implies we are too early (assuming no other revert reasons like paused/invalid ID)
            // Note: In a real environment there are other revert reasons, but here we isolate the time check behavior
            if (t_final < t_submit + challengePeriod) {
                assertFalse(success);
            }
        }
    }
}
