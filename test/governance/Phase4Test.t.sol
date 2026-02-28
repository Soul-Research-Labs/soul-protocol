// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/governance/ZaseonGovernance.sol";
import "../../contracts/crosschain/ZaseonCrossChainRelay.sol";
import "../../contracts/crosschain/MessageBatcher.sol";

// Mock ProofHub
contract MockProofHub {
    function submitProofInstant(
        bytes calldata, bytes calldata, bytes32, uint64, uint64, bytes32
    ) external pure {}
}

// Mock Bridge Adapter
contract MockRelayAdapter {
    event MessageSent(bytes payload);
    function dispatch(uint32, bytes32, bytes calldata payload) external payable {
        emit MessageSent(payload);
    }
}

contract Phase4Test is Test {
    ZaseonGovernance public governance;
    ZaseonCrossChainRelay public relay;
    MessageBatcher public batcher;
    MockProofHub public proofHub;
    MockRelayAdapter public relayAdapter;

    address public admin = address(this);
    address public proposer = makeAddr("proposer");
    address public executor = makeAddr("executor");
    address public user = makeAddr("user");

    function setUp() public {
        // Deploy dependencies
        proofHub = new MockProofHub();
        relayAdapter = new MockRelayAdapter();

        // Deploy Relay
        relay = new ZaseonCrossChainRelay(address(proofHub), ZaseonCrossChainRelay.BridgeType.HYPERLANE);
        
        // Configure Relay
        ZaseonCrossChainRelay.ChainConfig memory config = ZaseonCrossChainRelay.ChainConfig({
            proofHub: address(proofHub),
            relayAdapter: address(relayAdapter),
            bridgeChainId: 100,
            active: true
        });
        relay.configureChain(100, config);

        // Deploy Governance
        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;
        
        governance = new ZaseonGovernance(
            1 days, // minDelay
            proposers,
            executors,
            admin
        );

        // Deploy Batcher
        batcher = new MessageBatcher(address(relay), admin);

        // Setup Roles
        // Grant Batcher RELAYER_ROLE on Relay?
        // Relay checks RELAYER_ROLE for relayProof, but what about relayBatch?
        // Let's check relayBatch in ZaseonCrossChainRelay.sol
        // It does NOT have `onlyRole(RELAYER_ROLE)`!
        // It is `external payable nonReentrant whenNotPaused`.
        // So anyone can call relayBatch. Good.
        
        vm.deal(user, 100 ether);
    }

    function test_GovernanceFlow() public {
        // Transfer Relay ownership to Governance
        relay.grantRole(relay.DEFAULT_ADMIN_ROLE(), address(governance));
        relay.revokeRole(relay.DEFAULT_ADMIN_ROLE(), admin);

        // Proposal: Update Relay pause state (requires OPERATOR_ROLE, or ADMIN to grant role?)
        // Governance is ADMIN.
        // Let's propose to grant OPERATOR_ROLE to user.
        
        bytes memory data = abi.encodeWithSelector(
            AccessControl.grantRole.selector,
            relay.OPERATOR_ROLE(),
            user
        );
        
        vm.startPrank(proposer);
        governance.schedule(
            address(relay),
            0,
            data,
            bytes32(0),
            bytes32("salt"),
            1 days
        );
        vm.stopPrank();

        // Wait
        vm.warp(block.timestamp + 1 days + 1);

        // Execute
        vm.startPrank(executor);
        governance.execute(
            address(relay),
            0,
            data,
            bytes32(0),
            bytes32("salt")
        );
        vm.stopPrank();

        // Check result
        assertTrue(relay.hasRole(relay.OPERATOR_ROLE(), user));
    }

    function test_MessageBatching() public {
        // Queue 2 messages
        bytes32 proofId = keccak256("proof");
        
        vm.startPrank(user);
        
        // Message 1
        batcher.queueProof{value: 0.1 ether}(
            proofId, hex"AA", hex"BB", bytes32(0), 100, bytes32("type")
        );
        
        // Message 2
        batcher.queueProof{value: 0.1 ether}(
            proofId, hex"CC", hex"DD", bytes32(0), 100, bytes32("type")
        );
        
        assertEq(address(batcher).balance, 0.2 ether);
        
        // Trigger send
        vm.expectEmit(true, true, false, false); // Don't check data
        emit MockRelayAdapter.MessageSent(hex""); 
        batcher.sendBatch(100);
        
        vm.stopPrank();
        
        assertEq(address(batcher).balance, 0 ether); // All sent to relay/bridge
    }
    
    function test_AutoBatchSend() public {
        batcher.setMaxBatchSize(2);
        
        vm.startPrank(user);
        batcher.queueProof{value: 0.1 ether}(
            bytes32("1"), hex"", hex"", bytes32(0), 100, bytes32(0)
        );
        // Should trigger auto-send on 2nd
        batcher.queueProof{value: 0.1 ether}(
            bytes32("2"), hex"", hex"", bytes32(0), 100, bytes32(0)
        );
        vm.stopPrank();
        
        // Queue should be empty
        // Cannot access mapping length directly easily, but next send should fail
        vm.expectRevert("Queue empty");
        batcher.sendBatch(100);
    }
}
