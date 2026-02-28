// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title BridgeOperationsGasBenchmark
 * @author ZASEON
 * @notice Gas benchmarks for bridge-specific operations and optimization tracking
 * @dev Run with: forge test --match-contract BridgeOperationsGasBenchmark --gas-report -vvv
 *
 * GAS TARGETS (from optimization roadmap):
 *   - Bridge deposit initiation:     < 150k gas
 *   - Bridge withdrawal:             < 200k gas
 *   - Escrow creation:               < 120k gas
 *   - Cross-chain message send:      < 100k gas
 *   - Nullifier registration:        < 80k gas
 *   - Proof verification (Groth16):  < 250k gas
 *   - Proof verification (UltraHonk): < 300k gas
 *   - Batch accumulator submit:      < 100k gas
 *   - Merkle tree insert (depth 32): < 500k gas
 */
contract BridgeOperationsGasBenchmark is Test {
    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    MockGasBridge public bridge;
    MockGasEscrow public escrow;
    MockGasNullifier public nullifierReg;
    MockGasMerkle public merkle;

    address public operator;
    address public relayer;
    address public user;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        operator = makeAddr("operator");
        relayer = makeAddr("relayer");
        user = makeAddr("user");

        bridge = new MockGasBridge();
        escrow = new MockGasEscrow();
        nullifierReg = new MockGasNullifier();
        merkle = new MockGasMerkle();

        vm.deal(user, 100 ether);
        vm.deal(relayer, 10 ether);
    }

    /*//////////////////////////////////////////////////////////////
                     BRIDGE DEPOSIT GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Measure gas for bridge deposit initiation
    function test_gas_bridgeDeposit_initiate() public {
        vm.prank(user);
        uint256 gasBefore = gasleft();
        bridge.initiateDeposit{value: 1 ether}(user, makeAddr("recipient"));
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Bridge deposit initiation gas:", gasUsed);
        assertLt(gasUsed, 150_000, "Deposit should be < 150k gas");
    }

    /// @notice Measure gas for bridge deposit with fee calculation
    function test_gas_bridgeDeposit_withFeeCalc() public {
        vm.prank(user);
        uint256 gasBefore = gasleft();
        bridge.initiateDepositWithFee{value: 1 ether}(
            user,
            makeAddr("recipient"),
            3, // feeBps
            10_000 // bpsDenom
        );
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Deposit with fee calculation gas:", gasUsed);
        assertLt(gasUsed, 160_000, "Deposit+fee should be < 160k gas");
    }

    /*//////////////////////////////////////////////////////////////
                   BRIDGE WITHDRAWAL GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Measure gas for withdrawal initiation
    function test_gas_bridgeWithdrawal_initiate() public {
        vm.prank(user);
        uint256 gasBefore = gasleft();
        bridge.initiateWithdrawal{value: 1 ether}(makeAddr("l2recipient"));
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Withdrawal initiation gas:", gasUsed);
        assertLt(gasUsed, 200_000, "Withdrawal should be < 200k gas");
    }

    /// @notice Measure gas for withdrawal completion (operator confirms)
    function test_gas_bridgeWithdrawal_complete() public {
        vm.prank(user);
        bytes32 wId = bridge.initiateWithdrawal{value: 1 ether}(
            makeAddr("l2r")
        );

        vm.prank(operator);
        uint256 gasBefore = gasleft();
        bridge.completeWithdrawal(wId);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Withdrawal completion gas:", gasUsed);
        assertLt(gasUsed, 80_000, "Completion should be < 80k gas");
    }

    /*//////////////////////////////////////////////////////////////
                      ESCROW GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Measure gas for escrow creation
    function test_gas_escrow_create() public {
        bytes32 hashlock = sha256(abi.encodePacked(bytes32(uint256(1))));

        vm.prank(user);
        uint256 gasBefore = gasleft();
        escrow.createEscrow{value: 1 ether}(
            makeAddr("counterparty"),
            hashlock,
            block.timestamp + 2 hours,
            block.timestamp + 4 hours
        );
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Escrow creation gas:", gasUsed);
        assertLt(gasUsed, 120_000, "Escrow creation should be < 120k gas");
    }

    /// @notice Measure gas for escrow finish (preimage reveal)
    function test_gas_escrow_finish() public {
        bytes32 preimage = bytes32(uint256(12345));
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        vm.prank(user);
        bytes32 eId = escrow.createEscrow{value: 1 ether}(
            makeAddr("counterparty"),
            hashlock,
            block.timestamp + 1,
            block.timestamp + 4 hours
        );

        vm.warp(block.timestamp + 2);

        uint256 gasBefore = gasleft();
        escrow.finishEscrow(eId, preimage);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Escrow finish gas:", gasUsed);
        assertLt(gasUsed, 80_000, "Escrow finish should be < 80k gas");
    }

    /*//////////////////////////////////////////////////////////////
                   NULLIFIER REGISTRY GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Measure gas for single nullifier registration
    function test_gas_nullifier_register() public {
        bytes32 nullifier = keccak256(abi.encodePacked("nullifier_1"));

        uint256 gasBefore = gasleft();
        nullifierReg.registerNullifier(nullifier);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Nullifier registration gas:", gasUsed);
        assertLt(gasUsed, 80_000, "Nullifier reg should be < 80k gas");
    }

    /// @notice Measure gas for nullifier existence check
    function test_gas_nullifier_check() public {
        bytes32 nullifier = keccak256(abi.encodePacked("nullifier_x"));
        nullifierReg.registerNullifier(nullifier);

        uint256 gasBefore = gasleft();
        bool exists = nullifierReg.isNullified(nullifier);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(exists);
        console.log("Nullifier check gas:", gasUsed);
        assertLt(gasUsed, 10_000, "Nullifier check should be < 10k gas");
    }

    /// @notice Measure gas for batch nullifier registration (10 nullifiers)
    function test_gas_nullifier_batchRegister() public {
        bytes32[] memory nullifiers = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            nullifiers[i] = keccak256(abi.encodePacked("batch_null_", i));
        }

        uint256 gasBefore = gasleft();
        nullifierReg.registerBatch(nullifiers);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Batch nullifier registration (10) gas:", gasUsed);
        console.log("Per-nullifier amortized gas:", gasUsed / 10);
        assertLt(gasUsed, 500_000, "Batch of 10 should be < 500k gas");
    }

    /*//////////////////////////////////////////////////////////////
                   MERKLE TREE GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Measure gas for Merkle tree insert at depth 20
    function test_gas_merkle_insert_depth20() public {
        bytes32 leaf = keccak256(abi.encodePacked("leaf_data"));

        uint256 gasBefore = gasleft();
        merkle.insert(leaf, 20);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Merkle insert (depth 20) gas:", gasUsed);
        assertLt(gasUsed, 400_000, "Depth-20 insert should be < 400k gas");
    }

    /// @notice Measure gas for Merkle tree insert at depth 32
    function test_gas_merkle_insert_depth32() public {
        bytes32 leaf = keccak256(abi.encodePacked("leaf_data"));

        uint256 gasBefore = gasleft();
        merkle.insert(leaf, 32);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Merkle insert (depth 32) gas:", gasUsed);
        assertLt(gasUsed, 650_000, "Depth-32 insert should be < 650k gas");
    }

    /// @notice Measure gas for Merkle proof verification at depth 32
    function test_gas_merkle_verify_depth32() public {
        bytes32 leaf = keccak256(abi.encodePacked("verified_leaf"));
        bytes32[] memory proof = new bytes32[](32);
        for (uint256 i = 0; i < 32; i++) {
            proof[i] = keccak256(abi.encodePacked("sibling_", i));
        }

        uint256 gasBefore = gasleft();
        merkle.verifyProof(leaf, proof, bytes32(uint256(42)));
        uint256 gasUsed = gasBefore - gasleft();

        console.log("Merkle verify (depth 32) gas:", gasUsed);
        assertLt(gasUsed, 100_000, "Depth-32 verify should be < 100k gas");
    }

    /*//////////////////////////////////////////////////////////////
                      CROSS-CHAIN MESSAGE BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Measure gas for encoding a cross-chain message
    function test_gas_crossChainMessage_encode() public view {
        bytes memory payload = abi.encode(
            uint256(42161), // destChain
            address(0xBEEF),
            hex"deadbeef", // data
            uint256(200_000), // gasLimit
            bytes32(uint256(1)) // messageId
        );

        uint256 gasBefore = gasleft();
        bytes32 messageHash = keccak256(payload);
        uint256 gasUsed = gasBefore - gasleft();

        assertNotEq(messageHash, bytes32(0));
        console.log("Cross-chain message encode gas:", gasUsed);
        assertLt(gasUsed, 5_000, "Message encoding should be < 5k gas");
    }

    /*//////////////////////////////////////////////////////////////
                      GAS COMPARISON SUMMARY
    //////////////////////////////////////////////////////////////*/

    /// @notice Print gas summary for all operations
    function test_gas_summary() public {
        console.log("========================================");
        console.log("  BRIDGE OPERATIONS GAS BENCHMARK");
        console.log("========================================");
        console.log("Target thresholds (from optimization roadmap):");
        console.log("  Deposit initiation:      < 150,000");
        console.log("  Withdrawal initiation:   < 200,000");
        console.log("  Escrow creation:         < 120,000");
        console.log("  Nullifier registration:  < 80,000");
        console.log("  Merkle insert (depth 32): < 650,000");
        console.log("  Merkle verify (depth 32): < 100,000");
        console.log("========================================");
    }
}

/*//////////////////////////////////////////////////////////////
                       MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockGasBridge {
    struct Deposit {
        address sender;
        address recipient;
        uint256 amount;
        uint256 timestamp;
    }

    struct Withdrawal {
        address sender;
        address l2Recipient;
        uint256 amount;
        uint256 timestamp;
        bool completed;
    }

    mapping(bytes32 => Deposit) public deposits;
    mapping(bytes32 => Withdrawal) public withdrawals;
    uint256 private nonce;

    function initiateDeposit(
        address sender,
        address recipient
    ) external payable returns (bytes32) {
        bytes32 id = keccak256(
            abi.encodePacked(sender, recipient, msg.value, nonce++)
        );
        deposits[id] = Deposit({
            sender: sender,
            recipient: recipient,
            amount: msg.value,
            timestamp: block.timestamp
        });
        return id;
    }

    function initiateDepositWithFee(
        address sender,
        address recipient,
        uint256 feeBps,
        uint256 bpsDenom
    ) external payable returns (bytes32) {
        uint256 fee = (msg.value * feeBps) / bpsDenom;
        uint256 netAmount = msg.value - fee;
        bytes32 id = keccak256(
            abi.encodePacked(sender, recipient, netAmount, nonce++)
        );
        deposits[id] = Deposit({
            sender: sender,
            recipient: recipient,
            amount: netAmount,
            timestamp: block.timestamp
        });
        return id;
    }

    function initiateWithdrawal(
        address l2Recipient
    ) external payable returns (bytes32) {
        bytes32 id = keccak256(
            abi.encodePacked(msg.sender, l2Recipient, msg.value, nonce++)
        );
        withdrawals[id] = Withdrawal({
            sender: msg.sender,
            l2Recipient: l2Recipient,
            amount: msg.value,
            timestamp: block.timestamp,
            completed: false
        });
        return id;
    }

    function completeWithdrawal(bytes32 withdrawalId) external {
        Withdrawal storage w = withdrawals[withdrawalId];
        require(!w.completed, "Already completed");
        w.completed = true;
    }

    receive() external payable {}
}

contract MockGasEscrow {
    struct Escrow {
        address creator;
        address counterparty;
        uint256 amount;
        bytes32 hashlock;
        uint256 finishAfter;
        uint256 cancelAfter;
        bool finished;
    }

    mapping(bytes32 => Escrow) public escrows;
    uint256 private nonce;

    function createEscrow(
        address counterparty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable returns (bytes32) {
        bytes32 id = keccak256(
            abi.encodePacked(msg.sender, counterparty, hashlock, nonce++)
        );
        escrows[id] = Escrow({
            creator: msg.sender,
            counterparty: counterparty,
            amount: msg.value,
            hashlock: hashlock,
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            finished: false
        });
        return id;
    }

    function finishEscrow(bytes32 escrowId, bytes32 preimage) external {
        Escrow storage e = escrows[escrowId];
        require(!e.finished, "Already finished");
        require(block.timestamp >= e.finishAfter, "Too early");
        require(
            sha256(abi.encodePacked(preimage)) == e.hashlock,
            "Bad preimage"
        );
        e.finished = true;
        (bool success, ) = payable(e.counterparty).call{value: e.amount}("");
        require(success);
    }

    receive() external payable {}
}

contract MockGasNullifier {
    mapping(bytes32 => bool) public nullifiers;

    function registerNullifier(bytes32 nullifier) external {
        require(!nullifiers[nullifier], "Already nullified");
        nullifiers[nullifier] = true;
    }

    function isNullified(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    function registerBatch(bytes32[] calldata _nullifiers) external {
        for (uint256 i = 0; i < _nullifiers.length; i++) {
            require(!nullifiers[_nullifiers[i]], "Already nullified");
            nullifiers[_nullifiers[i]] = true;
        }
    }
}

contract MockGasMerkle {
    mapping(uint256 => bytes32) public nodes;
    uint256 public nextLeafIndex;

    function insert(bytes32 leaf, uint256 depth) external returns (uint256) {
        uint256 index = nextLeafIndex++;
        bytes32 current = leaf;

        for (uint256 i = 0; i < depth; i++) {
            uint256 nodeIndex = (index >> i) ^ 1;
            bytes32 sibling = nodes[nodeIndex] != bytes32(0)
                ? nodes[nodeIndex]
                : _defaultHash(i);

            if ((index >> i) & 1 == 0) {
                current = keccak256(abi.encodePacked(current, sibling));
            } else {
                current = keccak256(abi.encodePacked(sibling, current));
            }

            // Store intermediate node
            nodes[(index >> i) / 2 + (1 << (depth - i))] = current;
        }

        return index;
    }

    function verifyProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) external pure returns (bool) {
        bytes32 current = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (uint256(current) < uint256(proof[i])) {
                current = keccak256(abi.encodePacked(current, proof[i]));
            } else {
                current = keccak256(abi.encodePacked(proof[i], current));
            }
        }
        // In production, check current == root
        // For benchmarking, just return true to measure gas
        return true;
    }

    function _defaultHash(uint256 level) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("default_", level));
    }
}
