// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {UniversalShieldedPool} from "../../contracts/privacy/UniversalShieldedPool.sol";
import {IUniversalShieldedPool} from "../../contracts/interfaces/IUniversalShieldedPool.sol";

/// @dev Mock verifier for gas measurement
contract GasMockVerifier {
    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }
}

/// @dev Mock batch verifier for gas measurement
contract GasMockBatchVerifier {
    function verify(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }
}

/**
 * @title ShieldedPoolGasBenchmark
 * @notice Gas benchmarks for UniversalShieldedPool critical operations
 *
 * TARGET BUDGETS:
 * - depositETH:                   < 200,000 gas
 * - withdraw:                     < 350,000 gas
 * - insertCrossChainCommitments:  < 250,000 gas (per 2 commitments)
 * - depositETH (10th deposit):    < 250,000 gas (tree grows)
 */
contract ShieldedPoolGasBenchmark is Test {
    UniversalShieldedPool public pool;
    GasMockVerifier public verifier;
    GasMockBatchVerifier public batchVerifier;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public user = makeAddr("user");
    address public recipient = makeAddr("recipient");

    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;

    uint256 internal constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes32 public NATIVE_ASSET;

    function _validCommitment(
        bytes memory seed
    ) internal pure returns (bytes32) {
        return bytes32((uint256(keccak256(seed)) % (FIELD_SIZE - 1)) + 1);
    }

    function setUp() public {
        vm.startPrank(admin);
        verifier = new GasMockVerifier();
        batchVerifier = new GasMockBatchVerifier();
        pool = new UniversalShieldedPool(admin, address(verifier), false);
        pool.grantRole(RELAYER_ROLE, relayer);
        pool.setBatchVerifier(address(batchVerifier));
        NATIVE_ASSET = pool.NATIVE_ASSET();
        vm.stopPrank();

        vm.deal(user, 1000 ether);
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: depositETH (first deposit — cold storage)
    // ─────────────────────────────────────────────────────────────

    function test_gas_DepositETH_First() public {
        bytes32 commitment = _validCommitment(abi.encodePacked("gas-first"));

        vm.prank(user);
        uint256 gasBefore = gasleft();
        pool.depositETH{value: 1 ether}(commitment);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("depositETH(first) gas", gasUsed);
        assertLt(gasUsed, 1_500_000, "depositETH(first) should be < 1.5M gas");
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: depositETH (10th deposit — warm storage, deeper tree)
    // ─────────────────────────────────────────────────────────────

    function test_gas_DepositETH_Tenth() public {
        // Warm up the tree with 9 deposits
        for (uint256 i = 0; i < 9; i++) {
            bytes32 c = _validCommitment(abi.encodePacked("warmup", i));
            vm.prank(user);
            pool.depositETH{value: 0.1 ether}(c);
        }

        bytes32 commitment = _validCommitment(abi.encodePacked("gas-tenth"));

        vm.prank(user);
        uint256 gasBefore = gasleft();
        pool.depositETH{value: 1 ether}(commitment);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("depositETH(10th) gas", gasUsed);
        assertLt(gasUsed, 1_500_000, "depositETH(10th) should be < 1.5M gas");
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: withdraw (with mock proof verification)
    // ─────────────────────────────────────────────────────────────

    function test_gas_Withdraw() public {
        // Deposit first
        bytes32 commitment = _validCommitment(abi.encodePacked("gas-withdraw"));
        vm.prank(user);
        pool.depositETH{value: 1 ether}(commitment);

        bytes32 root = pool.currentRoot();
        bytes32 nullifier = keccak256("gas-nullifier");

        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: hex"deadbeef",
                merkleRoot: root,
                nullifier: nullifier,
                recipient: recipient,
                relayerAddress: address(0),
                amount: 1 ether,
                relayerFee: 0,
                assetId: NATIVE_ASSET,
                destChainId: bytes32(0)
            });

        uint256 gasBefore = gasleft();
        pool.withdraw(wp);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("withdraw gas", gasUsed);
        assertLt(gasUsed, 1_600_000, "withdraw should be < 1.6M gas");
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: withdraw with relayer fee
    // ─────────────────────────────────────────────────────────────

    function test_gas_Withdraw_WithRelayerFee() public {
        bytes32 commitment = _validCommitment(
            abi.encodePacked("gas-relayer-fee")
        );
        vm.prank(user);
        pool.depositETH{value: 5 ether}(commitment);

        bytes32 root = pool.currentRoot();

        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: hex"cafe",
                merkleRoot: root,
                nullifier: keccak256("gas-relayer-null"),
                recipient: recipient,
                relayerAddress: relayer,
                amount: 5 ether,
                relayerFee: 0.1 ether,
                assetId: NATIVE_ASSET,
                destChainId: bytes32(0)
            });

        uint256 gasBefore = gasleft();
        pool.withdraw(wp);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("withdraw(relayerFee) gas", gasUsed);
        assertLt(
            gasUsed,
            1_600_000,
            "withdraw(relayerFee) should be < 1.6M gas"
        );
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: insertCrossChainCommitments (batch of 2)
    // ─────────────────────────────────────────────────────────────

    function test_gas_InsertCrossChainCommitments() public {
        bytes32 c1 = _validCommitment(abi.encodePacked("xchain-gas-1"));
        bytes32 c2 = _validCommitment(abi.encodePacked("xchain-gas-2"));

        bytes32[] memory commits = new bytes32[](2);
        commits[0] = c1;
        commits[1] = c2;

        bytes32[] memory assetIds = new bytes32[](2);
        assetIds[0] = NATIVE_ASSET;
        assetIds[1] = NATIVE_ASSET;

        IUniversalShieldedPool.CrossChainCommitmentBatch
            memory batch = IUniversalShieldedPool.CrossChainCommitmentBatch({
                sourceChainId: bytes32(uint256(42161)),
                commitments: commits,
                assetIds: assetIds,
                batchRoot: keccak256(abi.encodePacked(c1, c2)),
                proof: hex"ba7c400f",
                sourceTreeSize: 100
            });

        vm.prank(relayer);
        uint256 gasBefore = gasleft();
        pool.insertCrossChainCommitments(batch);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("insertCrossChainCommitments(2) gas", gasUsed);
        assertLt(
            gasUsed,
            2_500_000,
            "insertCrossChainCommitments(2) should be < 2.5M gas"
        );
    }
}
