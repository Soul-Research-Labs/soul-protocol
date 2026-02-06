// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/EthereumL1Bridge.sol";

contract EthereumL1BridgeFuzz is Test {
    EthereumL1Bridge public bridge;

    address public admin = address(0xA);
    address public operator = address(0xB);
    address public guardian = address(0xC);
    address public relayer = address(0xD);
    address public user1 = address(0xE);

    function setUp() public {
        vm.prank(admin);
        bridge = new EthereumL1Bridge();
        vm.startPrank(admin);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        vm.stopPrank();
    }

    // --- L2 Chain Support ---
    function test_defaultL2ChainsConfigured() public view {
        uint256[] memory chains = bridge.getSupportedChainIds();
        assertTrue(chains.length > 0);
    }

    function testFuzz_isChainSupported(uint256 chainId) public view {
        // Most random chain IDs are not supported
        if (chainId != 42161 && chainId != 10 && chainId != 8453 && chainId != 324 &&
            chainId != 534352 && chainId != 59144 && chainId != 1101 && chainId != 42170) {
            assertFalse(bridge.isChainSupported(chainId));
        }
    }

    // --- Deposit ETH ---
    function testFuzz_depositETHToSupportedChain(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 10 ether);
        uint256[] memory chains = bridge.getSupportedChainIds();
        vm.assume(chains.length > 0);
        uint256 targetChain = chains[0];
        vm.deal(user1, amount);
        vm.prank(user1);
        bridge.depositETH{value: amount}(targetChain, bytes32(uint256(1)));
    }

    function testFuzz_depositETHUnsupportedChainReverts(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 10 ether);
        vm.deal(user1, amount);
        vm.prank(user1);
        vm.expectRevert();
        bridge.depositETH{value: amount}(99999, bytes32(uint256(1)));
    }

    // --- Nullifier Protection ---
    function testFuzz_nullifierUsedCheck(bytes32 nullifier) public view {
        assertFalse(bridge.isNullifierUsed(nullifier));
    }

    // --- State Commitments ---
    function testFuzz_submitStateCommitmentRequiresSupported(bytes32 root, bytes32 proofRoot, uint256 blockNum) public {
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        vm.expectRevert();
        bridge.submitStateCommitment{value: 0.01 ether}(99999, root, proofRoot, blockNum);
    }

    // --- Pause ---
    function test_pauseAndUnpause() public {
        vm.prank(guardian);
        bridge.pause();
        assertTrue(bridge.paused());
        vm.prank(operator);
        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != admin && caller != guardian);
        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    // --- Access Control ---
    function testFuzz_onlyOperatorConfiguresChain(address caller) public {
        vm.assume(caller != admin && caller != operator);
        EthereumL1Bridge.L2Config memory config = EthereumL1Bridge.L2Config({
            chainId: 777,
            name: "Test",
            rollupType: EthereumL1Bridge.RollupType.ZK_ROLLUP,
            canonicalBridge: address(1),
            messenger: address(2),
            stateCommitmentChain: address(3),
            challengePeriod: 7 days,
            confirmationBlocks: 1,
            enabled: true,
            gasLimit: 1000000,
            lastSyncedBlock: 0
        });
        vm.prank(caller);
        vm.expectRevert();
        bridge.configureL2Chain(config);
    }

    // --- Rate Limits ---
    function testFuzz_setRateLimits(uint256 max) public {
        max = bound(max, 1, 1000);
        vm.prank(admin);
        bridge.setMaxCommitmentsPerHour(max);
        assertEq(bridge.maxCommitmentsPerHour(), max);
    }

    // --- Receive ---
    function testFuzz_receiveETH(uint256 amount) public {
        amount = bound(amount, 1, 10 ether);
        vm.deal(user1, amount);
        vm.prank(user1);
        (bool ok,) = address(bridge).call{value: amount}("");
        assertTrue(ok);
    }
}
