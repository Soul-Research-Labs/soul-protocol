// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/privacy/PrivateRelayerNetwork.sol";

contract PrivateRelayerNetworkTest is Test {
    PrivateRelayerNetwork public network;
    PrivateRelayerNetwork public impl;

    address public admin = makeAddr("admin");
    address public feeRecipient = makeAddr("feeRecipient");
    address public operator = makeAddr("operator");
    address public slasher = makeAddr("slasher");
    address public relayer1 = makeAddr("relayer1");
    address public relayer2 = makeAddr("relayer2");
    address public relayer3 = makeAddr("relayer3");

    uint256 public constant PROTOCOL_FEE_BPS = 500; // 5%

    function setUp() public {
        impl = new PrivateRelayerNetwork();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(PrivateRelayerNetwork.initialize.selector, admin, feeRecipient, PROTOCOL_FEE_BPS)
        );
        network = PrivateRelayerNetwork(payable(address(proxy)));

        // Grant roles
        vm.startPrank(admin);
        network.grantRole(network.OPERATOR_ROLE(), operator);
        network.grantRole(network.SLASHER_ROLE(), slasher);
        vm.stopPrank();

        // Fund accounts
        vm.deal(relayer1, 50 ether);
        vm.deal(relayer2, 50 ether);
        vm.deal(relayer3, 50 ether);
        vm.deal(address(this), 50 ether);
    }

    // ─── Initialization ─────────────────────────────────────

    function test_initialize() public view {
        assertEq(network.protocolFeeRecipient(), feeRecipient);
        assertEq(network.protocolFeeBps(), PROTOCOL_FEE_BPS);
        assertTrue(network.hasRole(network.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_initialize_revert_doubleInit() public {
        vm.expectRevert();
        network.initialize(admin, feeRecipient, PROTOCOL_FEE_BPS);
    }

    // ─── Registration ───────────────────────────────────────

    function test_registerRelayer() public {
        bytes memory stealthMeta = _stealthMeta(relayer1);
        bytes32 vrfKey = keccak256("vrf1");

        vm.prank(relayer1);
        network.registerRelayer{value: 1 ether}(stealthMeta, vrfKey);

        PrivateRelayerNetwork.Relayer memory r = network.getRelayerInfo(relayer1);
        assertEq(r.relayerAddress, relayer1);
        assertEq(r.stake, 1 ether);
        assertTrue(r.status == PrivateRelayerNetwork.RelayerStatus.ACTIVE);
        assertEq(r.vrfKeyHash, vrfKey);
    }

    function test_registerRelayer_emitsEvent() public {
        bytes memory stealthMeta = _stealthMeta(relayer1);
        vm.prank(relayer1);
        vm.expectEmit(true, false, false, true);
        emit PrivateRelayerNetwork.RelayerRegistered(relayer1, 1 ether, stealthMeta);
        network.registerRelayer{value: 1 ether}(stealthMeta, keccak256("vrf"));
    }

    function test_registerRelayer_revert_insufficientStake() public {
        vm.prank(relayer1);
        vm.expectRevert(PrivateRelayerNetwork.InsufficientStake.selector);
        network.registerRelayer{value: 0.5 ether}(_stealthMeta(relayer1), keccak256("vrf"));
    }

    function test_registerRelayer_revert_alreadyRegistered() public {
        _registerRelayer(relayer1);

        vm.prank(relayer1);
        vm.expectRevert(PrivateRelayerNetwork.RelayerAlreadyRegistered.selector);
        network.registerRelayer{value: 1 ether}(_stealthMeta(relayer1), keccak256("vrf"));
    }

    // ─── Add Stake ──────────────────────────────────────────

    function test_addStake() public {
        _registerRelayer(relayer1);

        vm.prank(relayer1);
        network.addStake{value: 2 ether}();

        PrivateRelayerNetwork.Relayer memory r = network.getRelayerInfo(relayer1);
        assertEq(r.stake, 3 ether);
    }

    function test_addStake_revert_notActive() public {
        vm.prank(relayer1);
        vm.expectRevert();
        network.addStake{value: 1 ether}();
    }

    // ─── Exit Flow ──────────────────────────────────────────

    function test_requestExit() public {
        _registerRelayer(relayer1);

        vm.prank(relayer1);
        network.requestExit();

        PrivateRelayerNetwork.Relayer memory r = network.getRelayerInfo(relayer1);
        assertTrue(r.status == PrivateRelayerNetwork.RelayerStatus.EXITING);
        assertTrue(r.exitRequestedAt > 0);
    }

    function test_completeExit() public {
        _registerRelayer(relayer1);

        vm.prank(relayer1);
        network.requestExit();

        // Wait 7 days
        vm.warp(block.timestamp + 7 days + 1);

        uint256 balBefore = relayer1.balance;
        vm.prank(relayer1);
        network.completeExit();

        assertGe(relayer1.balance, balBefore);
    }

    function test_completeExit_revert_tooEarly() public {
        _registerRelayer(relayer1);

        vm.prank(relayer1);
        network.requestExit();

        // Don't wait long enough
        vm.warp(block.timestamp + 1 days);

        vm.prank(relayer1);
        vm.expectRevert(PrivateRelayerNetwork.ExitNotReady.selector);
        network.completeExit();
    }

    // ─── Commitment / Reveal ────────────────────────────────

    function test_submitCommitment() public {
        _registerRelayer(relayer1);

        bytes32 commitHash = keccak256("commitment");
        vm.prank(relayer1);
        network.submitCommitment(commitHash);

        PrivateRelayerNetwork.Commitment memory c = network.getCommitment(commitHash);
        assertEq(c.relayer, relayer1);
        assertTrue(c.status == PrivateRelayerNetwork.CommitmentStatus.COMMITTED);
    }

    function test_revealIntent() public {
        _registerRelayer(relayer1);

        // Build intent
        PrivateRelayerNetwork.RelayIntent memory intent;
        intent.transferId = keccak256("transfer1");
        intent.sourceChainId = 1;
        intent.targetChainId = 42161;
        intent.proofHash = keccak256("proof");
        intent.payload = "data";
        intent.fee = 0.01 ether;
        intent.deadline = block.timestamp + 1 hours;
        intent.relayType = PrivateRelayerNetwork.RelayType.STANDARD;
        intent.encryptedMetadata = "encrypted";

        // Compute commitment hash = H(intentHash, secret, block.timestamp)
        bytes32 secret = keccak256("secret");
        bytes32 intentHash = keccak256(abi.encode(intent));
        bytes32 commitHash = keccak256(
            abi.encodePacked(intentHash, secret, block.timestamp)
        );

        vm.prank(relayer1);
        network.submitCommitment(commitHash);

        // Advance blocks past COMMITMENT_WINDOW (3) but keep same timestamp
        vm.roll(block.number + 4);

        vm.prank(relayer1);
        network.revealIntent(secret, intent);
    }

    // ─── VRF Rounds ─────────────────────────────────────────

    function test_startVRFRound() public {
        // Need MIN_RELAYERS (3) active relayers
        _registerThreeRelayers();

        bytes32 seed = keccak256("seed");
        vm.prank(operator);
        network.startVRFRound(seed);

        assertTrue(network.currentVRFRound() != bytes32(0));
    }

    function test_selectRelayer() public {
        _registerThreeRelayers();

        bytes32 seed = keccak256("seed");
        vm.prank(operator);
        network.startVRFRound(seed);

        bytes32 roundId = network.currentVRFRound();
        bytes32 vrfOutput = keccak256("vrfOutput");

        vm.prank(operator);
        network.selectRelayer(roundId, vrfOutput);

        address selected = network.getSelectedRelayer(roundId);
        assertTrue(selected != address(0));
    }

    function test_startVRFRound_revert_notOperator() public {
        vm.prank(relayer1);
        vm.expectRevert();
        network.startVRFRound(keccak256("seed"));
    }

    // ─── Stealth Fee ────────────────────────────────────────

    function test_payStealthFee() public {
        _registerRelayer(relayer1);

        address stealthAddr = makeAddr("stealth");
        bytes memory ephKey = abi.encodePacked(keccak256("ephemeral"));

        vm.deal(address(this), 1 ether);
        network.payStealthFee{value: 0.1 ether}(relayer1, stealthAddr, ephKey, keccak256("transfer1"));
    }

    // ─── Slashing ───────────────────────────────────────────

    function test_slashRelayer() public {
        _registerRelayer(relayer1);

        vm.prank(slasher);
        network.slashRelayer(relayer1, "misbehavior");

        PrivateRelayerNetwork.Relayer memory r = network.getRelayerInfo(relayer1);
        assertTrue(r.status == PrivateRelayerNetwork.RelayerStatus.JAILED);
        assertTrue(r.slashedAmount > 0);
    }

    function test_slashRelayer_revert_notSlasher() public {
        _registerRelayer(relayer1);

        vm.prank(relayer1);
        vm.expectRevert();
        network.slashRelayer(relayer1, "nope");
    }

    function test_unjailRelayer() public {
        _registerRelayer(relayer1);

        vm.prank(slasher);
        network.slashRelayer(relayer1, "test");

        // Wait cooldown
        vm.warp(block.timestamp + 1 days + 1);

        vm.prank(relayer1);
        network.unjailRelayer();

        PrivateRelayerNetwork.Relayer memory r = network.getRelayerInfo(relayer1);
        assertTrue(r.status == PrivateRelayerNetwork.RelayerStatus.ACTIVE);
    }

    // ─── View Functions ─────────────────────────────────────

    function test_getRelayerCount() public {
        assertEq(network.getRelayerCount(), 0);
        _registerRelayer(relayer1);
        assertEq(network.getRelayerCount(), 1);
    }

    function test_getActiveRelayers() public {
        _registerThreeRelayers();
        address[] memory active = network.getActiveRelayers();
        assertEq(active.length, 3);
    }

    // ─── Receive ETH ────────────────────────────────────────

    function test_receiveETH() public {
        (bool ok,) = address(network).call{value: 1 ether}("");
        assertTrue(ok);
    }

    // ─── Fuzz ───────────────────────────────────────────────

    function testFuzz_registerRelayer_stake(uint256 stake) public {
        stake = bound(stake, 1 ether, 100 ether);
        vm.deal(relayer1, stake);
        vm.prank(relayer1);
        network.registerRelayer{value: stake}(_stealthMeta(relayer1), keccak256("vrf"));

        PrivateRelayerNetwork.Relayer memory r = network.getRelayerInfo(relayer1);
        assertEq(r.stake, stake);
    }

    // ─── Helpers ────────────────────────────────────────────

    function _stealthMeta(address a) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encodePacked(a)));
    }

    function _registerRelayer(address relayer) internal {
        vm.prank(relayer);
        network.registerRelayer{value: 1 ether}(
            _stealthMeta(relayer),
            keccak256(abi.encodePacked("vrf_", relayer))
        );
    }

    function _registerThreeRelayers() internal {
        _registerRelayer(relayer1);
        _registerRelayer(relayer2);
        _registerRelayer(relayer3);
    }
}
