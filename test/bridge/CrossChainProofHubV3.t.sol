// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CrossChainProofHubV3} from "../../contracts/bridge/CrossChainProofHubV3.sol";
import {ICrossChainProofHubV3, BatchProofInput} from "../../contracts/interfaces/ICrossChainProofHubV3.sol";
import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";

contract MockProofVerifier is IProofVerifier {
    bool public returnValue;

    constructor(bool _returnValue) {
        returnValue = _returnValue;
    }

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view override returns (bool) {
        return returnValue;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view override returns (bool) {
        return returnValue;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external view override returns (bool) {
        return returnValue;
    }

    function getPublicInputCount() external pure override returns (uint256) {
        return 1;
    }

    function isReady() external pure override returns (bool) {
        return true;
    }
}

contract CrossChainProofHubV3Test is Test {
    CrossChainProofHubV3 public hub;

    address public admin;
    address public relayer = address(0xAA01);
    address public challenger = address(0xAA02);
    address public operator = address(0xAA03);
    address public user = address(0xCCCC);

    MockProofVerifier public trueVerifier;
    MockProofVerifier public falseVerifier;

    bytes32 constant PROOF_TYPE =
        0x8cdf3a8b78ebe00eba9fa85c0a9029fb57ab374b0492d22d68498e28e9e5b598;

    function setUp() public {
        admin = address(this);
        hub = new CrossChainProofHubV3();

        trueVerifier = new MockProofVerifier(true);
        falseVerifier = new MockProofVerifier(false);

        // Set up roles
        hub.grantRole(hub.RELAYER_ROLE(), relayer);
        hub.grantRole(hub.CHALLENGER_ROLE(), challenger);
        hub.grantRole(hub.OPERATOR_ROLE(), operator);
        hub.grantRole(hub.VERIFIER_ADMIN_ROLE(), admin);

        // Install verifier
        hub.setVerifier(PROOF_TYPE, address(trueVerifier));

        // Add a supported destination chain
        hub.addSupportedChain(42161); // Arbitrum

        // Confirm role separation so submission works
        hub.confirmRoleSeparation();

        // Fund relayer for staking
        vm.deal(relayer, 10 ether);
        vm.deal(challenger, 10 ether);
        vm.deal(user, 10 ether);
    }

    // ======= Initial State =======

    function test_initialState() public view {
        assertEq(hub.totalProofs(), 0);
        assertEq(hub.totalBatches(), 0);
        assertEq(hub.challengePeriod(), 1 hours);
        assertEq(hub.minRelayerStake(), 0.1 ether);
        assertEq(hub.minChallengerStake(), 0.05 ether);
        assertEq(hub.proofSubmissionFee(), 0.001 ether);
        assertTrue(hub.supportedChains(block.chainid));
        assertTrue(hub.rolesSeparated());
    }

    // ======= Stake Management =======

    function test_depositStake() public {
        vm.prank(relayer);
        hub.depositStake{value: 1 ether}();

        (uint256 stake, , ) = hub.getRelayerStats(relayer);
        assertEq(stake, 1 ether);
    }

    function test_withdrawStake() public {
        vm.prank(relayer);
        hub.depositStake{value: 1 ether}();

        vm.prank(relayer);
        hub.withdrawStake(0.5 ether);

        (uint256 stake, , ) = hub.getRelayerStats(relayer);
        assertEq(stake, 0.5 ether);
    }

    function test_withdrawStake_insufficientBalance() public {
        vm.prank(relayer);
        hub.depositStake{value: 0.1 ether}();

        vm.prank(relayer);
        vm.expectRevert();
        hub.withdrawStake(1 ether);
    }

    // ======= Proof Submission =======

    function test_submitProof() public {
        _stakeRelayer();

        bytes memory proof = hex"deadbeef";
        bytes memory inputs = hex"cafe";
        bytes32 commitment = keccak256("commitment1");

        vm.prank(relayer);
        bytes32 proofId = hub.submitProof{value: 0.001 ether}(
            proof,
            inputs,
            commitment,
            uint64(block.chainid),
            42161
        );

        assertEq(hub.totalProofs(), 1);

        ICrossChainProofHubV3.ProofSubmission memory sub = hub.getProof(
            proofId
        );
        assertEq(sub.commitment, commitment);
        assertEq(sub.sourceChainId, uint64(block.chainid));
        assertEq(sub.destChainId, 42161);
        assertEq(sub.relayer, relayer);
        assertEq(
            uint256(sub.status),
            uint256(ICrossChainProofHubV3.ProofStatus.Pending)
        );
    }

    function test_submitProof_insufficientFee() public {
        _stakeRelayer();

        vm.prank(relayer);
        vm.expectRevert();
        hub.submitProof{value: 0.0001 ether}(
            hex"aa",
            hex"bb",
            keccak256("c1"),
            uint64(block.chainid),
            42161
        );
    }

    function test_submitProof_insufficientStake() public {
        // Don't stake — should fail
        vm.prank(relayer);
        vm.expectRevert();
        hub.submitProof{value: 0.001 ether}(
            hex"aa",
            hex"bb",
            keccak256("c1"),
            uint64(block.chainid),
            42161
        );
    }

    function test_submitProof_unsupportedChain() public {
        _stakeRelayer();

        vm.prank(relayer);
        vm.expectRevert();
        hub.submitProof{value: 0.001 ether}(
            hex"aa",
            hex"bb",
            keccak256("c1"),
            uint64(block.chainid),
            99999
        );
    }

    // ======= Instant Proof Submission =======

    function test_submitProofInstant() public {
        _stakeRelayer();

        // Build publicInputs with binding hash as first 32 bytes (H-6 fix)
        bytes32 commitment = keccak256("c1");
        uint64 srcChain = uint64(block.chainid);
        uint64 dstChain = 42161;
        bytes32 binding = keccak256(
            abi.encodePacked(commitment, srcChain, dstChain)
        );
        bytes memory publicInputs = abi.encodePacked(binding, bytes32(0));
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(0xdeadbeef)),
            bytes32(0)
        );

        vm.prank(relayer);
        bytes32 proofId = hub.submitProofInstant{value: 0.003 ether}(
            proof,
            publicInputs,
            commitment,
            srcChain,
            dstChain,
            PROOF_TYPE
        );

        ICrossChainProofHubV3.ProofSubmission memory sub = hub.getProof(
            proofId
        );
        // Instant verification should set status to Verified
        assertEq(
            uint256(sub.status),
            uint256(ICrossChainProofHubV3.ProofStatus.Verified)
        );
    }

    function test_submitProofInstant_failedVerification() public {
        _stakeRelayer();
        hub.setVerifier(PROOF_TYPE, address(falseVerifier));

        bytes32 commitment = keccak256("c1");
        uint64 srcChain = uint64(block.chainid);
        uint64 dstChain = 42161;
        bytes32 binding = keccak256(
            abi.encodePacked(commitment, srcChain, dstChain)
        );
        bytes memory publicInputs = abi.encodePacked(binding, bytes32(0));
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(0xdeadbeef)),
            bytes32(0)
        );

        vm.prank(relayer);
        vm.expectRevert();
        hub.submitProofInstant{value: 0.003 ether}(
            proof,
            publicInputs,
            commitment,
            srcChain,
            dstChain,
            PROOF_TYPE
        );
    }

    // ======= Batch Submission =======

    function test_submitBatch() public {
        _stakeRelayer();

        BatchProofInput[] memory inputs = new BatchProofInput[](3);
        for (uint256 i = 0; i < 3; i++) {
            inputs[i] = BatchProofInput({
                proofHash: keccak256(abi.encode("proof", i)),
                publicInputsHash: keccak256(abi.encode("inputs", i)),
                commitment: keccak256(abi.encode("commit", i)),
                sourceChainId: uint64(block.chainid),
                destChainId: 42161
            });
        }

        bytes32 merkleRoot = keccak256("batchRoot");

        vm.prank(relayer);
        bytes32 batchId = hub.submitBatch{value: 0.003 ether}(
            inputs,
            merkleRoot
        );

        ICrossChainProofHubV3.BatchSubmission memory batch = hub.getBatch(
            batchId
        );
        assertEq(batch.merkleRoot, merkleRoot);
        assertEq(batch.proofCount, 3);
        assertEq(batch.relayer, relayer);
        assertEq(hub.totalBatches(), 1);
    }

    function test_submitBatch_emptyReverts() public {
        _stakeRelayer();

        BatchProofInput[] memory inputs = new BatchProofInput[](0);

        vm.prank(relayer);
        vm.expectRevert();
        hub.submitBatch{value: 0.001 ether}(inputs, keccak256("root"));
    }

    // ======= Proof Finalization =======

    function test_finalizeProof_afterChallengePeriod() public {
        bytes32 proofId = _submitProofAsRelayer();

        // Advance past challenge period
        vm.warp(block.timestamp + hub.challengePeriod() + 1);

        hub.finalizeProof(proofId);

        assertTrue(hub.isProofFinalized(proofId));
    }

    function test_finalizeProof_beforeChallengePeriod_reverts() public {
        bytes32 proofId = _submitProofAsRelayer();

        vm.expectRevert();
        hub.finalizeProof(proofId);
    }

    // ======= Challenge System =======

    function test_challengeProof() public {
        bytes32 proofId = _submitProofAsRelayer();

        vm.prank(challenger);
        hub.challengeProof{value: 0.05 ether}(proofId, "Invalid proof data");

        ICrossChainProofHubV3.Challenge memory c = hub.getChallenge(proofId);
        assertEq(c.challenger, challenger);
        assertFalse(c.resolved);
        assertEq(c.reason, "Invalid proof data");
    }

    function test_challengeProof_insufficientStake() public {
        bytes32 proofId = _submitProofAsRelayer();

        vm.prank(challenger);
        vm.expectRevert();
        hub.challengeProof{value: 0.001 ether}(proofId, "bad proof");
    }

    function test_resolveChallenge_challengerWins() public {
        bytes32 proofId = _submitProofAsRelayer();

        vm.prank(challenger);
        hub.challengeProof{value: 0.05 ether}(proofId, "bad");

        // Install a failing verifier to make challenger win
        hub.setVerifier(PROOF_TYPE, address(falseVerifier));

        vm.prank(challenger);
        hub.resolveChallenge(proofId, hex"deadbeef", hex"cafe", PROOF_TYPE);

        ICrossChainProofHubV3.Challenge memory c = hub.getChallenge(proofId);
        assertTrue(c.resolved);
        assertTrue(c.challengerWon);
    }

    function test_resolveChallenge_relayerWins() public {
        bytes32 proofId = _submitProofAsRelayer();

        vm.prank(challenger);
        hub.challengeProof{value: 0.05 ether}(proofId, "bad");

        // Challenger resolves with the SAME proof data → verifier confirms validity → relayer wins
        // trueVerifier returns true, so the original proof is proven valid
        vm.prank(challenger);
        hub.resolveChallenge(proofId, hex"deadbeef", hex"cafe", PROOF_TYPE);

        ICrossChainProofHubV3.Challenge memory c = hub.getChallenge(proofId);
        assertTrue(c.resolved);
        assertFalse(c.challengerWon);
    }

    function test_expireChallenge() public {
        bytes32 proofId = _submitProofAsRelayer();

        vm.prank(challenger);
        hub.challengeProof{value: 0.05 ether}(proofId, "bad");

        // Advance past challenge deadline
        ICrossChainProofHubV3.Challenge memory c = hub.getChallenge(proofId);
        vm.warp(c.deadline + 1);

        hub.expireChallenge(proofId);

        c = hub.getChallenge(proofId);
        assertTrue(c.resolved);
        assertFalse(c.challengerWon); // Expired = relayer wins
    }

    // ======= Admin Functions =======

    function test_addSupportedChain() public {
        hub.addSupportedChain(10); // Optimism
        assertTrue(hub.supportedChains(10));
    }

    function test_removeSupportedChain() public {
        hub.addSupportedChain(10);
        hub.removeSupportedChain(10);
        assertFalse(hub.supportedChains(10));
    }

    function test_setChallengePeriod() public {
        hub.setChallengePeriod(2 hours);
        assertEq(hub.challengePeriod(), 2 hours);
    }

    function test_setMinStakes() public {
        hub.setMinStakes(0.5 ether, 0.2 ether);
        assertEq(hub.minRelayerStake(), 0.5 ether);
        assertEq(hub.minChallengerStake(), 0.2 ether);
    }

    function test_setProofSubmissionFee() public {
        hub.setProofSubmissionFee(0.01 ether);
        assertEq(hub.proofSubmissionFee(), 0.01 ether);
    }

    function test_setRateLimits() public {
        hub.setRateLimits(500, 500 ether);
        assertEq(hub.maxProofsPerHour(), 500);
        assertEq(hub.maxValuePerHour(), 500 ether);
    }

    function test_setTrustedRemote() public {
        address remote = address(0xBEEF);
        vm.prank(operator);
        hub.setTrustedRemote(42161, remote);
        assertEq(hub.trustedRemotes(42161), remote);
    }

    function test_pause_unpause() public {
        hub.pause();
        assertTrue(hub.paused());

        hub.unpause();
        assertFalse(hub.paused());
    }

    function test_withdrawFees() public {
        // Submit a proof to generate fees
        _stakeRelayer();
        vm.prank(relayer);
        hub.submitProof{value: 0.001 ether}(
            hex"aa",
            hex"bb",
            keccak256("c1"),
            uint64(block.chainid),
            42161
        );

        address payable recipient = payable(address(0xFEED));
        uint256 balBefore = recipient.balance;
        hub.withdrawFees(recipient);
        assertTrue(recipient.balance >= balBefore);
    }

    // ======= View Functions =======

    function test_getRelayerStats() public {
        _stakeRelayer();

        (uint256 stake, uint256 success, uint256 slash) = hub.getRelayerStats(
            relayer
        );
        assertEq(stake, 1 ether);
        assertEq(success, 0);
        assertEq(slash, 0);
    }

    function test_isProofFinalized_false() public {
        bytes32 proofId = _submitProofAsRelayer();
        assertFalse(hub.isProofFinalized(proofId));
    }

    // ======= Access Control =======

    function test_onlyRelayerCanSubmit() public {
        vm.prank(user);
        vm.expectRevert();
        hub.submitProof{value: 0.001 ether}(
            hex"aa",
            hex"bb",
            keccak256("c1"),
            uint64(block.chainid),
            42161
        );
    }

    function test_onlyAdminCanSetChallengePeriod() public {
        vm.prank(user);
        vm.expectRevert();
        hub.setChallengePeriod(2 hours);
    }

    // ======= Fuzz Tests =======

    function testFuzz_depositStake(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 5 ether);
        vm.deal(relayer, amount);

        vm.prank(relayer);
        hub.depositStake{value: amount}();

        (uint256 stake, , ) = hub.getRelayerStats(relayer);
        assertEq(stake, amount);
    }

    function testFuzz_setChallengePeriod(uint256 period) public {
        period = bound(period, 10 minutes, 7 days);
        hub.setChallengePeriod(period);
        assertEq(hub.challengePeriod(), period);
    }

    // ======= Receive ETH =======

    function test_receiveETH() public {
        (bool sent, ) = address(hub).call{value: 1 ether}("");
        assertTrue(sent);
    }

    // ======= Helpers =======

    function _stakeRelayer() internal {
        vm.prank(relayer);
        hub.depositStake{value: 1 ether}();
    }

    function _submitProofAsRelayer() internal returns (bytes32) {
        _stakeRelayer();

        vm.prank(relayer);
        return
            hub.submitProof{value: 0.001 ether}(
                hex"deadbeef",
                hex"cafe",
                keccak256("commitment1"),
                uint64(block.chainid),
                42161
            );
    }
}
