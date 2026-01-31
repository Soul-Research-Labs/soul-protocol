// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/primitives/ZKBoundStateLocks.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

contract MockVerifier is IProofVerifier {
    bool public result;
    function setResult(bool _result) public { result = _result; }
    function verify(bytes calldata, uint256[] calldata) external view returns (bool) { return result; }
    function verifySingle(bytes calldata, uint256) external view returns (bool) { return result; }
    function getPublicInputCount() external pure returns (uint256) { return 6; }
    function isReady() external pure returns (bool) { return true; }
}

contract ZKStakeHardeningTest is Test {
    ZKBoundStateLocks public locks;
    MockVerifier public verifier;
    
    address public alice = address(0x1111);
    address public bob = address(0x2222);
    
    bytes32 public domainSeparator;
    uint256 public constant MIN_CHALLENGER_STAKE = 0.01 ether;

    function setUp() public {
        verifier = new MockVerifier();
        locks = new ZKBoundStateLocks(address(verifier));
        
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        
        // Register domain
        vm.prank(address(this));
        locks.grantRole(locks.DOMAIN_ADMIN_ROLE(), address(this));
        domainSeparator = locks.registerDomain(1, 1, 0, "Test Domain");
    }

    function createLockAndOptimisticUnlock() public returns (bytes32, ZKBoundStateLocks.UnlockProof memory) {
        vm.startPrank(alice);
        bytes32 lockId = locks.createLock(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            domainSeparator,
            0
        );
        
        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks.UnlockProof({
            lockId: lockId,
            zkProof: hex"1234",
            newStateCommitment: bytes32(uint256(4)),
            nullifier: bytes32(uint256(5)),
            verifierKeyHash: bytes32(0),
            auxiliaryData: hex""
        });
        
        locks.optimisticUnlock{value: 0.1 ether}(proof);
        vm.stopPrank();
        return (lockId, proof);
    }

    /**
     * @notice Hardening Test: Verify MIN_CHALLENGER_STAKE strict boundary
     * This addresses the surviving Mutant 2 (MIN - 1 check)
     */
    function test_Harden_ChallengeStakeBoundary() public {
        (bytes32 lockId, ZKBoundStateLocks.UnlockProof memory proof) = createLockAndOptimisticUnlock();
        
        vm.startPrank(bob);
        
        // CASE 1: Boundary check (MIN - 1 wei) -> SHOULD FAIL
        vm.expectRevert(abi.encodeWithSignature("InsufficientChallengerStake(uint256,uint256)", MIN_CHALLENGER_STAKE, MIN_CHALLENGER_STAKE - 1));
        locks.challengeOptimisticUnlock{value: MIN_CHALLENGER_STAKE - 1}(lockId, proof);
        
        // CASE 2: Exact boundary -> SHOULD SUCCEED (reverting mock logic is fine, we just check stake check passed)
        // We set verifier to true so challenge logic proceeds to "failed challenge" branch (which is simpler path here)
        verifier.setResult(true); 
        locks.challengeOptimisticUnlock{value: MIN_CHALLENGER_STAKE}(lockId, proof);
        
        vm.stopPrank();
    }
    
    /**
     * @notice Hardening Test: Verify Stake Distribution on Failed Challenge
     * Unlocker should receive the challenger's stake as compensation.
     */
    function test_Harden_FailedChallenge_CompensatesUnlocker() public {
        (bytes32 lockId, ZKBoundStateLocks.UnlockProof memory proof) = createLockAndOptimisticUnlock();
        verifier.setResult(true); // Challenge fails (proof is valid)
        
        uint256 aliceBalance = alice.balance;
        uint256 stake = MIN_CHALLENGER_STAKE;
        
        vm.prank(bob);
        locks.challengeOptimisticUnlock{value: stake}(lockId, proof);
        
        // Alice receives the stake
        assertEq(alice.balance, aliceBalance + stake, "Unlocker should receive challenger stake");
    }

    /**
     * @notice Hardening Test: Verify Stake Distribution on Successful Challenge
     * Challenger should receive their stake back + unlocker's bond.
     */
    function test_Harden_SuccessfulChallenge_RewardsChallenger() public {
        (bytes32 lockId, ZKBoundStateLocks.UnlockProof memory proof) = createLockAndOptimisticUnlock();
        verifier.setResult(false); // Challenge succeeds (fraud proof)
        
        uint256 bobBalance = bob.balance;
        uint256 bond = 0.1 ether;
        uint256 stake = MIN_CHALLENGER_STAKE;
        
        vm.prank(bob);
        locks.challengeOptimisticUnlock{value: stake}(lockId, proof);
        
        // Bob gets his stake back + Alice's bond
        assertEq(bob.balance, bobBalance - stake + stake + bond, "Challenger should get stake back + bond");
    }
}
