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

contract ZKLockDoSProtectionTest is Test {
    ZKBoundStateLocks public locks;
    MockVerifier public verifier;
    
    address public alice = address(0x1111);
    address public bob = address(0x2222);
    address public charlie = address(0x3333);
    
    bytes32 public domainSeparator;

    struct UnlockProof {
        bytes32 lockId;
        bytes zkProof;
        bytes32 newStateCommitment;
        bytes32 nullifier;
        bytes32 verifierKeyHash;
        bytes auxiliaryData;
    }

    function setUp() public {
        verifier = new MockVerifier();
        locks = new ZKBoundStateLocks(address(verifier));
        
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(charlie, 100 ether);
        
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

    function test_ChallengeEnforcesMinStake() public {
        (bytes32 lockId, ZKBoundStateLocks.UnlockProof memory proof) = createLockAndOptimisticUnlock();
        
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSignature("InsufficientChallengerStake(uint256,uint256)", 0.01 ether, 0.005 ether));
        locks.challengeOptimisticUnlock{value: 0.005 ether}(lockId, proof);
        vm.stopPrank();
    }

    function test_SuccessChallengeRewardsChallenger() public {
        (bytes32 lockId, ZKBoundStateLocks.UnlockProof memory proof) = createLockAndOptimisticUnlock();
        
        // Mock verifier to fail (meaning challenge succeeds as a fraud proof)
        verifier.setResult(false);
        
        uint256 bobBalanceBefore = bob.balance;
        
        vm.prank(bob);
        locks.challengeOptimisticUnlock{value: 0.01 ether}(lockId, proof);
        
        // Bob should get his 0.01 ETH stake back + Alice's 0.1 ETH bond
        assertEq(bob.balance, bobBalanceBefore + 0.1 ether);
    }

    function test_FailedChallengeCompensatesUnlocker() public {
        (bytes32 lockId, ZKBoundStateLocks.UnlockProof memory proof) = createLockAndOptimisticUnlock();
        
        // Mock verifier to succeed (meaning challenge fails as it's not a fraud)
        verifier.setResult(true);
        
        uint256 aliceBalanceBefore = alice.balance;
        uint256 bobBalanceBefore = bob.balance;
        
        vm.prank(bob);
        locks.challengeOptimisticUnlock{value: 0.01 ether}(lockId, proof);
        
        // Bob should lose his 0.01 ETH stake
        assertEq(bob.balance, bobBalanceBefore - 0.01 ether);
        // Alice should get Bob's 0.01 ETH stake as compensation
        assertEq(alice.balance, aliceBalanceBefore + 0.01 ether);
    }
}
