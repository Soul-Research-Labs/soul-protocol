// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/core/ConfidentialStateContainerV3.sol";
import "../../contracts/mocks/MockProofVerifier.sol";

contract ConfidentialStateContainerV3Test is Test {
    ConfidentialStateContainerV3 public container;
    MockProofVerifier public verifier;

    address public admin;
    address public operator;
    address public emergency;
    address public user1;
    address public user2;

    bytes32 constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    bytes constant SAMPLE_STATE = hex"deadbeef0123456789abcdef";
    bytes constant SAMPLE_PROOF = hex"0102030405060708";
    bytes32 constant SAMPLE_METADATA = bytes32(uint256(42));

    function setUp() public {
        admin = address(this);
        operator = makeAddr("operator");
        emergency = makeAddr("emergency");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");

        verifier = new MockProofVerifier();
        container = new ConfidentialStateContainerV3(address(verifier));

        container.grantRole(OPERATOR_ROLE, operator);
        container.grantRole(EMERGENCY_ROLE, emergency);
    }

    // ─── Helper ─────────────────────────────────────────────────
    function _registerState(bytes32 commitment, bytes32 nullifier) internal {
        container.registerState(
            SAMPLE_STATE,
            commitment,
            nullifier,
            SAMPLE_PROOF,
            SAMPLE_METADATA
        );
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsVerifier() public view {
        assertEq(address(container.verifier()), address(verifier));
    }

    function test_Constructor_ZeroVerifier_Reverts() public {
        vm.expectRevert(ConfidentialStateContainerV3.ZeroAddress.selector);
        new ConfidentialStateContainerV3(address(0));
    }

    function test_InitialCounters() public view {
        assertEq(container.totalStates(), 0);
        assertEq(container.activeStates(), 0);
    }

    function test_InitialConfig() public view {
        assertEq(container.proofValidityWindow(), 1 hours);
        assertEq(container.maxStateSize(), 65536);
    }

    function test_ChainIdAndDomain() public view {
        assertEq(container.CHAIN_ID(), block.chainid);
        assertTrue(container.DOMAIN_SEPARATOR() != bytes32(0));
    }

    function test_AdminRoles() public view {
        assertTrue(container.hasRole(container.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(container.hasRole(OPERATOR_ROLE, admin));
        assertTrue(container.hasRole(EMERGENCY_ROLE, admin));
    }

    /*//////////////////////////////////////////////////////////////
                        STATE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterState() public {
        bytes32 commitment = keccak256("c1");
        bytes32 nullifier = keccak256("n1");

        _registerState(commitment, nullifier);

        assertEq(container.totalStates(), 1);
        assertEq(container.activeStates(), 1);
        assertTrue(container.isStateActive(commitment));
        assertTrue(container.nullifiers(nullifier));
        assertEq(container.nullifierToCommitment(nullifier), commitment);
    }

    function test_RegisterState_EmitsEvent() public {
        bytes32 commitment = keccak256("c1");
        bytes32 nullifier = keccak256("n1");

        vm.expectEmit(true, true, false, true);
        emit ConfidentialStateContainerV3.StateRegistered(
            commitment,
            admin,
            nullifier,
            block.timestamp
        );

        _registerState(commitment, nullifier);
    }

    function test_RegisterState_StoresCorrectData() public {
        bytes32 commitment = keccak256("c1");
        bytes32 nullifier = keccak256("n1");

        _registerState(commitment, nullifier);

        ConfidentialStateContainerV3.EncryptedState memory s = container
            .getState(commitment);
        assertEq(s.commitment, commitment);
        assertEq(s.nullifier, nullifier);
        assertEq(s.metadata, SAMPLE_METADATA);
        assertEq(s.owner, admin);
        assertEq(
            uint8(s.status),
            uint8(ConfidentialStateContainerV3.StateStatus.Active)
        );
        assertEq(s.version, 1);
        assertEq(s.encryptedState, SAMPLE_STATE);
    }

    function test_RegisterState_TracksOwnerCommitments() public {
        bytes32 c1 = keccak256("c1");
        bytes32 c2 = keccak256("c2");

        _registerState(c1, keccak256("n1"));
        _registerState(c2, keccak256("n2"));

        bytes32[] memory owned = container.getOwnerCommitments(admin);
        assertEq(owned.length, 2);
        assertEq(owned[0], c1);
        assertEq(owned[1], c2);
    }

    function test_RegisterState_RevertDuplicateCommitment() public {
        bytes32 commitment = keccak256("c1");
        _registerState(commitment, keccak256("n1"));

        vm.expectRevert(
            abi.encodeWithSelector(
                ConfidentialStateContainerV3.CommitmentAlreadyExists.selector,
                commitment
            )
        );
        _registerState(commitment, keccak256("n2"));
    }

    function test_RegisterState_RevertDuplicateNullifier() public {
        bytes32 nullifier = keccak256("n1");
        _registerState(keccak256("c1"), nullifier);

        vm.expectRevert(
            abi.encodeWithSelector(
                ConfidentialStateContainerV3.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        _registerState(keccak256("c2"), nullifier);
    }

    function test_RegisterState_RevertEmptyState() public {
        vm.expectRevert(
            ConfidentialStateContainerV3.EmptyEncryptedState.selector
        );
        container.registerState(
            "",
            keccak256("c1"),
            keccak256("n1"),
            SAMPLE_PROOF,
            SAMPLE_METADATA
        );
    }

    function test_RegisterState_RevertInvalidProof() public {
        verifier.setVerificationResult(false);

        vm.expectRevert(ConfidentialStateContainerV3.InvalidProof.selector);
        _registerState(keccak256("c1"), keccak256("n1"));
    }

    function test_RegisterState_RevertStateTooLarge() public {
        bytes memory largeState = new bytes(65537);
        vm.expectRevert(
            abi.encodeWithSelector(
                ConfidentialStateContainerV3.StateSizeTooLarge.selector,
                65537,
                65536
            )
        );
        container.registerState(
            largeState,
            keccak256("c1"),
            keccak256("n1"),
            SAMPLE_PROOF,
            SAMPLE_METADATA
        );
    }

    function test_RegisterState_RevertWhenPaused() public {
        vm.prank(emergency);
        container.pause();

        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        _registerState(keccak256("c1"), keccak256("n1"));
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_BatchRegister() public {
        BatchStateInput[] memory inputs = new BatchStateInput[](3);
        for (uint256 i = 0; i < 3; i++) {
            inputs[i] = BatchStateInput({
                encryptedState: SAMPLE_STATE,
                commitment: keccak256(abi.encodePacked("c", i)),
                nullifier: keccak256(abi.encodePacked("n", i)),
                proof: SAMPLE_PROOF,
                metadata: SAMPLE_METADATA
            });
        }

        container.batchRegisterStates(inputs);

        assertEq(container.totalStates(), 3);
        assertEq(container.activeStates(), 3);
    }

    function test_BatchRegister_RevertTooLarge() public {
        BatchStateInput[] memory inputs = new BatchStateInput[](51);
        for (uint256 i = 0; i < 51; i++) {
            inputs[i] = BatchStateInput({
                encryptedState: SAMPLE_STATE,
                commitment: keccak256(abi.encodePacked("c", i)),
                nullifier: keccak256(abi.encodePacked("n", i)),
                proof: SAMPLE_PROOF,
                metadata: SAMPLE_METADATA
            });
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                ConfidentialStateContainerV3.BatchTooLarge.selector,
                51,
                50
            )
        );
        container.batchRegisterStates(inputs);
    }

    /*//////////////////////////////////////////////////////////////
                        STATE TRANSFER
    //////////////////////////////////////////////////////////////*/

    function test_TransferState() public {
        bytes32 oldC = keccak256("cold");
        bytes32 oldN = keccak256("nold");
        _registerState(oldC, oldN);

        bytes32 newC = keccak256("cnew");
        bytes32 newN = keccak256("nnew");
        bytes32 spendN = keccak256("spend");

        container.transferState(
            oldC,
            SAMPLE_STATE,
            newC,
            newN,
            spendN,
            SAMPLE_PROOF,
            user1
        );

        // Old state retired
        assertFalse(container.isStateActive(oldC));
        ConfidentialStateContainerV3.EncryptedState memory oldState = container
            .getState(oldC);
        assertEq(
            uint8(oldState.status),
            uint8(ConfidentialStateContainerV3.StateStatus.Retired)
        );

        // New state active
        assertTrue(container.isStateActive(newC));
        ConfidentialStateContainerV3.EncryptedState memory newState = container
            .getState(newC);
        assertEq(newState.owner, user1);
        assertEq(newState.version, 2);

        // Nullifiers registered
        assertTrue(container.nullifiers(spendN));
        assertTrue(container.nullifiers(newN));
    }

    function test_TransferState_EmitsEvent() public {
        bytes32 oldC = keccak256("cold");
        _registerState(oldC, keccak256("nold"));

        bytes32 newC = keccak256("cnew");

        vm.expectEmit(true, true, true, true);
        emit ConfidentialStateContainerV3.StateTransferred(
            oldC,
            newC,
            user1,
            2
        );

        container.transferState(
            oldC,
            SAMPLE_STATE,
            newC,
            keccak256("nn"),
            keccak256("sn"),
            SAMPLE_PROOF,
            user1
        );
    }

    function test_TransferState_RevertNotOwner() public {
        bytes32 oldC = keccak256("cold");
        _registerState(oldC, keccak256("nold"));

        vm.prank(user2);
        vm.expectRevert(
            abi.encodeWithSelector(
                ConfidentialStateContainerV3.NotStateOwner.selector,
                user2,
                admin
            )
        );
        container.transferState(
            oldC,
            SAMPLE_STATE,
            keccak256("cn"),
            keccak256("nn"),
            keccak256("sn"),
            SAMPLE_PROOF,
            user1
        );
    }

    function test_TransferState_RevertZeroNewOwner() public {
        bytes32 oldC = keccak256("cold");
        _registerState(oldC, keccak256("nold"));

        vm.expectRevert(ConfidentialStateContainerV3.ZeroAddress.selector);
        container.transferState(
            oldC,
            SAMPLE_STATE,
            keccak256("cn"),
            keccak256("nn"),
            keccak256("sn"),
            SAMPLE_PROOF,
            address(0)
        );
    }

    function test_TransferState_RevertCommitmentNotFound() public {
        bytes32 bogus = keccak256("nope");
        vm.expectRevert(
            abi.encodeWithSelector(
                ConfidentialStateContainerV3.CommitmentNotFound.selector,
                bogus
            )
        );
        container.transferState(
            bogus,
            SAMPLE_STATE,
            keccak256("cn"),
            keccak256("nn"),
            keccak256("sn"),
            SAMPLE_PROOF,
            user1
        );
    }

    function test_TransferState_RecordsHistory() public {
        bytes32 oldC = keccak256("cold");
        _registerState(oldC, keccak256("nold"));

        bytes32 newC = keccak256("cnew");
        container.transferState(
            oldC,
            SAMPLE_STATE,
            newC,
            keccak256("nn"),
            keccak256("sn"),
            SAMPLE_PROOF,
            user1
        );

        ConfidentialStateContainerV3.StateTransition[] memory hist = container
            .getStateHistory(oldC);
        assertEq(hist.length, 1);
        assertEq(hist[0].fromCommitment, oldC);
        assertEq(hist[0].toCommitment, newC);
        assertEq(hist[0].fromOwner, admin);
        assertEq(hist[0].toOwner, user1);
    }

    function test_TransferState_RevertLockedState() public {
        bytes32 oldC = keccak256("cold");
        _registerState(oldC, keccak256("nold"));

        vm.prank(operator);
        container.lockState(oldC);

        vm.expectRevert(
            abi.encodeWithSelector(
                ConfidentialStateContainerV3.StateNotActive.selector,
                oldC,
                ConfidentialStateContainerV3.StateStatus.Locked
            )
        );
        container.transferState(
            oldC,
            SAMPLE_STATE,
            keccak256("cn"),
            keccak256("nn"),
            keccak256("sn"),
            SAMPLE_PROOF,
            user1
        );
    }

    /*//////////////////////////////////////////////////////////////
                       ADMIN / OPERATOR ACTIONS
    //////////////////////////////////////////////////////////////*/

    function test_LockState() public {
        bytes32 c = keccak256("c1");
        _registerState(c, keccak256("n1"));

        vm.prank(operator);
        container.lockState(c);

        ConfidentialStateContainerV3.EncryptedState memory s = container
            .getState(c);
        assertEq(
            uint8(s.status),
            uint8(ConfidentialStateContainerV3.StateStatus.Locked)
        );
    }

    function test_UnlockState() public {
        bytes32 c = keccak256("c1");
        _registerState(c, keccak256("n1"));

        vm.startPrank(operator);
        container.lockState(c);
        container.unlockState(c);
        vm.stopPrank();

        assertTrue(container.isStateActive(c));
    }

    function test_FreezeState() public {
        bytes32 c = keccak256("c1");
        _registerState(c, keccak256("n1"));

        assertEq(container.activeStates(), 1);

        vm.prank(emergency);
        container.freezeState(c);

        ConfidentialStateContainerV3.EncryptedState memory s = container
            .getState(c);
        assertEq(
            uint8(s.status),
            uint8(ConfidentialStateContainerV3.StateStatus.Frozen)
        );
        assertEq(container.activeStates(), 0);
    }

    function test_LockState_RevertUnauthorized() public {
        bytes32 c = keccak256("c1");
        _registerState(c, keccak256("n1"));

        vm.prank(user1);
        vm.expectRevert();
        container.lockState(c);
    }

    function test_FreezeState_RevertUnauthorized() public {
        bytes32 c = keccak256("c1");
        _registerState(c, keccak256("n1"));

        vm.prank(user1);
        vm.expectRevert();
        container.freezeState(c);
    }

    function test_LockState_RevertNotFound() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ConfidentialStateContainerV3.CommitmentNotFound.selector,
                keccak256("nope")
            )
        );
        container.lockState(keccak256("nope"));
    }

    function test_SetProofValidityWindow() public {
        uint256 newWindow = 2 hours;
        container.setProofValidityWindow(newWindow);
        assertEq(container.proofValidityWindow(), newWindow);
    }

    function test_SetMaxStateSize() public {
        uint256 newSize = 32768;
        container.setMaxStateSize(newSize);
        assertEq(container.maxStateSize(), newSize);
    }

    function test_SetProofValidityWindow_RevertUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        container.setProofValidityWindow(2 hours);
    }

    /*//////////////////////////////////////////////////////////////
                          PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function test_Pause() public {
        vm.prank(emergency);
        container.pause();

        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        _registerState(keccak256("c1"), keccak256("n1"));
    }

    function test_Unpause() public {
        vm.prank(emergency);
        container.pause();

        container.unpause(); // admin can unpause

        _registerState(keccak256("c1"), keccak256("n1"));
        assertEq(container.totalStates(), 1);
    }

    function test_Pause_RevertUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        container.pause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetOwnerCommitmentsPaginated() public {
        // Register 5 states
        for (uint256 i = 0; i < 5; i++) {
            _registerState(
                keccak256(abi.encodePacked("c", i)),
                keccak256(abi.encodePacked("n", i))
            );
        }

        // Page 1: offset=0, limit=2
        (bytes32[] memory page1, uint256 total1) = container
            .getOwnerCommitmentsPaginated(admin, 0, 2);
        assertEq(page1.length, 2);
        assertEq(total1, 5);

        // Page 3: offset=4, limit=2 → only 1 remaining
        (bytes32[] memory page3, uint256 total3) = container
            .getOwnerCommitmentsPaginated(admin, 4, 2);
        assertEq(page3.length, 1);
        assertEq(total3, 5);

        // Past end: offset=10
        (bytes32[] memory pageEnd, ) = container.getOwnerCommitmentsPaginated(
            admin,
            10,
            2
        );
        assertEq(pageEnd.length, 0);
    }

    // NOTE: isStateActive returns true for nonexistent commitments because
    // StateStatus.Active == 0 (default). Use getState().owner != address(0)
    // to check existence. This is documented contract behavior.
    function test_IsStateActive_TrueForNonexistent_KnownBehavior() public view {
        // Default storage maps to Status.Active (0) — verify the quirk is documented
        assertTrue(container.isStateActive(keccak256("nope")));
        // But the state has no owner — that's how you check existence
        assertEq(container.getState(keccak256("nope")).owner, address(0));
    }

    function test_GetNonce() public view {
        assertEq(container.getNonce(user1), 0);
    }

    function test_GetState_EmptyForNonexistent() public view {
        ConfidentialStateContainerV3.EncryptedState memory s = container
            .getState(keccak256("nope"));
        assertEq(s.owner, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_RegisterAndQuery(bytes32 seed) public {
        bytes32 commitment = keccak256(abi.encodePacked(seed, "c"));
        bytes32 nullifier = keccak256(abi.encodePacked(seed, "n"));

        _registerState(commitment, nullifier);

        assertTrue(container.isStateActive(commitment));
        assertTrue(container.nullifiers(nullifier));
        assertEq(container.totalStates(), 1);
        assertEq(container.activeStates(), 1);

        ConfidentialStateContainerV3.EncryptedState memory s = container
            .getState(commitment);
        assertEq(s.owner, admin);
        assertEq(s.version, 1);
    }

    function testFuzz_MultipleRegistrationsIncrementCounters(
        uint8 count
    ) public {
        uint256 n = bound(count, 1, 20);
        for (uint256 i = 0; i < n; i++) {
            _registerState(
                keccak256(abi.encodePacked("c", i)),
                keccak256(abi.encodePacked("n", i))
            );
        }
        assertEq(container.totalStates(), n);
        assertEq(container.activeStates(), n);
    }

    function testFuzz_LockUnlockPreservesActive(bytes32 seed) public {
        bytes32 commitment = keccak256(abi.encodePacked(seed, "c"));
        _registerState(commitment, keccak256(abi.encodePacked(seed, "n")));

        vm.startPrank(operator);
        container.lockState(commitment);
        assertFalse(container.isStateActive(commitment));
        container.unlockState(commitment);
        assertTrue(container.isStateActive(commitment));
        vm.stopPrank();
    }
}
