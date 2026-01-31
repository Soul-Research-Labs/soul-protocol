// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SoulTimelock.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import "../primitives/ProofCarryingContainer.sol";
import "../primitives/PolicyBoundProofs.sol";
import "../primitives/ExecutionAgnosticStateCommitments.sol";
import "../primitives/CrossDomainNullifierAlgebra.sol";

/**
 * @title TimelockAdmin
 * @author Soul Protocol
 * @notice Wrapper for timelocked administrative operations on Soul v2 contracts
 * @dev Provides type-safe interfaces for proposing timelocked admin operations
 *
 * Usage Pattern:
 * 1. Call propose* function to schedule an operation
 * 2. Wait for the timelock delay period
 * 3. Other proposers confirm the operation
 * 4. Execute the operation after ready time
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract TimelockAdmin {
    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The timelock controller
    SoulTimelock public immutable timelock;

    /// @notice ProofCarryingContainer contract
    ProofCarryingContainer public immutable pc3;

    /// @notice PolicyBoundProofs contract
    PolicyBoundProofs public immutable pbp;

    /// @notice ExecutionAgnosticStateCommitments contract
    ExecutionAgnosticStateCommitments public immutable easc;

    /// @notice CrossDomainNullifierAlgebra contract
    CrossDomainNullifierAlgebra public immutable cdna;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event AdminOperationScheduled(
        bytes32 indexed operationId,
        string operationType,
        address indexed target,
        uint256 delay
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotProposer();
    error NotExecutor();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _timelock,
        address _pc3,
        address _pbp,
        address _easc,
        address _cdna
    ) {
        timelock = SoulTimelock(payable(_timelock));
        pc3 = ProofCarryingContainer(_pc3);
        pbp = PolicyBoundProofs(_pbp);
        easc = ExecutionAgnosticStateCommitments(_easc);
        cdna = CrossDomainNullifierAlgebra(_cdna);
    }

    /*//////////////////////////////////////////////////////////////
                      PC3 ADMIN OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedule pausing the PC3 contract
     * @param salt Unique salt for this operation
     * @return operationId The scheduled operation ID
     */
    function schedulePausePC3(
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            ProofCarryingContainer.pause.selector
        );

        operationId = timelock.propose(address(pc3), 0, data, bytes32(0), salt);

        emit AdminOperationScheduled(
            operationId,
            "PAUSE_PC3",
            address(pc3),
            timelock.minDelay()
        );
    }

    /**
     * @notice Schedule unpausing the PC3 contract
     * @param salt Unique salt for this operation
     * @return operationId The scheduled operation ID
     */
    function scheduleUnpausePC3(
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            ProofCarryingContainer.unpause.selector
        );

        operationId = timelock.propose(address(pc3), 0, data, bytes32(0), salt);

        emit AdminOperationScheduled(
            operationId,
            "UNPAUSE_PC3",
            address(pc3),
            timelock.minDelay()
        );
    }

    /**
     * @notice Schedule granting a role on PC3
     * @param role The role to grant
     * @param account The account to receive the role
     * @param salt Unique salt
     * @return operationId The scheduled operation ID
     */
    function scheduleGrantRolePC3(
        bytes32 role,
        address account,
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            IAccessControl.grantRole.selector,
            role,
            account
        );

        operationId = timelock.propose(address(pc3), 0, data, bytes32(0), salt);

        emit AdminOperationScheduled(
            operationId,
            "GRANT_ROLE_PC3",
            address(pc3),
            timelock.minDelay()
        );
    }

    /**
     * @notice Schedule revoking a role on PC3
     * @param role The role to revoke
     * @param account The account to lose the role
     * @param salt Unique salt
     * @return operationId The scheduled operation ID
     */
    function scheduleRevokeRolePC3(
        bytes32 role,
        address account,
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            IAccessControl.revokeRole.selector,
            role,
            account
        );

        operationId = timelock.propose(address(pc3), 0, data, bytes32(0), salt);

        emit AdminOperationScheduled(
            operationId,
            "REVOKE_ROLE_PC3",
            address(pc3),
            timelock.minDelay()
        );
    }

    /*//////////////////////////////////////////////////////////////
                      PBP ADMIN OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedule pausing the PBP contract
     */
    function schedulePausePBP(
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            PolicyBoundProofs.pause.selector
        );

        operationId = timelock.propose(address(pbp), 0, data, bytes32(0), salt);

        emit AdminOperationScheduled(
            operationId,
            "PAUSE_PBP",
            address(pbp),
            timelock.minDelay()
        );
    }

    /**
     * @notice Schedule unpausing the PBP contract
     */
    function scheduleUnpausePBP(
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            PolicyBoundProofs.unpause.selector
        );

        operationId = timelock.propose(address(pbp), 0, data, bytes32(0), salt);

        emit AdminOperationScheduled(
            operationId,
            "UNPAUSE_PBP",
            address(pbp),
            timelock.minDelay()
        );
    }

    /**
     * @notice Schedule deactivating a policy
     */
    function scheduleDeactivatePolicy(
        bytes32 policyId,
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            PolicyBoundProofs.deactivatePolicy.selector,
            policyId
        );

        operationId = timelock.propose(address(pbp), 0, data, bytes32(0), salt);

        emit AdminOperationScheduled(
            operationId,
            "DEACTIVATE_POLICY",
            address(pbp),
            timelock.minDelay()
        );
    }

    /*//////////////////////////////////////////////////////////////
                      EASC ADMIN OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedule pausing the EASC contract
     */
    function schedulePauseEASC(
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            ExecutionAgnosticStateCommitments.pause.selector
        );

        operationId = timelock.propose(
            address(easc),
            0,
            data,
            bytes32(0),
            salt
        );

        emit AdminOperationScheduled(
            operationId,
            "PAUSE_EASC",
            address(easc),
            timelock.minDelay()
        );
    }

    /**
     * @notice Schedule deactivating a backend
     */
    function scheduleDeactivateBackend(
        bytes32 backendId,
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            ExecutionAgnosticStateCommitments.deactivateBackend.selector,
            backendId
        );

        operationId = timelock.propose(
            address(easc),
            0,
            data,
            bytes32(0),
            salt
        );

        emit AdminOperationScheduled(
            operationId,
            "DEACTIVATE_BACKEND",
            address(easc),
            timelock.minDelay()
        );
    }

    /**
     * @notice Schedule updating backend trust score
     */
    function scheduleUpdateBackendTrust(
        bytes32 backendId,
        uint256 trustScore,
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            ExecutionAgnosticStateCommitments.updateBackendTrust.selector,
            backendId,
            trustScore
        );

        operationId = timelock.propose(
            address(easc),
            0,
            data,
            bytes32(0),
            salt
        );

        emit AdminOperationScheduled(
            operationId,
            "UPDATE_BACKEND_TRUST",
            address(easc),
            timelock.minDelay()
        );
    }

    /*//////////////////////////////////////////////////////////////
                      CDNA ADMIN OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedule pausing the CDNA contract
     */
    function schedulePauseCDNA(
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            CrossDomainNullifierAlgebra.pause.selector
        );

        operationId = timelock.propose(
            address(cdna),
            0,
            data,
            bytes32(0),
            salt
        );

        emit AdminOperationScheduled(
            operationId,
            "PAUSE_CDNA",
            address(cdna),
            timelock.minDelay()
        );
    }

    /**
     * @notice Schedule deactivating a domain
     */
    function scheduleDeactivateDomain(
        bytes32 domainId,
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            CrossDomainNullifierAlgebra.deactivateDomain.selector,
            domainId
        );

        operationId = timelock.propose(
            address(cdna),
            0,
            data,
            bytes32(0),
            salt
        );

        emit AdminOperationScheduled(
            operationId,
            "DEACTIVATE_DOMAIN",
            address(cdna),
            timelock.minDelay()
        );
    }

    /**
     * @notice Schedule updating epoch duration
     */
    function scheduleUpdateEpochDuration(
        uint64 duration,
        bytes32 salt
    ) external returns (bytes32 operationId) {
        bytes memory data = abi.encodeWithSelector(
            CrossDomainNullifierAlgebra.setEpochDuration.selector,
            duration
        );

        operationId = timelock.propose(
            address(cdna),
            0,
            data,
            bytes32(0),
            salt
        );

        emit AdminOperationScheduled(
            operationId,
            "UPDATE_EPOCH_DURATION",
            address(cdna),
            timelock.minDelay()
        );
    }

    /*//////////////////////////////////////////////////////////////
                      EMERGENCY OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedule emergency pause of all contracts
     * @dev Uses emergency delay (shorter than standard)
     */
    function scheduleEmergencyPauseAll(
        bytes32 salt
    ) external returns (bytes32 operationId) {
        address[] memory targets = new address[](4);
        targets[0] = address(pc3);
        targets[1] = address(pbp);
        targets[2] = address(easc);
        targets[3] = address(cdna);

        uint256[] memory values = new uint256[](4);
        // All zeros

        bytes[] memory datas = new bytes[](4);
        datas[0] = abi.encodeWithSelector(
            ProofCarryingContainer.pause.selector
        );
        datas[1] = abi.encodeWithSelector(PolicyBoundProofs.pause.selector);
        datas[2] = abi.encodeWithSelector(
            ExecutionAgnosticStateCommitments.pause.selector
        );
        datas[3] = abi.encodeWithSelector(
            CrossDomainNullifierAlgebra.pause.selector
        );

        operationId = timelock.proposeBatch(
            targets,
            values,
            datas,
            bytes32(0),
            salt
        );

        emit AdminOperationScheduled(
            operationId,
            "EMERGENCY_PAUSE_ALL",
            address(this),
            timelock.minDelay()
        );
    }

    /*//////////////////////////////////////////////////////////////
                        EXECUTION HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute a scheduled pause operation
     */
    function executePause(address target, bytes32 salt) external {
        bytes memory data = abi.encodeWithSelector(
            bytes4(keccak256("pause()"))
        );

        timelock.execute(target, 0, data, bytes32(0), salt);
    }

    /**
     * @notice Execute a scheduled unpause operation
     */
    function executeUnpause(address target, bytes32 salt) external {
        bytes memory data = abi.encodeWithSelector(
            bytes4(keccak256("unpause()"))
        );

        timelock.execute(target, 0, data, bytes32(0), salt);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get pending operation status
     */
    function getOperationInfo(
        bytes32 operationId
    )
        external
        view
        returns (
            SoulTimelock.OperationStatus status,
            uint256 readyAt,
            uint8 confirmations,
            uint8 required
        )
    {
        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            uint256 _readyAt,
            ,
            SoulTimelock.OperationStatus _status,
            ,
            uint8 _confirmations,
        ) = timelock.operations(operationId);

        return (
            _status,
            _readyAt,
            _confirmations,
            timelock.requiredConfirmations()
        );
    }
}
