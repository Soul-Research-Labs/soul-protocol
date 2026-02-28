// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/governance/ZaseonGovernor.sol";
import "../../contracts/governance/ZaseonUpgradeTimelock.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/governance/IGovernor.sol";

/// @dev Minimal ERC20Votes token for testing governance
contract MockVotesToken is ERC20, ERC20Permit, ERC20Votes {
    constructor()
        ERC20("Zaseon Governance Token", "ZASEON")
        ERC20Permit("Zaseon Governance Token")
    {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    // Required overrides
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20, ERC20Votes) {
        super._update(from, to, value);
    }

    function nonces(
        address owner
    ) public view override(ERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }

    function clock() public view override returns (uint48) {
        return uint48(block.timestamp);
    }

    // solhint-disable-next-line func-name-mixedcase
    function CLOCK_MODE() public pure override returns (string memory) {
        return "mode=timestamp&from=default";
    }
}

contract ZaseonGovernorTest is Test {
    ZaseonGovernor public governor;
    ZaseonUpgradeTimelock public timelock;
    MockVotesToken public token;

    address public admin = makeAddr("admin");
    address public proposer = makeAddr("proposer");
    address public voter1 = makeAddr("voter1");
    address public voter2 = makeAddr("voter2");
    address public voter3 = makeAddr("voter3");
    address public target = makeAddr("target");

    uint256 constant INITIAL_SUPPLY = 10_000_000e18;
    uint256 constant PROPOSAL_THRESHOLD = 100_000e18;

    function setUp() public {
        // Deploy token
        token = new MockVotesToken();

        // Distribute tokens
        token.mint(voter1, 5_000_000e18);
        token.mint(voter2, 3_000_000e18);
        token.mint(voter3, 1_500_000e18);
        token.mint(proposer, 500_000e18);

        // Voters delegate to themselves
        vm.prank(voter1);
        token.delegate(voter1);
        vm.prank(voter2);
        token.delegate(voter2);
        vm.prank(voter3);
        token.delegate(voter3);
        vm.prank(proposer);
        token.delegate(proposer);

        // Deploy timelock
        address[] memory proposers = new address[](1);
        proposers[0] = admin;
        address[] memory executors = new address[](1);
        executors[0] = address(0); // anyone can execute
        timelock = new ZaseonUpgradeTimelock(
            1 days, // minDelay
            proposers,
            executors,
            admin
        );

        // Deploy governor with defaults (pass 0s)
        governor = new ZaseonGovernor(
            IVotes(address(token)),
            TimelockController(payable(address(timelock))),
            0, // votingDelay -> DEFAULT_VOTING_DELAY (1 day)
            0, // votingPeriod -> DEFAULT_VOTING_PERIOD (5 days)
            0, // proposalThreshold -> DEFAULT_PROPOSAL_THRESHOLD (100k)
            0 // quorumPercentage -> DEFAULT_QUORUM_PERCENTAGE (4%)
        );

        // Grant governor the proposer and executor roles on timelock
        vm.startPrank(admin);
        timelock.grantRole(timelock.PROPOSER_ROLE(), address(governor));
        timelock.grantRole(timelock.EXECUTOR_ROLE(), address(governor));
        timelock.grantRole(timelock.CANCELLER_ROLE(), address(governor));
        vm.stopPrank();

        // Advance 1 block so voting power is checkpointed
        vm.warp(block.timestamp + 1);
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Governor_Name() public view {
        assertEq(governor.name(), "ZaseonGovernor");
    }

    function test_VotingDelay_Default() public view {
        assertEq(governor.votingDelay(), 1 days);
    }

    function test_VotingPeriod_Default() public view {
        assertEq(governor.votingPeriod(), 5 days);
    }

    function test_ProposalThreshold_Default() public view {
        assertEq(governor.proposalThreshold(), 100_000e18);
    }

    function test_Quorum() public view {
        // 4% of 10M total supply = 400k
        uint256 q = governor.quorum(block.timestamp - 1);
        assertEq(q, 400_000e18);
    }

    function test_ClockMode() public view {
        assertEq(governor.CLOCK_MODE(), "mode=timestamp&from=default");
    }

    function test_Clock() public view {
        assertEq(governor.clock(), uint48(block.timestamp));
    }

    /*//////////////////////////////////////////////////////////////
                        PROPOSAL LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function _createProposal()
        internal
        returns (
            uint256 proposalId,
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas
        )
    {
        targets = new address[](1);
        targets[0] = target;
        values = new uint256[](1);
        values[0] = 0;
        calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("doSomething()");

        vm.prank(proposer);
        proposalId = governor.propose(
            targets,
            values,
            calldatas,
            "Test proposal"
        );
    }

    function test_Propose() public {
        (uint256 proposalId, , , ) = _createProposal();
        assertTrue(proposalId != 0);
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Pending)
        );
    }

    function test_Propose_BelowThreshold_Reverts() public {
        address lowHolder = makeAddr("lowHolder");
        token.mint(lowHolder, 1000e18);
        vm.prank(lowHolder);
        token.delegate(lowHolder);
        vm.warp(block.timestamp + 1);

        address[] memory targets = new address[](1);
        targets[0] = target;
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);

        vm.prank(lowHolder);
        vm.expectRevert();
        governor.propose(targets, values, calldatas, "Should fail");
    }

    function test_Vote_For() public {
        (uint256 proposalId, , , ) = _createProposal();

        // Advance past voting delay
        vm.warp(block.timestamp + governor.votingDelay() + 1);

        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Active)
        );

        // Cast vote
        vm.prank(voter1);
        governor.castVote(proposalId, 1); // For

        (
            uint256 againstVotes,
            uint256 forVotes,
            uint256 abstainVotes
        ) = governor.proposalVotes(proposalId);

        assertEq(forVotes, 5_000_000e18);
        assertEq(againstVotes, 0);
        assertEq(abstainVotes, 0);
    }

    function test_Vote_Against() public {
        (uint256 proposalId, , , ) = _createProposal();
        vm.warp(block.timestamp + governor.votingDelay() + 1);

        vm.prank(voter2);
        governor.castVote(proposalId, 0); // Against

        (, uint256 forVotes, ) = governor.proposalVotes(proposalId);
        (uint256 againstVotes, , ) = governor.proposalVotes(proposalId);

        assertEq(forVotes, 0);
        assertEq(againstVotes, 3_000_000e18);
    }

    function test_Vote_Abstain() public {
        (uint256 proposalId, , , ) = _createProposal();
        vm.warp(block.timestamp + governor.votingDelay() + 1);

        vm.prank(voter3);
        governor.castVote(proposalId, 2); // Abstain

        (, , uint256 abstainVotes) = governor.proposalVotes(proposalId);
        assertEq(abstainVotes, 1_500_000e18);
    }

    function test_FullLifecycle_Propose_Vote_Queue_Execute() public {
        (
            uint256 proposalId,
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas
        ) = _createProposal();

        // 1. Advance past voting delay
        vm.warp(block.timestamp + governor.votingDelay() + 1);

        // 2. Vote (voter1 + voter2 = 8M tokens > 400k quorum + majority)
        vm.prank(voter1);
        governor.castVote(proposalId, 1);
        vm.prank(voter2);
        governor.castVote(proposalId, 1);

        // 3. Advance past voting period
        vm.warp(block.timestamp + governor.votingPeriod() + 1);

        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Succeeded)
        );

        // 4. Queue in timelock
        governor.queue(
            targets,
            values,
            calldatas,
            keccak256(bytes("Test proposal"))
        );

        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Queued)
        );

        // 5. Advance past timelock delay
        vm.warp(block.timestamp + timelock.getMinDelay() + 1);

        // 6. Execute
        governor.execute(
            targets,
            values,
            calldatas,
            keccak256(bytes("Test proposal"))
        );

        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Executed)
        );
    }

    function test_Defeated_Proposal() public {
        (uint256 proposalId, , , ) = _createProposal();

        vm.warp(block.timestamp + governor.votingDelay() + 1);

        // voter1 votes against, voter3 votes for
        // Against: 5M, For: 1.5M -> defeated
        vm.prank(voter1);
        governor.castVote(proposalId, 0);
        vm.prank(voter3);
        governor.castVote(proposalId, 1);

        vm.warp(block.timestamp + governor.votingPeriod() + 1);

        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Defeated)
        );
    }

    function test_QuorumNotReached_Defeated() public {
        // Only voter3 (1.5M) votes, quorum is 400k — but need majority
        // voter3 alone won't make quorum if no one votes against and total < threshold
        // Actually 1.5M > 400k quorum, so this passes quorum
        // Let's use a smaller holder
        address smallHolder = makeAddr("smallHolder");
        token.mint(smallHolder, 200_000e18); // under 400k quorum
        vm.prank(smallHolder);
        token.delegate(smallHolder);
        vm.warp(block.timestamp + 1);

        (uint256 proposalId, , , ) = _createProposal();
        vm.warp(block.timestamp + governor.votingDelay() + 1);

        vm.prank(smallHolder);
        governor.castVote(proposalId, 1);

        vm.warp(block.timestamp + governor.votingPeriod() + 1);

        // 200k < 400k quorum -> Defeated
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Defeated)
        );
    }

    function test_Cancel_ByProposer() public {
        (
            uint256 proposalId,
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas
        ) = _createProposal();

        vm.prank(proposer);
        governor.cancel(
            targets,
            values,
            calldatas,
            keccak256(bytes("Test proposal"))
        );

        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Canceled)
        );
    }

    function test_DoubleVote_Reverts() public {
        (uint256 proposalId, , , ) = _createProposal();
        vm.warp(block.timestamp + governor.votingDelay() + 1);

        vm.prank(voter1);
        governor.castVote(proposalId, 1);

        vm.prank(voter1);
        vm.expectRevert();
        governor.castVote(proposalId, 0);
    }

    /*//////////////////////////////////////////////////////////////
                        CUSTOM PARAMETER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CustomParameters() public {
        ZaseonGovernor customGov = new ZaseonGovernor(
            IVotes(address(token)),
            TimelockController(payable(address(timelock))),
            2 days, // custom voting delay
            7 days, // custom voting period
            500_000e18, // custom threshold
            10 // 10% quorum
        );

        assertEq(customGov.votingDelay(), 2 days);
        assertEq(customGov.votingPeriod(), 7 days);
        assertEq(customGov.proposalThreshold(), 500_000e18);

        // Warp forward so quorum checkpoint is in the past
        vm.warp(block.timestamp + 1);
        // 10% of 10M = 1M
        assertEq(customGov.quorum(block.timestamp - 1), 1_000_000e18);
    }

    /*//////////////////////////////////////////////////////////////
                        TIMELOCK INTEGRATION
    //////////////////////////////////////////////////////////////*/

    function test_Executor_IsTimelock() public view {
        // The governor's executor should be the timelock
        assertEq(governor.timelock(), address(timelock));
    }

    function test_ProposalNeedsQueuing() public {
        (uint256 proposalId, , , ) = _createProposal();
        assertTrue(governor.proposalNeedsQueuing(proposalId));
    }
}
