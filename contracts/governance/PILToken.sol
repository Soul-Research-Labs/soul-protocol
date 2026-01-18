// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title PILToken
 * @notice Governance token for the Privacy Interoperability Layer
 * @dev ERC20 with voting capabilities for on-chain governance
 */
contract PILToken is ERC20, ERC20Permit, ERC20Votes, Ownable {
    uint256 public constant MAX_SUPPLY = 100_000_000e18; // 100M tokens

    // Vesting
    struct VestingSchedule {
        uint256 totalAmount;
        uint256 releasedAmount;
        uint256 startTime;
        uint256 duration;
        uint256 cliff;
    }

    mapping(address => VestingSchedule) public vestingSchedules;

    // Events
    event VestingScheduleCreated(
        address indexed beneficiary,
        uint256 totalAmount,
        uint256 startTime,
        uint256 duration,
        uint256 cliff
    );
    event TokensReleased(address indexed beneficiary, uint256 amount);

    constructor(
        address initialOwner
    ) ERC20("PIL Token", "PIL") ERC20Permit("PIL Token") Ownable(initialOwner) {
        // Initial distribution
        // 40% - Community/Treasury
        // 25% - Team (4-year vesting, 1-year cliff)
        // 20% - Investors (2-year vesting, 6-month cliff)
        // 10% - Ecosystem grants
        // 5% - Initial liquidity

        // Mint initial liquidity to owner
        _mint(initialOwner, 5_000_000e18);
    }

    /// @notice Mint tokens (owner only)
    function mint(address to, uint256 amount) external onlyOwner {
        require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
        _mint(to, amount);
    }

    /// @notice Create a vesting schedule for a beneficiary
    function createVestingSchedule(
        address beneficiary,
        uint256 totalAmount,
        uint256 startTime,
        uint256 duration,
        uint256 cliff
    ) external onlyOwner {
        require(
            vestingSchedules[beneficiary].totalAmount == 0,
            "Schedule exists"
        );
        require(
            totalSupply() + totalAmount <= MAX_SUPPLY,
            "Exceeds max supply"
        );

        vestingSchedules[beneficiary] = VestingSchedule({
            totalAmount: totalAmount,
            releasedAmount: 0,
            startTime: startTime,
            duration: duration,
            cliff: cliff
        });

        // Mint to this contract for vesting
        _mint(address(this), totalAmount);

        emit VestingScheduleCreated(
            beneficiary,
            totalAmount,
            startTime,
            duration,
            cliff
        );
    }

    /// @notice Release vested tokens to beneficiary
    function releaseVestedTokens() external {
        VestingSchedule storage schedule = vestingSchedules[msg.sender];
        require(schedule.totalAmount > 0, "No vesting schedule");

        uint256 releasable = _vestedAmount(msg.sender) -
            schedule.releasedAmount;
        require(releasable > 0, "No tokens to release");

        schedule.releasedAmount += releasable;
        _transfer(address(this), msg.sender, releasable);

        emit TokensReleased(msg.sender, releasable);
    }

    /// @notice Get vested amount for a beneficiary
    function vestedAmount(address beneficiary) external view returns (uint256) {
        return _vestedAmount(beneficiary);
    }

    /// @notice Get releasable amount for a beneficiary
    function releasableAmount(
        address beneficiary
    ) external view returns (uint256) {
        return
            _vestedAmount(beneficiary) -
            vestingSchedules[beneficiary].releasedAmount;
    }

    function _vestedAmount(
        address beneficiary
    ) internal view returns (uint256) {
        VestingSchedule memory schedule = vestingSchedules[beneficiary];

        if (schedule.totalAmount == 0) {
            return 0;
        }

        if (block.timestamp < schedule.startTime + schedule.cliff) {
            return 0;
        }

        if (block.timestamp >= schedule.startTime + schedule.duration) {
            return schedule.totalAmount;
        }

        return
            (schedule.totalAmount * (block.timestamp - schedule.startTime)) /
            schedule.duration;
    }

    // Required overrides for ERC20Votes

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
}
