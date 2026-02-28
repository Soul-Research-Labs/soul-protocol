// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ZaseonToken
 * @author ZASEON
 * @notice Governance token for the ZASEON ecosystem.
 * @dev Implements ERC20 with:
 *      - ERC20Votes: Vote delegation and snapshotting for governance
 *      - ERC20Permit: Gasless approvals via EIP-2612
 *      - ERC20Capped: Hard supply cap (non-inflationary)
 *      - AccessControl: Role-based minting authority
 *      - Timestamp-based clock (L2-compatible, matching ZaseonGovernor)
 *
 * TOKEN ECONOMICS:
 * ┌──────────────────────────────────────────────────────────────────┐
 * │  Max Supply:  1,000,000,000 ZASEON (1 billion, 18 decimals)       │
 * │  Minting:     Only MINTER_ROLE, respects cap                    │
 * │  Burning:     Any holder can burn own tokens                    │
 * │  Transfer:    Unrestricted (no allowlist/blocklist)             │
 * │  Governance:  Self-delegation required for voting power         │
 * └──────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@zaseon.network
 */
contract ZaseonToken is
    ERC20,
    ERC20Capped,
    ERC20Permit,
    ERC20Votes,
    AccessControl
{
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum supply: 1 billion tokens
    uint256 public constant MAX_SUPPLY = 1_000_000_000e18;

    /// @notice Role that can mint new tokens (up to the cap)
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when tokens are burned
    event TokensBurned(address indexed burner, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when attempting to mint zero tokens
    error MintAmountZero();

    /// @notice Thrown when attempting to burn zero tokens
    error BurnAmountZero();

    /// @notice Thrown when recipient is the zero address
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param _admin Default admin who can grant roles
     * @param _initialMintRecipient Receives the initial mint (e.g., treasury multisig)
     * @param _initialMintAmount Amount to mint at deployment (must be <= MAX_SUPPLY)
     */
    constructor(
        address _admin,
        address _initialMintRecipient,
        uint256 _initialMintAmount
    )
        ERC20("ZASEON", "ZASEON")
        ERC20Capped(MAX_SUPPLY)
        ERC20Permit("ZASEON")
    {
        if (_admin == address(0)) revert ZeroAddress();
        if (_initialMintRecipient == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(MINTER_ROLE, _admin);

        if (_initialMintAmount > 0) {
            _mint(_initialMintRecipient, _initialMintAmount);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          MINTING & BURNING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Mint new tokens to a recipient (up to the cap)
     * @param to Recipient address
     * @param amount Amount to mint
     */
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert MintAmountZero();
        _mint(to, amount);
    }

    /**
     * @notice Burn tokens from the caller's balance
     * @param amount Amount to burn
     */
    function burn(uint256 amount) external {
        if (amount == 0) revert BurnAmountZero();
        _burn(msg.sender, amount);
        emit TokensBurned(msg.sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                         CLOCK MODE (L2 COMPAT)
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Use block.timestamp for the voting clock — required for L2 compatibility
     *      where block numbers are unreliable. Matches ZaseonGovernor.clock().
     */
        /**
     * @notice Clock
     * @return The result value
     */
function clock() public view override returns (uint48) {
        return uint48(block.timestamp);
    }

    /**
     * @dev Machine-readable clock mode descriptor (ERC-6372).
     */
    // solhint-disable-next-line func-name-mixedcase
        /**
     * @notice C l o c k_ m o d e
     * @return The result value
     */
function CLOCK_MODE() public pure override returns (string memory) {
        return "mode=timestamp&from=default";
    }

    /*//////////////////////////////////////////////////////////////
                         REQUIRED OVERRIDES
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ERC20Capped
        /**
     * @notice _update
     * @param from The source address
     * @param to The destination address
     * @param value The value to set
     */
function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20, ERC20Capped, ERC20Votes) {
        super._update(from, to, value);
    }

    /// @inheritdoc ERC20Permit
        /**
     * @notice Nonces
     * @param owner The owner address
     * @return The result value
     */
function nonces(
        address owner
    ) public view override(ERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }

    /// @inheritdoc AccessControl
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
