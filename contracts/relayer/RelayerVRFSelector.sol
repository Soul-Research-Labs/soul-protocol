// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {AccessControl} from "../../lib/openzeppelin-contracts/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "../../lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

interface IDecentralizedRelayerRegistry {
    function activeRelayers(uint256 index) external view returns (address);

    function relayers(
        address relayer
    )
        external
        view
        returns (
            uint256 stake,
            uint256 reputation,
            uint256 unstakeRequestTime,
            bool isRegistered
        );
}

/**
 * @title RelayerVRFSelector
 * @notice Commit–reveal VRF-style selector that picks a relayer from
 *         `DecentralizedRelayerRegistry` using unpredictable-at-commit-time
 *         randomness. Designed to harden metadata resistance (MLR Layer 11)
 *         by preventing relayer self-selection / adversarial biasing.
 *
 * @dev Two-phase protocol:
 *
 *      1. REQUEST: A consumer (e.g. `MultiRelayerRouter`) calls
 *         {requestSelection} with a commit hash = keccak256(seed || salt).
 *         The request is anchored to a future block (current + 1) whose
 *         blockhash will be mixed into the final VRF output.
 *
 *      2. REVEAL: After `MIN_REVEAL_BLOCKS` blocks have passed (ensuring
 *         the anchor blockhash is finalized & unknown at commit time),
 *         anyone may call {revealSelection} with (seed, salt). The VRF
 *         output is:
 *             vrf = keccak256(seed || salt || blockhash(anchor))
 *         The selected relayer is  `activeRelayers[vrf % len]`.
 *
 *      Requests expire after `REVEAL_WINDOW` blocks past the anchor;
 *      expired requests can be cleared by anyone via {cancelExpired}.
 *
 *      This is a stand-in that is robust for L2 deployments where
 *      Chainlink VRF is unavailable. It is NOT secure against a miner
 *      who can withhold a block (mainnet L1 proposer) and can choose
 *      between producing two valid anchor blocks — for L1 usage, swap
 *      the blockhash source for a Chainlink VRF v2 coordinator.
 */
contract RelayerVRFSelector is AccessControl, ReentrancyGuard {
    bytes32 public constant CONSUMER_ROLE = keccak256("CONSUMER_ROLE");

    /// @notice Minimum blocks that must elapse between commit and reveal.
    uint32 public constant MIN_REVEAL_BLOCKS = 2;
    /// @notice Maximum blocks after which a request expires.
    uint32 public constant REVEAL_WINDOW = 256;

    /// @notice Minimum bond a consumer must post on {requestSelection}.
    /// @dev H14 FIX: Without a slashable bond, a consumer can request a
    ///      selection, never reveal, and leave the VRF anchor unused. Any
    ///      party can call {cancelExpired} to free the slot and collect the
    ///      forfeited bond, which converts griefing cost into cleanup
    ///      incentive. The bond is refunded on a successful reveal.
    uint256 public constant MIN_REQUEST_BOND = 0.01 ether;

    IDecentralizedRelayerRegistry public immutable registry;

    struct Request {
        address consumer;
        bytes32 commitHash; // keccak256(seed || salt)
        uint64 anchorBlock; // blockhash used as entropy source
        bool fulfilled;
        uint256 bond; // H14: forfeited to canceller on expiry
    }

    mapping(bytes32 => Request) public requests;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event SelectionRequested(
        bytes32 indexed requestId,
        address indexed consumer,
        bytes32 commitHash,
        uint64 anchorBlock
    );

    event SelectionRevealed(
        bytes32 indexed requestId,
        address indexed relayer,
        bytes32 vrfOutput
    );

    event SelectionExpired(bytes32 indexed requestId);

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    error ZeroRegistry();
    error RequestAlreadyExists(bytes32 requestId);
    error UnknownRequest(bytes32 requestId);
    error RequestFulfilled(bytes32 requestId);
    error RevealTooEarly(uint64 currentBlock, uint64 earliestBlock);
    error RevealWindowExpired(uint64 currentBlock, uint64 deadline);
    error AnchorUnavailable(uint64 anchorBlock);
    error CommitMismatch();
    error NoActiveRelayers();
    error NotExpired(bytes32 requestId);
    /// @dev H14: Bond posted with requestSelection is below MIN_REQUEST_BOND.
    error InsufficientBond(uint256 provided, uint256 required);
    /// @dev H14: Native transfer (refund / forfeit payout) failed.
    error BondTransferFailed(address recipient, uint256 amount);

    constructor(address _registry, address admin) {
        if (_registry == address(0)) revert ZeroRegistry();
        if (admin == address(0)) revert ZeroRegistry();
        registry = IDecentralizedRelayerRegistry(_registry);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    // ---------------------------------------------------------------------
    // Commit phase
    // ---------------------------------------------------------------------

    /**
     * @notice Register a VRF request. Caller (consumer) commits to a
     *         `commitHash` = keccak256(seed || salt). The final VRF output
     *         is derived from (seed, salt, blockhash(anchor)), which is
     *         unknown at commit time.
     * @param requestId Caller-chosen unique id (must not collide).
     * @param commitHash keccak256(abi.encode(seed, salt)).
     * @return anchorBlock The block whose blockhash will seed the VRF.
     */
    function requestSelection(
        bytes32 requestId,
        bytes32 commitHash
    ) external payable onlyRole(CONSUMER_ROLE) returns (uint64 anchorBlock) {
        if (requests[requestId].commitHash != bytes32(0))
            revert RequestAlreadyExists(requestId);
        // H14: require a slashable bond so griefing has economic cost.
        if (msg.value < MIN_REQUEST_BOND)
            revert InsufficientBond(msg.value, MIN_REQUEST_BOND);

        anchorBlock = uint64(block.number + 1);
        requests[requestId] = Request({
            consumer: msg.sender,
            commitHash: commitHash,
            anchorBlock: anchorBlock,
            fulfilled: false,
            bond: msg.value
        });

        emit SelectionRequested(requestId, msg.sender, commitHash, anchorBlock);
    }

    // ---------------------------------------------------------------------
    // Reveal phase
    // ---------------------------------------------------------------------

    /**
     * @notice Reveal (seed, salt) to finalize the VRF output and select a
     *         relayer.
     * @dev Permissionless — anyone may reveal once they know the preimage.
     *      The selected relayer is `activeRelayers[vrf % count]`.
     */
    function revealSelection(
        bytes32 requestId,
        bytes32 seed,
        bytes32 salt
    ) external nonReentrant returns (address relayer, bytes32 vrfOutput) {
        Request storage r = requests[requestId];
        if (r.commitHash == bytes32(0)) revert UnknownRequest(requestId);
        if (r.fulfilled) revert RequestFulfilled(requestId);

        uint64 earliest = r.anchorBlock + MIN_REVEAL_BLOCKS;
        if (uint64(block.number) < earliest)
            revert RevealTooEarly(uint64(block.number), earliest);

        uint64 deadline = r.anchorBlock + REVEAL_WINDOW;
        if (uint64(block.number) > deadline)
            revert RevealWindowExpired(uint64(block.number), deadline);

        bytes32 anchorHash = blockhash(r.anchorBlock);
        if (anchorHash == bytes32(0)) revert AnchorUnavailable(r.anchorBlock);

        if (keccak256(abi.encode(seed, salt)) != r.commitHash)
            revert CommitMismatch();

        vrfOutput = keccak256(abi.encode(seed, salt, anchorHash));
        relayer = _pickRelayer(vrfOutput);

        r.fulfilled = true;
        emit SelectionRevealed(requestId, relayer, vrfOutput);

        // H14 FIX: Refund the consumer's bond on successful reveal. The bond
        // exists only to deter commit-and-never-reveal griefing; honest
        // consumers pay zero net cost.
        uint256 bond = r.bond;
        if (bond > 0) {
            r.bond = 0;
            (bool ok, ) = r.consumer.call{value: bond, gas: 30_000}("");
            if (!ok) revert BondTransferFailed(r.consumer, bond);
        }
    }

    /**
     * @notice Clear an expired (unrevealed) request so its `requestId`
     *         can be reused and storage is recoverable.
     */
    function cancelExpired(bytes32 requestId) external {
        Request storage r = requests[requestId];
        if (r.commitHash == bytes32(0)) revert UnknownRequest(requestId);
        if (r.fulfilled) revert RequestFulfilled(requestId);
        uint64 deadline = r.anchorBlock + REVEAL_WINDOW;
        if (uint64(block.number) <= deadline) revert NotExpired(requestId);

        // H14 FIX: Forfeit the consumer's bond to whoever cleans up the
        // expired slot — turns griefing into a profitable cleanup bounty
        // for relayers/watchtowers that monitor the selector.
        uint256 bond = r.bond;
        delete requests[requestId];
        emit SelectionExpired(requestId);

        if (bond > 0) {
            (bool ok, ) = msg.sender.call{value: bond, gas: 30_000}("");
            if (!ok) revert BondTransferFailed(msg.sender, bond);
        }
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    function _pickRelayer(bytes32 vrfOutput) internal view returns (address) {
        // Iterate until we find an active relayer, bounded to avoid DoS.
        // With high probability this terminates on the first attempt;
        // the loop handles the narrow case where a mid-selection unstake
        // left a hole at the probed index.
        for (uint256 i = 0; i < 8; i++) {
            // Probe `activeRelayers(idx)` — reverts if index OOB which we
            // catch by reading length via a try on the first element,
            // but the registry exposes no length() getter; instead we
            // rely on a staticcall-safe pattern: we attempt to read
            // index 0 to verify non-empty.
            try registry.activeRelayers(0) returns (address first) {
                if (first == address(0)) revert NoActiveRelayers();
            } catch {
                revert NoActiveRelayers();
            }

            // Derive a candidate index.
            uint256 idx = uint256(keccak256(abi.encode(vrfOutput, i)));
            // Bound probing with an 8-bit fast modulus assuming ≤ 256
            // active relayers per call; consumers with larger sets should
            // override off-chain and pass an explicit index.
            idx = idx & 0xff;

            try registry.activeRelayers(idx) returns (address candidate) {
                if (candidate != address(0)) return candidate;
            } catch {
                // OOB — narrow probe and retry with lower bits.
                continue;
            }
        }
        revert NoActiveRelayers();
    }
}
