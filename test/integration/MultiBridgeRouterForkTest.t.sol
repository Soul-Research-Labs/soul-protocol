// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ForkTestBase} from "../base/ForkTestBase.t.sol";
import {DirectL2Messenger} from "../../contracts/crosschain/DirectL2Messenger.sol";
import {MultiBridgeRouter} from "../../contracts/bridge/MultiBridgeRouter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import {IMultiBridgeRouter} from "../../contracts/interfaces/IMultiBridgeRouter.sol";

/**
 * @title MultiBridgeRouterForkTest
 * @notice Fork-mode integration tests for MultiBridgeRouter across L2 chains.
 * @dev Validates:
 *   - Router deploys and operates identically on Arbitrum, Optimism, and Base
 *   - Chain-specific message hashes differ (no cross-chain replay)
 *   - Bridge health tracking is per-instance (not shared across chains)
 *   - Domain separator uniqueness across chains
 *
 * Run (local):  forge test --match-contract MultiBridgeRouterForkTest -vvv
 * Run (forks):  FORK_TESTS=true forge test --match-contract MultiBridgeRouterForkTest -vvv
 */
contract MultiBridgeRouterForkTest is ForkTestBase {
    /*//////////////////////////////////////////////////////////////
                           STATE
    //////////////////////////////////////////////////////////////*/

    mapping(L2Chain => MultiBridgeRouter) public routers;
    mapping(L2Chain => DirectL2Messenger) public messengers;

    MockBridgeAdapterFork public mockAdapter;

    /*//////////////////////////////////////////////////////////////
                           SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        _registerChain(L2Chain.Arbitrum);
        _registerChain(L2Chain.Optimism);
        _registerChain(L2Chain.Base);
        _initForks();

        _deployOnAllChains();
    }

    function _deployOnChain(L2Chain chain) internal override {
        vm.startPrank(admin);
        routers[chain] = new MultiBridgeRouter(admin);
        messengers[chain] = new DirectL2Messenger(
            admin,
            address(routers[chain])
        );

        // Register a mock adapter on each router
        mockAdapter = new MockBridgeAdapterFork();
        routers[chain].registerAdapter(
            IMultiBridgeRouter.BridgeType.LAYERZERO,
            address(mockAdapter),
            80, // security score
            1000 ether // maxValuePerTx
        );

        // Add all registered chains as supported destinations
        for (uint256 i = 0; i < registeredChains.length; i++) {
            L2Chain destChain = registeredChains[i];
            if (destChain != chain) {
                routers[chain].addSupportedChain(
                    IMultiBridgeRouter.BridgeType.LAYERZERO,
                    _chainId(destChain)
                );
            }
        }
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
               TEST: ROUTER DEPLOYS ON ALL CHAINS
    //////////////////////////////////////////////////////////////*/

    function test_routerDeployedOnAllChains() public {
        for (uint256 i = 0; i < registeredChains.length; i++) {
            L2Chain chain = registeredChains[i];
            _switchToChain(chain);
            assertTrue(
                address(routers[chain]) != address(0),
                string.concat("Router not deployed on ", _chainLabel(chain))
            );
            assertTrue(
                routers[chain].hasRole(
                    routers[chain].DEFAULT_ADMIN_ROLE(),
                    admin
                ),
                "Admin role not set"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
         TEST: MESSENGER CHAIN BINDING ACROSS FORKS
    //////////////////////////////////////////////////////////////*/

    function test_messengerChainBinding() public {
        for (uint256 i = 0; i < registeredChains.length; i++) {
            L2Chain chain = registeredChains[i];
            _switchToChain(chain);
            assertEq(
                messengers[chain].currentChainId(),
                _chainId(chain),
                string.concat("Chain ID mismatch on ", _chainLabel(chain))
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
           TEST: MESSAGE HASH UNIQUENESS ACROSS CHAINS
    //////////////////////////////////////////////////////////////*/

    function test_messageHashDivergenceAcrossChains() public {
        bytes memory payload = abi.encode("test_payload", uint256(42));
        uint256 nonce = 1;

        bytes32[] memory hashes = new bytes32[](registeredChains.length);
        for (uint256 i = 0; i < registeredChains.length; i++) {
            hashes[i] = keccak256(
                abi.encode(payload, _chainId(registeredChains[i]), nonce)
            );
        }
        _assertAllUnique(hashes);
    }

    /*//////////////////////////////////////////////////////////////
           TEST: BRIDGE HEALTH IS PER-INSTANCE
    //////////////////////////////////////////////////////////////*/

    function test_bridgeHealthIsolatedPerChain() public {
        // Record failures only on Arbitrum
        _switchToChain(L2Chain.Arbitrum);
        vm.startPrank(admin);
        for (uint256 i = 0; i < 5; i++) {
            routers[L2Chain.Arbitrum].recordFailure(
                IMultiBridgeRouter.BridgeType.LAYERZERO
            );
        }
        vm.stopPrank();

        // Arbitrum health should show failures
        (, , , uint256 arbSuccesses, uint256 arbFailures, , , ) = routers[
            L2Chain.Arbitrum
        ].bridges(IMultiBridgeRouter.BridgeType.LAYERZERO);

        // Optimism should be clean
        _switchToChain(L2Chain.Optimism);
        (, , , uint256 optSuccesses, uint256 optFailures, , , ) = routers[
            L2Chain.Optimism
        ].bridges(IMultiBridgeRouter.BridgeType.LAYERZERO);

        assertGt(arbFailures, 0, "Arbitrum should have failures");
        assertEq(optFailures, 0, "Optimism should have no failures");
        // Ensure Optimism successes are independent
        assertEq(optSuccesses, 0, "Optimism should have no successes yet");
    }

    /*//////////////////////////////////////////////////////////////
         TEST: DOMAIN SEPARATOR UNIQUENESS
    //////////////////////////////////////////////////////////////*/

    function test_domainSeparatorUniqueness() public {
        address verifier = address(0xBEEF);

        bytes32[] memory separators = new bytes32[](registeredChains.length);
        for (uint256 i = 0; i < registeredChains.length; i++) {
            separators[i] = _domainSeparator(
                "ZaseonProtocol",
                "1",
                _chainId(registeredChains[i]),
                verifier
            );
        }
        _assertAllUnique(separators);
    }

    /*//////////////////////////////////////////////////////////////
           TEST: NULLIFIER DOMAIN UNIQUENESS
    //////////////////////////////////////////////////////////////*/

    function test_nullifierDomainDerivation() public {
        bytes32 baseNullifier = keccak256("user_secret_nullifier");

        bytes32[] memory nullifiers = new bytes32[](registeredChains.length);
        for (uint256 i = 0; i < registeredChains.length; i++) {
            nullifiers[i] = keccak256(
                abi.encode(baseNullifier, _chainId(registeredChains[i]))
            );
        }
        _assertAllUnique(nullifiers);
    }

    /*//////////////////////////////////////////////////////////////
         FUZZ: CHAIN ID UNIQUENESS GENERALIZED
    //////////////////////////////////////////////////////////////*/

    function testFuzz_anyTwoChainsDifferentDomains(
        uint256 chainA,
        uint256 chainB
    ) public pure {
        vm.assume(chainA != chainB);
        vm.assume(chainA > 0 && chainB > 0);

        bytes32 domainA = keccak256(abi.encode("ZaseonProtocol", chainA));
        bytes32 domainB = keccak256(abi.encode("ZaseonProtocol", chainB));
        assertTrue(
            domainA != domainB,
            "Distinct chain IDs must yield distinct domains"
        );
    }
}

/*//////////////////////////////////////////////////////////////
                  MOCK BRIDGE ADAPTER
//////////////////////////////////////////////////////////////*/

contract MockBridgeAdapterFork is IBridgeAdapter {
    uint256 public messageCount;
    mapping(bytes32 => bool) public verified;

    function bridgeMessage(
        address,
        bytes calldata,
        address
    ) external payable override returns (bytes32) {
        messageCount++;
        bytes32 id = keccak256(abi.encode(msg.sender, messageCount));
        verified[id] = true;
        return id;
    }

    function estimateFee(
        address,
        bytes calldata
    ) external pure override returns (uint256) {
        return 0.001 ether;
    }

    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verified[messageId];
    }
}
