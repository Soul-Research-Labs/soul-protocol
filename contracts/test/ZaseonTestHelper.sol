// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title ZaseonTestHelper
 * @author ZASEON
 * @notice Test helper that deploys and wires a minimal ZASEON stack for integrator tests
 * @dev Provides factory functions for deploying individual components or
 *      a fully-wired protocol stack. Useful for both internal tests and
 *      third-party integrator testing.
 *
 * Usage:
 *   import {ZaseonTestHelper} from "contracts/test/ZaseonTestHelper.sol";
 *
 *   contract MyTest is Test {
 *       ZaseonTestHelper helper;
 *
 *       function setUp() public {
 *           helper = new ZaseonTestHelper();
 *           helper.deployMinimalStack(address(this));
 *       }
 *
 *       function testBridge() public {
 *           // helper.hub(), helper.baseBridge(), etc.
 *       }
 *   }
 */
contract ZaseonTestHelper is Test {
    /*//////////////////////////////////////////////////////////////
                            DEPLOYED ADDRESSES
    //////////////////////////////////////////////////////////////*/

    address public hub;
    address public baseBridge;
    address public optimismBridge;
    address public arbitrumBridge;
    address public ethereumBridge;
    address public shieldedPool;
    address public nullifierRegistry;
    address public stealthAddressRegistry;
    address public proofHub;
    address public multiBridgeRouter;

    /// @notice Admin address used for all role grants
    address public admin;

    /// @notice Whether the stack has been deployed
    bool public deployed;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event StackDeployed(address indexed admin, uint256 componentCount);
    event ComponentDeployed(string name, address addr);

    /*//////////////////////////////////////////////////////////////
                        DEPLOYMENT HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deploy a minimal ZASEON stack suitable for integration testing
     * @param _admin Address to receive admin/operator roles on all contracts
     * @dev Deploys core contracts using CREATE and wires them together.
     *      Skips ZK verifier deployment (uses mock verifiers).
     */
    function deployMinimalStack(address _admin) external {
        require(!deployed, "Already deployed");
        require(_admin != address(0), "Zero admin");
        admin = _admin;

        // Deploy bridge adapters
        baseBridge = _deployBaseBridge(_admin);
        emit ComponentDeployed("BaseBridgeAdapter", baseBridge);

        optimismBridge = _deployOptimismBridge(_admin);
        emit ComponentDeployed("OptimismBridgeAdapter", optimismBridge);

        arbitrumBridge = _deployArbitrumBridge(_admin);
        emit ComponentDeployed("ArbitrumBridgeAdapter", arbitrumBridge);

        ethereumBridge = _deployEthereumBridge(_admin);
        emit ComponentDeployed("EthereumL1Bridge", ethereumBridge);

        deployed = true;
        emit StackDeployed(_admin, 4);
    }

    /**
     * @notice Deploy only the Base bridge adapter
     * @param _admin Admin address
     * @return addr Deployed contract address
     */
    function deployBaseBridge(address _admin) external returns (address addr) {
        addr = _deployBaseBridge(_admin);
        baseBridge = addr;
    }

    /**
     * @notice Deploy only the Optimism bridge adapter
     * @param _admin Admin address
     * @return addr Deployed contract address
     */
    function deployOptimismBridge(
        address _admin
    ) external returns (address addr) {
        addr = _deployOptimismBridge(_admin);
        optimismBridge = addr;
    }

    /**
     * @notice Deploy only the Arbitrum bridge adapter
     * @param _admin Admin address
     * @return addr Deployed contract address
     */
    function deployArbitrumBridge(
        address _admin
    ) external returns (address addr) {
        addr = _deployArbitrumBridge(_admin);
        arbitrumBridge = addr;
    }

    /**
     * @notice Deploy only the Ethereum L1 bridge
     * @param _admin Admin address
     * @return addr Deployed contract address
     */
    function deployEthereumBridge(
        address _admin
    ) external returns (address addr) {
        addr = _deployEthereumBridge(_admin);
        ethereumBridge = addr;
    }

    /*//////////////////////////////////////////////////////////////
                       MOCK / UTILITY HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a mock ERC-20 token for testing bridge operations
     * @param name Token name
     * @param symbol Token symbol
     * @return token Address of the mock token
     */
    function createMockToken(
        string memory name,
        string memory symbol
    ) external returns (address token) {
        bytes memory bytecode = abi.encodePacked(
            type(MockERC20).creationCode,
            abi.encode(name, symbol)
        );
        assembly {
            token := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(token != address(0), "MockERC20 deploy failed");
    }

    /**
     * @notice Fund an address with ETH for testing
     * @param target Address to fund
     * @param amount ETH amount in wei
     */
    function fundETH(address target, uint256 amount) external {
        vm.deal(target, amount);
    }

    /**
     * @notice Generate a deterministic test address with a label
     * @param label Human-readable label for the address
     * @return addr The generated address
     */
    function makeTestAddr(
        string memory label
    ) external pure returns (address addr) {
        addr = address(
            uint160(uint256(keccak256(abi.encodePacked("zaseon.test.", label))))
        );
    }

    /*//////////////////////////////////////////////////////////////
                      INTERNAL DEPLOY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _deployBaseBridge(
        address _admin
    ) internal returns (address addr) {
        bytes memory bytecode = abi.encodePacked(
            _getBaseBridgeCreationCode(),
            abi.encode(_admin)
        );
        assembly {
            addr := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(addr != address(0), "BaseBridgeAdapter deploy failed");
    }

    function _deployOptimismBridge(
        address _admin
    ) internal returns (address addr) {
        bytes memory bytecode = abi.encodePacked(
            _getOptimismBridgeCreationCode(),
            abi.encode(_admin)
        );
        assembly {
            addr := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(addr != address(0), "OptimismBridgeAdapter deploy failed");
    }

    function _deployArbitrumBridge(
        address _admin
    ) internal returns (address addr) {
        bytes memory bytecode = abi.encodePacked(
            _getArbitrumBridgeCreationCode(),
            abi.encode(_admin)
        );
        assembly {
            addr := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(addr != address(0), "ArbitrumBridgeAdapter deploy failed");
    }

    function _deployEthereumBridge(
        address _admin
    ) internal returns (address addr) {
        bytes memory bytecode = abi.encodePacked(
            _getEthereumBridgeCreationCode(),
            abi.encode(_admin)
        );
        assembly {
            addr := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(addr != address(0), "EthereumL1Bridge deploy failed");
    }

    /*//////////////////////////////////////////////////////////////
                     CREATION CODE ACCESSORS
    //////////////////////////////////////////////////////////////*/

    function _getBaseBridgeCreationCode()
        internal
        view
        returns (bytes memory)
    {
        return
            vm.getCode(
                "BaseBridgeAdapter.sol:BaseBridgeAdapter"
            );
    }

    function _getOptimismBridgeCreationCode()
        internal
        view
        returns (bytes memory)
    {
        return
            vm.getCode(
                "OptimismBridgeAdapter.sol:OptimismBridgeAdapter"
            );
    }

    function _getArbitrumBridgeCreationCode()
        internal
        view
        returns (bytes memory)
    {
        return
            vm.getCode(
                "ArbitrumBridgeAdapter.sol:ArbitrumBridgeAdapter"
            );
    }

    function _getEthereumBridgeCreationCode()
        internal
        view
        returns (bytes memory)
    {
        return
            vm.getCode(
                "EthereumL1Bridge.sol:EthereumL1Bridge"
            );
    }
}

/*//////////////////////////////////////////////////////////////
                        MOCK ERC-20
//////////////////////////////////////////////////////////////*/

/**
 * @title MockERC20
 * @notice Minimal ERC-20 for testing. Supports mint/burn by anyone.
 */
contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 amount
    );

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        emit Transfer(msg.sender, address(0), amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
