// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// import {IServiceManager} from "eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {IStrategyManager} from "eigenlayer-contracts/src/contracts/interfaces/IStrategyManager.sol";
import {ISignatureUtils} from "eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";
import {Ownable} from "@openzeppelin@v5.1.0/access/Ownable.sol";
import {Pausable} from "@openzeppelin@v5.1.0/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin@v5.1.0/utils/ReentrancyGuard.sol";
import {IDelegationManager} from "eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";

interface IServiceManager {
    /**
     * @notice Sets the metadata URI for the AVS
     * @param _metadataURI is the metadata URI for the AVS
     */
    function setMetadataURI(string memory _metadataURI) external;

    /**
     * @notice Forwards a call to EigenLayer's DelegationManager contract to confirm operator registration with the AVS
     * @param operator The address of the operator to register.
     * @param operatorSignature The signature, salt, and expiry of the operator's signature.
     */
    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) external;

    /**
     * @notice Forwards a call to EigenLayer's DelegationManager contract to confirm operator deregistration from the AVS
     * @param operator The address of the operator to deregister.
     */
    function deregisterOperatorFromAVS(address operator) external;

    /**
     * @notice Returns the list of strategies that the operator has potentially restaked on the AVS
     * @param operator The address of the operator to get restaked strategies for
     * @dev This function is intended to be called off-chain
     * @dev No guarantee is made on whether the operator has shares for a strategy in a quorum or uniqueness
     *      of each element in the returned array. The off-chain service should do that validation separately
     */
    function getOperatorRestakedStrategies(address operator) external view returns (address[] memory);

    /**
     * @notice Returns the list of strategies that the AVS supports for restaking
     * @dev This function is intended to be called off-chain
     * @dev No guarantee is made on uniqueness of each element in the returned array.
     *      The off-chain service should do that validation separately
     */
    function getRestakeableStrategies() external view returns (address[] memory);
}

/// @title ServiceManager Contract
/// @notice This contract manages the registration and deregistration of operators, as well as the management of middleware times.
/// @dev Inherits from IServiceManager, Ownable, Pausable, and ReentrancyGuard.
contract ServiceManager is Ownable, Pausable, ReentrancyGuard {
    /* ================== STATE VARS =================== */

    IDelegationManager public s_delegationManager;
    IStrategyManager public s_strategyManager;

    mapping(address => bool) public s_registeredOperators;
    address[] public s_operatorList;

    string public s_avsMetadataURI;
    uint256 public constant QUORUM_THRESHOLD = 2;
    // Minimum stake, can be changed
    uint256 public constant MIN_STAKE = 1 ether;

    struct MiddlewareTimes {
        uint256 startTime;
        uint256 endTime;
    }

    // IServiceManager.MiddlewareTimes[] public s_middlewareTimesList;
    MiddlewareTimes[] public s_middlewareTimesList;

    /* ==================== EVENTS ==================== */

    event OperatorRegistered(address operator);
    event OperatorDeregistered(address operator);
    event AVSMetadataURIUpdated(string newMetadataURI);

    /* ==================== ERRORS ==================== */

    error ServiceManager__OperatorAlreadyRegistered();
    error ServiceManager__NotAnEigenLayerOperator();
    error ServiceManager__OperatorNotRegistered();
    error ServiceManager__IndexOutOfBounds();

    /* =================== CONSTRUCTOR =================== */

    /// @notice Initializes the ServiceManager contract
    /// @param _delegationManager The delegation manager contract
    /// @param _strategyManager The strategy manager contract
    /// @param _initialOwner The initial owner of the contract
    constructor(IDelegationManager _delegationManager, IStrategyManager _strategyManager, address _initialOwner)
        Ownable(_initialOwner)
    {
        s_delegationManager = _delegationManager;
        s_strategyManager = _strategyManager;
    }

    /* ==================== EXTERNAL ==================== */

    /// @notice Initializes the delegation and strategy managers
    /// @param _delegationManager The delegation manager contract
    /// @param _strategyManager The strategy manager contract
    function initialize(IDelegationManager _delegationManager, IStrategyManager _strategyManager) external onlyOwner {
        s_delegationManager = _delegationManager;
        s_strategyManager = _strategyManager;
    }

    /// @notice Returns the length of the middleware times list
    /// @return The length of the middleware times list
    function middlewareTimesLength() external view returns (uint32) {
        return uint32(s_middlewareTimesList.length);
    }

    /// @notice Returns the middleware times at a specific index
    /// @param _index The index of the middleware times
    /// @return The middleware times at the specified index
    function middlewareTimes(uint256 _index) external view returns (MiddlewareTimes memory) {
        // ) external view returns (IServiceManager.MiddlewareTimes memory) {
        require(_index < s_middlewareTimesList.length, "ServiceManager__IndexOutOfBounds()");
        return s_middlewareTimesList[_index];
    }

    /// @notice Returns the list of active operators
    /// @return An array of active operator addresses
    function getActiveOperators() external view returns (address[] memory) {
        uint256 activeCount = 0;
        address[] memory operatorList = s_operatorList; // @TODO: Check if memory or storage
        for (uint256 i = 0; i < operatorList.length; i++) {
            if (isActiveOperator(operatorList[i])) {
                activeCount++;
            }
        }

        address[] memory activeOperators = new address[](activeCount);
        uint256 index = 0;
        for (uint256 i = 0; i < operatorList.length; i++) {
            if (isActiveOperator(operatorList[i])) {
                activeOperators[index] = operatorList[i];
                index++;
            }
        }

        return activeOperators;
    }

    /// @notice Registers a new operator
    /// @param _operator The address of the operator to register
    /// @param _operatorMetadataURI The metadata URI of the operator
    function registerOperator(address _operator, string calldata _operatorMetadataURI) external nonReentrant {
        require(!s_registeredOperators[_operator], "ServiceManager__OperatorAlreadyRegistered()");
        require(s_delegationManager.isOperator(_operator), "ServiceManager__NotAnEigenLayerOperator()");

        s_registeredOperators[_operator] = true;
        s_operatorList.push(_operator);

        emit OperatorRegistered(_operator);
    }

    /// @notice Deregisters an operator
    /// @param _operator The address of the operator to deregister
    function deregisterOperator(address _operator) external nonReentrant {
        require(s_registeredOperators[_operator], "ServiceManager__OperatorNotRegistered()");

        s_registeredOperators[_operator] = false;
        address[] memory operatorList = s_operatorList;
        for (uint256 i = 0; i < operatorList.length; i++) {
            if (operatorList[i] == _operator) {
                s_operatorList[i] = operatorList[operatorList.length - 1]; // TODO: Check if this is correct
                s_operatorList.pop();
                break;
            }
        }

        emit OperatorDeregistered(_operator);
    }

    /// @notice Updates the AVS metadata URI
    /// @param _newMetadataURI The new metadata URI
    function updateAVSMetadataURI(string calldata _newMetadataURI) external onlyOwner {
        s_avsMetadataURI = _newMetadataURI;
        emit AVSMetadataURIUpdated(_newMetadataURI);
    }

    /// @notice Adds new middleware times
    /// @param _newTimes The new middleware times to add
    function addMiddlewareTimes(MiddlewareTimes memory _newTimes)
        external
        // IServiceManager.MiddlewareTimes memory _newTimes
        onlyOwner
    {
        s_middlewareTimesList.push(_newTimes);
    }

    /// @notice Removes middleware times at a specific index
    /// @param _index The index of the middleware times to remove
    function removeMiddlewareTimes(uint256 _index) external onlyOwner {
        require(_index < s_middlewareTimesList.length, "ServiceManager__IndexOutOfBounds()");
        s_middlewareTimesList[_index] = s_middlewareTimesList[s_middlewareTimesList.length - 1];
        s_middlewareTimesList.pop();
    }

    /* ==================== PUBLIC ==================== */

    /// @notice Checks if an operator is active
    /// @param _operator The address of the operator to check
    /// @return isActive A boolean indicating whether the operator is active
    function isActiveOperator(address _operator) public view returns (bool isActive) {
        return s_registeredOperators[_operator] && s_delegationManager.isOperator(_operator);
        // &&
        // s_strategyManager.stakedInStrategy(_operator, address(this)) >=
        // MIN_STAKE;
    }
}
