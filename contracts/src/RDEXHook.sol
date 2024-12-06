// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";
import {IERC165} from "@openzeppelin@v5.1.0/interfaces/IERC165.sol";
import {Ownable} from "@openzeppelin@v5.1.0/access/Ownable.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {Pool} from "v4-core/src/libraries/Pool.sol";
import {PoolId} from "v4-core/src/types/PoolId.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IERC3643IdentityRegistry} from "./interfaces/ERC3643/IERC3643IdentityRegistry.sol";
import {IERC3643IdentityRegistryStorage} from "./interfaces/ERC3643/IERC3643IdentityRegistryStorage.sol";
import {IERC3643} from "./interfaces/ERC3643/IERC3643.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {ERC20RDEXWrapper, MAX_SUPPLY} from "./ERC20RDEXWrapper.sol";
import {Clones} from "@openzeppelin@v5.1.0/proxy/Clones.sol";
import {CurrencySettler} from "v4-core/test/utils/CurrencySettler.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {Constants} from "v4-core/test/utils/Constants.sol";
import {Position} from "v4-core/src/libraries/Position.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";

// TODO: Add OnlyPoolManager modifier to hook functions

/// @title RDEXHook
/// @notice This contract is a hook for managing dynamic fees and identity verification in a decentralized exchange.
contract RDEXHook is BaseHook, Ownable {
    /* ==================  TYPES =================== */
    using Clones for address;
    using CurrencySettler for Currency; // TODO: Do not use lib from v4-core but internal funcitons

    struct CallBackData {
        bool initializePool;
        bool modifyLiquidity;
        IERC3643 token;
        ERC20RDEXWrapper erc20Wrapper;
        PoolKey poolKey;
        address user;
        address refCurrencyAddr;
        uint160 sqrtPriceX96;
        IPoolManager.ModifyLiquidityParams modifyLiquidityParams;
    }

    /* ================== STATE VARS =================== */
    IERC3643IdentityRegistryStorage public identityRegistryStorage;
    uint256 public refCurrencyClaimTopic;
    address public refCurrencyClaimTrustedIssuer; // This can be modified to allow to set multiple trusted issuers that will asses that a token is a refCurrency

    uint256 internal constant BASE_FEE = 10_000; // 1%

    uint24 internal immutable i_minimumFee;

    // discountBasisPoints is a percentage of the fee that will be discounted 1 to 1000 1 is 0.001% and 1000 is 0.1%
    mapping(uint256 claimTopic => uint16 discountBasisPoints) internal s_topicToDiscount;

    uint256[] public s_topicsWithDiscount;

    address public immutable i_erc20WrapperImplementation;
    mapping(address ERC3643 => ERC20RDEXWrapper) public ERC3643ToERC20WrapperInstances;
    mapping(PoolId => PoolKey) public poolIdToWrapperPoolKey;

    /* ==================== EVENTS ==================== */

    event IdentityRegistryStorageSet(address identityRegistryStorage);
    event RefCurrencyClaimTopicSet(uint256 refCurrencyClaimTopic);
    event RefCurrencyClaimTrustedIssuerSet(address refCurrencyClaimTrustedIssuer);
    // TODO: ADD event to track liquidity modifications since PM one des not contains user info.

    /* ==================== ERRORS ==================== */
    error NeitherTokenIsERC3643Compliant();
    error HookNotVerifiedByERC3643IdentityRegistry();
    error RefCurrencyClaimNotValid();
    error LiquidityMustBeAddedThroughHook();
    error ERC3642DoNotHaveERC20Wrapper();

    /* ==================== MODIFIERS ==================== */

    /* =================== CONSTRUCTOR =================== */

    /// @notice Constructor to initialize the RDEXHook contract
    /// @param _manager The address of the pool manager
    /// @param _owner The address of the owner
    constructor(
        IPoolManager _manager,
        address _owner,
        uint24 _minimumFee,
        IERC3643IdentityRegistryStorage _identityRegistryStorage,
        uint256 _refCurrencyClaimTopic,
        address _refCurrencyClaimTrustedIssuer
    ) BaseHook(_manager) Ownable(_owner) {
        i_minimumFee = _minimumFee;

        identityRegistryStorage = _identityRegistryStorage;
        refCurrencyClaimTopic = _refCurrencyClaimTopic;
        refCurrencyClaimTrustedIssuer = _refCurrencyClaimTrustedIssuer;

        // Deploy implementation  for ERC20Wrapper clones
        i_erc20WrapperImplementation = address(new ERC20RDEXWrapper());
    }

    /* ==================== EXTERNAL ==================== */

    function modifyLiquidity(
        PoolKey memory key,
        IPoolManager.ModifyLiquidityParams memory params,
        bytes memory hookData
    ) external payable returns (BalanceDelta delta) {
        CallBackData memory callBackData;
        callBackData.modifyLiquidity = true;
        callBackData.poolKey = key;
        callBackData.user = msg.sender;
        callBackData.modifyLiquidityParams = params;

        // get the wrapper token address
        if (address(ERC3643ToERC20WrapperInstances[Currency.unwrap(key.currency0)]) != address(0)) {
            callBackData.token = IERC3643(Currency.unwrap(key.currency0));
            callBackData.erc20Wrapper = ERC3643ToERC20WrapperInstances[Currency.unwrap(key.currency0)];
            callBackData.refCurrencyAddr = Currency.unwrap(key.currency1);
        } else if (address(ERC3643ToERC20WrapperInstances[Currency.unwrap(key.currency1)]) != address(0)) {
            callBackData.token = IERC3643(Currency.unwrap(key.currency1));
            callBackData.erc20Wrapper = ERC3643ToERC20WrapperInstances[Currency.unwrap(key.currency1)];
            callBackData.refCurrencyAddr = Currency.unwrap(key.currency0);
        } else {
            revert ERC3642DoNotHaveERC20Wrapper();
        }
        poolManager.unlock(abi.encode(callBackData));
    }

    /// @notice Hook that is called before initializing a pool
    /// @param _key The pool key
    /// @return The selector for the beforeInitialize function
    function beforeInitialize(address, PoolKey calldata _key, uint160 sqrtPriceX96)
        external
        override
        returns (bytes4)
    {
        CallBackData memory callBackData;
        callBackData.initializePool = true;
        callBackData.poolKey = _key;
        callBackData.sqrtPriceX96 = sqrtPriceX96;

        bool currency0IsERC3643 = false;
        bool currency1IsERC3643 = false;
        try IERC165(Currency.unwrap(_key.currency0)).supportsInterface(type(IERC3643).interfaceId) returns (
            bool isERC3643
        ) {
            currency0IsERC3643 = isERC3643;
        } catch {}
        try IERC165(Currency.unwrap(_key.currency1)).supportsInterface(type(IERC3643).interfaceId) returns (
            bool isERC3643
        ) {
            currency1IsERC3643 = isERC3643;
        } catch {}

        IIdentity identity;
        bytes memory sig;
        bytes memory data;
        // @dev: Problem here? it is possible that a ref currenty to be an ERC3643? if not is ok. IMO ref currency will be stableoin or ETH so no.
        if (currency0IsERC3643) {
            // Check if  address(this) is verified by the identity registry of currency 0
            IERC3643 token = IERC3643(Currency.unwrap(_key.currency0));
            IERC3643IdentityRegistry identityRegistry = token.identityRegistry();
            if (!identityRegistry.isVerified(address(this))) revert HookNotVerifiedByERC3643IdentityRegistry();
            // Check if currency 1 is a verified refCurrency
            callBackData.refCurrencyAddr = Currency.unwrap(_key.currency1);
            identity = IIdentity(identityRegistryStorage.storedIdentity(callBackData.refCurrencyAddr));
            bytes32 claimId = keccak256(abi.encode(refCurrencyClaimTrustedIssuer, refCurrencyClaimTopic));
            (,,, sig, data,) = identity.getClaim(claimId);
        } else if (currency1IsERC3643) {
            // Check if  address(this) is verified by the identity registry of currency 1
            IERC3643 token = IERC3643(Currency.unwrap(_key.currency1));
            IERC3643IdentityRegistry identityRegistry = token.identityRegistry();
            if (!identityRegistry.isVerified(address(this))) revert HookNotVerifiedByERC3643IdentityRegistry();
            // Check if currency 1 is a verified refCurrency
            callBackData.refCurrencyAddr = Currency.unwrap(_key.currency0);
            identity = IIdentity(identityRegistryStorage.storedIdentity(callBackData.refCurrencyAddr));
            bytes32 claimId = keccak256(abi.encode(refCurrencyClaimTrustedIssuer, refCurrencyClaimTopic));
            (,,, sig, data,) = identity.getClaim(claimId);
        } else {
            revert NeitherTokenIsERC3643Compliant();
        }

        if (!IClaimIssuer(refCurrencyClaimTrustedIssuer).isClaimValid(identity, refCurrencyClaimTopic, sig, data)) {
            revert RefCurrencyClaimNotValid();
        }

        // Deploy  ERC20RDEXWrapper clone for the ERC3643 token
        // TODO: To simplify the code we can use create2 to mint the wrapper with an address that keeps the address sorting equal so we don't have to sort the addresses in swaps and  liquidity provision
        callBackData.erc20Wrapper = ERC20RDEXWrapper(i_erc20WrapperImplementation.clone());
        // Compute new name and symbol for the ERC20RDEXWrapper
        string memory ERC20RDEXWrapperName = string.concat(
            currency0IsERC3643
                ? IERC3643(Currency.unwrap(_key.currency0)).name()
                : IERC3643(Currency.unwrap(_key.currency1)).name(),
            "ERC20RDEXWrapper"
        );
        string memory ERC20RDEXWrapperSymbol = string.concat(
            currency0IsERC3643
                ? IERC3643(Currency.unwrap(_key.currency0)).symbol()
                : IERC3643(Currency.unwrap(_key.currency1)).symbol(),
            "rdexw"
        );
        // Initialize the ERC20RDEXWrapper clone
        address[] memory whitelist = new address[](2);
        whitelist[0] = address(this);
        whitelist[1] = address(poolManager);
        callBackData.erc20Wrapper.initialize(ERC20RDEXWrapperName, ERC20RDEXWrapperSymbol, whitelist);
        // Continue initialization in the callback, _key.to
        poolManager.unlock(abi.encode(callBackData));
        // Save the ERC20RDEXWrapper clone instance in the instances mapping
        ERC3643ToERC20WrapperInstances[currency0IsERC3643
            ? Currency.unwrap(_key.currency0)
            : Currency.unwrap(_key.currency1)] = callBackData.erc20Wrapper;

        return (IHooks.beforeInitialize.selector);
    }

    /// @notice Hook that is called before a swap
    /// @return The selector for the beforeSwap function, the delta, and the fee with flag
    function beforeSwap(address _sender, PoolKey calldata, IPoolManager.SwapParams calldata, bytes calldata)
        external
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        uint24 fee = _calculateFee(_sender);
        // poolManager.updateDynamicLPFee(_key, fee);
        uint24 feeWithFlag = fee | LPFeeLibrary.OVERRIDE_FEE_FLAG;

        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, feeWithFlag);
    }

    /// @notice Sets the identity registry storage
    /// @param _identityRegistryStorage The address of the identity registry storage
    function setIdentityRegistryStorage(address _identityRegistryStorage) external onlyOwner {
        identityRegistryStorage = IERC3643IdentityRegistryStorage(_identityRegistryStorage);
        emit IdentityRegistryStorageSet(_identityRegistryStorage);
    }

    /// @notice Sets the refCurrency claim topic
    /// @param _refCurrencyClaimTopic The refCurrency claim topic
    function setRefCurrencyClaimTopic(uint256 _refCurrencyClaimTopic) external onlyOwner {
        refCurrencyClaimTopic = _refCurrencyClaimTopic;
        emit RefCurrencyClaimTopicSet(_refCurrencyClaimTopic);
    }

    /// @notice Sets the refCurrency claim trusted issuer
    /// @param _refCurrencyClaimTrustedIssuer The address of the refCurrency claim trusted issuer
    function setRefCurrencyClaimTrustedIssuer(address _refCurrencyClaimTrustedIssuer) external onlyOwner {
        refCurrencyClaimTrustedIssuer = _refCurrencyClaimTrustedIssuer;
        emit RefCurrencyClaimTrustedIssuerSet(_refCurrencyClaimTrustedIssuer);
    }

    function setDynamicFee(uint256 _topic, uint16 _discountBasisPoints) external onlyOwner {
        s_topicToDiscount[_topic] = _discountBasisPoints;
    }

    function setTopicsWithDiscount(uint256[] calldata _topicsWithDiscount) external onlyOwner {
        s_topicsWithDiscount = _topicsWithDiscount;
    }

    function dynamicFee(uint256 _topic) external view returns (uint16) {
        return s_topicToDiscount[_topic];
    }

    /**
     * @notice Retrieves the position information of a pool without needing to calculate the `positionId`.
     * @dev Corresponds to pools[poolId].positions[positionId]
     * @param _poolId The ID of the pool.
     * @param _owner The owner of the liquidity position.
     * @param _tickLower The lower tick of the liquidity range.
     * @param _tickUpper The upper tick of the liquidity range.
     * @param _salt The bytes32 randomness to further distinguish position state.
     * @return liquidity The liquidity of the position.
     * @return feeGrowthInside0LastX128 The fee growth inside the position for token0.
     * @return feeGrowthInside1LastX128 The fee growth inside the position for token1.
     */
    function getPositionInfo(PoolId _poolId, address _owner, int24 _tickLower, int24 _tickUpper, bytes32 _salt)
        external
        view
        returns (uint128 liquidity, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128)
    {
        bytes32 salt = keccak256(abi.encodePacked(_owner, _salt));
        bytes32 positionKey = Position.calculatePositionKey(address(this), _tickLower, _tickUpper, salt);

        (liquidity, feeGrowthInside0LastX128, feeGrowthInside1LastX128) =
            StateLibrary.getPositionInfo(poolManager, poolIdToWrapperPoolKey[_poolId].toId(), positionKey);
    }

    /* ==================== PUBLIC ==================== */

    // TODO: Define permissions
    /// @notice Returns the hook permissions
    /// @return The hook permissions
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: true,
            afterInitialize: false,
            beforeAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterAddLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    /* ==================== INTERNAL ==================== */

    /// @notice Calculates the fee
    /// @return The calculated fee
    function _calculateFee(address _sender) internal returns (uint24) {
        uint256 discountedFee = BASE_FEE;

        for (uint256 i = 0; i < s_topicsWithDiscount.length; i++) {
            uint256 topic = s_topicsWithDiscount[i];
            uint256 discountBasisPoints = s_topicToDiscount[topic];
            IIdentity identity = IIdentity(identityRegistryStorage.storedIdentity(_sender));
            bytes32 claimId = keccak256(abi.encode(refCurrencyClaimTrustedIssuer, topic));

            (uint256 foundClaimTopic, uint256 scheme, address issuer, bytes memory sig, bytes memory data,) =
                identity.getClaim(claimId);
            if (IClaimIssuer(issuer).isClaimValid(identity, s_topicsWithDiscount[i], sig, data)) {
                unchecked {
                    discountedFee = discountedFee - discountBasisPoints;
                }

                if (discountedFee < i_minimumFee) {
                    return i_minimumFee;
                }
            }
        }
    }

    /// @notice sorts two addresses and returns them as currencies
    /// TODO: if we use create2 to mint the wrappers to enforce the address orders we can remove this function
    function _sortCurrencies(address _currencyAAddr, address _currencyBAddr)
        internal
        returns (Currency currency0, Currency currency1)
    {
        if (_currencyAAddr < _currencyBAddr) {
            currency0 = Currency.wrap(_currencyAAddr);
            currency1 = Currency.wrap(_currencyBAddr);
        } else {
            currency0 = Currency.wrap(_currencyBAddr);
            currency1 = Currency.wrap(_currencyAAddr);
        }
    }

    function _unlockCallback(bytes calldata data) internal override returns (bytes memory) {
        CallBackData memory callBackData = abi.decode(data, (CallBackData));

        // Wrapper pool Initialization
        if (callBackData.initializePool) {
            callBackData.erc20Wrapper.approve(address(poolManager), MAX_SUPPLY);
            // Mint  max suplly of claim tokens in the pool manager
            poolManager.mint(address(this), uint256(uint160(address(callBackData.erc20Wrapper))), MAX_SUPPLY);
            // Settle delta
            Currency currency = Currency.wrap(address(callBackData.erc20Wrapper));
            currency.settle(poolManager, address(this), MAX_SUPPLY, false);
            (Currency _WCurrency0, Currency _WCurrency1) =
                _sortCurrencies(callBackData.refCurrencyAddr, address(callBackData.erc20Wrapper));
            // Initialize the pool of the Wrapper against the reference currency this will be the real traded pool
            // TODO:  check how to do dynamic fees, we cannot have a pool with dynamic fees without a hook
            PoolKey memory wrapperPoolKey = PoolKey(
                _WCurrency0,
                _WCurrency1,
                3000, /*LPFeeLibrary.DYNAMIC_FEE_FLAG*/
                callBackData.poolKey.tickSpacing,
                IHooks(address(0))
            );
            poolManager.initialize(wrapperPoolKey, callBackData.sqrtPriceX96);
            poolIdToWrapperPoolKey[callBackData.poolKey.toId()] = wrapperPoolKey;
        } else if (callBackData.modifyLiquidity) {
            IPoolManager.ModifyLiquidityParams memory params = callBackData.modifyLiquidityParams;
            params.tickLower = callBackData.modifyLiquidityParams.tickLower;
            params.tickUpper = callBackData.modifyLiquidityParams.tickUpper;
            params.liquidityDelta = callBackData.modifyLiquidityParams.liquidityDelta;
            params.salt = keccak256(abi.encodePacked(callBackData.user, callBackData.modifyLiquidityParams.salt));

            PoolKey memory wrapperPoolKey = poolIdToWrapperPoolKey[callBackData.poolKey.toId()];
            (BalanceDelta delta,) = poolManager.modifyLiquidity(wrapperPoolKey, params, "");

            int256 delta0 = delta.amount0();
            int256 delta1 = delta.amount1();

            if (
                Currency.unwrap(wrapperPoolKey.currency0) == address(callBackData.erc20Wrapper)
                    && Currency.unwrap(wrapperPoolKey.currency1) == callBackData.refCurrencyAddr
            ) {
                //  currency0 is ERC20Wrapper and currency1 is refCurrency
                if (delta0 < 0) {
                    wrapperPoolKey.currency0.settle(poolManager, address(this), uint256(-delta0), true);
                    callBackData.token.transferFrom(callBackData.user, address(this), uint256(-delta0));
                }
                if (delta1 < 0) {
                    wrapperPoolKey.currency1.settle(poolManager, callBackData.user, uint256(-delta1), false);
                }
                if (delta0 > 0) {
                    wrapperPoolKey.currency0.take(poolManager, address(this), uint256(delta0), true);
                    callBackData.token.transfer(callBackData.user, uint256(delta0));
                }
                if (delta1 > 0) wrapperPoolKey.currency1.take(poolManager, callBackData.user, uint256(delta1), false);
            } else {
                // currency0 is refCurrency and currency1 is ERC20Wrapper
                if (delta0 < 0) {
                    wrapperPoolKey.currency0.settle(poolManager, callBackData.user, uint256(-delta0), false);
                }

                if (delta1 < 0) {
                    wrapperPoolKey.currency1.settle(poolManager, address(this), uint256(-delta1), true);
                    callBackData.token.transferFrom(callBackData.user, address(this), uint256(-delta1));
                }

                if (delta0 > 0) wrapperPoolKey.currency0.take(poolManager, callBackData.user, uint256(delta0), false);
                if (delta1 > 0) {
                    wrapperPoolKey.currency1.take(poolManager, address(this), uint256(delta1), true);
                    callBackData.token.transfer(callBackData.user, uint256(delta1));
                }
            }

            // @dev : return abi.encode(delta)???
        }
    }
}
