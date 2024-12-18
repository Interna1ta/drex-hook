// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC165} from "@openzeppelin@v5.1.0/interfaces/IERC165.sol";
import {Ownable} from "@openzeppelin@v5.1.0/access/Ownable.sol";
import {Clones} from "@openzeppelin@v5.1.0/proxy/Clones.sol";
import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {Pool} from "v4-core/src/libraries/Pool.sol";
import {PoolId} from "v4-core/src/types/PoolId.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {CurrencySettler} from "v4-core/test/utils/CurrencySettler.sol";
import {Constants} from "v4-core/test/utils/Constants.sol";
import {Position} from "v4-core/src/libraries/Position.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";

import {ERC20RDEXWrapper, MAX_SUPPLY} from "./ERC20RDEXWrapper.sol";
import {IERC3643IdentityRegistryStorage} from "./interfaces/ERC3643/IERC3643IdentityRegistryStorage.sol";
import {IERC3643IdentityRegistry} from "./interfaces/ERC3643/IERC3643IdentityRegistry.sol";
import {IERC3643} from "./interfaces/ERC3643/IERC3643.sol";

/// @title RDEXHook
/// @notice This Hook allows to create and operate markets with ERC3643 tokens with built-in compliance in combination with ONCHAINID
contract RDEXHook is BaseHook, Ownable {
    using Clones for address;
    using CurrencySettler for Currency;

    /* ==================== ERRORS ==================== */

    error RDEXHook__NeitherTokenIsERC3643Compliant();
    error RDEXHook__HookNotVerifiedByERC3643IdentityRegistry();
    error RDEXHook__RefCurrencyClaimNotValid();
    error RDEXHook__ERC3643DoNotHaveERC20Wrapper();

    /* ==================== TYPES ===================== */

    struct CallBackData {
        bool initializePool;
        bool modifyLiquidity;
        bool swap;
        IERC3643 token;
        ERC20RDEXWrapper erc20Wrapper;
        PoolKey poolKey;
        address user;
        address refCurrencyAddr;
        uint160 sqrtPriceX96;
        IPoolManager.ModifyLiquidityParams modifyLiquidityParams;
        IPoolManager.SwapParams swapParams;
        bool isReducedFee;
    }

    /* ================== STATE VARS ================== */

    IERC3643IdentityRegistryStorage public s_identityRegistryStorage;
    uint256 public s_refCurrencyClaimTopic;
    address public s_refCurrencyClaimTrustedIssuer; // @dev: This can be modified to allow to set multiple trusted issuers that will asses that a token is a refCurrency

    IHooks public immutable i_dynamicFeeHook;

    address public immutable i_erc20WrapperImplementation;
    mapping(address ERC3643 => ERC20RDEXWrapper) public s_ERC3643ToERC20WrapperInstances;
    mapping(PoolId => PoolKey) public s_poolIdToWrapperPoolKey;

    /* ==================== EVENTS ==================== */

    event IdentityRegistryStorageSet(address identityRegistryStorage);
    event RefCurrencyClaimTopicSet(uint256 refCurrencyClaimTopic);
    event RefCurrencyClaimTrustedIssuerSet(address refCurrencyClaimTrustedIssuer);
    event RDEXModifyLiquidity(
        PoolId indexed id, address indexed sender, int24 tickLower, int24 tickUpper, int256 liquidityDelta, bytes32 salt
    );
    event RDEXSwap(PoolId indexed id, address indexed sender, int128 amount0, int128 amount1);

    /* ================== CONSTRUCTOR ================== */

    /// @notice Constructor to initialize the RDEXHook contract
    /// @param _manager The address of the pool manager
    /// @param _owner The address of the owner
    /// @param _identityRegistryStorage The address of the identity registry storage
    /// @param _refCurrencyClaimTopic The reference currency claim topic
    /// @param _refCurrencyClaimTrustedIssuer The address of the trusted issuer for the reference currency claim
    constructor(
        IPoolManager _manager,
        address _owner,
        IERC3643IdentityRegistryStorage _identityRegistryStorage,
        uint256 _refCurrencyClaimTopic,
        address _refCurrencyClaimTrustedIssuer,
        IHooks _dynamicFeeHook
    ) BaseHook(_manager) Ownable(_owner) {
        s_identityRegistryStorage = _identityRegistryStorage;
        s_refCurrencyClaimTopic = _refCurrencyClaimTopic;
        s_refCurrencyClaimTrustedIssuer = _refCurrencyClaimTrustedIssuer;

        i_dynamicFeeHook = _dynamicFeeHook;

        // Deploy implementation  for ERC20Wrapper clones
        i_erc20WrapperImplementation = address(new ERC20RDEXWrapper());
    }

    /* ==================== EXTERNAL ==================== */

    /// @notice Modify the liquidity for the given pool
    /// @dev The liquidity is not added to the pool but to the Wrapper pool
    /// @param _key The key of the pool for which liquidity is being modified
    /// @param _params Parameters for modifying liquidity, including amounts and directions
    function modifyLiquidity(PoolKey memory _key, IPoolManager.ModifyLiquidityParams memory _params, bytes memory)
        external
        payable
    {
        CallBackData memory callBackData;
        callBackData.modifyLiquidity = true;
        callBackData.poolKey = _key;
        callBackData.user = msg.sender;
        callBackData.modifyLiquidityParams = _params;

        if (address(s_ERC3643ToERC20WrapperInstances[Currency.unwrap(_key.currency0)]) != address(0)) {
            callBackData.token = IERC3643(Currency.unwrap(_key.currency0));
            callBackData.erc20Wrapper = s_ERC3643ToERC20WrapperInstances[Currency.unwrap(_key.currency0)];
            callBackData.refCurrencyAddr = Currency.unwrap(_key.currency1);
        } else if (address(s_ERC3643ToERC20WrapperInstances[Currency.unwrap(_key.currency1)]) != address(0)) {
            callBackData.token = IERC3643(Currency.unwrap(_key.currency1));
            callBackData.erc20Wrapper = s_ERC3643ToERC20WrapperInstances[Currency.unwrap(_key.currency1)];
            callBackData.refCurrencyAddr = Currency.unwrap(_key.currency0);
        } else {
            revert RDEXHook__ERC3643DoNotHaveERC20Wrapper();
        }

        poolManager.unlock(abi.encode(callBackData));

        emit RDEXModifyLiquidity(
            _key.toId(), msg.sender, _params.tickLower, _params.tickUpper, _params.liquidityDelta, _params.salt
        );
    }

    /// @notice Swap against the given pool
    /// @dev The given pool is a dummy one; the actual swap occurs in the Wrapper pool.
    /// @param _key The key identifying the pool against which the swap is executed.
    /// @param _params Parameters defining the swap details such as amount, direction, and other specifics.
    /// @param _isReducedFee Indicates whether the swap is subject to reduced fees.
    function swap(PoolKey memory _key, IPoolManager.SwapParams memory _params, bool _isReducedFee) external payable {
        CallBackData memory callBackData;
        callBackData.swap = true;
        callBackData.poolKey = _key;
        callBackData.user = msg.sender;
        callBackData.swapParams = _params;
        callBackData.isReducedFee = _isReducedFee;

        if (address(s_ERC3643ToERC20WrapperInstances[Currency.unwrap(_key.currency0)]) != address(0)) {
            callBackData.token = IERC3643(Currency.unwrap(_key.currency0));
            callBackData.erc20Wrapper = s_ERC3643ToERC20WrapperInstances[Currency.unwrap(_key.currency0)];
            callBackData.refCurrencyAddr = Currency.unwrap(_key.currency1);
        } else if (address(s_ERC3643ToERC20WrapperInstances[Currency.unwrap(_key.currency1)]) != address(0)) {
            callBackData.token = IERC3643(Currency.unwrap(_key.currency1));
            callBackData.erc20Wrapper = s_ERC3643ToERC20WrapperInstances[Currency.unwrap(_key.currency1)];
            callBackData.refCurrencyAddr = Currency.unwrap(_key.currency0);
        } else {
            revert RDEXHook__ERC3643DoNotHaveERC20Wrapper();
        }

        BalanceDelta delta = abi.decode(poolManager.unlock(abi.encode(callBackData)), (BalanceDelta));

        emit RDEXSwap(_key.toId(), msg.sender, delta.amount0(), delta.amount1());
    }

    /// @inheritdoc IHooks
    function beforeInitialize(address, PoolKey calldata _key, uint160 _sqrtPriceX96)
        external
        override
        onlyPoolManager
        returns (bytes4)
    {
        CallBackData memory callBackData;
        callBackData.initializePool = true;
        callBackData.poolKey = _key;
        callBackData.sqrtPriceX96 = _sqrtPriceX96;

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
        // @dev: Problem here? it is possible that a ref currently to be an ERC3643? if not is ok. IMO ref currency will be stableoin or ETH so no.
        if (currency0IsERC3643) {
            // Check if  address(this) is verified by the identity registry of currency 0
            IERC3643 token = IERC3643(Currency.unwrap(_key.currency0));
            IERC3643IdentityRegistry identityRegistry = token.identityRegistry();
            if (!identityRegistry.isVerified(address(this))) {
                revert RDEXHook__HookNotVerifiedByERC3643IdentityRegistry();
            }
            // Check if currency 1 is a verified refCurrency
            callBackData.refCurrencyAddr = Currency.unwrap(_key.currency1);
            identity = IIdentity(s_identityRegistryStorage.storedIdentity(callBackData.refCurrencyAddr));
            bytes32 claimId = keccak256(abi.encode(s_refCurrencyClaimTrustedIssuer, s_refCurrencyClaimTopic));
            (,,, sig, data,) = identity.getClaim(claimId);
        } else if (currency1IsERC3643) {
            // Check if  address(this) is verified by the identity registry of currency 1
            IERC3643 token = IERC3643(Currency.unwrap(_key.currency1));
            IERC3643IdentityRegistry identityRegistry = token.identityRegistry();
            if (!identityRegistry.isVerified(address(this))) {
                revert RDEXHook__HookNotVerifiedByERC3643IdentityRegistry();
            }
            // Check if currency 1 is a verified refCurrency
            callBackData.refCurrencyAddr = Currency.unwrap(_key.currency0);
            identity = IIdentity(s_identityRegistryStorage.storedIdentity(callBackData.refCurrencyAddr));
            bytes32 claimId = keccak256(abi.encode(s_refCurrencyClaimTrustedIssuer, s_refCurrencyClaimTopic));
            (,,, sig, data,) = identity.getClaim(claimId);
        } else {
            revert RDEXHook__NeitherTokenIsERC3643Compliant();
        }

        if (!IClaimIssuer(s_refCurrencyClaimTrustedIssuer).isClaimValid(identity, s_refCurrencyClaimTopic, sig, data)) {
            revert RDEXHook__RefCurrencyClaimNotValid();
        }

        // Deploy  ERC20RDEXWrapper clone for the ERC3643 token
        // @dev: To simplify the code we can use create2 to mint the wrapper with an address that keeps the address sorted so that we don't have to sort them with on-chain computation
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
        s_ERC3643ToERC20WrapperInstances[currency0IsERC3643
            ? Currency.unwrap(_key.currency0)
            : Currency.unwrap(_key.currency1)] = callBackData.erc20Wrapper;

        return (IHooks.beforeInitialize.selector);
    }

    /// @notice Sets the identity registry storage
    /// @dev This function can only be called by the contract owner
    /// @param _identityRegistryStorage The address of the identity registry storage
    function setIdentityRegistryStorage(address _identityRegistryStorage) external onlyOwner {
        s_identityRegistryStorage = IERC3643IdentityRegistryStorage(_identityRegistryStorage);
        emit IdentityRegistryStorageSet(_identityRegistryStorage);
    }

    /// @notice Sets the refCurrency claim topic
    /// @dev This function can only be called by the contract owner
    /// @param _refCurrencyClaimTopic The refCurrency claim topic
    function setRefCurrencyClaimTopic(uint256 _refCurrencyClaimTopic) external onlyOwner {
        s_refCurrencyClaimTopic = _refCurrencyClaimTopic;
        emit RefCurrencyClaimTopicSet(_refCurrencyClaimTopic);
    }

    /// @notice Sets the trusted issuer for the reference currency claim
    /// @dev This function can only be called by the contract owner
    /// @param _refCurrencyClaimTrustedIssuer The address of the new trusted issuer for the reference currency claim
    function setRefCurrencyClaimTrustedIssuer(address _refCurrencyClaimTrustedIssuer) external onlyOwner {
        s_refCurrencyClaimTrustedIssuer = _refCurrencyClaimTrustedIssuer;
        emit RefCurrencyClaimTrustedIssuerSet(_refCurrencyClaimTrustedIssuer);
    }

    /// @notice Retrieves the position information of a pool without needing to calculate the `positionId`.
    /// @dev The position info is retrived from the Wrapper pool, the salt is keccak256(msg.sender,_salt)
    /// @param _poolId The ID of the pool.
    /// @param _owner The owner of the liquidity position.
    /// @param _tickLower The lower tick of the liquidity range.
    /// @param _tickUpper The upper tick of the liquidity range.
    /// @param _salt The bytes32 randomness to further distinguish position state.
    /// @return liquidity The liquidity of the position.
    /// @return feeGrowthInside0LastX128 The fee growth inside the position for token0.
    /// @return feeGrowthInside1LastX128 The fee growth inside the position for token1.
    function getPositionInfo(PoolId _poolId, address _owner, int24 _tickLower, int24 _tickUpper, bytes32 _salt)
        external
        view
        returns (uint128 liquidity, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128)
    {
        bytes32 salt = keccak256(abi.encodePacked(_owner, _salt));
        bytes32 positionKey = Position.calculatePositionKey(address(this), _tickLower, _tickUpper, salt);

        (liquidity, feeGrowthInside0LastX128, feeGrowthInside1LastX128) =
            StateLibrary.getPositionInfo(poolManager, s_poolIdToWrapperPoolKey[_poolId].toId(), positionKey);
    }

    /* ==================== PUBLIC ==================== */

    /// @inheritdoc BaseHook
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

    function _unlockCallback(bytes calldata _data) internal override returns (bytes memory) {
        CallBackData memory callBackData = abi.decode(_data, (CallBackData));

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
            PoolKey memory wrapperPoolKey = PoolKey(
                _WCurrency0,
                _WCurrency1,
                LPFeeLibrary.DYNAMIC_FEE_FLAG,
                callBackData.poolKey.tickSpacing,
                i_dynamicFeeHook
            );
            poolManager.initialize(wrapperPoolKey, callBackData.sqrtPriceX96);
            s_poolIdToWrapperPoolKey[callBackData.poolKey.toId()] = wrapperPoolKey;
            return "";
        } else if (callBackData.modifyLiquidity) {
            // Compute wrapped liquidity position
            IPoolManager.ModifyLiquidityParams memory params = callBackData.modifyLiquidityParams;
            params.tickLower = callBackData.modifyLiquidityParams.tickLower;
            params.tickUpper = callBackData.modifyLiquidityParams.tickUpper;
            params.liquidityDelta = callBackData.modifyLiquidityParams.liquidityDelta;
            params.salt = keccak256(abi.encodePacked(callBackData.user, callBackData.modifyLiquidityParams.salt));

            // Modify liquidity
            PoolKey memory wrapperPoolKey = s_poolIdToWrapperPoolKey[callBackData.poolKey.toId()];
            (BalanceDelta delta,) = poolManager.modifyLiquidity(wrapperPoolKey, params, "");

            // Settle delta
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
            return "";
        } else if (callBackData.swap) {
            // Swap
            PoolKey memory wrapperPoolKey = s_poolIdToWrapperPoolKey[callBackData.poolKey.toId()];
            BalanceDelta delta = poolManager.swap(
                wrapperPoolKey, callBackData.swapParams, abi.encode(callBackData.isReducedFee, callBackData.user)
            );
            // Settle delta
            if (
                Currency.unwrap(wrapperPoolKey.currency0) == address(callBackData.erc20Wrapper)
                    && Currency.unwrap(wrapperPoolKey.currency1) == callBackData.refCurrencyAddr
            ) {
                //  currency0 is ERC20Wrapper and currency1 is refCurrency
                if (callBackData.swapParams.zeroForOne) {
                    wrapperPoolKey.currency0.settle(poolManager, address(this), uint256(int256(-delta.amount0())), true);
                    callBackData.token.transferFrom(callBackData.user, address(this), uint256(int256(-delta.amount0())));
                    wrapperPoolKey.currency1.take(
                        poolManager, callBackData.user, uint256(int256(delta.amount1())), false
                    );
                } else {
                    wrapperPoolKey.currency1.settle(
                        poolManager, callBackData.user, uint256(int256(-delta.amount1())), false
                    );
                    wrapperPoolKey.currency0.take(poolManager, address(this), uint256(int256(delta.amount0())), true);
                    callBackData.token.transfer(callBackData.user, uint256(int256(delta.amount0())));
                }
            } else {
                // currency0 is refCurrency and currency1 is ERC20Wrapper
                if (callBackData.swapParams.zeroForOne) {
                    wrapperPoolKey.currency0.settle(
                        poolManager, callBackData.user, uint256(int256(-delta.amount0())), false
                    );
                    wrapperPoolKey.currency1.take(poolManager, address(this), uint256(int256(delta.amount1())), true);
                    callBackData.token.transfer(callBackData.user, uint256(int256(delta.amount1())));
                } else {
                    wrapperPoolKey.currency1.settle(poolManager, address(this), uint256(int256(-delta.amount1())), true);
                    callBackData.token.transferFrom(callBackData.user, address(this), uint256(int256(-delta.amount1())));
                    wrapperPoolKey.currency0.take(
                        poolManager, callBackData.user, uint256(int256(delta.amount0())), false
                    );
                }
            }
            return abi.encode(delta);
        }
        return "";
    }

    function _sortCurrencies(address _currencyAAddr, address _currencyBAddr)
        internal
        pure
        returns (Currency currency0, Currency currency1)
    {
        /// @dev: if we use create2 to mint the wrappers to enforce the address order we can remove this function
        if (_currencyAAddr < _currencyBAddr) {
            currency0 = Currency.wrap(_currencyAAddr);
            currency1 = Currency.wrap(_currencyBAddr);
        } else {
            currency0 = Currency.wrap(_currencyBAddr);
            currency1 = Currency.wrap(_currencyAAddr);
        }
    }
}
