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
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {ERC20RDEXWrapper, MAX_SUPPLY} from "./ERC20RDEXWrapper.sol";
import {Clones} from "@openzeppelin@v5.1.0/proxy/Clones.sol";
import {CurrencySettler} from "v4-core/test/utils/CurrencySettler.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {Constants} from "v4-core/test/utils/Constants.sol";

// TODO: Add OnlyPoolManager modifier to hook functions

/// @title RDEXHook
/// @notice This contract is a hook for managing dynamic fees and identity verification in a decentralized exchange.
contract RDEXHook is BaseHook, Ownable {
    /* ==================  TYPES =================== */
    using Clones for address;
    using CurrencySettler for Currency; // TODO: Do not use lib from v4-core but internal funcitons

    struct CallBackData {
        ERC20RDEXWrapper erc20WrapperToInitialize;
        address refCurrencyAddr;
        int24 tickSpacing;
        PoolId poolId;
        uint160 sqrtPriceX96;
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

    /* ==================== ERRORS ==================== */
    error NeitherTokenIsERC3643Compliant();
    error HookNotVerifiedByERC3643IdentityRegistry();
    error RefCurrencyClaimNotValid();
    error LiquidityMustBeAddedThroughHook();

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

    // TODO: May be not necessary
    // function modifyLiquidity(
    //     PoolKey memory key,
    //     IPoolManager.ModifyLiquidityParams memory params,
    //     bytes memory hookData
    // ) external payable returns (BalanceDelta delta) {}

    /// @notice Hook that is called before initializing a pool
    /// @param _key The pool key
    /// @return The selector for the beforeInitialize function
    function beforeInitialize(address, PoolKey calldata _key, uint160 sqrtPriceX96)
        external
        override
        returns (bytes4)
    {
        CallBackData memory callBackData;
        callBackData.tickSpacing = _key.tickSpacing;
        callBackData.poolId = _key.toId();
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
        callBackData.erc20WrapperToInitialize = ERC20RDEXWrapper(i_erc20WrapperImplementation.clone());
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
        callBackData.erc20WrapperToInitialize.initialize(ERC20RDEXWrapperName, ERC20RDEXWrapperSymbol, whitelist);

        // Continue initialization in the callback, _key.to
        poolManager.unlock(abi.encode(callBackData));

        // Save the ERC20RDEXWrapper clone instance in the instances mapping
        ERC3643ToERC20WrapperInstances[currency0IsERC3643
            ? Currency.unwrap(_key.currency0)
            : Currency.unwrap(_key.currency1)] = callBackData.erc20WrapperToInitialize;

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
            afterAddLiquidity: true,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: true,
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

    function _unlockCallback(bytes calldata data) internal override returns (bytes memory) {
        CallBackData memory callBackData = abi.decode(data, (CallBackData));

        // Wrapper pool Initialization
        if (address(callBackData.erc20WrapperToInitialize) != address(0)) {
            callBackData.erc20WrapperToInitialize.approve(address(poolManager), MAX_SUPPLY);
            // Mint  max suplly of claim tokens in the pool manager
            poolManager.mint(
                address(this), uint256(uint160(address(callBackData.erc20WrapperToInitialize))), MAX_SUPPLY
            );
            // Settle delta
            Currency currency = Currency.wrap(address(callBackData.erc20WrapperToInitialize));
            currency.settle(poolManager, address(this), MAX_SUPPLY, false);

            // Initialize the pool of the Wrapper against the reference currency this will be the real traded pool
            Currency _WCurrency0;
            Currency _WCurrency1;
            if (address(callBackData.erc20WrapperToInitialize) < callBackData.refCurrencyAddr) {
                _WCurrency0 = Currency.wrap(address(callBackData.erc20WrapperToInitialize));
                _WCurrency1 = Currency.wrap(callBackData.refCurrencyAddr);
            } else {
                _WCurrency0 = Currency.wrap(callBackData.refCurrencyAddr);
                _WCurrency1 = Currency.wrap(address(callBackData.erc20WrapperToInitialize));
            }
            // TODO:  check how to do dynamic fees, we cannot have a pool with dynamic fees without a hook
            PoolKey memory wrapperPoolKey = PoolKey(
                _WCurrency0,
                _WCurrency1,
                3000, /*LPFeeLibrary.DYNAMIC_FEE_FLAG*/
                callBackData.tickSpacing,
                IHooks(address(0))
            );
            poolManager.initialize(wrapperPoolKey, callBackData.sqrtPriceX96);
            poolIdToWrapperPoolKey[callBackData.poolId] = wrapperPoolKey;
        }
    }
}
