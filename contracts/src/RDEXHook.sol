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
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IERC3643IdentityRegistry} from "./interfaces/ERC3643/IERC3643IdentityRegistry.sol";
import {IERC3643IdentityRegistryStorage} from "./interfaces/ERC3643/IERC3643IdentityRegistryStorage.sol";
import {IERC3643} from "./interfaces/ERC3643/IERC3643.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";

/// @title RDEXHook
/// @notice This contract is a hook for managing dynamic fees and identity verification in a decentralized exchange.
contract RDEXHook is BaseHook, Ownable {
    /* ================== STATE VARS =================== */

    IERC3643IdentityRegistryStorage internal s_identityRegistryStorage;
    uint256 internal s_refCurrencyClaimTopic;
    address internal s_refCurrencyClaimTrustedIssuer; // This can be modified to allow to set multiple trusted issuers that will asses that a token is a refCurrency

    uint256 internal constant BASE_FEE = 10_000; // 1%

    uint24 internal immutable i_minimumFee;

    // discountBasisPoints is a percentage of the fee that will be discounted 1 to 1000 1 is 0.001% and 1000 is 0.1%
    mapping(uint256 claimTopic => uint16 discountBasisPoints)
        internal s_topicToDiscount;

    uint256[] internal s_topicsWithDiscount;

    /* ==================== EVENTS ==================== */

    event IdentityRegistryStorageSet(address identityRegistryStorage);
    event RefCurrencyClaimTopicSet(uint256 refCurrencyClaimTopic);
    event RefCurrencyClaimTrustedIssuerSet(
        address refCurrencyClaimTrustedIssuer
    );

    /* ==================== ERRORS ==================== */
    error NeitherTokenIsERC3643Compliant();
    error HookNotVerifiedByERC3643IdentityRegistry();
    error RefCurrencyClaimNotValid();

    /* ==================== MODIFIERS ==================== */

    /* =================== CONSTRUCTOR =================== */

    /// @notice Constructor to initialize the RDEXHook contract
    /// @param _manager The address of the pool manager
    /// @param _owner The address of the owner
    // TODO: Initiailize ALL storage variables
    constructor(
        IPoolManager _manager,
        address _owner,
        uint24 _minimumFee
    ) BaseHook(_manager) Ownable(_owner) {
        i_minimumFee = _minimumFee;
    }

    /* ==================== EXTERNAL ==================== */

    /// @notice Hook that is called before initializing a pool
    /// @param _key The pool key
    /// @return The selector for the beforeInitialize function
    function beforeInitialize(
        address,
        PoolKey calldata _key,
        uint160
    ) external view override returns (bytes4) {
        address currency0Addr = Currency.unwrap(_key.currency0);
        address currency1Addr = Currency.unwrap(_key.currency1);

        bool currency0IsERC3643 = false;
        bool currency1IsERC3643 = false;
        try
            IERC165(currency0Addr).supportsInterface(type(IERC3643).interfaceId)
        returns (bool isERC3643) {
            currency0IsERC3643 = isERC3643;
        } catch {}
        try
            IERC165(currency1Addr).supportsInterface(type(IERC3643).interfaceId)
        returns (bool isERC3643) {
            currency1IsERC3643 = isERC3643;
        } catch {}

        IIdentity identity;
        bytes memory sig;
        bytes memory data;
        // @dev: Problem here? it is possible that a ref currenty to be an ERC3643? if not is ok. IMO ref currency will be stableoin or ETH so no.
        if (currency0IsERC3643) {
            // Check if  address(this) is verified by the identity registry of currency 0
            IERC3643 token = IERC3643(currency0Addr);
            IERC3643IdentityRegistry identityRegistry = token
                .identityRegistry();
            if (!identityRegistry.isVerified(address(this)))
                revert HookNotVerifiedByERC3643IdentityRegistry();
            // Check if currency 1 is a verified refCurrency
            identity = IIdentity(
                s_identityRegistryStorage.storedIdentity(currency1Addr)
            );
            bytes32 claimId = keccak256(
                abi.encode(
                    s_refCurrencyClaimTrustedIssuer,
                    s_refCurrencyClaimTopic
                )
            );
            (, , , sig, data, ) = identity.getClaim(claimId);
        } else if (currency1IsERC3643) {
            // Check if  address(this) is verified by the identity registry of currency 1
            IERC3643 token = IERC3643(currency1Addr);
            IERC3643IdentityRegistry identityRegistry = token
                .identityRegistry();
            if (!identityRegistry.isVerified(address(this)))
                revert HookNotVerifiedByERC3643IdentityRegistry();
            // Check if currency 1 is a verified refCurrency
            identity = IIdentity(
                s_identityRegistryStorage.storedIdentity(currency0Addr)
            );
            bytes32 claimId = keccak256(
                abi.encode(
                    s_refCurrencyClaimTrustedIssuer,
                    s_refCurrencyClaimTopic
                )
            );
            (, , , sig, data, ) = identity.getClaim(claimId);
        } else {
            revert NeitherTokenIsERC3643Compliant();
        }

        if (
            !IClaimIssuer(s_refCurrencyClaimTrustedIssuer).isClaimValid(
                identity,
                s_refCurrencyClaimTopic,
                sig,
                data
            )
        ) {
            revert RefCurrencyClaimNotValid();
        }

        return (IHooks.beforeInitialize.selector);
    }

    /// @notice Hook that is called before a swap
    /// @return The selector for the beforeSwap function, the delta, and the fee with flag
    function beforeSwap(
        address _sender,
        PoolKey calldata,
        IPoolManager.SwapParams calldata,
        bytes calldata
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        uint24 fee = _calculateFee(_sender);
        // poolManager.updateDynamicLPFee(_key, fee);
        uint24 feeWithFlag = fee | LPFeeLibrary.OVERRIDE_FEE_FLAG;

        return (
            BaseHook.beforeSwap.selector,
            BeforeSwapDeltaLibrary.ZERO_DELTA,
            feeWithFlag
        );
    }

    /// @notice Sets the identity registry storage
    /// @param _identityRegistryStorage The address of the identity registry storage
    function setIdentityRegistryStorage(
        address _identityRegistryStorage
    ) external onlyOwner {
        s_identityRegistryStorage = IERC3643IdentityRegistryStorage(
            _identityRegistryStorage
        );
        emit IdentityRegistryStorageSet(_identityRegistryStorage);
    }

    /// @notice Sets the refCurrency claim topic
    /// @param _refCurrencyClaimTopic The refCurrency claim topic
    function setRefCurrencyClaimTopic(
        uint256 _refCurrencyClaimTopic
    ) external onlyOwner {
        s_refCurrencyClaimTopic = _refCurrencyClaimTopic;
        emit RefCurrencyClaimTopicSet(_refCurrencyClaimTopic);
    }

    /// @notice Sets the refCurrency claim trusted issuer
    /// @param _refCurrencyClaimTrustedIssuer The address of the refCurrency claim trusted issuer
    function setRefCurrencyClaimTrustedIssuer(
        address _refCurrencyClaimTrustedIssuer
    ) external onlyOwner {
        s_refCurrencyClaimTrustedIssuer = _refCurrencyClaimTrustedIssuer;
        emit RefCurrencyClaimTrustedIssuerSet(_refCurrencyClaimTrustedIssuer);
    }

    function setDynamicFee(
        uint256 _topic,
        uint16 _discountBasisPoints
    ) external onlyOwner {
        s_topicToDiscount[_topic] = _discountBasisPoints;
    }

    function setTopicsWithDiscount(
        uint256[] calldata _topicsWithDiscount
    ) external onlyOwner {
        s_topicsWithDiscount = _topicsWithDiscount;
    }

    // TODO: Explore if we need this getters or we can direclty use public variables
    function topicsWithDiscount() external view returns (uint256[] memory) {
        return s_topicsWithDiscount;
    }

    function dynamicFee(uint256 _topic) external view returns (uint16) {
        return s_topicToDiscount[_topic];
    }

    /// @notice Returns the identity registry storage
    /// @return The identity registry storage
    function identityRegistryStorage()
        external
        view
        returns (IERC3643IdentityRegistryStorage)
    {
        return s_identityRegistryStorage;
    }

    /// @notice Returns the refCurrency claim topic
    /// @return The refCurrency claim topic
    function refCurrencyClaimTopic() external view returns (uint256) {
        return s_refCurrencyClaimTopic;
    }

    /// @notice Returns the refCurrency claim trusted issuer
    /// @return The refCurrency claim trusted issuer
    function refCurrencyClaimTrustedIssuer() external view returns (address) {
        return s_refCurrencyClaimTrustedIssuer;
    }

    /* ==================== PUBLIC ==================== */

    // TODO: Define permissions
    /// @notice Returns the hook permissions
    /// @return The hook permissions
    function getHookPermissions()
        public
        pure
        override
        returns (Hooks.Permissions memory)
    {
        return
            Hooks.Permissions({
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
        //TODO: find way to let user say which topics it wants to be checked for discount during swap
        //TODO: find way to test that discounts actually get applied
        uint256 discountedFee = BASE_FEE;

        for (uint256 i = 0; i < s_topicsWithDiscount.length; i++) {
            uint256 topic = s_topicsWithDiscount[i];
            uint256 discountBasisPoints = s_topicToDiscount[topic];
            IIdentity identity = IIdentity(
                s_identityRegistryStorage.storedIdentity(_sender)
            );
            bytes32 claimId = keccak256(
                abi.encode(s_refCurrencyClaimTrustedIssuer, topic)
            );

            (, , , bytes memory sig, bytes memory data, ) = identity.getClaim(
                claimId
            );
            if (
                IClaimIssuer(s_refCurrencyClaimTrustedIssuer).isClaimValid(
                    identity,
                    s_topicsWithDiscount[i],
                    sig,
                    data
                )
            ) {
                unchecked {
                    discountedFee = discountedFee - discountBasisPoints;
                }

                if (discountedFee < i_minimumFee) {
                    return i_minimumFee;
                }
            }
        }
    }
    // Private
}
