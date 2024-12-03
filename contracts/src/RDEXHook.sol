// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC165} from "@openzeppelin@v5.1.0/interfaces/IERC165.sol";
import {Ownable} from "@openzeppelin@v5.1.0/access/Ownable.sol";
import {Ownable} from "@openzeppelin@v5.1.0/access/Ownable.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IERC3643IdentityRegistry} from "./interfaces/ERC3643/IERC3643IdentityRegistry.sol";
import {IERC3643IdentityRegistryStorage} from "./interfaces/ERC3643/IERC3643IdentityRegistryStorage.sol";

contract RDEXHook is BaseHook, Ownable {
    // State Vars
    IERC3643IdentityRegistryStorage internal _identityRegistryStorage;
    uint256 internal _stablecoinClaimTopic;
    address internal _stablecoinClaimTrustedIssuer; // This can be modified to allow to set multiple trusted issuers that will asses that a token is a stablecoin

    // discountBasisPoints is a percentage of the fee that will be discounted 1 to 1000 1 is 0.001% and 1000 is 0.1%
    mapping(bytes32 claimId => uint16 discountBasisPoints) public s_dynamicFees;

    /* ==================== EVENTS ==================== */

    event IdentityRegistryStorageSet(address identityRegistryStorage);
    event RefCurrencyClaimTopicSet(uint256 stablecoinClaimTopic);
    event RefCurrencyClaimTrustedIssuerSet(address stablecoinClaimTrustedIssuer);

    /* ==================== ERRORS ==================== */
    error NeitherTokenIsERC3643Compliant();
    error HookNotVerifiedByIdentityRegistry();
    error RefCurrencyClaimNotValid();

    /* ==================== MODIFIERS ==================== */

    /* =================== CONSTRUCTOR =================== */

    /// @notice Constructor to initialize the RDEXHook contract
    /// @param _manager The address of the pool manager
    /// @param _owner The address of the owner
    constructor(
        IPoolManager _manager,
        address _owner
    ) BaseHook(_manager) Ownable(_owner) {}

    // External

    function beforeInitialize(address, PoolKey calldata key, uint160 sqrtPriceX96) external override returns (bytes4) {
        address currency0Addr = Currency.unwrap(key.currency0);
        address currency1Addr = Currency.unwrap(key.currency1);


        bool currency0IsERC3643 = false;
        bool currency1IsERC3643 = false;
        try IERC165(currency0Addr).supportsInterface(type(IERC3643).interfaceId) returns (bool isERC3643) {
            currency0IsERC3643 = isERC3643;
        } catch {}
        try IERC165(currency1Addr).supportsInterface(type(IERC3643).interfaceId) returns (bool isERC3643) {
            currency1IsERC3643 = isERC3643;
        } catch {}

        IIdentity identity;
        bytes memory sig;
        bytes memory data;

        if (IERC165(currency0Addr).supportsInterface(type(IERC3643).interfaceId)) {
            // Check if  address(this) is verified by the identity registry of currency 0
            IERC3643 token = IERC3643(currency0Addr);
            IERC3643IdentityRegistry identityRegistry = token
                .identityRegistry();
            if (!identityRegistry.isVerified(address(this)))
                revert HookNotVerifiedByIdentityRegistry();
            // Check if currency 1 is a verified stablecoin
            identity = IIdentity(_identityRegistryStorage.storedIdentity(currency1Addr));
            bytes32 claimId = keccak256(abi.encode(_stablecoinClaimTrustedIssuer, _stablecoinClaimTopic));
            (foundClaimTopic, scheme, issuer, sig, data,) = identity.getClaim(claimId);
        } else if (IERC165(currency1Addr).supportsInterface(type(IERC3643).interfaceId)) {
            // Check if  address(this) is verified by the identity registry of currency 1
            IERC3643 token = IERC3643(currency1Addr);
            IERC3643IdentityRegistry identityRegistry = token
                .identityRegistry();
            if (!identityRegistry.isVerified(address(this)))
                revert HookNotVerifiedByIdentityRegistry();
            // Check if currency 1 is a verified stablecoin
            identity = IIdentity(_identityRegistryStorage.storedIdentity(currency0Addr));
            bytes32 claimId = keccak256(abi.encode(_stablecoinClaimTrustedIssuer, _stablecoinClaimTopic));
            (foundClaimTopic, scheme, issuer, sig, data,) = identity.getClaim(claimId);
        } else {
            revert NeitherTokenIsERC3643Compliant();
        }

        if (!IClaimIssuer(issuer).isClaimValid(identity, _stablecoinClaimTopic, sig, data)) {
            revert StablecoinClaimNotValid();
        }

        return (IHooks.beforeInitialize.selector);
    }

    /// @notice Hook that is called before a swap
    /// @return The selector for the beforeSwap function, the delta, and the fee with flag
    function beforeSwap(
        address,
        PoolKey calldata,
        IPoolManager.SwapParams calldata,
        bytes calldata
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        uint24 fee = _calculateFee();
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

    function setStablecoinClaimTopic(uint256 __stablecoinClaimTopic) external onlyOwner {
        _stablecoinClaimTopic = __stablecoinClaimTopic;
        emit StablecoinClaimTopicSet(__stablecoinClaimTopic);
    }

    function setStablecoinClaimTrustedIssuer(address __stablecoinClaimTrustedIssuer) external onlyOwner {
        _stablecoinClaimTrustedIssuer = __stablecoinClaimTrustedIssuer;
        emit StablecoinClaimTrustedIssuerSet(__stablecoinClaimTrustedIssuer);
    }

    /// @notice Returns the identity registry storage
    /// @return The identity registry storage
    function getIdentityRegistryStorage()
        external
        view
        returns (IERC3643IdentityRegistryStorage)
    {
        return s_identityRegistryStorage;
    }

    function stablecoinClaimTopic() external view returns (uint256) {
        return _stablecoinClaimTopic;
    }

    function stablecoinClaimTrustedIssuer() external view returns (address) {
        return _stablecoinClaimTrustedIssuer;
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
    function _calculateFee() internal returns (uint24) {
        //1- Get claims from swapper
        //2- apply discounts according to the claims
        //3- calculate the fee
    }
    // Private
}
