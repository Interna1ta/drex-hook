// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {Ownable} from "@openzeppelin@v5.1.0/access/Ownable.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {IERC3643IdentityRegistryStorage} from "./interfaces/ERC3643/IERC3643IdentityRegistryStorage.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";

contract RDEXDynamicFeeHook is BaseHook, Ownable {
    using LPFeeLibrary for uint24;

    /* ==================== ERRORS ==================== */

    error RDEXDynamicFeeHook__FeeExeedTheLimit();
    error RDEXDynamicFeeHook__FeeHihgerThanBase();
    error RDEXDynamicFeeHook__InvalidReducedFeeClaim();

    /* ================== STATE VARS ================== */

    IERC3643IdentityRegistryStorage public s_identityRegistryStorage;
    uint256 public s_reducedFeeClaimTopic;
    address public s_reducedFeeClaimTrustedIssuer;
    uint24 public s_baseLPFee;

    /* ================== CONSTRUCTOR ================== */

    constructor(
        IPoolManager _manager,
        address _owner,
        IERC3643IdentityRegistryStorage _identityRegistryStorage,
        uint256 _reducedFeeClaimTopic,
        address _reducedFeeClaimTrustedIssuer,
        uint24 _baseLPFee
    ) BaseHook(_manager) Ownable(_owner) {
        s_identityRegistryStorage = _identityRegistryStorage;
        s_reducedFeeClaimTopic = _reducedFeeClaimTopic;
        s_reducedFeeClaimTrustedIssuer = _reducedFeeClaimTrustedIssuer;
        if (_baseLPFee > LPFeeLibrary.MAX_LP_FEE) revert RDEXDynamicFeeHook__FeeExeedTheLimit();
        s_baseLPFee = _baseLPFee;
    }

    /* ==================== EXTERNAL ==================== */

    /// @notice Sets the base liquidity provider fee
    /// @dev This function can only be called by the contract owner
    /// @param _baseLPFee The new base liquidity provider fee
    function setBaseLPFee(uint24 _baseLPFee) external onlyOwner {
        if (_baseLPFee > LPFeeLibrary.MAX_LP_FEE) revert RDEXDynamicFeeHook__FeeExeedTheLimit();
        s_baseLPFee = _baseLPFee;
    }

    /// @notice Sets the identity registry storage contract
    /// @dev This function can only be called by the contract owner
    /// @param _identityRegistryStorage The address of the new identity registry storage contract
    function setIdentityRegistryStorage(IERC3643IdentityRegistryStorage _identityRegistryStorage) external onlyOwner {
        s_identityRegistryStorage = _identityRegistryStorage;
    }

    /// @notice Sets the reduced fee topic
    /// @dev Only the owner can call this function
    /// @param _reducedFeeClaimTopic The new reduced fee topic to be set
    function setReducedFeeClaimTopic(uint16 _reducedFeeClaimTopic) external onlyOwner {
        s_reducedFeeClaimTopic = _reducedFeeClaimTopic;
    }

    /// @notice Sets the trusted issuer for the reduced fee claim topic
    /// @dev This function can only be called by the contract owner
    /// @param _reducedFeeClaimTrustedIssuer The new trusted issuer for the reduced fee claim topic
    function setReducedFeeClaimTopicTrustedIssuer(address _reducedFeeClaimTrustedIssuer) external onlyOwner {
        s_reducedFeeClaimTrustedIssuer = _reducedFeeClaimTrustedIssuer;
    }

    /// @inheritdoc IHooks
    function afterInitialize(address, PoolKey calldata _key, uint160, int24) external override returns (bytes4) {
        poolManager.updateDynamicLPFee(_key, s_baseLPFee);
        return (IHooks.afterInitialize.selector);
    }

    /// @inheritdoc IHooks
    function beforeSwap(address, PoolKey calldata _key, IPoolManager.SwapParams calldata, bytes calldata _hookData)
        external
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        (bool isReducedFee, address user) = abi.decode(_hookData, (bool, address));
        uint24 fee = 0;
        if (isReducedFee) {
            fee = _calculateFee(user) | LPFeeLibrary.OVERRIDE_FEE_FLAG;
        }

        return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, fee);
    }

    /* ==================== PUBLIC ==================== */

    /// @inheritdoc BaseHook
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: true,
            beforeAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterAddLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
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

    function _calculateFee(address _user) internal view returns (uint24) {
        IIdentity identity = IIdentity(s_identityRegistryStorage.storedIdentity(_user));
        bytes32 claimId = keccak256(abi.encode(s_reducedFeeClaimTrustedIssuer, s_reducedFeeClaimTopic));

        (,,, bytes memory sig, bytes memory data,) = identity.getClaim(claimId);
        if (!IClaimIssuer(s_reducedFeeClaimTrustedIssuer).isClaimValid(identity, s_reducedFeeClaimTopic, sig, data)) {
            revert RDEXDynamicFeeHook__InvalidReducedFeeClaim();
        }
        uint24 fee = uint24(abi.decode(data, (uint16)));
        if (fee >= s_baseLPFee) revert RDEXDynamicFeeHook__FeeHihgerThanBase();

        return fee;
    }
}
