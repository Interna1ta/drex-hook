// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";
import {IERC165} from "@openzeppelin@v5.1.0/interfaces/IERC165.sol";
import {IERC3643} from "./interfaces/ERC3643/IERC3643.sol";
import {IERC3643IdentityRegistry} from "./interfaces/ERC3643/IERC3643IdentityRegistry.sol";
import {IERC3643IdentityRegistryStorage} from "./interfaces/ERC3643/IERC3643IdentityRegistryStorage.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Ownable} from "@openzeppelin@v5.1.0/access/Ownable.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";

contract RDEXHook is BaseHook, Ownable {
    // State Vars
    IERC3643IdentityRegistryStorage internal _identityRegistryStorage;
    uint256 internal _stablecoinClaimTopic;
    address internal _stablecoinClaimTrustedIssuer; // This can be modified to allow to set multiple trusted issuers that will asses that a token is a stablecoin

    // Events
    event IdentityRegistryStorageSet(address identityRegistryStorage);
    event StablecoinClaimTopicSet(uint256 stablecoinClaimTopic);
    event StablecoinClaimTrustedIssuerSet(address stablecoinClaimTrustedIssuer);

    // Errors
    error NeitherTokenIsERC3643Compliant();
    error HookNotVerifiedByIdentityRegistry();
    error StablecoinClaimNotValid();

    // Modifiers

    constructor(IPoolManager _manager, address _owner) BaseHook(_manager) Ownable(_owner) {}

    // External

    function beforeInitialize(address, PoolKey calldata key, uint160 sqrtPriceX96) external override returns (bytes4) {
        address currency0Addr = Currency.unwrap(key.currency0);
        address currency1Addr = Currency.unwrap(key.currency1);

        IIdentity identity;
        uint256 foundClaimTopic;
        uint256 scheme;
        address issuer;
        bytes memory sig;
        bytes memory data;

        if (IERC165(currency0Addr).supportsInterface(type(IERC3643).interfaceId)) {
            // Check if  address(this) is verified by the identity registry of currency 0
            IERC3643 token = IERC3643(currency0Addr);
            IERC3643IdentityRegistry identityRegistry = token.identityRegistry();
            if (!identityRegistry.isVerified(address(this))) revert HookNotVerifiedByIdentityRegistry();
            // Check if currency 1 is a verified stablecoin
            identity = IIdentity(_identityRegistryStorage.storedIdentity(currency1Addr));
            bytes32 claimId = keccak256(abi.encode(_stablecoinClaimTrustedIssuer, _stablecoinClaimTopic));
            (foundClaimTopic, scheme, issuer, sig, data,) = identity.getClaim(claimId);
        } else if (IERC165(currency1Addr).supportsInterface(type(IERC3643).interfaceId)) {
            // Check if  address(this) is verified by the identity registry of currency 1
            IERC3643 token = IERC3643(currency1Addr);
            IERC3643IdentityRegistry identityRegistry = token.identityRegistry();
            if (!identityRegistry.isVerified(address(this))) revert HookNotVerifiedByIdentityRegistry();
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

        // emit event
        // TODO: Emit new PoolEvent
        return (IHooks.beforeInitialize.selector);
    }

    function setIdentityRegistryStorage(address __identityRegistryStorage) external onlyOwner {
        _identityRegistryStorage = IERC3643IdentityRegistryStorage(__identityRegistryStorage);
        emit IdentityRegistryStorageSet(__identityRegistryStorage);
    }

    function setStablecoinClaimTopic(uint256 __stablecoinClaimTopic) external onlyOwner {
        _stablecoinClaimTopic = __stablecoinClaimTopic;
        emit StablecoinClaimTopicSet(__stablecoinClaimTopic);
    }

    function setStablecoinClaimTrustedIssuer(address __stablecoinClaimTrustedIssuer) external onlyOwner {
        _stablecoinClaimTrustedIssuer = __stablecoinClaimTrustedIssuer;
        emit StablecoinClaimTrustedIssuerSet(__stablecoinClaimTrustedIssuer);
    }

    function identityRegistryStorage() external view returns (IERC3643IdentityRegistryStorage) {
        return _identityRegistryStorage;
    }

    function stablecoinClaimTopic() external view returns (uint256) {
        return _stablecoinClaimTopic;
    }

    function stablecoinClaimTrustedIssuer() external view returns (address) {
        return _stablecoinClaimTrustedIssuer;
    }

    // Public

    // TODO: Define permissions
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

    // Internal

    // Private
}
