// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IERC3643IdentityRegistryStorage} from "./IERC3643IdentityRegistryStorage.sol";
import {IERC3643TrustedIssuersRegistry} from "./IERC3643TrustedIssuersRegistry.sol";
import {IERC3643ClaimTopicsRegistry} from "./IERC3643ClaimTopicsRegistry.sol";

event ClaimTopicsRegistrySet(address indexed _claimTopicsRegistry);

event IdentityStorageSet(address indexed _identityStorage);

event TrustedIssuersRegistrySet(address indexed _trustedIssuersRegistry);

event IdentityRegistered(address indexed _investorAddress, IIdentity indexed _identity);

event IdentityRemoved(address indexed _investorAddress, IIdentity indexed _identity);

event IdentityUpdated(IIdentity indexed _oldIdentity, IIdentity indexed _newIdentity);

event CountryUpdated(address indexed _investorAddress, uint16 indexed _country);

interface IERC3643IdentityRegistry {
    function setIdentityRegistryStorage(address _identityRegistryStorage) external;
    function setClaimTopicsRegistry(address _claimTopicsRegistry) external;
    function setTrustedIssuersRegistry(address _trustedIssuersRegistry) external;
    function registerIdentity(address _userAddress, IIdentity _identity, uint16 _country) external;
    function deleteIdentity(address _userAddress) external;
    function updateCountry(address _userAddress, uint16 _country) external;
    function updateIdentity(address _userAddress, IIdentity _identity) external;
    function batchRegisterIdentity(
        address[] calldata _userAddresses,
        IIdentity[] calldata _identities,
        uint16[] calldata _countries
    ) external;
    function contains(address _userAddress) external view returns (bool);
    function isVerified(address _userAddress) external view returns (bool);
    function identity(address _userAddress) external view returns (IIdentity);
    function investorCountry(address _userAddress) external view returns (uint16);
    function identityStorage() external view returns (IERC3643IdentityRegistryStorage);
    function issuersRegistry() external view returns (IERC3643TrustedIssuersRegistry);
    function topicsRegistry() external view returns (IERC3643ClaimTopicsRegistry);
}
