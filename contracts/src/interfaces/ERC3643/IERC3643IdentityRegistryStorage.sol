// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";

event IdentityStored(address indexed _investorAddress, IIdentity indexed _identity);

event IdentityUnstored(address indexed _investorAddress, IIdentity indexed _identity);

event IdentityModified(IIdentity indexed _oldIdentity, IIdentity indexed _newIdentity);

event CountryModified(address indexed _investorAddress, uint16 indexed _country);

event IdentityRegistryBound(address indexed _identityRegistry);

event IdentityRegistryUnbound(address indexed _identityRegistry);

interface IERC3643IdentityRegistryStorage {
    function addIdentityToStorage(address _userAddress, IIdentity _identity, uint16 _country) external;
    function removeIdentityFromStorage(address _userAddress) external;
    function modifyStoredInvestorCountry(address _userAddress, uint16 _country) external;
    function modifyStoredIdentity(address _userAddress, IIdentity _identity) external;
    function bindIdentityRegistry(address _identityRegistry) external;
    function unbindIdentityRegistry(address _identityRegistry) external;
    function linkedIdentityRegistries() external view returns (address[] memory);
    function storedIdentity(address _userAddress) external view returns (IIdentity);
    function storedInvestorCountry(address _userAddress) external view returns (uint16);
}
