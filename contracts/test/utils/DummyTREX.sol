// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// DUMMY CONTRACT USED TO FORCE COMPILATION OF TREX CONTRACTS
import {ClaimTopicsRegistry} from "@T-REX/registry/implementation/ClaimTopicsRegistry.sol";
import {ClaimTopicsRegistryProxy} from "@T-REX/proxy/ClaimTopicsRegistryProxy.sol";
import {TrustedIssuersRegistry} from "@T-REX/registry/implementation/TrustedIssuersRegistry.sol";
import {TrustedIssuersRegistryProxy} from "@T-REX/proxy/TrustedIssuersRegistryProxy.sol";
import {IdentityRegistryStorage} from "@T-REX/registry/implementation/IdentityRegistryStorage.sol";
import {IdentityRegistryStorageProxy} from "@T-REX/proxy/IdentityRegistryStorageProxy.sol";
import {IdentityRegistry} from "@T-REX/registry/implementation/IdentityRegistry.sol";
import {IdentityRegistryProxy} from "@T-REX/proxy/IdentityRegistryProxy.sol";
import {DefaultCompliance} from "@T-REX/compliance/legacy/DefaultCompliance.sol";
import {Token} from "@T-REX/token/Token.sol";
import {TREXImplementationAuthority} from "@T-REX/proxy/authority/TREXImplementationAuthority.sol";
import {TREXFactory} from "@T-REX/factory/TREXFactory.sol";
