// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";

event TrustedIssuerAdded(IClaimIssuer indexed _trustedIssuer, uint256[] _claimTopics);

event TrustedIssuerRemoved(IClaimIssuer indexed _trustedIssuer);

event ClaimTopicsUpdated(IClaimIssuer indexed _trustedIssuer, uint256[] _claimTopics);

interface IERC3643TrustedIssuersRegistry {
    function addTrustedIssuer(IClaimIssuer _trustedIssuer, uint256[] calldata _claimTopics) external;
    function removeTrustedIssuer(IClaimIssuer _trustedIssuer) external;
    function updateIssuerClaimTopics(IClaimIssuer _trustedIssuer, uint256[] calldata _claimTopics) external;
    function getTrustedIssuers() external view returns (IClaimIssuer[] memory);
    function getTrustedIssuersForClaimTopic(uint256 claimTopic) external view returns (IClaimIssuer[] memory);
    function isTrustedIssuer(address _issuer) external view returns (bool);
    function getTrustedIssuerClaimTopics(IClaimIssuer _trustedIssuer) external view returns (uint256[] memory);
    function hasClaimTopic(address _issuer, uint256 _claimTopic) external view returns (bool);
}
