// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

event ClaimTopicAdded(uint256 indexed _claimTopic);

event ClaimTopicRemoved(uint256 indexed _claimTopic);

interface IERC3643ClaimTopicsRegistry {
    function addClaimTopic(uint256 _claimTopic) external;
    function removeClaimTopic(uint256 _claimTopic) external;
    function getClaimTopics() external view returns (uint256[] memory);
}
