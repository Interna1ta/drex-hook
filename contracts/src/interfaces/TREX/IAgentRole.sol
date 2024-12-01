// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

event AgentAdded(address indexed _agent);

event AgentRemoved(address indexed _agent);

interface IAgentRole {
    function addAgent(address _agent) external;
    function removeAgent(address _agent) external;
    function isAgent(address _agent) external view returns (bool);
}
