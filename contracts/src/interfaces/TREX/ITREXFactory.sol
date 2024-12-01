// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

event Deployed(address indexed _addr);

event IdFactorySet(address _idFactory);

event TREXSuiteDeployed(
    address indexed _token, address _ir, address _irs, address _tir, address _ctr, address _mc, string indexed _salt
);

interface ITREXFactory {
    struct TokenDetails {
        address owner;
        string name;
        string symbol;
        uint8 decimals;
        address irs;
        address ONCHAINID;
        address[] irAgents;
        address[] tokenAgents;
        address[] complianceModules;
        bytes[] complianceSettings;
    }

    struct ClaimDetails {
        uint256[] claimTopics;
        address[] issuers;
        uint256[][] issuerClaims;
    }

    function setImplementationAuthority(address _implementationAuthority) external;
    function setIdFactory(address _idFactory) external;
    function deployTREXSuite(
        string memory _salt,
        TokenDetails calldata _tokenDetails,
        ClaimDetails calldata _claimDetails
    ) external;
    function recoverContractOwnership(address _contract, address _newOwner) external;
    function getImplementationAuthority() external view returns (address);
    function getIdFactory() external view returns (address);
    function getToken(string calldata _salt) external view returns (address);
}
