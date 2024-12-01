// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";

// ERC3643 interfaces
import {IERC3643ClaimTopicsRegistry} from "src/interfaces/ERC3643/IERC3643ClaimTopicsRegistry.sol";
import {IERC3643TrustedIssuersRegistry} from "src/interfaces/ERC3643/IERC3643TrustedIssuersRegistry.sol";
import {IERC3643IdentityRegistryStorage} from "src/interfaces/ERC3643/IERC3643IdentityRegistryStorage.sol";
import {IERC3643IdentityRegistry} from "src/interfaces/ERC3643/IERC3643IdentityRegistry.sol";
import {IERC3643Compliance} from "src/interfaces/ERC3643/IERC3643Compliance.sol";
import {IERC3643} from "src/interfaces/ERC3643/IERC3643.sol";

// TREX interfaces
import {ITREXImplementationAuthority} from "src/interfaces/TREX/ITREXImplementationAuthority.sol";
import {ITREXFactory} from "src/interfaces/TREX/ITREXFactory.sol";
import {IAgentRole} from "src/interfaces/TREX/IAgentRole.sol";

// ONCHAINID interfaces
import {IImplementationAuthority} from "@onchain-id/solidity/contracts/interface/IImplementationAuthority.sol";
import {IIdFactory} from "@onchain-id/solidity/contracts/factory/IIdFactory.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";

contract TREXSuite is Test {
    address public deployer = makeAddr("Deployer"); // This Role Deploys the entire system and manages the agents and claim issuers

    // Contracts
    ITREXImplementationAuthority public trexIA;
    ITREXFactory public trexFactory;
    IImplementationAuthority public identityIA;
    IIdFactory public identityFactory;
    IERC3643IdentityRegistryStorage public identityRegistryStorage;

    function deployArtifact(string memory artifactName, bytes memory constructorArgs) internal returns (address addr) {
        bytes memory artifactCode = vm.getCode(artifactName);
        bytes memory initializationCode = abi.encodePacked(artifactCode, constructorArgs);
        assembly {
            addr := create(0, add(initializationCode, 0x20), mload(initializationCode))
        }
    }

    function deployTREXFactory() internal {
        // TODO: Some of the roles need signing keys change makeAddr to makeAddrWithKey

        vm.startPrank(deployer);

        // Deploy TREX Implementations
        address claimTopicsRegistryImplementation =
            deployArtifact("out/ClaimTopicsRegistry.sol/ClaimTopicsRegistry.json", hex"");
        address trustedIssuersRegistryImplementation =
            deployArtifact("out/TrustedIssuersRegistry.sol/TrustedIssuersRegistry.json", hex"");
        address identityRegistryStorageImplementation =
            deployArtifact("out/IdentityRegistryStorage.sol/IdentityRegistryStorage.json", hex"");
        address identityRegistryImplementation = deployArtifact(
            "out/IdentityRegistry.sol/IdentityRegistry.json", abi.encode(identityRegistryStorageImplementation)
        );
        address tokenImplementation = deployArtifact("out/Token.sol/Token.json", hex"");

        // Deploy and configure TREXImplementationAutority
        trexIA = ITREXImplementationAuthority(
            deployArtifact(
                "out/TREXImplementationAuthority.sol/TREXImplementationAuthority.json",
                abi.encode(true, address(0), address(0))
            )
        );
        trexIA.addAndUseTREXVersion(
            ITREXImplementationAuthority.Version(4, 0, 0),
            ITREXImplementationAuthority.TREXContracts(
                tokenImplementation,
                claimTopicsRegistryImplementation,
                identityRegistryImplementation,
                identityRegistryStorageImplementation,
                trustedIssuersRegistryImplementation,
                address(1) // <-- pass the zero check
            )
        );

        // Deploy Identity Registry Storage
        identityRegistryStorage = IERC3643IdentityRegistryStorage(
            deployArtifact("out/IdentityRegistryStorageProxy.sol/IdentityRegistryStorageProxy.json", abi.encode(trexIA))
        );

        // Deploy ONCHAINID
        address identityImplementation = deployArtifact("out/Identity.sol/Identity.json", abi.encode(deployer, true));
        identityIA = IImplementationAuthority(
            deployArtifact(
                "out/ImplementationAuthority.sol/ImplementationAuthority.json", abi.encode(identityImplementation)
            )
        );
        identityFactory = IIdFactory(deployArtifact("out/IdFactory.sol/IdFactory.json", abi.encode(identityIA)));

        // Deploy TREXFactory
        trexFactory =
            ITREXFactory(deployArtifact("out/TREXFactory.sol/TREXFactory.json", abi.encode(trexIA, identityFactory)));

        // Add TREXFactory as a token factory in idenitityFactory
        identityFactory.addTokenFactory(address(trexFactory));

        vm.stopPrank();
    }

    struct TokenContracts {
        IIdentity identity;
        IERC3643ClaimTopicsRegistry claimTopicsRegistry;
        IERC3643TrustedIssuersRegistry trustedIssuersRegistry;
        IERC3643Compliance compliance;
        IERC3643IdentityRegistry identityRegistry;
        IERC3643 token;
        address agentManager;
    }

    function deployToken(
        string memory name,
        string memory symbol,
        uint256 decimals,
        address tokenIssuer,
        address tokenAgent,
        address tokenAdmin,
        TokenContracts storage tokenContracts
    ) internal {
        vm.startPrank(deployer);
        // Deploy token ONCHAINID
        tokenContracts.identity =
            IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, tokenIssuer)));

        // Deploy token contracts
        tokenContracts.claimTopicsRegistry = IERC3643ClaimTopicsRegistry(
            deployArtifact("out/ClaimTopicsRegistryProxy.sol/ClaimTopicsRegistryProxy.json", abi.encode(trexIA))
        );
        tokenContracts.trustedIssuersRegistry = IERC3643TrustedIssuersRegistry(
            deployArtifact("out/TrustedIssuersRegistryProxy.sol/TrustedIssuersRegistryProxy.json", abi.encode(trexIA))
        );
        tokenContracts.compliance =
            IERC3643Compliance(deployArtifact("out/DefaultCompliance.sol/DefaultCompliance.json", hex"")); // Mock compliance canTransfer always true
        tokenContracts.identityRegistry = IERC3643IdentityRegistry(
            deployArtifact(
                "out/IdentityRegistryProxy.sol/IdentityRegistryProxy.json",
                abi.encode(
                    trexIA,
                    tokenContracts.trustedIssuersRegistry,
                    tokenContracts.claimTopicsRegistry,
                    identityRegistryStorage
                )
            )
        );
        tokenContracts.token = IERC3643(
            deployArtifact(
                "out/TokenProxy.sol/TokenProxy.json",
                abi.encode(
                    trexIA,
                    tokenContracts.identityRegistry,
                    tokenContracts.compliance,
                    name,
                    symbol,
                    decimals,
                    tokenContracts.identity
                )
            )
        );
        vm.stopPrank();

        // Deploy AgentManager
        vm.startPrank(tokenAgent);
        tokenContracts.agentManager =
            deployArtifact("out/AgentManager.sol/AgentManager.json", abi.encode(tokenContracts.token));
        vm.stopPrank();

        vm.startPrank(deployer);
        // Bind Identity registry to token
        identityRegistryStorage.bindIdentityRegistry(address(tokenContracts.identityRegistry));

        // Add Agent to the token
        IAgentRole(address(tokenContracts.token)).addAgent(tokenAgent);
        vm.stopPrank();
    }

    struct ClaimData {
        bytes data;
        address issuer;
        uint256 topic;
        uint256 scheme;
        IIdentity identity;
    }

    function signClaim(ClaimData memory claim, uint256 privateKey) internal returns (bytes memory signature) {
        bytes32 dataHash = keccak256(abi.encode(claim.identity, claim.topic, claim.data));
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, prefixedHash);
        signature = abi.encodePacked(r, s, v);
    }
}
