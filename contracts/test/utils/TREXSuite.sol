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

// ONCHAINID interfaces
import {IImplementationAuthority} from "@onchain-id/solidity/contracts/interface/IImplementationAuthority.sol";
import {IIdFactory} from "@onchain-id/solidity/contracts/factory/IIdFactory.sol";

contract TREXSuite is Test {
    // TODO: comment what the roles do
    address public deployer = makeAddr("Deployer"); // Deploys and owns the factory contracts
    address public tokenIssuer = makeAddr("TokenIssuer");
    address public tokenAgent = makeAddr("TokenAgent");
    address public tokenAdmin = makeAddr("TokenAdmin");
    address public claimIssuer = makeAddr("ClaimIssuer");
    address public aliceWallet = makeAddr("AliceWallet");
    address public bobWallet = makeAddr("BobWallet");

    // Contracts
    ITREXImplementationAuthority public trexIA;
    ITREXFactory public trexFactory;
    IImplementationAuthority public identityIA;
    IIdFactory public identityFactory;
    IERC3643ClaimTopicsRegistry public claimTopicsRegistry;
    IERC3643TrustedIssuersRegistry public trustedIssuersRegistry;
    IERC3643IdentityRegistryStorage public identityRegistryStorage;
    IERC3643IdentityRegistry public identityRegistry;
    IERC3643Compliance public compliance;

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

        // Deploy Proxies
        claimTopicsRegistry = IERC3643ClaimTopicsRegistry(
            deployArtifact("out/ClaimTopicsRegistryProxy.sol/ClaimTopicsRegistryProxy.json", abi.encode(trexIA))
        );
        trustedIssuersRegistry = IERC3643TrustedIssuersRegistry(
            deployArtifact("out/TrustedIssuersRegistryProxy.sol/TrustedIssuersRegistryProxy.json", abi.encode(trexIA))
        );
        identityRegistryStorage = IERC3643IdentityRegistryStorage(
            deployArtifact("out/IdentityRegistryStorageProxy.sol/IdentityRegistryStorageProxy.json", abi.encode(trexIA))
        );
        // We use DefaultCompliance as mock, canTransfer will be always true
        compliance = IERC3643Compliance(deployArtifact("out/DefaultCompliance.sol/DefaultCompliance.json", hex""));
        identityRegistry = IERC3643IdentityRegistry(
            deployArtifact(
                "out/IdentityRegistryProxy.sol/IdentityRegistryProxy.json",
                abi.encode(trexIA, trustedIssuersRegistry, claimTopicsRegistry, identityRegistryStorage)
            )
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
}
