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
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";

contract TREXSuite is Test {
    address public deployer = makeAddr("Deployer"); // This Role Deploys the entire system and manages the agents and claim issuers
    address public identityRegistryStorageAgent = makeAddr("identityRegistryStorageAgent"); // Agent in charge of register new identities directly to the storage registry

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
        IAgentRole(address(identityRegistryStorage)).addAgent(identityRegistryStorageAgent);

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

    /**
     * TEST (TST) Token schenario deployment
     */
    address internal TSTTokenIssuer = makeAddr("TokenIssuer"); // Key controller of the token Identity contract
    address internal TSTTokenAgent = makeAddr("TokenAgent"); // Agent in charge of register new identities, and mint/burn tokens.,
    address internal TSTTokenAdmin = makeAddr("TokenAdmin"); // Admin of the agentManager contract
    address internal TSTClaimIssuerAddr; // Issuer in charge of issue a specific claim ("CLAIM_TOPIC")
    uint256 internal TSTClaimIssuerKey;
    IClaimIssuer internal TSTClaimIssuerIdentity;
    TokenContracts internal TSTContracts;

    // Users
    address internal aliceAddr;
    IIdentity internal aliceIdentity;
    uint256 internal aliceKey;

    address internal bobAddr;
    IIdentity internal bobIdentity;
    uint256 internal bobKey;

    address internal charlieAddr;
    IIdentity internal charlieIdentity;
    uint256 internal charlieKey;

    // Constants
    uint256 internal INITIAL_SUPPLY = 1000000000000000000000000;
    uint256 internal TOPIC = uint256(keccak256("CLAIM_TOPIC"));

    function deployTSTTokenSchenario() internal {
        // Deploy TST token
        deployToken("TEST", "TST", 18, TSTTokenIssuer, TSTTokenAgent, TSTTokenAdmin, TSTContracts);

        // Add sample claim topics
        vm.startPrank(deployer);
        uint256[] memory topics = new uint256[](1);
        topics[0] = TOPIC;
        TSTContracts.claimTopicsRegistry.addClaimTopic(topics[0]);
        vm.stopPrank();

        // Deploy claim issuer idenitity
        (TSTClaimIssuerAddr, TSTClaimIssuerKey) = makeAddrAndKey("ClaimIssuer");
        vm.startPrank(TSTClaimIssuerAddr);
        TSTClaimIssuerIdentity =
            IClaimIssuer(deployArtifact("out/ClaimIssuer.sol/ClaimIssuer.json", abi.encode(TSTClaimIssuerAddr)));
        TSTClaimIssuerIdentity.addKey(keccak256(abi.encode(TSTClaimIssuerAddr)), 3, 1);
        vm.stopPrank();

        // Add issuer to trusted issuers registry
        vm.startPrank(deployer);
        TSTContracts.trustedIssuersRegistry.addTrustedIssuer((TSTClaimIssuerIdentity), topics);
        vm.stopPrank();

        // Deploy Alice identity
        (aliceAddr, aliceKey) = makeAddrAndKey("Alice");
        vm.startPrank(aliceAddr);
        aliceIdentity =
            IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, aliceAddr)));
        vm.stopPrank();

        // Deploy Bob identity
        (bobAddr, bobKey) = makeAddrAndKey("Bob");
        vm.startPrank(bobAddr);
        bobIdentity =
            IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, bobAddr)));
        vm.stopPrank();

        // Deploy Charlie identity
        vm.startPrank(charlieAddr);
        (charlieAddr, charlieKey) = makeAddrAndKey("Charlie");
        charlieIdentity =
            IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, charlieAddr)));
        vm.stopPrank();

        vm.startPrank(deployer);
        // Add new agents to the token
        IAgentRole(address(TSTContracts.identityRegistry)).addAgent(address(TSTTokenAgent));
        IAgentRole(address(TSTContracts.identityRegistry)).addAgent(address(TSTContracts.token));
        vm.stopPrank();

        vm.startPrank(TSTTokenAgent);
        // Register Alice and Bob in the identity registry
        address[] memory addrs = new address[](2);
        addrs[0] = aliceAddr;
        addrs[1] = bobAddr;
        IIdentity[] memory identities = new IIdentity[](2);
        identities[0] = aliceIdentity;
        identities[1] = bobIdentity;
        uint16[] memory countries = new uint16[](2);
        countries[0] = 42;
        countries[1] = 666;
        TSTContracts.identityRegistry.batchRegisterIdentity(addrs, identities, countries);
        vm.stopPrank();

        //  Sign claims for alice and bob
        ClaimData memory claimForAlice = ClaimData(aliceIdentity, topics[0], "Alice public data!");
        ClaimData memory claimForBob = ClaimData(bobIdentity, topics[0], "Bob public data!");
        bytes memory signatureAliceClaim = signClaim(claimForAlice, TSTClaimIssuerKey);
        bytes memory signatureBobClaim = signClaim(claimForBob, TSTClaimIssuerKey);

        // Add claims to Alice and Bob identities
        vm.startPrank(aliceAddr);
        aliceIdentity.addClaim(
            claimForAlice.topic, 1, address(TSTClaimIssuerIdentity), signatureAliceClaim, claimForAlice.data, ""
        );
        vm.stopPrank();
        vm.startPrank(bobAddr);
        bobIdentity.addClaim(
            claimForBob.topic, 1, address(TSTClaimIssuerIdentity), signatureBobClaim, claimForBob.data, ""
        );
        vm.stopPrank();

        // Mint tokens for Alice and Bob
        vm.startPrank(TSTTokenAgent);
        TSTContracts.token.mint(aliceAddr, INITIAL_SUPPLY);
        TSTContracts.token.mint(bobAddr, INITIAL_SUPPLY);
        vm.stopPrank();

        // Final Agent configuration
        vm.startPrank(TSTTokenAgent);
        (bool success,) =
            TSTContracts.agentManager.call(abi.encodeWithSignature("addAgentAdmin(address)", TSTTokenAdmin));
        vm.stopPrank();
        vm.startPrank(deployer);
        IAgentRole(address(TSTContracts.token)).addAgent(TSTContracts.agentManager);
        IAgentRole(address(TSTContracts.identityRegistry)).addAgent(TSTContracts.agentManager);
        vm.stopPrank();
        vm.startPrank(TSTTokenAgent);
        TSTContracts.token.unpause();
        vm.stopPrank();
    }

    struct ClaimData {
        IIdentity identity;
        uint256 topic;
        bytes data;
    }

    function signClaim(ClaimData memory claim, uint256 privateKey) internal pure returns (bytes memory signature) {
        bytes32 dataHash = keccak256(abi.encode(claim.identity, claim.topic, claim.data));
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, prefixedHash);
        signature = abi.encodePacked(r, s, v);
    }

    /**
     *   Other Test Utils
     */
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
}
