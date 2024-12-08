// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";

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

// Uniswap v4 contracts
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";

// Hooks
import {RDEXHook} from "src/RDEXHook.sol";
import {RDEXDynamicFeeHook} from "src/RDEXDynamicFeeHook.sol";

uint256 constant TOPIC = uint256(keccak256("CLAIM_TOPIC"));
address constant owner = 0x1038d5A420AEa8aDc479D654D815f92ADC0106c0;

// Unichain Sepolia: 1301
address constant PM_ADDRESS = 0xC81462Fec8B23319F288047f8A03A57682a35C1A;
address constant trexfeeHookAddr = 0x74e3A272AE44fDF370659f919d46EA30EBcC9080;
bytes32 constant feeHookSalt = 0xdc0d29918bce0d14e86332e1de811666d755e3d8a0157ff64182a3d365c4062a;
address constant hookAddr = 0x25A8680890d9A8E61F6B2ee68f845321c10B2000;
bytes32 constant hookSalt = 0xe5e30d7a533454505ffb586546381a7aaa6ec352497a1a62c172b40ed3d5f792;
address constant trexIA = 0xD1B274E8afCaB3faa664Ff81cA830521Fa1871bD;
address constant identityRegistryStorage = 0x0CC39Caa12A812A53A448028536B64ec0cD09D70;
address constant identityIA = 0xF1a818E4b40a47Bdf235Df1712c293Be309E98B9;
address constant tokenIdentity = 0x5E5064ec7cf549FDb242Cf3e1528047f3CaeB74a;
address constant tokenClaimTopicsRegistry = 0x38AFaD0b7C80863FD436F20CDBB577E9692F37Da;
address constant tokenTrustedIssuersRegistry = 0x90df67D7E821B85f19fEA26894e55d388cdD295f;
address constant tokenCompliance = 0x1d79574C0Ae43F381470dA5EC91EE13b42ABff4D;
address constant tokenIdentityRegistry = 0xD8a33dDaE377450ea6657B2d6B973F288602D5eE;
address constant tokenToken = 0x98000e1F41C75ea1Ff688978ef79932a022d2cB4;
address constant tokenAgentManager = 0x059841FA575d8Cf37b5D658aCE4DebC1d4fa2BDB;
address constant UHIClaimIssuerIdentity = 0xC304B65C6f82a6C438f9B1B442d844b1058d0B07;
address constant USDC = 0x31d0220469e10c4E71834a79b1f276d740d3768F;

// Sepolia: 11155111
// address constant PM_ADDRESS = 0x8C4BcBE6b9eF47855f97E675296FA3F6fafa5F1A;
//address constant feeHookAddr = 0xFD75d54faf4062D2B465964Aa55B8e0543C79080;
//bytes32 constant feeHookSalt = 0x92dcfaac179029f091009a4e71483ecbc4ad757f92391e4f3c461cdd8b57d198;
//address constant hookAddr = 0x422096783AB2a81a230D3b9DcaFd8c337b24a000;
//bytes32 constant hookSalt = 0x646a804fff68e4334ed4d2f0e5a224f81aa82dd8d0a4cb91429cd3db114b1f94;

IPoolManager constant manager = IPoolManager(PM_ADDRESS);

contract DeployUtils is Script {
    function deployArtifact(string memory artifactName, bytes memory constructorArgs) internal returns (address addr) {
        bytes memory artifactCode = vm.getCode(artifactName);
        bytes memory initializationCode = abi.encodePacked(artifactCode, constructorArgs);
        assembly {
            addr := create(0, add(initializationCode, 0x20), mload(initializationCode))
        }
    }

    struct ClaimData {
        IIdentity identity;
        uint256 topic;
        bytes data;
    }

    function signClaim(ClaimData memory claim, uint256 privateKey) internal returns (bytes memory signature) {
        bytes32 dataHash = keccak256(abi.encode(claim.identity, claim.topic, claim.data));
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, prefixedHash);
        signature = abi.encodePacked(r, s, v);
    }
}

contract DeployTREXSuite is Script, DeployUtils {
    function run() public {
        vm.startBroadcast();

        /**
         *   Deploy TREX suite
         */
        // Deploy implementation
        ITREXImplementationAuthority trexIA;
        ITREXFactory trexFactory;
        IImplementationAuthority identityIA;
        IIdFactory identityFactory;
        IERC3643IdentityRegistryStorage identityRegistryStorage;

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

        // Deploy Identity Registry Storage Proxy
        identityRegistryStorage = IERC3643IdentityRegistryStorage(
            deployArtifact("out/IdentityRegistryStorageProxy.sol/IdentityRegistryStorageProxy.json", abi.encode(trexIA))
        );
        IAgentRole(address(identityRegistryStorage)).addAgent(owner);

        // Deploy ONCHAINID
        address identityImplementation = deployArtifact("out/Identity.sol/Identity.json", abi.encode(owner, true));
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

        /* Log all deployed contracts */
        console.log("unichain contracts");
        console.log("**ClaimTopicsRegistry Implemetation**: %s", claimTopicsRegistryImplementation);
        console.log("**TrustedIssuersRegistry Implemetation**: %s", trustedIssuersRegistryImplementation);
        console.log("**IdentityRegistryStorage Implemetation**: %s", identityRegistryStorageImplementation);
        console.log("**IdentityRegistry Implemetation**: %s", identityRegistryImplementation);
        console.log("**Token Implemetation**: %s", tokenImplementation);
        console.log("**TREXImplementationAuthority**: %s", address(trexIA));
        console.log("**IdentityRegistryStorage**: %s", address(identityRegistryStorage));
        console.log("**IdentityImplemetation**: %s", address(identityImplementation));
        console.log("**IdentityIA**: %s", address(identityIA));
        console.log("**IdentityFactory**: %s", address(identityFactory));
        console.log("**TREXFactory**: %s", address(trexFactory));
        vm.stopBroadcast();
    }
}

contract DeployUHIToken is Script, DeployUtils {
    function run() public {
        vm.startBroadcast();

        IIdentity tokenIdentitiy;
        IERC3643ClaimTopicsRegistry claimTopicsRegistry;
        IERC3643TrustedIssuersRegistry trustedIssuersRegistry;
        IERC3643Compliance compliance;
        IERC3643IdentityRegistry identityRegistry;
        IERC3643 token;
        address agentManager;

        /**
         * Deploy UHI ERC3643 Token
         */
        // Deploy token ONCHAINID
        tokenIdentitiy =
            IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, owner)));

        // Deploy token contracts
        claimTopicsRegistry = IERC3643ClaimTopicsRegistry(
            deployArtifact("out/ClaimTopicsRegistryProxy.sol/ClaimTopicsRegistryProxy.json", abi.encode(trexIA))
        );
        trustedIssuersRegistry = IERC3643TrustedIssuersRegistry(
            deployArtifact("out/TrustedIssuersRegistryProxy.sol/TrustedIssuersRegistryProxy.json", abi.encode(trexIA))
        );
        compliance = IERC3643Compliance(deployArtifact("out/DefaultCompliance.sol/DefaultCompliance.json", hex"")); // Mock compliance canTransfer always true
        identityRegistry = IERC3643IdentityRegistry(
            deployArtifact(
                "out/IdentityRegistryProxy.sol/IdentityRegistryProxy.json",
                abi.encode(trexIA, trustedIssuersRegistry, claimTopicsRegistry, identityRegistryStorage)
            )
        );
        token = IERC3643(
            deployArtifact(
                "out/TokenProxy.sol/TokenProxy.json",
                abi.encode(trexIA, identityRegistry, compliance, "UHI", "Hook Incubator Token", 18, tokenIdentitiy)
            )
        );

        agentManager = deployArtifact("out/AgentManager.sol/AgentManager.json", abi.encode(token));

        // Bind Identity registry to token
        IERC3643IdentityRegistryStorage(identityRegistryStorage).bindIdentityRegistry(address(identityRegistry));

        // Add Agent to the token
        IAgentRole(address(token)).addAgent(owner);

        // Deploy token identity
        console.log("unichain contracts");
        console.log("**UHI Token Identity**: %s", address(tokenIdentitiy));
        console.log("**UHI Token ClaimTopicsRegistry**: %s", address(claimTopicsRegistry));
        console.log("**UHI Token TrustedIssuersRegistry**: %s", address(trustedIssuersRegistry));
        console.log("**UHI Token Compliance**: %s", address(compliance));
        console.log("**UHI Token IdentityRegistry**: %s", address(identityRegistry));
        console.log("**UHI Token Token**: %s", address(token));
        console.log("**UHI Token AgentManager**: %s", address(agentManager));
        vm.stopBroadcast();
    }
}

contract ConfigureTokenAndTraderIdentities is Script, DeployUtils {
    function run() public {
        vm.startBroadcast();
        // Add claim topic to the claim topic registry
        uint256[] memory topics = new uint256[](1);
        topics[0] = TOPIC;
        IERC3643ClaimTopicsRegistry(tokenClaimTopicsRegistry).addClaimTopic(topics[0]);

        // Deploy Claim Issuer identity
        IClaimIssuer UHIClaimIssuerIdentity =
            IClaimIssuer(deployArtifact("out/ClaimIssuer.sol/ClaimIssuer.json", abi.encode(owner)));
        UHIClaimIssuerIdentity.addKey(keccak256(abi.encode(owner)), 3, 1);

        // Add issuer to trusted issuers registry
        IERC3643TrustedIssuersRegistry(tokenTrustedIssuersRegistry).addTrustedIssuer(UHIClaimIssuerIdentity, topics);

        // Add agent to identity registry
        IAgentRole(address(tokenIdentityRegistry)).addAgent(address(owner));
        IAgentRole(address(tokenIdentityRegistry)).addAgent(address(tokenToken));

        // Deploy Alice idenitiy
        address alice = 0xFB17d0D1b2Dc3f99705459A70210981b42BfA5d2;
        uint256 alicePrivateKey = 0x148ac551a5681c86fdbfd0152d6eefa0fbfcad07b7ec157201cb75da975ec9ff;
        IIdentity aliceIdentity =
            IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, owner)));

        // Register alice identity
        IERC3643IdentityRegistry(tokenIdentityRegistry).registerIdentity(alice, aliceIdentity, uint16(42));

        // Sign claim for alice 
        ClaimData memory claimForAlice = ClaimData(aliceIdentity, topics[0], "Owner public data!");
        bytes memory signatureAliceClaim = signClaim(claimForAlice, vm.envUint("OWNER_SK_HEX"));

        // Add claim to alice identity
        IIdentity(aliceIdentity).addClaim(
            claimForAlice.topic, 1, address(UHIClaimIssuerIdentity), signatureAliceClaim, claimForAlice.data, ""
        );

        // Mint tokens for alice 
        IERC3643(tokenToken).mint(alice, 1000000000000000000000000000);

        // Final agent configuration
        (bool success,) = tokenAgentManager.call(abi.encodeWithSignature("addAgentAdmin(address)", owner));
        IAgentRole(address(tokenToken)).addAgent(tokenAgentManager);
        IAgentRole(address(tokenIdentityRegistry)).addAgent(tokenAgentManager);
        IERC3643(tokenToken).unpause();

        console.log("unichain contracts");
        console.log("**Claim Issuer Identity**: %s", address(UHIClaimIssuerIdentity));
        console.log("**Alice Identity**: %s", address(aliceIdentity));
        vm.stopBroadcast();
    }
}

contract DeployHooks is Script, DeployUtils {
    function run() public {
        vm.startBroadcast();

        /**
         * Deploy Hooks to determinisitic address with create 2
         */
        // new RDEXDynamicFeeHook{salt: feeHookSalt}(
        //      manager, owner, IERC3643IdentityRegistryStorage(address(0)), 0, address(0), 0
        //  );

        //new RDEXHook{salt: hookSalt}(
        //    manager, owner, IERC3643IdentityRegistryStorage(address(0)), 0, address(0), IHooks(address(feeHookAddr))
        //);

        // Set the identity registry storage of the Hook
        RDEXHook(hookAddr).setIdentityRegistryStorage(address(identityRegistryStorage));

        // Deplopy hoook identity
        IIdentity hookIdentity =
            IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, owner)));

        // Add identity of the hook to the identity registry of TSTToken
        IERC3643IdentityRegistry(tokenIdentityRegistry).registerIdentity(address(hookAddr), hookIdentity, uint16(42));

        // Sign claim for hook
        ClaimData memory claimForHook = ClaimData(hookIdentity, TOPIC, "Hook public data!");
        bytes memory signatureHookClaim = signClaim(claimForHook, vm.envUint("OWNER_SK_HEX"));

        // Add claim to alice identity
        IIdentity(hookIdentity).addClaim(
            claimForHook.topic, 1, address(UHIClaimIssuerIdentity), signatureHookClaim, claimForHook.data, ""
        );

        console.log("unichain contracts");
        console.log("**hook Identity**: %s", address(hookIdentity));

        /* Log all deployed contracts */
        vm.stopBroadcast();
    }
}


contract DeployOnchainId is Script, DeployUtils {
/**
 * Deploy ONCHAINID for my user
 */
}
