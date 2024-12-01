// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {TREXSuite} from "./utils/TREXSuite.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";
import {IAgentRole} from "src/interfaces/TREX/IAgentRole.sol";
//import {Deployers} from "contracts/lib/v4-periphery/lib/v4-core/test/utils/Deployers.sol";

contract ERC6909FaultPoC is Test, TREXSuite {
    // TST TOKEN
    address internal TSTTokenIssuer = makeAddr("TokenIssuer"); // Key controller of the token Identity contract
    address internal TSTTokenAgent = makeAddr("TokenAgent"); // Agent in charge of register new identities, and mint/burn tokens.,
    address internal TSTTokenAdmin = makeAddr("TokenAdmin"); // Admin of the agentManager contract
    address internal TSTClaimIssuerAddr; // Issuer in charge of issue a specific claim ("CLAIM_TOPIC")
    uint256 internal TSTClaimIssuerKey;
    IClaimIssuer internal TSTClaimIssuerIdentity;

    TokenContracts internal TSTContracts;

    // Entities
    address internal aliceAddr;
    IIdentity internal aliceIdentity;
    uint256 internal aliceKey;

    address internal bobAddr;
    IIdentity internal bobIdentity;
    uint256 internal bobKey;

    address internal charlieAddr;
    IIdentity internal charlieIdentity;
    uint256 internal charlieKey;

    // Initial supply
    uint256 internal INITIAL_SUPLY = 1000000000000000000000000;

    function setUp() public {
        /**
         * TREX INFRA + TOKEN DEPLOYMENT
         */
        deployTREXFactory();
        deployToken("TEST", "TST", 18, TSTTokenIssuer, TSTTokenAgent, TSTTokenAdmin, TSTContracts);

        // Add sample claim topics
        vm.startPrank(deployer);
        uint256[] memory topics = new uint256[](1);
        topics[0] = uint256(keccak256("CLAIM_TOPIC"));
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
        ClaimData memory claimForAlice =
            ClaimData("Alice public data!", address(TSTClaimIssuerIdentity), topics[0], 1, address(aliceIdentity));
        ClaimData memory claimForBob =
            ClaimData("Bob public data!", address(TSTClaimIssuerIdentity), topics[0], 1, address(bobIdentity));
        bytes memory signatureAliceClaim = signClaim(claimForAlice, TSTClaimIssuerKey);
        bytes memory signatureBobClaim = signClaim(claimForBob, TSTClaimIssuerKey);

        // Add claims to Alice and Bob identities
        vm.startPrank(aliceAddr);
        aliceIdentity.addClaim(
            claimForAlice.topic, claimForAlice.scheme, claimForAlice.issuer, signatureAliceClaim, claimForAlice.data, ""
        );
        vm.stopPrank();
        vm.startPrank(bobAddr);
        bobIdentity.addClaim(
            claimForBob.topic, claimForBob.scheme, claimForBob.issuer, signatureBobClaim, claimForBob.data, ""
        );
        vm.stopPrank();

        // Mint tokens for Alice and Bob
        vm.startPrank(TSTTokenAgent);
        TSTContracts.token.mint(aliceAddr, INITIAL_SUPLY);
        TSTContracts.token.mint(bobAddr, INITIAL_SUPLY);
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

        /**
         * UNISWAP V4 DEPLOYMENT
         */
    }

    function test_complianceCanBeBypassed() public {
        // ERC6909FaultPoC is a dummy contract to force compilation of T-REX contracts
        // This test is a placeholder for future tests
    }
}
