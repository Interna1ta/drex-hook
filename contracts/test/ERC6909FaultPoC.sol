// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {TREXSuite} from "./utils/TREXSuite.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";

contract ERC6909FaultPoC is Test, TREXSuite {
    // TST TOKEN
    address public TSTtokenIssuer = makeAddr("TokenIssuer");
    address public TSTtokenAgent = makeAddr("TokenAgent");
    address public TSTtokenAdmin = makeAddr("TokenAdmin");
    address public TSTclaimIssuerAddr;
    uint256 public TSTclaimIssuerKey;
    IClaimIssuer public TSTclaimIssuerIdentity;

    TokenContracts public TSTContracts;

    // Entities
    address public AliceAddr;
    IIdentity public AliceIdentity;
    uint256 public AliceKey;
    
    address public BobAddr;
    IIdentity public BobIdentity;
    uint256 public BobKey;

    address public CharlieAddr;
    IIdentity public CharlieIdentity;
    uint256 public CharlieKey;


    function setUp() public {
        deployTREXFactory();
        deployToken("TEST", "TST", 18, TSTtokenIssuer, TSTtokenAgent, TSTtokenAdmin, TSTContracts);

        // Add sample claim topics
        vm.startPrank(deployer);
        uint256[] memory topics = new uint256[](1);
        topics[0] = uint256(keccak256("CLAIM_TOPIC"));
        TSTContracts.claimTopicsRegistry.addClaimTopic(topics[0]);
        vm.stopPrank();

        // Deploy claim issuer idenitity
        (TSTclaimIssuerAddr, TSTclaimIssuerKey) = makeAddrAndKey("ClaimIssuer");
        vm.startPrank(TSTclaimIssuerAddr);
        TSTclaimIssuerIdentity =
            IClaimIssuer(deployArtifact("out/ClaimIssuer.sol/ClaimIssuer.json", abi.encode(TSTclaimIssuerAddr)));
        TSTclaimIssuerIdentity.addKey(keccak256(abi.encode(TSTclaimIssuerAddr)), 3, 1);
        vm.stopPrank();

        // Add issuer to trusted issuers registry
        vm.startPrank(deployer);
        TSTContracts.trustedIssuersRegistry.addTrustedIssuer((TSTclaimIssuerIdentity), topics);
        vm.stopPrank();

        // Deploy Alice identity
        vm.startPrank(deployer);
        (AliceAddr, AliceKey) = makeAddrAndKey("Alice");
        AliceIdentity = IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, AliceAddr)));
        
        // Deploy Bob identity
        (BobAddr, BobKey) = makeAddrAndKey("Bob");
        BobIdentity = IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, BobAddr)));
        
        // Deploy Charlie identity
        (CharlieAddr, CharlieKey) = makeAddrAndKey("Charlie");
        CharlieIdentity = IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, CharlieAddr)));
        vm.stopPrank();

        // Add new key in Alice identity
        vm.startPrank(AliceAddr);
        AliceIdentity.addKey(keccak256(abi.encode(AliceAddr)), 2, 1);
        vm.stopPrank();

        vm.startPrank(deployer);
        // Add new agents to the token
        TSTContracts.identityRegistry.addAgent(address(TSTtokenAgent));        
        TSTContracts.identityRegistry.addAgent(address(TSTContracts.token));        
        
        // TODO: Register Alice and Bob identities in the claim registry
        vm.stopPrank();
    }

    function test_complianceCanBeBypassed() public {
        // ERC6909FaultPoC is a dummy contract to force compilation of T-REX contracts
        // This test is a placeholder for future tests
    }
}
