// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

// Uniswap v4 contracts
import {Deployers} from "v4-core/test/utils/Deployers.sol";
import {Currency} from "v4-core/src/types/Currency.sol";

// ONCHAINID contracts
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";

// RDEX Hook contracts
import {TREXSuite} from "./utils/TREXSuite.t.sol";

contract ERC6909ProblemPoC is Test, TREXSuite, Deployers {
    uint256 public constant AMOUNT = 100;
    uint16 public constant COUNTRY_CODE = 42;

    function setUp() public {
        /**
         * TREX INFRA + TOKEN DEPLOYMENT + USERS IDENTITY DEPLOYMENTS
         */
        deployTREXFactory();
        deployTSTTokenSchenario();
        /**
         * UNISWAP V4 DEPLOYMENT
         */
        deployFreshManagerAndRouters();
    }

    function test_nonWhitelistedUserCannotReceiveERC3643Tokens() public {
        vm.startPrank(aliceAddr);
        vm.expectRevert();
        TSTContracts.token.transfer(charlieAddr, AMOUNT);
        vm.stopPrank();
    }

    function test_UniV4CannotReceiveERC3643Tokens() public {
        vm.startPrank(aliceAddr);
        vm.expectRevert(); // isVerified call fails since PoolManager is not whitelisted
        claimsRouter.deposit(Currency.wrap(address(TSTContracts.token)), aliceAddr, AMOUNT);
        vm.stopPrank();
    }

    function test_complianceCanBeBypassed() public {
        /**
         * To allow to the pool manager to have ERC-3643 tokens in his balance,
         * the first thought is to create an identitiy and whitelist it , nevertheless
         * this can be problematic since ERC6909 can be used to bypass  compliance rules.
         */
        // Deploy PoolManager identity
        address PMIdAdmin = makeAddr("PMIdAdmin");
        vm.startPrank(PMIdAdmin);
        IIdentity PMId =
            IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, PMIdAdmin)));
        vm.stopPrank();

        // Register PoolManager identity in the identity registry
        vm.startPrank(TSTTokenAgent);
        TSTContracts.identityRegistry.registerIdentity(address(manager), PMId, COUNTRY_CODE);
        vm.stopPrank();

        //  Sign claim for PoolManager identity
        ClaimData memory claim = ClaimData(PMId, TOPIC, "PoolManager public data!");
        bytes memory signatureClaim = signClaim(claim, TSTClaimIssuerKey);

        // Add claim to PoolManager identity
        vm.startPrank(PMIdAdmin);
        PMId.addClaim(claim.topic, 1, address(TSTClaimIssuerIdentity), signatureClaim, claim.data, "");
        vm.stopPrank();

        // Now Alice can deposit tokens and Mint ERC-6909 tokens
        Currency currency = Currency.wrap(address(TSTContracts.token));
        vm.startPrank(aliceAddr);
        TSTContracts.token.approve(address(claimsRouter), AMOUNT);
        claimsRouter.deposit(currency, aliceAddr, AMOUNT);
        vm.stopPrank();
        assertEq(manager.balanceOf(aliceAddr, currency.toId()), AMOUNT);

        // Now Alice can send claim tokens charlie, this is wrong since charlie is not whitelisted
        vm.startPrank(aliceAddr);
        manager.transfer(charlieAddr, currency.toId(), AMOUNT);
        vm.stopPrank();
        console.log("This is wrong since charlie is not whitelisted:");
        console.log(
            "Charlie balance of TEST(as ERC-6909 claim tokens in PoolManager):",
            manager.balanceOf(charlieAddr, currency.toId())
        );
        console.log("Charlie isVerified:", TSTContracts.identityRegistry.isVerified(charlieAddr));
    }
}
