// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {MockERC20} from "forge-std/mocks/MockERC20.sol";

// Uniswap v4 contracts
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {PoolSwapTest} from "v4-core/src/test/PoolSwapTest.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";

// ONCHAINID contracts
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";

// RDEX Hook contracts
import {RDEXHook} from "src/RDEXHook.sol";
import {TREXSuite} from "./utils/TREXSuite.t.sol";
import {RDEXDynamicFeeHook} from "../src/RDEXDynamicFeeHook.sol";

contract MockERC20Mint is MockERC20 {
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

contract RDEXHookFeesTest is Test, TREXSuite, Deployers {
    using StateLibrary for IPoolManager;

    IIdentity hookIdentity;
    address hookIdentityAdmin = makeAddr("RDEXHookIdentityAdmin");

    RDEXDynamicFeeHook feesHook;
    RDEXHook hook;

    uint256 internal refCurrencyClaimIssuerKey;
    address internal refCurrencyClaimIssuerAddr;
    IClaimIssuer internal refCurrencyClaimIssuerIdentity;
    MockERC20Mint internal refCurrency;
    IIdentity internal refCurrencyIdentity;
    address internal refCurrencyIdentityAdmin = makeAddr("RefCurrencyIdentityAdmin");
    uint256 internal REF_CURRENCY_TOPIC = uint256(keccak256("REF_CURRENCY_TOPIC"));

    string public REF_CURRENCY_NAME = "REF";
    string public REF_CURRENCY_SYMBOL = "REF";
    string public NON_COMPLIANT_TOKEN_NAME = "NAN";
    string public NON_COMPLIANT_TOKEN_SYMBOL = "NAN";
    uint8 public constant DECIMALS = 6;

    uint16 public constant COUNTRY_CODE = 42;

    uint16 public constant MOCK_REDUCED_FEE = 300;
    uint256 internal REDUCED_FEE_TOPIC = uint256(keccak256("REDUCED_FEE_TOPIC "));
    uint256 internal reducedFeeClaimIssuerKey;
    address internal reducedFeeClaimIssuerAddr;
    IClaimIssuer internal reducedFeeClaimIssuerIdentity;

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

        /*
        * RDEXDynamicFeeHook deployment
        */
        // Deploy reducedFee claim issuer identity
        (reducedFeeClaimIssuerAddr, reducedFeeClaimIssuerKey) = makeAddrAndKey("ReducedFeeClaimIssuer");
        vm.startPrank(reducedFeeClaimIssuerAddr);
        reducedFeeClaimIssuerIdentity =
            IClaimIssuer(deployArtifact("out/ClaimIssuer.sol/ClaimIssuer.json", abi.encode(reducedFeeClaimIssuerAddr)));
        reducedFeeClaimIssuerIdentity.addKey(keccak256(abi.encode(reducedFeeClaimIssuerAddr)), 3, 1);
        vm.stopPrank();

        // Deploy Hook
        address dynamicFeeHookAddress =
            address((uint160(makeAddr("RDEXDynamicFeeHook")) & ~Hooks.ALL_HOOK_MASK) | Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_INITIALIZE_FLAG);
        deployCodeTo(
            "RDEXDynamicFeeHook.sol:RDEXDynamicFeeHook",
            abi.encode(
                manager,
                deployer,
                address(identityRegistryStorage),
                REDUCED_FEE_TOPIC,
                reducedFeeClaimIssuerIdentity,
                3000
            ),
            dynamicFeeHookAddress
        );
        feesHook = RDEXDynamicFeeHook(dynamicFeeHookAddress);

        /*
         * RDEXHook deployment
         */
        // Deploy Hook
        address hookAddress =
            address((uint160(makeAddr("RDEXHook")) & ~Hooks.ALL_HOOK_MASK) | Hooks.BEFORE_INITIALIZE_FLAG);
        deployCodeTo(
            "RDEXHook.sol:RDEXHook",
            abi.encode(
                manager,
                deployer,
                address(identityRegistryStorage),
                REF_CURRENCY_TOPIC,
                address(0),
                dynamicFeeHookAddress
            ),
            hookAddress
        );
        hook = RDEXHook(hookAddress);

        // Deploy Hook identity
        vm.startPrank(hookIdentityAdmin);
        hookIdentity = IIdentity(
            deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, hookIdentityAdmin))
        );
        vm.stopPrank();

        // Add identity of the hook to the identity registry of TSTToken
        vm.startPrank(TSTTokenAgent);
        TSTContracts.identityRegistry.registerIdentity(address(hook), hookIdentity, 43);
        vm.stopPrank();

        // Sign claim for the hook identity
        ClaimData memory claimForHook =
            ClaimData(hookIdentity, TOPIC, "This is the claim for the hook to hold TST token");
        bytes memory signatureHookClaim = signClaim(claimForHook, TSTClaimIssuerKey);

        // Add claim to the hook identity
        vm.startPrank(hookIdentityAdmin);
        hookIdentity.addClaim(
            claimForHook.topic, 1, address(TSTClaimIssuerIdentity), signatureHookClaim, claimForHook.data, ""
        );
        vm.stopPrank();
        /**
         *  Deploy Verified Reference Currency
         */

        // Deploy ref currency claim issuer identity
        (refCurrencyClaimIssuerAddr, refCurrencyClaimIssuerKey) = makeAddrAndKey("RefCurrencyClaimIssuer");
        vm.startPrank(refCurrencyClaimIssuerAddr);
        refCurrencyClaimIssuerIdentity =
            IClaimIssuer(deployArtifact("out/ClaimIssuer.sol/ClaimIssuer.json", abi.encode(refCurrencyClaimIssuerAddr)));
        refCurrencyClaimIssuerIdentity.addKey(keccak256(abi.encode(refCurrencyClaimIssuerAddr)), 3, 1);
        vm.stopPrank();

        // Register ref currency claim issuer in the Hooks
        vm.startPrank(deployer);
        hook.setRefCurrencyClaimTrustedIssuer(address(refCurrencyClaimIssuerIdentity));
        vm.stopPrank();

        /**
         *  Deploy Verified Reference Currency
         */
        // Deploy Verified ref currency
        refCurrency = new MockERC20Mint();
        refCurrency.initialize("REF", "REF", 6);
        refCurrency.mint(address(this), INITIAL_SUPPLY);
        refCurrency.mint(aliceAddr, INITIAL_SUPPLY);
        refCurrency.mint(bobAddr, INITIAL_SUPPLY);

        // Deploy ref currency identity
        vm.startPrank(refCurrencyIdentityAdmin);
        refCurrencyIdentity = IIdentity(
            deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, refCurrencyIdentityAdmin))
        );
        vm.stopPrank();
        // Issue a claim for the ref currency identity
        ClaimData memory claimForRefCurrency =
            ClaimData(refCurrencyIdentity, REF_CURRENCY_TOPIC, "This is a verified stable coin by the SEC!");
        bytes memory signatureRefCurrencyClaim = signClaim(claimForRefCurrency, refCurrencyClaimIssuerKey);
        //// Add claim to ref currency identity
        vm.startPrank(refCurrencyIdentityAdmin);
        refCurrencyIdentity.addClaim(
            claimForRefCurrency.topic,
            1,
            address(refCurrencyClaimIssuerIdentity),
            signatureRefCurrencyClaim,
            claimForRefCurrency.data,
            ""
        );
        vm.stopPrank();
        // Register  Identity in the identinty registry storage
        vm.startPrank(identityRegistryStorageAgent);
        identityRegistryStorage.addIdentityToStorage(address(refCurrency), refCurrencyIdentity, COUNTRY_CODE);
        vm.stopPrank();

        /**
         * Issue Reduced Fees claim for Alice
         */
        ClaimData memory reducedFeeClaimForAlice =
            ClaimData(aliceIdentity, REDUCED_FEE_TOPIC, abi.encode(MOCK_REDUCED_FEE));
        bytes memory signatureReducedFeeClaimForAlice = signClaim(reducedFeeClaimForAlice, reducedFeeClaimIssuerKey);
        vm.startPrank(aliceAddr);
        aliceIdentity.addClaim(
            reducedFeeClaimForAlice.topic,
            1,
            address(reducedFeeClaimIssuerIdentity),
            signatureReducedFeeClaimForAlice,
            reducedFeeClaimForAlice.data,
            ""
        );
        vm.stopPrank();

        /**
         *  init Pool
         */
        Currency _currency0;
        Currency _currency1;
        if (address(refCurrency) < address(TSTContracts.token)) {
            _currency0 = Currency.wrap(address(refCurrency));
            _currency1 = Currency.wrap(address(TSTContracts.token));
        } else {
            _currency0 = Currency.wrap(address(TSTContracts.token));
            _currency1 = Currency.wrap(address(refCurrency));
        }
        // Init Pool
        (key,) = initPool(_currency0, _currency1, IHooks(hook), LPFeeLibrary.DYNAMIC_FEE_FLAG, SQRT_PRICE_1_1);

        /**
         *  Add liquidity to the pool
         */
        // Deposit Liquidity Alice
        vm.startPrank(aliceAddr);
        TSTContracts.token.approve(address(hook), type(uint256).max);
        refCurrency.approve(address(hook), type(uint256).max);

        // Deposit Liquidity
        hook.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: 10 ether,
                salt: bytes32(0)
            }),
            ZERO_BYTES
        );
        vm.stopPrank();

        // Deposit Liquidity Bob
        vm.startPrank(bobAddr);
        TSTContracts.token.approve(address(hook), type(uint256).max);
        refCurrency.approve(address(hook), type(uint256).max);

        // Deposit Liquidity
        hook.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -240,
                tickUpper: 240,
                liquidityDelta: 10 ether,
                salt: bytes32(0)
            }),
            ZERO_BYTES
        );
        vm.stopPrank();
    }

    function test_discountTopicsGetApplied() public {
        uint256 snap = vm.snapshotState();
        console.log("Allice exact input swap:");
        // swap with discount
        vm.startPrank(aliceAddr);
        uint256 aliceCurrency1BalanceBefore = key.currency1.balanceOf(aliceAddr);
        hook.swap(
            key,
            IPoolManager.SwapParams({
                zeroForOne: true,
                amountSpecified: -1000000,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            true
        );
        console.log(
            "Amount Received with discount (300):", key.currency1.balanceOf(aliceAddr) - aliceCurrency1BalanceBefore
        );
        vm.stopPrank();

        vm.revertToState(snap);
        // swap without discount
        vm.startPrank(aliceAddr);
        aliceCurrency1BalanceBefore = key.currency1.balanceOf(aliceAddr);
        hook.swap(
            key,
            IPoolManager.SwapParams({
                zeroForOne: true,
                amountSpecified: -1000000,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            false
        );
        console.log(
            "Amount Received without discount (3000):",
            key.currency1.balanceOf(aliceAddr) - aliceCurrency1BalanceBefore
        );
        vm.stopPrank();
    }

    function test_swapShoudlRevertIfDiscountIsSetButUserHasNotTheClaim() public {
        // swap withouth discount
        vm.startPrank(bobAddr);
        vm.expectRevert();
        hook.swap(
            key,
            IPoolManager.SwapParams({
                zeroForOne: true,
                amountSpecified: -100,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            true
        );
        hook.swap(
            key,
            IPoolManager.SwapParams({
                zeroForOne: true,
                amountSpecified: -100,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            false
        );
        vm.stopPrank();
    }
}
