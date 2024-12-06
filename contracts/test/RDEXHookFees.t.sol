// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {MockERC20} from "forge-std/mocks/MockERC20.sol";

// Uniswap v4 contracts
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";
import {Currency} from "v4-core/src/types/Currency.sol";

// ONCHAINID contracts
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";

// RDEX Hook contracts
import {RDEXHook} from "src/RDEXHook.sol";
import {TREXSuite} from "./utils/TREXSuite.t.sol";
import {PoolSwapTest} from "v4-core/src/test/PoolSwapTest.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";

contract MockERC20Mint is MockERC20 {
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

contract RDEXHookFeesTest is Test, TREXSuite, Deployers {
    RDEXHook hook;

    uint256 internal refCurrencyClaimIssuerKey;
    address internal refCurrencyClaimIssuerAddr;
    IClaimIssuer internal refCurrencyClaimIssuerIdentity;
    MockERC20 internal refCurrency;
    IIdentity internal refCurrencyIdentity;
    address internal refCurrencyIdentityAdmin = makeAddr("RefCurrencyIdentityAdmin");
    uint256 internal REF_CURRENCY_TOPIC = uint256(keccak256("REF_CURRENCY_TOPIC"));

    uint256 internal DISCOUNT_TOPIC = uint256(keccak256("DISCOUNT_TOPIC"));

    uint16 public constant MOCK_DISCOUNT = 1000;

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
         * RDEXHook deployment
         */
        // Deploy Hook
        address hookAddress = address(
            (uint160(makeAddr("RDEXHook")) & ~Hooks.ALL_HOOK_MASK) | Hooks.BEFORE_INITIALIZE_FLAG
        );
        deployCodeTo(
            "RDEXHook.sol:RDEXHook", abi.encode(manager, deployer, 3000, address(0), 0, address(0)), hookAddress
        );
        hook = RDEXHook(hookAddress);
        swapRouter = new PoolSwapTest(manager);

        // Set the identity registry storage of the Hook
        vm.startPrank(deployer);
        hook.setIdentityRegistryStorage(address(identityRegistryStorage));
        vm.stopPrank();

        // Deploy ref currency claim issuer identity
        (refCurrencyClaimIssuerAddr, refCurrencyClaimIssuerKey) = makeAddrAndKey("RefCurrencyClaimIssuer");
        vm.startPrank(refCurrencyClaimIssuerAddr);
        refCurrencyClaimIssuerIdentity =
            IClaimIssuer(deployArtifact("out/ClaimIssuer.sol/ClaimIssuer.json", abi.encode(refCurrencyClaimIssuerAddr)));
        refCurrencyClaimIssuerIdentity.addKey(keccak256(abi.encode(refCurrencyClaimIssuerAddr)), 3, 1);
        vm.stopPrank();

        // Register ref currency claim issuer in the Hook
        vm.startPrank(deployer);
        hook.setRefCurrencyClaimTrustedIssuer(address(refCurrencyClaimIssuerIdentity));
        // Register ref currency claim topic in the Hook
        hook.setRefCurrencyClaimTopic(REF_CURRENCY_TOPIC);
        vm.stopPrank();

        /**
         *  Deploy Verified Reference Currency
         */
        // Deploy Verified ref currency
        refCurrency = new MockERC20Mint();
        refCurrency.initialize("REF", "REF", 6);
        // TODO: Mint ref currency to users
        // Deploy ref currency identity
        vm.startPrank(refCurrencyIdentityAdmin);
        refCurrencyIdentity = IIdentity(
            deployArtifact("out/IdentityProxy.sol/IdentityProxy.json", abi.encode(identityIA, refCurrencyIdentityAdmin))
        );
        vm.stopPrank();
        // Issue a claim for the ref currency identity
        ClaimData memory claimForRefCurrency =
            ClaimData(refCurrencyIdentity, REF_CURRENCY_TOPIC, "This is a verified stable coin by the SEC!");
        //Issue a discount claim for the ref currency identity
        ClaimData memory claimForDiscount =
            ClaimData(refCurrencyIdentity, DISCOUNT_TOPIC, "This topic will have a discount!");
        bytes memory signatureRefCurrencyClaim = signClaim(claimForRefCurrency, refCurrencyClaimIssuerKey);

        bytes memory signatureDiscountClaim = signClaim(claimForDiscount, refCurrencyClaimIssuerKey);
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

        refCurrencyIdentity.addClaim(
            claimForDiscount.topic,
            1,
            address(refCurrencyClaimIssuerIdentity),
            signatureDiscountClaim,
            claimForDiscount.data,
            ""
        );
        vm.stopPrank();
        // Register  Identity in the identinty registry storage
        vm.startPrank(identityRegistryStorageAgent);
        identityRegistryStorage.addIdentityToStorage(address(refCurrency), refCurrencyIdentity, 42);
        vm.stopPrank();
    }

    function test_poolWithNonERC3643CompliantTokenCannotBeInitialized() public {
        // Deploy non compliant token
        MockERC20 nonCompliantToken = new MockERC20();
        nonCompliantToken.initialize("NON", "NON", 6);
        Currency _currency0;
        Currency _currency1;
        if (address(nonCompliantToken) < address(refCurrency)) {
            _currency0 = Currency.wrap(address(nonCompliantToken));
            _currency1 = Currency.wrap(address(refCurrency));
        } else {
            _currency0 = Currency.wrap(address(refCurrency));
            _currency1 = Currency.wrap(address(nonCompliantToken));
        }
        // Init Pool
        vm.expectRevert();
        initPool(_currency0, _currency1, IHooks(hook), LPFeeLibrary.DYNAMIC_FEE_FLAG, SQRT_PRICE_1_1);
    }

    function test_poolWithNonVerifiedReferenceCurrencyCannotBeInitialized() public {
        // Deploy non compliant token
        MockERC20 nonVerifiedRefCurrency = new MockERC20();
        nonVerifiedRefCurrency.initialize("NON", "NON", 6);
        Currency _currency0;
        Currency _currency1;
        if (address(nonVerifiedRefCurrency) < address(TSTContracts.token)) {
            _currency0 = Currency.wrap(address(nonVerifiedRefCurrency));
            _currency1 = Currency.wrap(address(TSTContracts.token));
        } else {
            _currency0 = Currency.wrap(address(TSTContracts.token));
            _currency1 = Currency.wrap(address(nonVerifiedRefCurrency));
        }
        // Init Pool
        vm.expectRevert();
        initPool(_currency0, _currency1, IHooks(hook), LPFeeLibrary.DYNAMIC_FEE_FLAG, SQRT_PRICE_1_1);
    }

    function test_discountTopicsGetApplied() public {
        // Set up our swap parameters
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: -0.00001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        uint256[] memory discountTopics = new uint256[](1);
        discountTopics[0] = DISCOUNT_TOPIC;
        vm.startPrank(deployer);
        //  hook.setTopicsWithDiscount(discountTopics);
        //  hook.setDynamicFee(DISCOUNT_TOPIC, MOCK_DISCOUNT);

        //  uint256 balanceOfToken1Before = currency1.balanceOfSelf();

        //   hook.swap(key, params, testSettings, ZERO_BYTES);
        //    uint256 balanceOfToken1After = currency1.balanceOfSelf();
        //    uint256 outputFromBaseFeeSwap = balanceOfToken1After -
        //        balanceOfToken1Before;

        //   assertGt(balanceOfToken1After, balanceOfToken1Before);

        //   assertEq(outputFromBaseFeeSwap, MOCK_DISCOUNT);

        //   assertEq(hook.dynamicFee(DISCOUNT_TOPIC), MOCK_DISCOUNT);
        vm.stopPrank();

        // Swap happens with discount
    }

    function test_minimumFeeGetsAppliedIfDiscountTooBig() public {
        // Set up our swap parameters
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: -0.00001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        uint256[] memory discountTopics = new uint256[](1);
        discountTopics[0] = DISCOUNT_TOPIC;
        vm.startPrank(deployer);
        // hook.setTopicsWithDiscount(discountTopics);
        //hook.setDynamicFee(DISCOUNT_TOPIC, 1000000);

        //  uint256 balanceOfToken1Before = currency1.balanceOfSelf();

        //   hook.swap(key, params, testSettings, ZERO_BYTES);
        //    uint256 balanceOfToken1After = currency1.balanceOfSelf();
        //    uint256 outputFromBaseFeeSwap = balanceOfToken1After -
        //        balanceOfToken1Before;

        //   assertGt(balanceOfToken1After, balanceOfToken1Before);

        //   assertEq(outputFromBaseFeeSwap, MINIMUM_FEE);

        //   assertEq(hook.dynamicFee(DISCOUNT_TOPIC), 1000);
        vm.stopPrank();

        // Swap happens with discount
    }
}
