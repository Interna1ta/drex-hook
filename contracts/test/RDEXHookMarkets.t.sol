// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {MockERC20} from "forge-std/mocks/MockERC20.sol";
import {MockERC20} from "forge-std/mocks/MockERC20.sol";

// Uniswap v4 contracts
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";

// ONCHAINID contracts
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";

// RDEX Hook contracts
import {ERC20RDEXWrapper, MAX_SUPPLY} from "../src/ERC20RDEXWrapper.sol";
import {RDEXHook} from "../src/RDEXHook.sol";
import {TREXSuite} from "./utils/TREXSuite.t.sol";

contract MockERC20Mint is MockERC20 {
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

contract RDEXHookMarketsTest is Test, TREXSuite, Deployers {
    using StateLibrary for IPoolManager;

    IIdentity hookIdentity;
    address hookIdentityAdmin = makeAddr("RDEXHookIdentityAdmin");

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
                | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG
        );
        deployCodeTo(
            "RDEXHook.sol:RDEXHook", abi.encode(manager, deployer, 3000, address(0), 0, address(0)), hookAddress
        );
        hook = RDEXHook(hookAddress);

        // Set the identity registry storage of the Hook
        vm.startPrank(deployer);
        hook.setIdentityRegistryStorage(address(identityRegistryStorage));
        vm.stopPrank();

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
    }

    function test_poolWithNonERC3643CompliantTokenCannotBeInitialized() public {
        // Deploy non compliant token
        MockERC20 nonCompliantToken = new MockERC20();
        nonCompliantToken.initialize(NON_COMPLIANT_TOKEN_NAME, NON_COMPLIANT_TOKEN_SYMBOL, DECIMALS);
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
        nonVerifiedRefCurrency.initialize(NON_COMPLIANT_TOKEN_NAME, NON_COMPLIANT_TOKEN_SYMBOL, DECIMALS);
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

    function test_poolWithCompliantTokenAndVerifiedReferenceCurrencyCanBeInitialized() public {
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
        initPool(_currency0, _currency1, IHooks(hook), LPFeeLibrary.DYNAMIC_FEE_FLAG, SQRT_PRICE_1_1);

        // Check if the ERC20 Wrapper has been deployed
        ERC20RDEXWrapper erc20Wrapper = hook.s_ERC3643ToERC20WrapperInstances(address(TSTContracts.token));

        assertEq(erc20Wrapper.totalSupply(), MAX_SUPPLY);
        assertEq(erc20Wrapper.balanceOf(address(hook)), 0);
        assertEq(erc20Wrapper.balanceOf(address(manager)), MAX_SUPPLY);
        assertEq(manager.balanceOf(address(hook), uint256(uint160(address(erc20Wrapper)))), MAX_SUPPLY);

        PoolKey memory poolKey = PoolKey({
            currency0: _currency0,
            currency1: _currency1,
            fee: LPFeeLibrary.DYNAMIC_FEE_FLAG,
            tickSpacing: 60,
            hooks: IHooks(hook)
        });

        (uint160 price,,,) = manager.getSlot0(poolKey.toId());
        assertEq(price, SQRT_PRICE_1_1);

        Currency _WCurrency0;
        Currency _WCurrency1;
        if (address(erc20Wrapper) < address(refCurrency)) {
            _WCurrency0 = Currency.wrap(address(erc20Wrapper));
            _WCurrency1 = Currency.wrap(address(refCurrency));
        } else {
            _WCurrency0 = Currency.wrap(address(refCurrency));
            _WCurrency1 = Currency.wrap(address(erc20Wrapper));
        }
        PoolKey memory poolKeyWrapped = PoolKey({
            currency0: _WCurrency0,
            currency1: _WCurrency1,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(0)) // TODO: Add hook for dynamic fee
        });

        (uint160 priceWrapped,,,) = manager.getSlot0(poolKeyWrapped.toId());
        assertEq(priceWrapped, SQRT_PRICE_1_1);
    }

    function test_tokenOnersShouldBeAbleToModifyLiquidity() public {
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

        // Deposit Liquidity Alice
        vm.startPrank(aliceAddr);
        TSTContracts.token.approve(address(hook), type(uint256).max);
        refCurrency.approve(address(hook), type(uint256).max);

        console.log("ERC3643 address", address(TSTContracts.token));
        console.log("refCurrency address", address(refCurrency));
        console.log("currency 0 address", Currency.unwrap(key.currency0));
        console.log("currency 1 address", Currency.unwrap(key.currency1));
        console.log("Alice balance of stablecoin before deposit: %18e", refCurrency.balanceOf(aliceAddr));
        console.log("Alice balance of ERC3643 before deposit: %18e", TSTContracts.token.balanceOf(aliceAddr));

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

        (uint128 liquidity, uint256 feeGrowthInside0X128, uint256 feeGrowthInside1X128) =
            hook.getPositionInfo(key.toId(), aliceAddr, -60, 60, bytes32(0));
        assertEq(liquidity, 10 ether);

        console.log("Alice balance of stablecoin after deposit: %18e", refCurrency.balanceOf(aliceAddr));
        console.log("Alice balance of ERC3643 after deposit: %18e", TSTContracts.token.balanceOf(aliceAddr));
        console.log("Position liquidity: %18e", liquidity);
        console.log("Position feeGrowthInside0X128:", feeGrowthInside0X128);
        console.log("Position feeGrowthInside1X128:", feeGrowthInside1X128);

        // Remove Liquidity
        hook.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: -5 ether,
                salt: bytes32(0)
            }),
            ZERO_BYTES
        );

        (liquidity, feeGrowthInside0X128, feeGrowthInside1X128) =
            hook.getPositionInfo(key.toId(), aliceAddr, -60, 60, bytes32(0));
        assertEq(liquidity, 5 ether);

        console.log(
            "Alice balance of stablecoin after remove 5 ether of liquidity: %18e", refCurrency.balanceOf(aliceAddr)
        );
        console.log(
            "Alice balance of ERC3643 after remove 5 ether of liquidity: %18e", TSTContracts.token.balanceOf(aliceAddr)
        );
        console.log("Position liquidity: %18e", liquidity);
        console.log("Position feeGrowthInside0X128:", feeGrowthInside0X128);
        console.log("Position feeGrowthInside1X128:", feeGrowthInside1X128);

        hook.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: -5 ether,
                salt: bytes32(0)
            }),
            ZERO_BYTES
        );

        (liquidity, feeGrowthInside0X128, feeGrowthInside1X128) =
            hook.getPositionInfo(key.toId(), aliceAddr, -60, 60, bytes32(0));
        assertEq(liquidity, 0 ether);

        console.log(
            "Alice balance of stablecoin after remove 10 ether of liquidity: %18e", refCurrency.balanceOf(aliceAddr)
        );
        console.log(
            "Alice balance of ERC3643 after remove 10 ether of liquidity: %18e", TSTContracts.token.balanceOf(aliceAddr)
        );
        console.log("Position liquidity: %18e", liquidity);
        console.log("Position feeGrowthInside0X128:", feeGrowthInside0X128);
        console.log("Position feeGrowthInside1X128:", feeGrowthInside1X128);
        vm.stopPrank();
    }
}
