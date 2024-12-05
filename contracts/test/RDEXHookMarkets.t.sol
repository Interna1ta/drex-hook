// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {TREXSuite} from "./utils/TREXSuite.t.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {RDEXHook} from "src/RDEXHook.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {MockERC20} from "forge-std/mocks/MockERC20.sol";
import {ERC20RDEXWrapper, MAX_SUPPLY} from "src/ERC20RDEXWrapper.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";

contract MockERC20Mint is MockERC20 {
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

contract RDEXHookMarketsTest is Test, TREXSuite, Deployers {
    using StateLibrary for IPoolManager;

    RDEXHook hook;
    IIdentity hookIdentity;
    address hookIdentityAdmin = makeAddr("RDEXHookIdentityAdmin");

    uint256 internal refCurrencyClaimIssuerKey;
    address internal refCurrencyClaimIssuerAddr;
    IClaimIssuer internal refCurrencyClaimIssuerIdentity;
    MockERC20 internal refCurrency;
    IIdentity internal refCurrencyIdentity;
    address internal refCurrencyIdentityAdmin = makeAddr("RefCurrencyIdentityAdmin");
    uint256 internal REF_CURRENCY_TOPIC = uint256(keccak256("REF_CURRENCY_TOPIC"));

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
        address hookAddress =
            address((uint160(makeAddr("RDEXHook")) & ~Hooks.ALL_HOOK_MASK) | Hooks.BEFORE_INITIALIZE_FLAG);
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
        ERC20RDEXWrapper erc20Wrapper = hook.ERC3643ToERC20WrapperInstances(address(TSTContracts.token));

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
}
