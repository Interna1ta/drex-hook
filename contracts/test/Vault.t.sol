// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {MockERC20} from "forge-std/mocks/MockERC20.sol";
import {MockERC20} from "forge-std/mocks/MockERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// Uniswap v4 contracts
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {LPFeeLibrary} from "v4-core/src/libraries/LPFeeLibrary.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";

// ONCHAINID contracts
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";

// RDEX Hook contracts
import {ERC20RDEXWrapper, MAX_SUPPLY} from "../src/ERC20RDEXWrapper.sol";
import {RDEXHook} from "../src/RDEXHook.sol";
import {Vault} from "../src/Vault.sol";
import {TREXSuite} from "./utils/TREXSuite.t.sol";

contract TestERC20 is ERC20 {
    constructor() ERC20("Test", "TEST") {
        _mint(msg.sender, 10000 * 10 ** decimals());
    }

    function mint(address _to, uint256 _amount) external {
        _mint(_to, _amount);
    }
}

contract MockERC20Mint is MockERC20 {
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

contract VaultTest is Test, TREXSuite, Deployers, EIP712("Jurassic", "1") {
    using StateLibrary for IPoolManager;

    IIdentity hookIdentity;
    address hookIdentityAdmin = makeAddr("RDEXHookIdentityAdmin");

    RDEXHook hook;

    uint256 internal refCurrencyClaimIssuerKey;
    address internal refCurrencyClaimIssuerAddr;
    IClaimIssuer internal refCurrencyClaimIssuerIdentity;
    MockERC20Mint internal refCurrency;
    MockERC20Mint internal refRemoteCurrency;


    IIdentity internal refCurrencyIdentity;
    address internal refCurrencyIdentityAdmin = makeAddr("RefCurrencyIdentityAdmin");
    uint256 internal REF_CURRENCY_TOPIC = uint256(keccak256("REF_CURRENCY_TOPIC"));

    string public REF_CURRENCY_NAME = "REF";
    string public REF_CURRENCY_SYMBOL = "REF";
    string public NON_COMPLIANT_TOKEN_NAME = "NAN";
    string public NON_COMPLIANT_TOKEN_SYMBOL = "NAN";
    uint8 public constant DECIMALS = 6;

    uint16 public constant COUNTRY_CODE = 42;

    // specify for vault
    Vault public vault;
    TestERC20 public testERC20;

    Vault public remoteVault;
    TestERC20 public remoteErc20;

    // address public deployer;
    // address public aliceAddr;
    // address public bobAddr;
    address public canonicalSigner;
    uint256 public canonicalSignerPkey;
    address public independentSigner;
    uint256 public independentSignerPkey;

    uint256 public constant BRIDGE_FEE = 0.005 ether;

    struct BridgeRequestData {
        address user;
        address tokenAddress;
        uint256 amountIn;
        uint256 amountOut;
        address destinationVault;
        address destinationAddress;
        uint256 transferIndex;
    }

    function _hooksSetUp() internal {
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

        /**
         *  Deploy Verified Reference Remote Currency
         */
        // Deploy Verified ref currency
        refRemoteCurrency = new MockERC20Mint();
        refRemoteCurrency.initialize("RET", "RET", 6);
        // refRemoteCurrency.mint(address(this), INITIAL_SUPPLY);
        // refRemoteCurrency.mint(aliceAddr, 0);
        // refRemoteCurrency.mint(bobAddr, 0);

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

    function setUp() public {
        vm.label(address(refCurrency), "refCurrency");
        vm.label(address(refRemoteCurrency), "refRemoteCurrency");
        _hooksSetUp();

        // deployer = address(0x4);
        canonicalSigner = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
        canonicalSignerPkey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        console.log("Canonical signer: %s", canonicalSigner);
        (independentSigner, independentSignerPkey) = makeAddrAndKey("indep");
        console.log("Independent signer: %s", independentSigner);

        vm.startPrank(deployer);

        vault = new Vault(deployer);
        vault.setCanonicalSigner(canonicalSigner);
        // testERC20 = new TestERC20();

        vault.setBridgeFee(BRIDGE_FEE);

        remoteVault = new Vault(deployer);
        // remoteErc20 = new TestERC20();

        remoteVault.whitelistSigner(independentSigner);
        remoteVault.setCanonicalSigner(canonicalSigner);

        vm.stopPrank();

        // aliceAddr = address(0x1);
        // bobAddr = address(0x2);

        vm.deal(aliceAddr, 1 ether);
        vm.deal(bobAddr, 1 ether);
        vm.deal(address(vault), 1 ether);
        vm.deal(address(remoteVault), 1 ether);

        // testERC20.mint(address(remoteVault), 10 ether);
        refCurrency.mint(address(remoteVault), 10 ether);
    }

    // forge test -vvv --mt test_bridge_e2e
    function test_bridge_e2e() public {
        // uint256 amount = 10 * 10 ** 18;
        uint256 amount = INITIAL_SUPPLY;
        
        // testERC20.mint(aliceAddr, amount);
        // remoteErc20.mint(address(remoteVault), amount);
        // refCurrency.mint(aliceAddr, amount);
        refRemoteCurrency.mint(address(remoteVault), amount); // TODO: check if this is correct

        // assertEq(testERC20.balanceOf(aliceAddr), amount);
        // assertEq(remoteErc20.balanceOf(address(remoteVault)), amount);
        assertEq(refCurrency.balanceOf(aliceAddr), amount);
        assertEq(refRemoteCurrency.balanceOf(address(remoteVault)), amount);
        // Alice bridges the tokens
        vm.startPrank(aliceAddr);

        Vault.BridgeRequestData memory brd = Vault.BridgeRequestData({
            user: aliceAddr,
            // tokenAddress: address(testERC20),
            tokenAddress: address(refCurrency),
            amountIn: amount,
            amountOut: amount,
            destinationVault: address(remoteVault),
            destinationAddress: aliceAddr,
            transferIndex: uint256(0)
        });

        bytes32 digest = remoteVault.getDigest(brd);

        console.logBytes32(digest);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(canonicalSignerPkey, digest);

        bytes memory canonicalSig = abi.encodePacked(r1, s1, v1);

        console.logBytes(canonicalSig);

        // testERC20.approve(address(vault), amount);
        // vault.bridge{value: BRIDGE_FEE}(address(testERC20), amount, amount, address(remoteVault), aliceAddr);
        refCurrency.approve(address(vault), amount);
        vault.bridge{value: BRIDGE_FEE}(address(refCurrency), amount, amount, address(remoteVault), aliceAddr);

        vm.stopPrank();

        // Verify Alice's tokens are in the source vault
        // assertEq(testERC20.balanceOf(address(vault)), amount);
        // assertEq(testERC20.balanceOf(aliceAddr), 0);
        assertEq(refCurrency.balanceOf(address(vault)), amount);
        assertEq(refCurrency.balanceOf(aliceAddr), 0);

        vm.startPrank(deployer);
        remoteVault.whitelistSigner(independentSigner);

        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(independentSignerPkey, digest);

        // Bob calls the crank with the signatures
        vm.startPrank(bobAddr);

        remoteVault.releaseFunds(canonicalSig, brd);

        vm.stopPrank();

        // Verify Alice receives the target tokens
        // assertEq(testERC20.balanceOf(aliceAddr), amount);
        assertEq(refCurrency.balanceOf(aliceAddr), amount);

        // Verify Bob receives the crank fee
        assertEq(bobAddr.balance, 1 ether);

        // Verify invalid signatures revert
        bytes32 invalidMessageHash = keccak256(abi.encodePacked(uint256(123)));
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(uint256(uint160(canonicalSigner)), invalidMessageHash);

        vm.expectRevert("Invalid canonical signature");
        remoteVault.releaseFunds(abi.encodePacked(r2, s2, v2), brd);

        // Verify non-matching third-party signature reverts
        //   (uint8 v4, bytes32 r4, bytes32 s4) = vm.sign(
        //       uint256(uint160(address(0x7))),
        //        digest
        //    );

        vm.expectRevert("Invalid signature");
        remoteVault.releaseFunds(abi.encodePacked(r1, s1, v1), brd);
    }

    function test_publishAttestation() public {
        vm.startPrank(deployer);
        vault.whitelistSigner(canonicalSigner);

        vm.startPrank(canonicalSigner);

        bytes memory attestation = abi.encodePacked("attestation");
        vault.publishAttestation(0, attestation);

        vm.stopPrank();
    }
}
