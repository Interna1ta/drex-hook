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

contract DeploySystem is Script {
    address constant owner = 0x1038d5A420AEa8aDc479D654D815f92ADC0106c0;

    // Unichain Sepolia: 1301
    address constant PM_ADDRESS = 0xC81462Fec8B23319F288047f8A03A57682a35C1A;
    // Sepolia: 11155111
    // address constant PM_ADDRESS = 0x8C4BcBE6b9eF47855f97E675296FA3F6fafa5F1A;

    IPoolManager manager = IPoolManager(PM_ADDRESS);

    function run() public {
        vm.startBroadcast();

        /**
         *   Deploy TREX suitei
         */
        // Contracts
        ITREXImplementationAuthority trexIA;
        ITREXFactory trexFactory;
        IImplementationAuthority identityIA;
        IIdFactory identityFactory;
        IERC3643IdentityRegistryStorage identityRegistryStorage;

        /**
         * Deploy UHI ERC3643 Token
         */

        /**
         * Deploy Hooks to determinisitic address with create 2
         */
        // Unichain Sepolia: 1301
        address feeHookAddr = 0x74e3A272AE44fDF370659f919d46EA30EBcC9080;
        bytes32 feeHookSalt = 0xdc0d29918bce0d14e86332e1de811666d755e3d8a0157ff64182a3d365c4062a;
        // Sepolia: 11155111
        //address feeHookAddr = 0xFD75d54faf4062D2B465964Aa55B8e0543C79080;
        //bytes32 feeHookSalt = 0x92dcfaac179029f091009a4e71483ecbc4ad757f92391e4f3c461cdd8b57d198;
        // new RDEXDynamicFeeHook{salt: feeHookSalt}(
        //      manager, owner, IERC3643IdentityRegistryStorage(address(0)), 0, address(0), 0
        //  );

        // Unichain Sepolia: 1301
        address hookAddr = 0x25A8680890d9A8E61F6B2ee68f845321c10B2000;
        bytes32 hookSalt = 0xe5e30d7a533454505ffb586546381a7aaa6ec352497a1a62c172b40ed3d5f792;
        // Sepolia: 11155111
        //address hookAddr = 0x422096783AB2a81a230D3b9DcaFd8c337b24a000;
        //bytes32 hookSalt = 0x646a804fff68e4334ed4d2f0e5a224f81aa82dd8d0a4cb91429cd3db114b1f94;
        //new RDEXHook{salt: hookSalt}(
        //    manager, owner, IERC3643IdentityRegistryStorage(address(0)), 0, address(0), IHooks(address(feeHookAddr))
        //);
        /**
         * Deploy ONCHAINID for my user
         */
        vm.stopBroadcast();
    }
}
