// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import {RDEXHook} from "src/RDEXHook.sol";
import {RDEXDynamicFeeHook} from "src/RDEXDynamicFeeHook.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";

contract HookAddressMinerInfo is Script {
    // Unichain Sepolia: 1301
    address constant PM_ADDRESS = 0xC81462Fec8B23319F288047f8A03A57682a35C1A;
    // Sepolia: 11155111
    // address constant PM_ADDRESS = 0x8C4BcBE6b9eF47855f97E675296FA3F6fafa5F1A;

    function run() public {
        address owner = 0x1038d5A420AEa8aDc479D654D815f92ADC0106c0;
        address feeHook = 0x74e3A272AE44fDF370659f919d46EA30EBcC9080;
        // RDEXDynamicFeeHook

        // IPoolManager _manager, <- set
        // address _owner, <- set
        // IERC3643IdentityRegistryStorage _identityRegistryStorage,
        // uint256 _reducedFeeClaimTopic,
        // address _reducedFeeClaimTrustedIssuer,
        // uint24 _baseLPFee
        console.log("RDEXDynamicFeeHook");
        console.log("Mask:");
        console.logBytes20(bytes20(uint160(Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_INITIALIZE_FLAG)));
        bytes memory creationCodeWithArgsFeeHook = abi.encodePacked(
            type(RDEXDynamicFeeHook).creationCode, abi.encode(PM_ADDRESS, owner, address(0), 0, address(0), 0)
        );
        console.log("Init code hash:");
        console.logBytes32(keccak256(creationCodeWithArgsFeeHook));

        // RDEXHook

        // Constructor args:
        // IPoolManager _manager, <- set
        // address _owner, <- set
        // IERC3643IdentityRegistryStorage _identityRegistryStorage,
        // uint256 _refCurrencyClaimTopic,
        // address _refCurrencyClaimTrustedIssuer,
        // IHooks _dynamicFeeHook <- immutable
        console.log("RDEXHook");
        console.log("Mask:");
        console.logBytes20(bytes20(uint160(Hooks.BEFORE_INITIALIZE_FLAG)));
        bytes memory creationCodeWithArgsHook = abi.encodePacked(
            type(RDEXHook).creationCode, abi.encode(PM_ADDRESS, owner, address(0), 0, address(0), feeHook)
        );
        console.log("Init code hash:");
        console.logBytes32(keccak256(creationCodeWithArgsHook));
    }
}
