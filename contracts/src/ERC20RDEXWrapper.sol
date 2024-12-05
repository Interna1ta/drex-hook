// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.22;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

uint256 constant MAX_SUPPLY = uint256(uint128(type(int128).max));

contract ERC20RDEXWrapper is Initializable, ERC20Upgradeable {
    mapping(address => bool) private whitelist;

    error OnlyWhitelistedAddressesCanReceive();

    constructor() {
        _disableInitializers();
    }

    function initialize(string memory _name, string memory _symbol, address[] memory _whitelist) public initializer {
        __ERC20_init(_name, _symbol);
        _mint(msg.sender, MAX_SUPPLY);
        uint256 whitelistLength = _whitelist.length;
        for (uint256 i = 0; i < whitelistLength; i++) {
            whitelist[_whitelist[i]] = true;
        }
    }

    function _transfer(address _from, address _to, uint256 _amount) internal override {
        if (!whitelist[_to]) revert OnlyWhitelistedAddressesCanReceive();
        super._transfer(_from, _to, _amount);
    }
}
