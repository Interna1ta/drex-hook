// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.22;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

uint256 constant MAX_SUPPLY = uint256(uint128(type(int128).max));

contract ERC20RDEXWrapper is Initializable, ERC20Upgradeable {

    /* ==================== ERRORS ==================== */

    error ERC20RDEXWrapper__OnlyWhitelistedAddressesCanReceive();

    /* ================== STATE VARS ================== */

    mapping(address => bool) private s_whitelist;

    /* ================== CONSTRUCTOR ================== */

    constructor() {
        _disableInitializers();
    }

    /* ==================== PUBLIC ==================== */

    function initialize(string memory _name, string memory _symbol, address[] memory _whitelist) public initializer {
        __ERC20_init(_name, _symbol);
        _mint(msg.sender, MAX_SUPPLY);
        uint256 whitelistLength = _whitelist.length;
        for (uint256 i = 0; i < whitelistLength; i++) {
            s_whitelist[_whitelist[i]] = true;
        }
    }

    /* ==================== INTERNAL ==================== */

    function _transfer(address _from, address _to, uint256 _amount) internal override {
        if (!s_whitelist[_to]) revert ERC20RDEXWrapper__OnlyWhitelistedAddressesCanReceive();
        super._transfer(_from, _to, _amount);
    }
}
