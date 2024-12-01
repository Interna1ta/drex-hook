// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {TREXSuite} from "./utils/TREXSuite.sol";

contract ERC6909FaultPoC is Test, TREXSuite {
    function setUp() public {
        deployTREXFactory();
    }

    function test_complianceCanBeBypassed() public {
        // ERC6909FaultPoC is a dummy contract to force compilation of T-REX contracts
        // This test is a placeholder for future tests
    }
}
