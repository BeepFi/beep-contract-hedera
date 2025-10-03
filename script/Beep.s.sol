// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {BeepContract} from "../src/BeepContract.sol";

contract BeepScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("HEDERA_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        address[] memory supportedTokens = new address[](2);
        supportedTokens[0] = address(0x4); // Mock token1
        supportedTokens[1] = address(0x5); // Mock token2
        string[] memory supportedProtocols = new string[](1);
        supportedProtocols[0] = "protocol1";
        uint64 defaultTimeoutHeight = 100;
        
        BeepContract beep = new BeepContract(supportedTokens, supportedProtocols, defaultTimeoutHeight);
        console.log("BeepContract deployed to:", address(beep));

        vm.stopBroadcast();
    }
}