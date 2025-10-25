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
        supportedTokens[0] = address(0x0); // Native HBAR
        supportedTokens[1] = address(0x7AEb2F07D1C5ca792D1D2966215E03C9F90e99E8); // bNGN token address on Hedera
        string[] memory supportedProtocols = new string[](0);
        uint64 defaultTimeoutHeight = 300;

        BeepContract beep = new BeepContract(supportedTokens, supportedProtocols, defaultTimeoutHeight);
        console.log("BeepContract deployed to:", address(beep));

        vm.stopBroadcast();
    }
}
