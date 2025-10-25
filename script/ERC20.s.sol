// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {BeepERC20} from "../src/ERC20.sol";

contract ERC20Script is Script {
    function run() external {
        // Load the HEDERA_PRIVATE_KEY from environment variables
        uint256 deployerPrivateKey = vm.envUint("HEDERA_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        console.log("Deployer address:", deployer);
        console.log("Deployer balance:", deployer.balance / 1e18, "HBAR");

        // Start broadcasting with HEDERA_PRIVATE_KEY
        vm.startBroadcast(deployerPrivateKey);

        // Deploy token with name "Beep NGN" and symbol "bNGN"
        BeepERC20 bNGN = new BeepERC20(deployer, "Beep NGN", "bNGN");
        console.log("bNGN token deployed to:", address(bNGN));

        // Optionally mint initial supply (e.g., 1,000,000 bNGN with 18 decimals)
        uint256 initialSupply = 1_000_000 * 1e18; // 1 million tokens
        bNGN.mint(deployer, initialSupply);
        console.log("Minted", initialSupply / 1e18, "bNGN to", deployer);

        // Stop broadcasting
        vm.stopBroadcast();
    }
}