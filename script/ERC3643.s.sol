// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {ERC3643} from "../src/ERC3643.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {IdentityRegistryStorage} from "../src/IdentityRegistryStorage.sol";
import {ClaimTopicsRegistry} from "../src/ClaimTopicsRegistry.sol";
import {TrustedIssuersRegistry} from "../src/TrustedIssuersRegistry.sol";
import {Compliance} from "../src/Compliance.sol";

contract ERC3643Script is Script {
    function run() external {
        // Retrieve deployer's private key and address
        uint256 deployerPrivateKey = vm.envUint("HEDERA_PRIVATE_KEY");
        address admin = vm.addr(deployerPrivateKey);

        // Retrieve private keys for other roles (must produce "beep" addresses)
        uint256 agentPrivateKey = vm.envUint("AGENT_PRIVATE_KEY");
        uint256 pauserPrivateKey = vm.envUint("PAUSER_PRIVATE_KEY");
        uint256 auditorPrivateKey = vm.envUint("AUDITOR_PRIVATE_KEY");
        uint256 trustedIssuerPrivateKey = vm.envUint("TRUSTED_ISSUER_PRIVATE_KEY");
        uint256 userPrivateKey = vm.envUint("USER_PRIVATE_KEY");
        uint256 identityContractPrivateKey = vm.envUint("IDENTITY_CONTRACT_PRIVATE_KEY");

        // Derive addresses
        address agent = vm.addr(agentPrivateKey);
        address pauser = vm.addr(pauserPrivateKey);
        address auditor = vm.addr(auditorPrivateKey);
        address trustedIssuer = vm.addr(trustedIssuerPrivateKey);
        address userAddress = vm.addr(userPrivateKey);
        address identityContract = vm.addr(identityContractPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy real dependencies
        IdentityRegistryStorage identityStorage = new IdentityRegistryStorage();
        console.log("IdentityRegistryStorage deployed to:", address(identityStorage));

        ClaimTopicsRegistry claimTopicsRegistry = new ClaimTopicsRegistry();
        console.log("ClaimTopicsRegistry deployed to:", address(claimTopicsRegistry));

        TrustedIssuersRegistry trustedIssuersRegistry = new TrustedIssuersRegistry();
        console.log("TrustedIssuersRegistry deployed to:", address(trustedIssuersRegistry));

        IdentityRegistry identityRegistry = new IdentityRegistry(
            address(identityStorage), address(claimTopicsRegistry), address(trustedIssuersRegistry)
        );
        console.log("IdentityRegistry deployed to:", address(identityRegistry));

        Compliance compliance = new Compliance(address(identityRegistry));
        console.log("Compliance deployed to:", address(compliance));

        // Token configuration
        string memory name = "Tokenized Naira";
        string memory symbol = "bNGN";

        // Deploy ERC3643 contract
        ERC3643 bNgn = new ERC3643(name, symbol, address(identityRegistry), address(compliance));
        console.log("ERC3643 (bNGN) deployed to:", address(bNgn));

        // Assign roles for ERC3643
        bNgn.grantRole(bNgn.DEFAULT_ADMIN_ROLE(), admin);
        console.log("Granted DEFAULT_ADMIN_ROLE to:", admin);
        bNgn.grantRole(bNgn.AGENT_ROLE(), agent);
        console.log("Granted AGENT_ROLE to:", agent);
        bNgn.grantRole(bNgn.PAUSER_ROLE(), pauser);
        console.log("Granted PAUSER_ROLE to:", pauser);
        bNgn.setAuditorStatus(auditor, true);
        console.log("Set auditor status for:", auditor);

        // Assign roles for dependencies
        identityStorage.grantRole(identityStorage.REGISTRY_ROLE(), address(identityRegistry));
        console.log("Granted REGISTRY_ROLE to IdentityRegistry:", address(identityRegistry));

        identityRegistry.grantRole(identityRegistry.AGENT_ROLE(), agent);
        console.log("Granted AGENT_ROLE to:", agent, "for IdentityRegistry");

        claimTopicsRegistry.grantRole(claimTopicsRegistry.MANAGER_ROLE(), admin);
        console.log("Granted MANAGER_ROLE to:", admin, "for ClaimTopicsRegistry");

        trustedIssuersRegistry.grantRole(trustedIssuersRegistry.MANAGER_ROLE(), admin);
        console.log("Granted MANAGER_ROLE to:", admin, "for TrustedIssuersRegistry");

        compliance.grantRole(compliance.AGENT_ROLE(), agent);
        console.log("Granted AGENT_ROLE to:", agent, "for Compliance");

        // Bind Compliance to ERC3643 token
        compliance.bindToken(address(bNgn));
        console.log("Compliance bound to ERC3643 token at:", address(bNgn));

        // Post-deployment configuration
        // 1. Add claim topics (KYC, AML)
        claimTopicsRegistry.addClaimTopic(1); // KYC
        console.log("Added claim topic: KYC (1)");
        claimTopicsRegistry.addClaimTopic(2); // AML
        console.log("Added claim topic: AML (2)");

        // 2. Set compliance limits
        compliance.setComplianceLimits(
            1_000_000 * 10 ** 18, // dailyLimit
            10_000_000 * 10 ** 18, // monthlyLimit
            100_000_000 * 10 ** 18, // maxBalance
            0 // minHoldingPeriod
        );
        console.log("Set compliance limits: daily=1M, monthly=10M, maxBalance=100M, minHoldingPeriod=0");

        // 3. Add trusted issuer
        uint256[] memory issuerTopics = new uint256[](2);
        issuerTopics[0] = 1; // KYC
        issuerTopics[1] = 2; // AML
        trustedIssuersRegistry.addTrustedIssuer(trustedIssuer, issuerTopics);
        console.log("Added trusted issuer:", trustedIssuer, "for topics KYC and AML");

        // 4. Register an identity (Nigeria country code = 234)
        identityRegistry.registerIdentity(userAddress, identityContract, 234);
        console.log("Registered identity for user:", userAddress, "with identity contract:", identityContract);

        // 5. Submit reserve proof (from environment variable)
        vm.stopBroadcast(); // Stop the deployer's broadcast
        vm.startBroadcast(auditorPrivateKey); // Start broadcast as auditor
        uint256 reserveAmount = vm.envUint("INITIAL_RESERVE_PROOF");
        bNgn.submitReserveProof(
            reserveAmount * 10 ** 18, // fiatReserves (scaled by decimals)
            0, // bondReserves
            "ipfs://QmbFMke1KXqnYy1Y8bW8z1kY5Qz1Y8bW8z1kY5Qz1Y8bW8" // proofUri
        );
        console.log("Submitted reserve proof:", reserveAmount, "NGN fiat-backed");

        vm.stopBroadcast(); // Stop the auditor's broadcast
    }
}
