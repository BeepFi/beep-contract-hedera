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
import {Identity} from "../src/Identity.sol";

contract ERC3643Script is Script {
    // Helper function to convert bytes32 to hexadecimal string
    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        bytes memory chars = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            bytes1 char = _bytes32[i];
            uint8 hi = uint8(char) / 16;
            uint8 lo = uint8(char) % 16;
            chars[i * 2] = hi < 10 ? bytes1(hi + 48) : bytes1(hi + 87);
            chars[i * 2 + 1] = lo < 10 ? bytes1(lo + 48) : bytes1(lo + 87);
        }
        return string(abi.encodePacked("0x", chars));
    }

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("HEDERA_PRIVATE_KEY");
        address admin = vm.addr(deployerPrivateKey);
        uint256 agentPrivateKey = vm.envUint("AGENT_PRIVATE_KEY");
        address agent = vm.addr(agentPrivateKey);
        uint256 pauserPrivateKey = vm.envUint("PAUSER_PRIVATE_KEY");
        address pauser = vm.addr(pauserPrivateKey);
        uint256 userPrivateKey = vm.envUint("USER_PRIVATE_KEY");
        address userAddress = vm.addr(userPrivateKey);

        console.log("=== ADDRESS VERIFICATION ===");
        console.log("Admin address:", admin);
        console.log("Agent address:", agent);
        console.log("Pauser address:", pauser);
        console.log("User address:", userAddress);
        console.log("Admin balance:", admin.balance / 1e18, "HBAR");
        console.log("Agent balance:", agent.balance / 1e18, "HBAR");
        
        require(admin != agent, "Admin and agent must be different addresses");
        require(admin != pauser, "Admin and pauser must be different addresses");

        vm.startBroadcast(deployerPrivateKey);

        // Fund agent account if needed (send 0.1 HBAR for gas)
        if (agent.balance <= 0.1 ether) {
            console.log("Funding agent account with 0.1 HBAR...");
            payable(agent).transfer(0.1 ether);
            console.log("Agent new balance:", agent.balance / 1e18, "HBAR");
            vm.pauseGasMetering();
            vm.sleep(2000);
            vm.resumeGasMetering();
        }

        // Fund pauser account if needed (send 0.1 HBAR for gas)
        if (pauser.balance < 0.1 ether) {
            console.log("Funding pauser account with 0.1 HBAR...");
            payable(pauser).transfer(0.1 ether);
            console.log("Pauser new balance:", pauser.balance / 1e18, "HBAR");
            vm.pauseGasMetering();
            vm.sleep(2000);
            vm.resumeGasMetering();
        }

        // Fund user account if needed (send 0.1 HBAR for gas)
        if (userAddress.balance < 0.1 ether) {
            console.log("Funding user account with 0.1 HBAR...");
            payable(userAddress).transfer(0.1 ether);
            console.log("User new balance:", userAddress.balance / 1e18, "HBAR");
            vm.pauseGasMetering();
            vm.sleep(2000);
            vm.resumeGasMetering();
        }

        console.log("=== DEPLOYING CORE INFRASTRUCTURE ===");

        // Deploy core infrastructure
        IdentityRegistryStorage identityStorage = new IdentityRegistryStorage();
        console.log("IdentityRegistryStorage deployed to:", address(identityStorage));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        ClaimTopicsRegistry claimTopicsRegistry = new ClaimTopicsRegistry();
        console.log("ClaimTopicsRegistry deployed to:", address(claimTopicsRegistry));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        TrustedIssuersRegistry trustedIssuersRegistry = new TrustedIssuersRegistry();
        console.log("TrustedIssuersRegistry deployed to:", address(trustedIssuersRegistry));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        IdentityRegistry identityRegistry = new IdentityRegistry(
            address(identityStorage), address(claimTopicsRegistry), address(trustedIssuersRegistry)
        );
        console.log("IdentityRegistry deployed to:", address(identityRegistry));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        Compliance compliance = new Compliance(address(identityRegistry));
        console.log("Compliance deployed to:", address(compliance));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        // Deploy separate identity contracts for agent and admin
        Identity agentIdentity = new Identity(agent);
        console.log("Agent Identity contract deployed to:", address(agentIdentity));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        Identity adminIdentity = new Identity(admin);
        console.log("Admin Identity contract deployed to:", address(adminIdentity));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        console.log("=== DEPLOYING TOKEN ===");

        string memory name = "Tokenized Naira";
        string memory symbol = "bNGN";

        ERC3643 bNgn = new ERC3643(name, symbol, address(identityRegistry), address(compliance));
        console.log("ERC3643 (bNGN) deployed to:", address(bNgn));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        console.log("=== GRANTING ROLES ===");

        // Grant roles
        bNgn.grantRole(bNgn.DEFAULT_ADMIN_ROLE(), admin);
        console.log("Granted DEFAULT_ADMIN_ROLE to:", admin);
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        bNgn.grantRole(bNgn.AGENT_ROLE(), agent);
        console.log("Granted AGENT_ROLE to:", agent);
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        bNgn.grantRole(bNgn.PAUSER_ROLE(), pauser);
        console.log("Granted PAUSER_ROLE to:", pauser);
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        bNgn.setAuditorStatus(admin, true);
        console.log("Set auditor status for admin:", admin);
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        identityStorage.grantRole(identityStorage.REGISTRY_ROLE(), address(identityRegistry));
        console.log("Granted REGISTRY_ROLE to IdentityRegistry");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        identityRegistry.grantRole(identityRegistry.AGENT_ROLE(), agent);
        console.log("Granted AGENT_ROLE to agent for IdentityRegistry");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        claimTopicsRegistry.grantRole(claimTopicsRegistry.MANAGER_ROLE(), admin);
        console.log("Granted MANAGER_ROLE to admin for ClaimTopicsRegistry");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        trustedIssuersRegistry.grantRole(trustedIssuersRegistry.MANAGER_ROLE(), admin);
        console.log("Granted MANAGER_ROLE to admin for TrustedIssuersRegistry");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        compliance.grantRole(compliance.AGENT_ROLE(), agent);
        console.log("Granted AGENT_ROLE to agent for Compliance");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        console.log("=== CONFIGURING COMPLIANCE ===");

        compliance.bindToken(address(bNgn));
        console.log("Compliance bound to ERC3643 token");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        // Add claim topics
        claimTopicsRegistry.addClaimTopic(1);
        console.log("Added claim topic: KYC (1)");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        claimTopicsRegistry.addClaimTopic(2);
        console.log("Added claim topic: AML (2)");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        compliance.setComplianceLimits(1_000_000 * 10 ** 18, 10_000_000 * 10 ** 18, 100_000_000 * 10 ** 18, 0);
        console.log("Set compliance limits: daily=1M, monthly=10M, maxBalance=100M");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        // Add agent as trusted issuer FIRST (before any identity registration)
        uint256[] memory issuerTopics = new uint256[](2);
        issuerTopics[0] = 1;
        issuerTopics[1] = 2;
        trustedIssuersRegistry.addTrustedIssuer(agent, address(agentIdentity), issuerTopics);
        console.log("Added trusted issuer (agent) for topics KYC and AML");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        vm.stopBroadcast();

        // ============================================================
        // SWITCH TO AGENT TO ADD CLAIMS
        // ============================================================
        console.log("=== ADDING CLAIMS (AS AGENT) ===");
        vm.startBroadcast(agentPrivateKey);

        // KYC claim for admin
        bytes memory kycData = "KYC verified";
        bytes memory kycEncodedData = abi.encode(agent, uint256(1), admin, kycData);
        bytes32 kycDataHash = keccak256(kycEncodedData);
        bytes32 kycPrefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", kycDataHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPrivateKey, kycPrefixedHash);
        bytes memory kycSignature = abi.encodePacked(r, s, v);

        adminIdentity.addClaim(admin, 1, 1, agent, kycSignature, kycData, "");
        console.log("Added KYC claim to admin's identity");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        // AML claim for admin
        bytes memory amlData = "AML verified";
        bytes memory amlEncodedData = abi.encode(agent, uint256(2), admin, amlData);
        bytes32 amlDataHash = keccak256(amlEncodedData);
        bytes32 amlPrefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", amlDataHash));
        (v, r, s) = vm.sign(agentPrivateKey, amlPrefixedHash);
        bytes memory amlSignature = abi.encodePacked(r, s, v);

        adminIdentity.addClaim(admin, 2, 1, agent, amlSignature, amlData, "");
        console.log("Added AML claim to admin's identity");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        // Register agent's identity
        if (identityRegistry.identity(agent) == address(0)) {
            identityRegistry.registerIdentity(agent, address(agentIdentity), 234);
            console.log("Registered agent identity");
        }
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        // Register admin's identity
        if (identityRegistry.identity(admin) == address(0)) {
            identityRegistry.registerIdentity(admin, address(adminIdentity), 234);
            console.log("Registered admin identity");
        }
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        vm.stopBroadcast();

        // ============================================================
        // SWITCH BACK TO ADMIN FOR VERIFICATION AND MINTING
        // ============================================================
        console.log("=== VERIFICATION AND MINTING (AS ADMIN) ===");
        vm.startBroadcast(deployerPrivateKey);

        // Verify the registered identity is correct
        address registeredAdminIdentity = identityRegistry.identity(admin);
        console.log("Registered admin identity:", registeredAdminIdentity);
        require(registeredAdminIdentity == address(adminIdentity), "Admin identity mismatch");

        // Check claims
        bytes32[] memory kycClaimIds = adminIdentity.getClaimIdsByTopic(admin, 1);
        console.log("KYC claim count for admin:", kycClaimIds.length);
        require(kycClaimIds.length > 0, "No KYC claims found");

        bytes32[] memory amlClaimIds = adminIdentity.getClaimIdsByTopic(admin, 2);
        console.log("AML claim count for admin:", amlClaimIds.length);
        require(amlClaimIds.length > 0, "No AML claims found");

        // Check verification status
        bool isAdminVerified = identityRegistry.isVerified(admin);
        console.log("Admin verification status:", isAdminVerified);
        require(isAdminVerified, "Admin not verified");

        console.log("=== ADMIN VERIFIED SUCCESSFULLY ===");

        // Register user's identity (share admin's identity for demo purposes)
        if (identityRegistry.identity(userAddress) == address(0)) {
            identityRegistry.registerIdentity(userAddress, address(adminIdentity), 234);
            console.log("Registered user identity");
        }
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        // Mint tokens
        uint256 reserveAmount = vm.envUint("INITIAL_RESERVE_PROOF");
        bNgn.submitReserveProof(reserveAmount * 10 ** 18, 0, "ipfs://QmbFMke1KXqnYy1Y8bW8z1kY5Qz1Y8bW8z1kY5Qz1Y8bW8");
        console.log("Submitted reserve proof:", reserveAmount, "NGN");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        uint256 mintAmount = reserveAmount * 10 ** 18;
        bNgn.mint(admin, mintAmount);
        console.log("Minted", mintAmount / 10 ** 18, "bNGN to admin");
        console.log("Admin bNGN balance:", bNgn.balanceOf(admin) / 10 ** 18);
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        console.log("=== DEPLOYMENT COMPLETE ===");
        console.log("Token:", address(bNgn));
        console.log("Identity Registry:", address(identityRegistry));
        console.log("Compliance:", address(compliance));
        console.log("Admin Identity:", address(adminIdentity));
        console.log("Agent Identity:", address(agentIdentity));

        vm.stopBroadcast();
    }
}