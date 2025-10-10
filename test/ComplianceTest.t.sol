// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Compliance, ACompliance} from "../src/Compliance.sol";
import {MockIdentityRegistry} from "../mocks/MockIdentityRegistry.sol";
import {MockERC3643} from "../mocks/MockERC3643.sol";
import {console} from "forge-std/console.sol";

contract ComplianceTest is Test {
    Compliance public compliance;
    MockIdentityRegistry public identityRegistry;
    MockERC3643 public token;

    address public admin = address(0x1);
    address public agent = address(0x2);
    address public user1 = address(0x4);
    address public user2 = address(0x5);
    address public newWallet = address(0x7);

    uint256 constant MINT_AMOUNT = 1000 * 10 ** 18;
    uint16 constant COUNTRY1 = 1; // Restricted country
    uint16 constant COUNTRY2 = 2; // Unrestricted country

    bytes32 constant AGENT_ROLE = keccak256("AGENT_ROLE");
    bytes32 constant DEFAULT_ADMIN_ROLE = keccak256("DEFAULT_ADMIN_ROLE");

    function setUp() public {
        identityRegistry = new MockIdentityRegistry();
        vm.prank(admin);
        compliance = new Compliance(address(identityRegistry));
        token = new MockERC3643("Test Token", "TST", 18, address(compliance));

        vm.startPrank(admin);
        compliance.grantRole(DEFAULT_ADMIN_ROLE, admin);
        compliance.grantRole(AGENT_ROLE, agent);
        compliance.bindToken(address(token));
        vm.stopPrank();

        vm.startPrank(address(this));
        identityRegistry.setVerificationStatus(user1, true);
        identityRegistry.setVerificationStatus(user2, true);
        identityRegistry.setVerificationStatus(newWallet, true);
        identityRegistry.setInvestorCountry(user1, COUNTRY1);
        identityRegistry.setInvestorCountry(user2, COUNTRY2);
        identityRegistry.setInvestorCountry(newWallet, COUNTRY2);
        token.mint(user1, MINT_AMOUNT);
        token.mint(user2, MINT_AMOUNT);
        vm.stopPrank();

        assertTrue(compliance.hasRole(AGENT_ROLE, agent), "Agent role not assigned in setUp");
        assertTrue(compliance.isTokenBound(address(token)), "Token not bound");
        assertTrue(identityRegistry.isVerified(user1), "user1 not verified");
        assertTrue(identityRegistry.isVerified(user2), "user2 not verified");
        assertTrue(identityRegistry.isVerified(newWallet), "newWallet not verified");
        assertEq(identityRegistry.investorCountry(user1), COUNTRY1, "user1 country incorrect");
        assertEq(identityRegistry.investorCountry(user2), COUNTRY2, "user2 country incorrect");
        assertEq(identityRegistry.investorCountry(newWallet), COUNTRY2, "newWallet country incorrect");
        assertEq(token.balanceOf(user1), MINT_AMOUNT, "user1 balance incorrect");
        assertEq(token.balanceOf(user2), MINT_AMOUNT, "user2 balance incorrect");
    }

    function testBindAndUnbindToken() public {
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ACompliance.TokenUnbound(address(token));
        compliance.unbindToken(address(token));
        assertFalse(compliance.isTokenBound(address(token)), "Token should be unbound");

        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ACompliance.TokenBound(address(token));
        compliance.bindToken(address(token));
        assertTrue(compliance.isTokenBound(address(token)), "Token should be rebound");
    }

    function testGrantAndRevokeRoles() public {
        address newAgent = address(0x8);
        vm.prank(admin);
        compliance.grantRole(AGENT_ROLE, newAgent);
        assertTrue(compliance.hasRole(AGENT_ROLE, newAgent), "New agent role not assigned");

        vm.prank(admin);
        compliance.revokeRole(AGENT_ROLE, newAgent);
        assertFalse(compliance.hasRole(AGENT_ROLE, newAgent), "New agent role not revoked");
    }

    function testSetComplianceLimits() public {
        uint256 newDailyLimit = 500_000 * 10 ** 18;
        uint256 newMonthlyLimit = 5_000_000 * 10 ** 18;
        uint256 newMaxBalance = 50_000_000 * 10 ** 18;
        uint256 newMinHoldingPeriod = 1 days;

        vm.prank(agent);
        vm.expectEmit(true, true, true, true);
        emit ACompliance.ComplianceLimitsUpdated(newDailyLimit, newMonthlyLimit, newMaxBalance, newMinHoldingPeriod);
        compliance.setComplianceLimits(newDailyLimit, newMonthlyLimit, newMaxBalance, newMinHoldingPeriod);

        (uint256 dailyLimit, uint256 monthlyLimit, uint256 maxBalance, uint256 minHoldingPeriod) = compliance.limits();
        assertEq(dailyLimit, newDailyLimit, "Daily limit not updated");
        assertEq(monthlyLimit, newMonthlyLimit, "Monthly limit not updated");
        assertEq(maxBalance, newMaxBalance, "Max balance not updated");
        assertEq(minHoldingPeriod, newMinHoldingPeriod, "Min holding period not updated");
    }

    function testBatchSetCountryRestrictions() public {
        uint16[] memory countries = new uint16[](2);
        countries[0] = COUNTRY1;
        countries[1] = COUNTRY2;
        bool[] memory restricted = new bool[](2);
        restricted[0] = true;
        restricted[1] = false;

        vm.prank(agent);
        vm.expectEmit(true, true, true, true);
        emit ACompliance.CountryRestrictionSet(COUNTRY1, true);
        emit ACompliance.CountryRestrictionSet(COUNTRY2, false);
        compliance.batchSetCountryRestrictions(countries, restricted);

        assertTrue(compliance.countryRestrictions(COUNTRY1), "COUNTRY1 should be restricted");
        assertFalse(compliance.countryRestrictions(COUNTRY2), "COUNTRY2 should not be restricted");

        assertFalse(
            compliance.canTransfer(user1, user2, MINT_AMOUNT / 2),
            "user1 should not transfer due to country restriction"
        );
        assertTrue(compliance.canTransfer(user2, newWallet, MINT_AMOUNT / 2), "user2 should transfer to newWallet");

        vm.prank(user2);
        bool success = token.transfer(newWallet, MINT_AMOUNT / 2);
        assertTrue(success, "Transfer from user2 failed");
        assertEq(token.balanceOf(newWallet), MINT_AMOUNT / 2, "newWallet balance incorrect");
        assertEq(token.balanceOf(user2), MINT_AMOUNT / 2, "user2 balance incorrect");
    }

    function testDailyAndMonthlyLimits() public {
        uint256 lowDailyLimit = 100 * 10 ** 18;
        uint256 lowMonthlyLimit = 200 * 10 ** 18;
        vm.prank(agent);
        compliance.setComplianceLimits(lowDailyLimit, lowMonthlyLimit, type(uint256).max, 0);

        vm.prank(user2);
        bool success = token.transfer(newWallet, lowDailyLimit / 2);
        assertTrue(success, "Transfer within daily limit failed");
        assertEq(compliance.getRemainingDailyLimit(user2), lowDailyLimit / 2, "Remaining daily limit incorrect");
        assertEq(
            compliance.getRemainingMonthlyLimit(user2),
            lowMonthlyLimit - lowDailyLimit / 2,
            "Remaining monthly limit incorrect"
        );

        vm.prank(user2);
        try token.transfer(newWallet, lowDailyLimit) returns (bool) {
            fail("Transfer exceeding daily limit should revert");
        } catch Error(string memory reason) {
            assertEq(reason, "Compliance check failed", "Incorrect revert reason for daily limit");
        }
    }

    function testMaxBalanceLimit() public {
        uint256 lowMaxBalance = 1500 * 10 ** 18;
        vm.prank(agent);
        compliance.setComplianceLimits(type(uint256).max, type(uint256).max, lowMaxBalance, 0);

        vm.prank(address(this));
        token.mint(newWallet, lowMaxBalance / 2);
        assertEq(token.balanceOf(newWallet), lowMaxBalance / 2, "newWallet balance incorrect after mint");

        assertFalse(
            compliance.canTransfer(user2, newWallet, MINT_AMOUNT),
            "Compliance should prevent transfer due to max balance"
        );

        vm.prank(user2);
        try token.transfer(newWallet, MINT_AMOUNT) returns (bool) {
            console.log("Transfer succeeded unexpectedly");
            fail("Transfer exceeding max balance should revert");
        } catch Error(string memory reason) {
            assertEq(reason, "Compliance check failed", "Incorrect revert reason for max balance");
        }
    }

    function testMinHoldingPeriod() public {
        uint256 holdingPeriod = 1 days;
        vm.prank(agent);
        compliance.setComplianceLimits(type(uint256).max, type(uint256).max, type(uint256).max, holdingPeriod);

        vm.prank(address(this));
        token.mint(user2, MINT_AMOUNT);

        vm.prank(user2);
        try token.transfer(newWallet, MINT_AMOUNT / 2) returns (bool) {
            fail("Transfer before holding period should revert");
        } catch Error(string memory reason) {
            assertEq(reason, "Compliance check failed", "Incorrect revert reason for holding period");
        }

        vm.warp(block.timestamp + holdingPeriod + 1);

        vm.prank(user2);
        bool success = token.transfer(newWallet, MINT_AMOUNT / 2);
        assertTrue(success, "Transfer after holding period failed");
        assertEq(token.balanceOf(newWallet), MINT_AMOUNT / 2, "newWallet balance incorrect");
    }

    function testMaxHoldersPerCountry() public {
        uint256 maxHolders = 1;
        vm.prank(agent);
        vm.expectEmit(true, true, true, true);
        emit ACompliance.MaxHoldersPerCountrySet(COUNTRY2, maxHolders);
        compliance.setMaxHoldersPerCountry(COUNTRY2, maxHolders);

        assertEq(compliance.getCountryHolderCount(COUNTRY2), 1, "Initial holder count incorrect");
        assertTrue(compliance.isHolder(user2), "user2 should be a holder");
        assertFalse(compliance.isHolder(newWallet), "newWallet should not be a holder");
        assertEq(compliance.maxHoldersPerCountry(COUNTRY2), maxHolders, "Max holders not set correctly");

        address newUser = address(0x9);
        vm.startPrank(address(this));
        identityRegistry.setVerificationStatus(newUser, true);
        identityRegistry.setInvestorCountry(newUser, COUNTRY2);

        assertFalse(
            compliance.canTransfer(address(0), newUser, MINT_AMOUNT),
            "Compliance should prevent mint due to max holders"
        );

        try token.mint(newUser, MINT_AMOUNT) {
            console.log("Mint succeeded unexpectedly for", newUser);
            fail("Mint exceeding max holders should revert");
        } catch Error(string memory reason) {
            assertEq(reason, "Compliance check failed", "Incorrect revert reason for max holders");
        }
        vm.stopPrank();

        assertEq(compliance.getCountryHolderCount(COUNTRY2), 1, "Holder count should not increase");
        assertEq(token.balanceOf(newUser), 0, "newUser balance should be zero");
        assertFalse(compliance.isHolder(newUser), "newUser should not be a holder");
    }

    function testMintAndBurn() public {
        uint256 initialCountryHolders = compliance.getCountryHolderCount(COUNTRY2);

        vm.startPrank(address(this));
        vm.expectEmit(true, true, true, true);
        emit ACompliance.TokenCreated(newWallet, MINT_AMOUNT, block.timestamp);
        token.mint(newWallet, MINT_AMOUNT);
        vm.stopPrank();

        assertEq(token.balanceOf(newWallet), MINT_AMOUNT, "newWallet balance incorrect after mint");
        assertEq(compliance.totalMinted(newWallet), MINT_AMOUNT, "Total minted incorrect");
        assertEq(compliance.mintCount(newWallet), 1, "Mint count incorrect");
        assertEq(
            compliance.getCountryHolderCount(COUNTRY2), initialCountryHolders + 1, "Holder count incorrect after mint"
        );
        assertEq(compliance.getCountryTotalMinted(COUNTRY2), MINT_AMOUNT * 2, "Country total minted incorrect");

        vm.startPrank(address(this));
        vm.expectEmit(true, true, true, true);
        emit ACompliance.TokenDestroyed(newWallet, MINT_AMOUNT, block.timestamp);
        token.burn(newWallet, MINT_AMOUNT);
        vm.stopPrank();

        assertEq(token.balanceOf(newWallet), 0, "newWallet balance incorrect after burn");
        assertEq(compliance.totalBurned(newWallet), MINT_AMOUNT, "Total burned incorrect");
        assertEq(compliance.burnCount(newWallet), 1, "Burn count incorrect");
        assertEq(
            compliance.getCountryHolderCount(COUNTRY2), initialCountryHolders, "Holder count should decrease after burn"
        );
        assertEq(compliance.getCountryTotalBurned(COUNTRY2), MINT_AMOUNT, "Country total burned incorrect");
    }

    function testResetTransferRecord() public {
        vm.prank(user2);
        bool success = token.transfer(newWallet, MINT_AMOUNT / 2);
        assertTrue(success, "Transfer from user2 failed");
        (uint256 dailyTotal, uint256 monthlyTotal,,) = compliance.getTransferRecord(user2);
        assertTrue(dailyTotal > 0, "Daily total should be updated");
        assertTrue(monthlyTotal > 0, "Monthly total should be updated");

        vm.prank(agent);
        compliance.resetTransferRecord(user2);
        (dailyTotal, monthlyTotal,,) = compliance.getTransferRecord(user2);
        assertEq(dailyTotal, 0, "Daily total not reset");
        assertEq(monthlyTotal, 0, "Monthly total not reset");
    }

    function testViewFunctions() public {
        vm.prank(user2);
        bool success = token.transfer(newWallet, MINT_AMOUNT / 2);
        assertTrue(success, "Transfer from user2 failed");

        (uint256 dailyTotal, uint256 monthlyTotal, uint256 dailyResetTime, uint256 monthlyResetTime) =
            compliance.getTransferRecord(user2);
        assertEq(dailyTotal, MINT_AMOUNT / 2, "Daily total incorrect");
        assertEq(monthlyTotal, MINT_AMOUNT / 2, "Monthly total incorrect");
        assertTrue(dailyResetTime > block.timestamp, "Daily reset time incorrect");
        assertTrue(monthlyResetTime > block.timestamp, "Monthly reset time incorrect");

        (uint256 dailyLimit, uint256 monthlyLimit,,) = compliance.limits();
        assertEq(
            compliance.getRemainingDailyLimit(user2), dailyLimit - MINT_AMOUNT / 2, "Remaining daily limit incorrect"
        );
        assertEq(
            compliance.getRemainingMonthlyLimit(user2),
            monthlyLimit - MINT_AMOUNT / 2,
            "Remaining monthly limit incorrect"
        );
    }
}
