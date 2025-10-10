// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC3643} from "../src/ERC3643.sol";
import {MockIdentityRegistry} from "../mocks/MockIdentityRegistry.sol";
import {MockCompliance} from "../mocks/MockCompliance.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract ERC3643Test is Test {
    // Test contract instance
    ERC3643 public bNgn;

    // Mock interfaces
    MockIdentityRegistry public identityRegistry;
    MockCompliance public compliance;

    // Test addresses
    address public admin = address(0x1);
    address public agent = address(0x2);
    address public pauser = address(0x3);
    address public user1 = address(0x4);
    address public user2 = address(0x5);
    address public auditor = address(0x6);
    address public newWallet = address(0x7);
    address public newAgent = address(0x8);
    address public newAuditor = address(0x9);
    address public newCompliance = address(0x10);

    // Constants
    string constant TOKEN_NAME = "Tokenized Naira";
    string constant TOKEN_SYMBOL = "bNGN";
    uint256 constant INITIAL_SUPPLY = 0;
    uint256 constant MINT_AMOUNT = 1000 * 10 ** 18;
    string constant PROOF_URI = "ipfs://test-proof";

    // Roles
    bytes32 constant AGENT_ROLE = keccak256("AGENT_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 constant DEFAULT_ADMIN_ROLE = keccak256("DEFAULT_ADMIN_ROLE");

    function setUp() public {
        // Deploy mock contracts
        identityRegistry = new MockIdentityRegistry();
        compliance = new MockCompliance();

        // Deploy TokenizedNaira contract
        vm.prank(admin);
        bNgn = new ERC3643(TOKEN_NAME, TOKEN_SYMBOL, address(identityRegistry), address(compliance));

        // Grant roles explicitly
        vm.startPrank(admin);
        bNgn.grantRole(DEFAULT_ADMIN_ROLE, admin);
        bNgn.grantRole(AGENT_ROLE, agent);
        bNgn.grantRole(PAUSER_ROLE, pauser);
        bNgn.setAuditorStatus(auditor, true);
        vm.stopPrank();

        // Set up mock responses
        vm.startPrank(address(this));
        identityRegistry.setVerificationStatus(user1, true);
        identityRegistry.setVerificationStatus(user2, true);
        identityRegistry.setVerificationStatus(newWallet, true);
        compliance.setCanTransfer(user1, user2, MINT_AMOUNT, true);
        compliance.setCanTransfer(user1, user2, MINT_AMOUNT / 2, true);
        compliance.setCanTransfer(user1, user2, MINT_AMOUNT - (MINT_AMOUNT / 4), true); // Added for testUnfreezePartialTokens
        vm.stopPrank();
    }

    // Test deployment
    function testDeployment() public view {
        assertEq(bNgn.name(), TOKEN_NAME);
        assertEq(bNgn.symbol(), TOKEN_SYMBOL);
        assertEq(bNgn.totalSupply(), INITIAL_SUPPLY);
        assertEq(address(bNgn.identityRegistry()), address(identityRegistry));
        assertEq(address(bNgn.compliance()), address(compliance));
        assertEq(bNgn.version(), "1.0.0");
        assertTrue(bNgn.hasRole(DEFAULT_ADMIN_ROLE, admin));
        assertTrue(bNgn.hasRole(AGENT_ROLE, agent));
        assertTrue(bNgn.hasRole(PAUSER_ROLE, pauser));
        assertTrue(bNgn.authorizedAuditors(auditor));
    }

    // Test minting
    function testMint() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT);
        assertEq(bNgn.totalSupply(), MINT_AMOUNT);
    }

    function testMintNotAgent() public {
        vm.prank(user1);
        vm.expectRevert("Caller is not an agent");
        bNgn.mint(user1, MINT_AMOUNT);
    }

    function testMintToUnverified() public {
        vm.prank(address(this));
        identityRegistry.setVerificationStatus(user2, false);

        vm.prank(agent);
        vm.expectRevert("Recipient not verified");
        bNgn.mint(user2, MINT_AMOUNT);
    }

    // Test batch minting
    function testBatchMint() public {
        address[] memory toList = new address[](2);
        toList[0] = user1;
        toList[1] = user2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = MINT_AMOUNT;
        amounts[1] = MINT_AMOUNT / 2;

        vm.prank(agent);
        bNgn.batchMint(toList, amounts);

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT);
        assertEq(bNgn.balanceOf(user2), MINT_AMOUNT / 2);
        assertEq(bNgn.totalSupply(), MINT_AMOUNT + (MINT_AMOUNT / 2));
    }

    function testBatchMintArrayMismatch() public {
        address[] memory toList = new address[](2);
        uint256[] memory amounts = new uint256[](1);
        vm.prank(agent);
        vm.expectRevert("Array length mismatch");
        bNgn.batchMint(toList, amounts);
    }

    // Test burning
    function testBurn() public {
        vm.startPrank(agent);
        bNgn.mint(user1, MINT_AMOUNT);
        bNgn.burnByAgent(user1, MINT_AMOUNT / 2);
        vm.stopPrank();

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT / 2);
        assertEq(bNgn.totalSupply(), MINT_AMOUNT / 2);
    }

    function testBurnNotAgent() public {
        vm.prank(user1);
        vm.expectRevert("Caller is not an agent");
        bNgn.burnByAgent(user1, MINT_AMOUNT);
    }

    // Test batch burning
    function testBatchBurn() public {
        address[] memory accounts = new address[](2);
        accounts[0] = user1;
        accounts[1] = user2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = MINT_AMOUNT / 2;
        amounts[1] = MINT_AMOUNT / 4;

        vm.startPrank(agent);
        bNgn.mint(user1, MINT_AMOUNT);
        bNgn.mint(user2, MINT_AMOUNT / 2);
        bNgn.batchBurn(accounts, amounts);
        vm.stopPrank();

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT - (MINT_AMOUNT / 2));
        assertEq(bNgn.balanceOf(user2), (MINT_AMOUNT / 2) - (MINT_AMOUNT / 4));
        assertEq(bNgn.totalSupply(), (MINT_AMOUNT + (MINT_AMOUNT / 2)) - (MINT_AMOUNT / 2 + MINT_AMOUNT / 4));
    }

    // Test transfer
    function testTransfer() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(user1);
        bool success = bNgn.transfer(user2, MINT_AMOUNT / 2);
        require(success, "Transfer failed");

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT / 2);
        assertEq(bNgn.balanceOf(user2), MINT_AMOUNT / 2);
    }

    function testTransferToUnverified() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(address(this));
        identityRegistry.setVerificationStatus(user2, false);

        vm.prank(user1);
        try bNgn.transfer(user2, MINT_AMOUNT / 2) returns (bool) {
            fail("Transfer should have reverted");
        } catch Error(string memory reason) {
            assertEq(reason, "Receiver not verified");
        }
    }

    function testTransferComplianceFail() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(address(this));
        compliance.setCanTransfer(user1, user2, MINT_AMOUNT / 2, false);

        vm.prank(user1);
        try bNgn.transfer(user2, MINT_AMOUNT / 2) returns (bool) {
            fail("Transfer should have reverted");
        } catch Error(string memory reason) {
            assertEq(reason, "Compliance check failed");
        }
    }

    // Test transferFrom
    function testTransferFrom() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(user1);
        bNgn.approve(user2, MINT_AMOUNT / 2);

        vm.prank(user2);
        bool success = bNgn.transferFrom(user1, user2, MINT_AMOUNT / 2);
        require(success, "TransferFrom failed");

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT / 2);
        assertEq(bNgn.balanceOf(user2), MINT_AMOUNT / 2);
        assertEq(bNgn.allowance(user1, user2), 0);
    }

    // Test forced transfer
    function testForcedTransfer() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(agent);
        bool success = bNgn.forcedTransfer(user1, user2, MINT_AMOUNT / 2);
        require(success, "Forced transfer failed");

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT / 2);
        assertEq(bNgn.balanceOf(user2), MINT_AMOUNT / 2);
    }

    function testForcedTransferNotAgent() public {
        vm.prank(user1);
        vm.expectRevert("Caller is not an agent");
        bNgn.forcedTransfer(user1, user2, MINT_AMOUNT);
    }

    // Test batch forced transfer
    function testBatchForcedTransfer() public {
        address[] memory fromList = new address[](2);
        fromList[0] = user1;
        fromList[1] = user2;
        address[] memory toList = new address[](2);
        toList[0] = user2;
        toList[1] = user1;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = MINT_AMOUNT / 2;
        amounts[1] = MINT_AMOUNT / 4;

        vm.startPrank(agent);
        bNgn.mint(user1, MINT_AMOUNT);
        bNgn.mint(user2, MINT_AMOUNT / 2);
        bNgn.batchForcedTransfer(fromList, toList, amounts);
        vm.stopPrank();

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT - (MINT_AMOUNT / 2) + (MINT_AMOUNT / 4));
        assertEq(bNgn.balanceOf(user2), (MINT_AMOUNT / 2) - (MINT_AMOUNT / 4) + (MINT_AMOUNT / 2));
    }

    // Test freezing
    function testFreezeAddress() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(agent);
        bNgn.setAddressFrozen(user1, true);
        assertTrue(bNgn.isFrozen(user1));

        vm.prank(user1);
        try bNgn.transfer(user2, MINT_AMOUNT / 2) returns (bool) {
            fail("Transfer should have reverted");
        } catch Error(string memory reason) {
            assertEq(reason, "Account is frozen");
        }
    }

    function testBatchSetAddressFrozen() public {
        // Mint tokens within a single prank to avoid state issues
        vm.startPrank(agent);
        bNgn.mint(user1, MINT_AMOUNT);
        bNgn.mint(user2, MINT_AMOUNT);
        vm.stopPrank();

        address[] memory addresses = new address[](2);
        addresses[0] = user1;
        addresses[1] = user2;
        bool[] memory freezeStatus = new bool[](2);
        freezeStatus[0] = true;
        freezeStatus[1] = false;

        // Verify agent role before calling
        assertTrue(bNgn.hasRole(AGENT_ROLE, agent), "Agent role not assigned");

        // Call batchSetAddressFrozen within a single prank
        vm.prank(agent);
        bNgn.batchSetAddressFrozen(addresses, freezeStatus);

        assertTrue(bNgn.isFrozen(user1), "user1 should be frozen");
        assertFalse(bNgn.isFrozen(user2), "user2 should not be frozen");

        // Verify user1 cannot transfer (frozen)
        vm.prank(user1);
        try bNgn.transfer(user2, MINT_AMOUNT / 2) returns (bool) {
            fail("Transfer should have reverted for frozen account");
        } catch Error(string memory reason) {
            assertEq(reason, "Account is frozen", "Incorrect revert reason");
        }

        // Set and verify compliance for user2 to newWallet
        vm.prank(address(this));
        compliance.setCanTransfer(user2, newWallet, MINT_AMOUNT / 2, true);
        bool canTransfer = compliance.canTransfer(user2, newWallet, MINT_AMOUNT / 2);
        assertTrue(canTransfer, "Compliance check should allow transfer");

        // Verify user2 can transfer to an unfrozen address (newWallet)
        vm.prank(user2);
        bool success = bNgn.transfer(newWallet, MINT_AMOUNT / 2);
        require(success, "Transfer failed for unfrozen account");
        assertEq(bNgn.balanceOf(newWallet), MINT_AMOUNT / 2, "newWallet should receive tokens");
        assertEq(bNgn.balanceOf(user2), MINT_AMOUNT / 2, "user2 balance should decrease");
    }

    function testFreezePartialTokens() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(agent);
        bNgn.freezePartialTokens(user1, MINT_AMOUNT / 2);

        assertEq(bNgn.getFrozenTokens(user1), MINT_AMOUNT / 2);
        assertEq(bNgn.getFreeBalance(user1), MINT_AMOUNT / 2);

        vm.prank(user1);
        bool success = bNgn.transfer(user2, MINT_AMOUNT / 2);
        require(success, "Transfer failed");

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT / 2);
        assertEq(bNgn.balanceOf(user2), MINT_AMOUNT / 2);
        assertEq(bNgn.getFrozenTokens(user1), MINT_AMOUNT / 2);
    }

    function testUnfreezePartialTokens() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(agent);
        bNgn.freezePartialTokens(user1, MINT_AMOUNT / 2);

        vm.prank(agent);
        bNgn.unfreezePartialTokens(user1, MINT_AMOUNT / 4);

        assertEq(bNgn.getFrozenTokens(user1), MINT_AMOUNT / 4);
        assertEq(bNgn.getFreeBalance(user1), MINT_AMOUNT - (MINT_AMOUNT / 4));

        vm.prank(user1);
        bool success = bNgn.transfer(user2, MINT_AMOUNT - (MINT_AMOUNT / 4));
        require(success, "Transfer failed");

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT / 4);
        assertEq(bNgn.balanceOf(user2), MINT_AMOUNT - (MINT_AMOUNT / 4));
        assertEq(bNgn.getFrozenTokens(user1), MINT_AMOUNT / 4);
    }

    function testBatchFreezePartialTokens() public {
        address[] memory addresses = new address[](2);
        addresses[0] = user1;
        addresses[1] = user2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = MINT_AMOUNT / 2;
        amounts[1] = MINT_AMOUNT / 4;

        vm.startPrank(agent);
        bNgn.mint(user1, MINT_AMOUNT);
        bNgn.mint(user2, MINT_AMOUNT / 2);
        bNgn.batchFreezePartialTokens(addresses, amounts);
        vm.stopPrank();

        assertEq(bNgn.getFrozenTokens(user1), MINT_AMOUNT / 2);
        assertEq(bNgn.getFreeBalance(user1), MINT_AMOUNT / 2);
        assertEq(bNgn.getFrozenTokens(user2), MINT_AMOUNT / 4);
        assertEq(bNgn.getFreeBalance(user2), (MINT_AMOUNT / 2) - (MINT_AMOUNT / 4));
    }

    function testBatchUnfreezePartialTokens() public {
        address[] memory addresses = new address[](2);
        addresses[0] = user1;
        addresses[1] = user2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = MINT_AMOUNT / 4;
        amounts[1] = MINT_AMOUNT / 8;

        vm.startPrank(agent);
        bNgn.mint(user1, MINT_AMOUNT);
        bNgn.mint(user2, MINT_AMOUNT / 2);
        bNgn.batchFreezePartialTokens(addresses, amounts);
        bNgn.batchUnfreezePartialTokens(addresses, amounts);
        vm.stopPrank();

        assertEq(bNgn.getFrozenTokens(user1), 0);
        assertEq(bNgn.getFreeBalance(user1), MINT_AMOUNT);
        assertEq(bNgn.getFrozenTokens(user2), 0);
        assertEq(bNgn.getFreeBalance(user2), MINT_AMOUNT / 2);
    }

    // Test recovery
    function testRecoveryAddress() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(agent);
        bNgn.freezePartialTokens(user1, MINT_AMOUNT / 2);

        vm.prank(agent);
        bool success = bNgn.recoveryAddress(user1, newWallet, user1);
        require(success, "Recovery failed");

        assertEq(bNgn.balanceOf(user1), 0);
        assertEq(bNgn.balanceOf(newWallet), MINT_AMOUNT);
        assertEq(bNgn.getFrozenTokens(newWallet), MINT_AMOUNT / 2);
        assertEq(bNgn.getFrozenTokens(user1), 0);
    }

    function testRecoveryNoBalance() public {
        vm.prank(agent);
        vm.expectRevert("No balance to recover");
        bNgn.recoveryAddress(user1, newWallet, user1);
    }

    // Test reserve proof
    function testSubmitReserveProof() public {
        uint256 fiatReserves = MINT_AMOUNT;
        uint256 bondReserves = MINT_AMOUNT;

        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(auditor);
        bNgn.submitReserveProof(fiatReserves, bondReserves, PROOF_URI);

        ERC3643.ReserveProof memory proof = bNgn.getLatestReserveProof();
        assertEq(proof.fiatReserves, fiatReserves);
        assertEq(proof.bondReserves, bondReserves);
        assertEq(proof.totalSupply, MINT_AMOUNT);
        assertEq(proof.auditor, auditor);
        assertEq(proof.proofUri, PROOF_URI);
        assertTrue(bNgn.isFullyBacked());
    }

    function testSubmitReserveProofInsufficientBacking() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(auditor);
        vm.expectRevert("Insufficient backing");
        bNgn.submitReserveProof(MINT_AMOUNT / 2, 0, PROOF_URI);
    }

    function testSubmitReserveProofNotAuditor() public {
        vm.prank(user1);
        vm.expectRevert("Not authorized auditor");
        bNgn.submitReserveProof(MINT_AMOUNT, MINT_AMOUNT, PROOF_URI);
    }

    function testGetReserveProofCount() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(auditor);
        bNgn.submitReserveProof(MINT_AMOUNT, MINT_AMOUNT, PROOF_URI);

        assertEq(bNgn.getReserveProofCount(), 1);

        vm.prank(auditor);
        bNgn.submitReserveProof(MINT_AMOUNT, MINT_AMOUNT, PROOF_URI);

        assertEq(bNgn.getReserveProofCount(), 2);
    }

    function testIsFullyBacked() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(auditor);
        bNgn.submitReserveProof(MINT_AMOUNT, MINT_AMOUNT, PROOF_URI);

        assertTrue(bNgn.isFullyBacked());
    }

    // Test pause functionality
    function testPause() public {
        vm.prank(pauser);
        bNgn.pause();
        assertTrue(bNgn.paused());

        vm.prank(agent);
        vm.expectRevert();
        bNgn.mint(user1, MINT_AMOUNT);
    }

    function testUnpause() public {
        vm.prank(pauser);
        bNgn.pause();
        vm.prank(pauser);
        bNgn.unpause();
        assertFalse(bNgn.paused());

        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);
        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT);
    }

    // Test admin functions
    function testSetIdentityRegistry() public {
        address newRegistry = address(0x11);
        vm.prank(admin);
        bNgn.setIdentityRegistry(newRegistry);
        assertEq(address(bNgn.identityRegistry()), newRegistry);
    }

    function testSetIdentityRegistryInvalidAddress() public {
        vm.prank(admin);
        vm.expectRevert("Invalid address");
        bNgn.setIdentityRegistry(address(0));
    }

    function testSetCompliance() public {
        vm.prank(address(this));
        compliance = new MockCompliance();
        compliance.setCanTransfer(user1, user2, MINT_AMOUNT / 2, true);

        vm.prank(admin);
        bNgn.setCompliance(address(compliance));
        assertEq(address(bNgn.compliance()), address(compliance));

        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(user1);
        bool success = bNgn.transfer(user2, MINT_AMOUNT / 2);
        require(success, "Transfer failed");
    }

    function testSetComplianceInvalidAddress() public {
        vm.prank(admin);
        vm.expectRevert("Invalid address");
        bNgn.setCompliance(address(0));
    }

    function testSetTokenInformation() public {
        string memory newName = "New Tokenized Naira";
        string memory newSymbol = "nNGN";
        string memory newVersion = "2.0.0";
        address newOnchainId = address(0x12);

        vm.prank(admin);
        bNgn.setTokenInformation(newName, newSymbol, newVersion, newOnchainId);

        assertEq(bNgn.version(), newVersion);
        assertEq(bNgn.onchainId(), newOnchainId);
        // Note: name and symbol are immutable in ERC20
    }

    // Test user-initiated burn
    function testUserBurn() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(user1);
        bNgn.burn(MINT_AMOUNT / 2);

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT / 2);
        assertEq(bNgn.totalSupply(), MINT_AMOUNT / 2);
    }

    function testUserBurnUnverified() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(address(this));
        identityRegistry.setVerificationStatus(user1, false);

        vm.prank(user1);
        vm.expectRevert("Caller not verified");
        bNgn.burn(MINT_AMOUNT / 2);
    }

    function testUserBurnInsufficientBalance() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(agent);
        bNgn.freezePartialTokens(user1, MINT_AMOUNT);

        vm.prank(user1);
        vm.expectRevert("Insufficient free balance");
        bNgn.burn(MINT_AMOUNT);
    }

    // Test burnFrom
    function testBurnFrom() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(user1);
        bNgn.approve(user2, MINT_AMOUNT / 2);

        vm.prank(user2);
        bNgn.burnFrom(user1, MINT_AMOUNT / 2);

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT / 2);
        assertEq(bNgn.totalSupply(), MINT_AMOUNT / 2);
        assertEq(bNgn.allowance(user1, user2), 0);
    }

    function testBurnFromUnverified() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(user1);
        bNgn.approve(user2, MINT_AMOUNT / 2);

        vm.prank(address(this));
        identityRegistry.setVerificationStatus(user1, false);

        vm.prank(user2);
        vm.expectRevert("Account not verified");
        bNgn.burnFrom(user1, MINT_AMOUNT / 2);
    }

    function testBurnFromInsufficientAllowance() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(user2);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientAllowance.selector,
                user2, // Spender address
                0, // Current allowance
                MINT_AMOUNT / 2 // Required allowance
            )
        );
        bNgn.burnFrom(user1, MINT_AMOUNT / 2);
    }

    function testBurnFromInsufficientBalance() public {
        vm.prank(agent);
        bNgn.mint(user1, MINT_AMOUNT);

        vm.prank(user1);
        bNgn.approve(user2, MINT_AMOUNT);

        vm.prank(agent);
        bNgn.freezePartialTokens(user1, MINT_AMOUNT);

        vm.prank(user2);
        vm.expectRevert("Insufficient free balance");
        bNgn.burnFrom(user1, MINT_AMOUNT);
    }

    // Test identity and compliance
    function testIdentityVerification() public {
        vm.prank(address(this));
        identityRegistry.setVerificationStatus(user1, true);

        assertTrue(identityRegistry.isVerified(user1));
    }

    function testComplianceCheck() public {
        vm.prank(address(this));
        compliance.setCanTransfer(user1, user2, MINT_AMOUNT, true);

        assertTrue(compliance.canTransfer(user1, user2, MINT_AMOUNT));
    }

    // Test role management
    function testGrantRole() public {
        vm.prank(admin);
        bNgn.grantRole(AGENT_ROLE, newAgent);

        assertTrue(bNgn.hasRole(AGENT_ROLE, newAgent));

        vm.prank(newAgent);
        bNgn.mint(user1, MINT_AMOUNT);

        assertEq(bNgn.balanceOf(user1), MINT_AMOUNT);
        assertEq(bNgn.totalSupply(), MINT_AMOUNT);
    }

    function testRevokeRole() public {
        vm.prank(admin);
        bNgn.grantRole(AGENT_ROLE, newAgent);
        assertTrue(bNgn.hasRole(AGENT_ROLE, newAgent));

        vm.prank(admin);
        bNgn.revokeRole(AGENT_ROLE, newAgent);
        assertFalse(bNgn.hasRole(AGENT_ROLE, newAgent));

        vm.prank(newAgent);
        vm.expectRevert("Caller is not an agent");
        bNgn.mint(user1, MINT_AMOUNT);
    }

    function testSetAuditorStatus() public {
        vm.prank(admin);
        bNgn.setAuditorStatus(newAuditor, true);

        assertTrue(bNgn.authorizedAuditors(newAuditor));

        vm.prank(newAuditor);
        bNgn.submitReserveProof(MINT_AMOUNT, MINT_AMOUNT, PROOF_URI);

        ERC3643.ReserveProof memory proof = bNgn.getLatestReserveProof();
        assertEq(proof.auditor, newAuditor);
    }

    function testIsAuditor() public {
        vm.prank(admin);
        bNgn.setAuditorStatus(newAuditor, true);

        assertTrue(bNgn.authorizedAuditors(newAuditor));

        vm.prank(admin);
        bNgn.setAuditorStatus(newAuditor, false);
        assertFalse(bNgn.authorizedAuditors(newAuditor));
    }
}
