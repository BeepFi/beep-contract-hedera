// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ICompliance} from "../interfaces/ICompliance.sol";

contract MockERC3643 {
    string public name;
    string public symbol;
    uint8 public decimals;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    ICompliance public compliance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        address complianceAddress
    ) {
        require(complianceAddress != address(0), "Invalid compliance address");
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        compliance = ICompliance(complianceAddress);
    }

    function mint(address to, uint256 amount) public {
        require(to != address(0), "Invalid recipient");
        require(compliance.canTransfer(address(0), to, amount), "Compliance check failed");
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
        compliance.created(to, amount);
    }

    function burn(address from, uint256 amount) public {
        require(from != address(0), "Invalid address");
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(compliance.canTransfer(from, address(0), amount), "Compliance check failed");
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
        compliance.destroyed(from, amount);
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(to != address(0), "Invalid recipient");
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        require(compliance.canTransfer(msg.sender, to, amount), "Compliance check failed");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        compliance.transferred(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(to != address(0), "Invalid recipient");
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        require(compliance.canTransfer(from, to, amount), "Compliance check failed");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        emit Transfer(from, to, amount);
        compliance.transferred(from, to, amount);
        return true;
    }
}
