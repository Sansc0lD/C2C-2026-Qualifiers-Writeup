// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import { ERC20 } from "./lib//ERC20.sol";
import { Ownable } from "./lib/Ownable2Step.sol";

contract Token is ERC20, Ownable {
    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10 ** 18;
    error MaxSupplyExceeded();

    constructor(string memory name, string memory symbol, uint256 initialSupply) 
        ERC20(name, symbol) 
        Ownable(msg.sender) 
    {
        require(initialSupply <= MAX_SUPPLY, MaxSupplyExceeded());
        _mint(msg.sender, initialSupply);
    }

    function mint(address account, uint256 amount) external onlyOwner {
        require(totalSupply() + amount <= MAX_SUPPLY, MaxSupplyExceeded());
        _mint(account, amount);
    }
}