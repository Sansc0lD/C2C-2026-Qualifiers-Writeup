// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Token} from "./Token.sol";

contract TGE {
    Token public immutable token;

    uint256 public constant TIER_1 = 1;
    uint256 public constant TIER_2 = 2;
    uint256 public constant TIER_3 = 3;

    address public owner;

    mapping(uint256 => uint256) public maxSupply;
    mapping(uint256 => uint256) public mintPrice;

    mapping(uint256 => uint256) public totalSupply;
    mapping(address => mapping(uint256 => uint256)) public balance;

    mapping(uint256 => uint256) public preTGESupply; // snapshot taken ONCE
    mapping(address => mapping(uint256 => uint256)) public preTGEBalance;

    mapping(address => uint256) public userTiers;
    uint256[] public tierIds;

    bool public isTgePeriod;
    bool public tgeActivated;

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor(
        address _token,
        uint256 maxSupplyTier1,
        uint256 maxSupplyTier2,
        uint256 maxSupplyTier3
    ) {
        require(_token != address(0), "token=0");
        require(maxSupplyTier1 > 0 && maxSupplyTier2 > 0 && maxSupplyTier3 > 0, "bad max");

        token = Token(_token);
        owner = msg.sender;

        maxSupply[TIER_1] = maxSupplyTier1;
        maxSupply[TIER_2] = maxSupplyTier2;
        maxSupply[TIER_3] = maxSupplyTier3;

        mintPrice[TIER_1] = maxSupplyTier1;

        tierIds.push(TIER_1);
        tierIds.push(TIER_2);
        tierIds.push(TIER_3);
    }

    function setTgePeriod(bool _isTge) external onlyOwner {
        if (!_isTge && isTgePeriod && !tgeActivated) {
            tgeActivated = true;
            _snapshotPreTGESupply();
        }

        isTgePeriod = _isTge;
    }

    function buy() external {
        require(isTgePeriod, "TGE closed");
        require(userTiers[msg.sender] == 0, "already registered");

        require(token.transferFrom(msg.sender, address(this), mintPrice[TIER_1]), "payment failed");

        _mint(msg.sender, TIER_1, 1);
        userTiers[msg.sender] = TIER_1;
    }

    function upgrade(uint256 tier) external {
        require(tier <= 3 && tier >= 2);
        require(userTiers[msg.sender]+1 == tier);
        require(tgeActivated && isTgePeriod);

        _burn(msg.sender, tier-1, 1);
        _mint(msg.sender, tier, 1);

        require(preTGEBalance[msg.sender][tier] > preTGESupply[tier], "not eligible");
        userTiers[msg.sender] = tier;
    }

    function _mint(address to, uint256 tier, uint256 quantity) internal {
        _validateTier(tier);
        require(quantity > 0, "qty=0");
        require(totalSupply[tier] + quantity <= maxSupply[tier], "max supply");

        totalSupply[tier] += quantity;
        balance[to][tier] += quantity;

        if (isTgePeriod) {
            preTGEBalance[to][tier] += quantity;
        }
    }

    function _burn(address from, uint256 tier, uint256 quantity) internal {
        _validateTier(tier);
        require(balance[from][tier] >= quantity, "insufficient");

        balance[from][tier] -= quantity;
        totalSupply[tier] -= quantity;
    }

    function _snapshotPreTGESupply() internal {
        for (uint256 i = 0; i < tierIds.length; i++) {
            uint256 id = tierIds[i];
            preTGESupply[id] = totalSupply[id];
        }
    }

    function _validateTier(uint256 tier) internal pure {
        require(tier == TIER_1 || tier == TIER_2 || tier == TIER_3, "invalid tier");
    }
}
