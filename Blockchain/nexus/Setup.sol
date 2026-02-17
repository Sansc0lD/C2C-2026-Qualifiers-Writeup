// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Essence.sol";
import "./CrystalNexus.sol";

contract Setup {
    Essence public essence;
    CrystalNexus public nexus;

    address public player;

    uint256 public constant PLAYER_ESSENCE = 10000 ether;
    uint256 public constant FIRST_ATTUNEMENT = 6000 ether;
    uint256 public constant SECOND_ATTUNEMENT = 9000 ether;
    uint256 public constant ASCENSION_THRESHOLD = 20250 ether;

    bool public ritualsComplete;

    constructor(address _player) {
        player = _player;

        essence = new Essence();
        nexus = new CrystalNexus(address(essence));

        essence.mint(player, PLAYER_ESSENCE);
    }

    function conductRituals() external {
        require(!ritualsComplete, "Rituals already performed");
        ritualsComplete = true;

        essence.mint(address(this), FIRST_ATTUNEMENT + SECOND_ATTUNEMENT);
        essence.approve(address(nexus), type(uint256).max);

        nexus.attune(FIRST_ATTUNEMENT);
        nexus.attune(SECOND_ATTUNEMENT);
    }

    function isSolved() external view returns (bool) {
        return essence.balanceOf(player) > ASCENSION_THRESHOLD;
    }
}
