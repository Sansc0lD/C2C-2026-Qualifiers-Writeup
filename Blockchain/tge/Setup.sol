// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {TGE} from "./TGE.sol";
import {Token} from "./Token.sol";

contract Setup {
    TGE public tge;
    Token public token;
    address public player;

    constructor(address _player) {
        player = _player;

        token = new Token("TOK", "TOK", 100);
        tge = new TGE(address(token), 15, 35, 50);
        tge.setTgePeriod(true);
        token.mint(player, 15);
    }

    function enableTge(bool _tge) public {
        tge.setTgePeriod(_tge);
    }

    function isSolved() external view returns (bool) {
        require(tge.userTiers(player) == 3, "not yet");
        return true;
    }
}
