// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Essence.sol";

interface ICrystalReceiver {
    function onCrystalReceived(address from, uint256 amount, uint256 crystals) external returns (bytes4);
}

contract CrystalNexus {
    Essence public immutable essence;

    uint256 public totalCrystals;
    mapping(address => uint256) public crystalBalance;
    mapping(address => bool) public attuned;

    uint256 public constant BASE_FRICTION = 200;
    uint256 public constant DYNAMIC_FRICTION = 2000;
    uint256 public constant PRECISION = 10000;

    uint256 public catalystReserve;
    bool public resonanceActive;
    address public guardian;

    event Attunement(address indexed entity, uint256 essence, uint256 crystals);
    event Dissolution(address indexed entity, uint256 crystals, uint256 essence);
    event CatalystAdded(address indexed donor, uint256 amount);
    event ResonancePulse(address indexed trigger, uint256 amplitude);

    error NotAttuned();
    error AlreadyAttuned();
    error InsufficientCrystals();
    error ResonanceUnstable();
    error GuardianOnly();

    constructor(address _essence) {
        essence = Essence(_essence);
        guardian = msg.sender;
    }

    function amplitude() public view returns (uint256) {
        return essence.balanceOf(address(this)) - catalystReserve;
    }

    function crystalWorth(uint256 crystalAmount) public view returns (uint256) {
        if (totalCrystals == 0) return crystalAmount;
        return (crystalAmount * amplitude()) / totalCrystals;
    }

    function essenceTocrystal(uint256 essenceAmount) public view returns (uint256) {
        uint256 amp = amplitude();
        if (amp == 0 || totalCrystals == 0) return essenceAmount;
        return (essenceAmount * totalCrystals) / amp;
    }

    function calculateFriction(address entity) public view returns (uint256) {
        if (totalCrystals == 0) return BASE_FRICTION;
        uint256 ownership = (crystalBalance[entity] * PRECISION) / totalCrystals;
        uint256 dynamicPart = (ownership * ownership * DYNAMIC_FRICTION) / (PRECISION * PRECISION);
        return BASE_FRICTION + dynamicPart;
    }

    function attune(uint256 essenceAmount) external returns (uint256 crystals) {
        crystals = essenceTocrystal(essenceAmount);

        essence.transferFrom(msg.sender, address(this), essenceAmount);

        totalCrystals += crystals;
        crystalBalance[msg.sender] += crystals;
        attuned[msg.sender] = true;

        if (_isContract(msg.sender)) {
            try ICrystalReceiver(msg.sender).onCrystalReceived(
                msg.sender,
                essenceAmount,
                crystals
            ) returns (bytes4 retval) {
                require(retval == ICrystalReceiver.onCrystalReceived.selector, "Invalid receiver");
            } catch {
                // Contract doesn't implement callback, that's fine
            }
        }

        emit Attunement(msg.sender, essenceAmount, crystals);
    }

    function dissolve(uint256 crystalAmount, address recipient) external returns (uint256 essenceOut) {
        if (crystalBalance[msg.sender] < crystalAmount) revert InsufficientCrystals();

        essenceOut = crystalWorth(crystalAmount);

        uint256 friction = calculateFriction(msg.sender);
        uint256 frictionAmount = (essenceOut * friction) / PRECISION;
        essenceOut -= frictionAmount;

        crystalBalance[msg.sender] -= crystalAmount;
        totalCrystals -= crystalAmount;

        essence.transfer(recipient, essenceOut);

        emit Dissolution(msg.sender, crystalAmount, essenceOut);
    }

    function infuse(uint256 amount) external {
        essence.transferFrom(msg.sender, address(this), amount);
        catalystReserve += amount;
        emit CatalystAdded(msg.sender, amount);
    }

    function activateResonance() external {
        if (!attuned[msg.sender]) revert NotAttuned();

        uint256 amp = amplitude();
        if (amp < 1000 ether) revert ResonanceUnstable();

        resonanceActive = true;
        emit ResonancePulse(msg.sender, amp);
    }

    function claimCatalyst() external {
        if (msg.sender != guardian) revert GuardianOnly();
        if (resonanceActive) revert ResonanceUnstable();

        uint256 amount = catalystReserve;
        catalystReserve = 0;
        essence.transfer(guardian, amount);
    }

    function harmonize(address target) external {
        if (!resonanceActive) revert ResonanceUnstable();
        if (!attuned[target]) revert NotAttuned();

        uint256 targetCrystals = crystalBalance[target];
        uint256 callerCrystals = crystalBalance[msg.sender];

        if (callerCrystals <= targetCrystals) revert InsufficientCrystals();

        uint256 transferAmount = targetCrystals / 10;
        crystalBalance[target] -= transferAmount;
        crystalBalance[msg.sender] += transferAmount;
    }

    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}
