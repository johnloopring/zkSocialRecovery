pragma solidity ^0.6.1;

import "./lib/ownable.sol";
import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "./interfaces/IProofValidator.sol";
import "./zk/verifier.sol";

//// @title Smart contract wallet with ZK recovery capability.
contract ZkWallet is Ownable {

    using SafeMath for uint256;

    event Received(address indexed _from, uint _amount);
    event Transferred(address indexed _to, uint _amount);
    event AddGuardian(uint firstHash, uint secondHash);
    event ProofValidator(address indexed validatorContract);

    address public validatorContract;
    uint public firstHash;
    uint public secondHash;

    /// @dev Constructor initializes the wallet top up limit and the vault contract.
    /// @param _owner is the owner account of the wallet contract.
    /// @param _transferable indicates whether the contract ownership can be transferred.
    constructor(address payable _owner, bool _transferable) Ownable(_owner, _transferable) public {
        Verifier validator = new Verifier();
        validatorContract = address(validator);
        emit ProofValidator(validatorContract);
    }

    /// @dev Receive function.
    fallback() external payable {
        emit Received(msg.sender, msg.value);
    }

    function addGuardian(uint _firstHalfOfHash, uint _secondHalfOfHash) external onlyOwner {
        firstHash = _firstHalfOfHash;
        secondHash = _secondHalfOfHash;
        emit AddGuardian(firstHash, secondHash);
    }

    function zkRecover(address payable _recoveryAddress, uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[3] memory inputs) public returns (bool) {
        require(firstHash == inputs[0], 'guardian not approved');
        require(secondHash == inputs[1], 'guardian not approved');

        bool isValid = IProofValidator(validatorContract).verifyTx(a, b, c, inputs);
        require(isValid == true, 'proof failed');
    
        _transferOwnership(_recoveryAddress, true);
    }

    /// @dev Transfers the specified asset to the recipient's address.
    /// @param _to is the recipient's address.
    /// @param _amount is the amount of assets to be transferred in base units.
    function transfer(address payable _to,  uint _amount) public onlyOwner {
        require(_to != address(0), "destination cannot be zero");
        _to.transfer(_amount);
        emit Transferred(_to, _amount);
    }
}