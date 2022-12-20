//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {ECDSA} from  "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Multisig {
    struct TxInfo {
        uint256 id;
        uint256 amount;
        address to;
        address[] isCommitted;
        bool isSent;
    }

    struct WithdrawalInfo {
        uint256 amount;
        address to;
    }

    TxInfo[] public txInfos;
    uint256 public nonce;

    string constant private MSG_PREFIX = "special_secret";

    address[] private _signers;
    mapping(address => bool) private _isSigner;
    uint private _threshold;

    constructor(address[] memory _newSigners, uint _newThreshold) {
        require(_newThreshold > 1, "there should be at least 2 signer");

        for (uint i=0; i < _newSigners.length; i++) {
            if (!_isSigner[_newSigners[i]]) {
                _isSigner[_newSigners[i]] = true;
                _signers.push(_newSigners[i]);
            }
        }
        require(_signers.length > 1, "there should be more unique signers than 1");
        require(_newThreshold <= _newSigners.length, "impossible to set threshold more than quantity of signers");
        _threshold = _newThreshold;
    }

    bool private _lock;
    modifier nonReentrant() {
        require(!_lock);
        _lock = true;
        _;
        _lock = false;
    }

    function initTx(WithdrawalInfo calldata _txn, uint256 _nonce, bytes calldata _signature) external nonReentrant {
        address signerAddress = verifySignature(_txn, _nonce, _signature);

        uint256 _id = txInfos.length;
        address[] memory _isCommitted = new address[](1);
        _isCommitted[0] = signerAddress;

        txInfos.push(TxInfo({
                id: _id,
                amount: _txn.amount,
                to: _txn.to,
                isCommitted: _isCommitted,
                isSent: false
            }));
    }

    function commit(uint256 id, WithdrawalInfo calldata _txn, uint256 _nonce, bytes calldata _signature) external nonReentrant {
        require(id <= txInfos.length, "unexistent tx");
        TxInfo storage txInfo = txInfos[id];
        require(txInfo.to == _txn.to, "tx index and tx don't match");
        require(txInfo.amount == _txn.amount, "tx index and tx don't match");

        address signerAddress = verifySignature(_txn, _nonce, _signature);
        (, bool exists) = _containAddress(txInfo.isCommitted, signerAddress);
        require(!exists, "tx is already committed");
        require(!txInfo.isSent, "tx is already sent");

        txInfo.isCommitted.push(signerAddress);
        if (txInfo.isCommitted.length >= _threshold) {
            _invokeTx(txInfo.to, txInfo.amount);
            txInfo.isSent = true;
        }
    }

    function revoke(uint256 id, WithdrawalInfo calldata _txn, uint256 _nonce, bytes calldata _signature) external nonReentrant {
        require(id <= txInfos.length, "unexistent tx");
        TxInfo storage txInfo = txInfos[id];
        require(txInfo.to == _txn.to, "tx index and tx don't match");
        require(txInfo.amount == _txn.amount, "tx index and tx don't match");

        address signerAddress = verifySignature(_txn, _nonce, _signature);
        require(!txInfo.isSent, "tx is already sent");
        (uint256 index, bool exists) = _containAddress(txInfo.isCommitted, signerAddress);
        require(exists, "you haven't committed this tx");

        delete txInfo.isCommitted[index];
    }

    function verifySignature(WithdrawalInfo calldata _txn, uint256 _nonce, bytes calldata _signature) private returns(address signerAddress) {
        require(_nonce > nonce, "nonce already used");
        bytes32 digest = _processWithdrawalInfo(_txn, _nonce);

        signerAddress = ECDSA.recover(digest, _signature);
        require(_isSigner[signerAddress], "not part of consortium");
        nonce = _nonce;
    }

    function _processWithdrawalInfo(WithdrawalInfo calldata _txn, uint256 _nonce) private pure returns(bytes32 _digest) {
        bytes memory encoded = abi.encode(_txn);
        _digest = keccak256(abi.encodePacked(encoded, _nonce));
        _digest = keccak256(abi.encodePacked(MSG_PREFIX, _digest));
    }

    function _invokeTx (address to, uint256 amount) private {
        (bool success, ) = payable(to).call{value: amount }("");
        require(success, "Transfer not fulfilled");
    }

    function _containAddress(address[] memory addresses, address a) private pure returns(uint256 index, bool exists) {
        index = 0;
        exists = false;
        for (uint256 i = 0; i < addresses.length; i++) {
            if (addresses[i] == a) {
                return (i, true);
            }
        }
    }
}