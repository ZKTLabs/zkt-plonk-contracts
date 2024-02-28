// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./IncrementalMerkleTree.sol";
import "../library/Bn254.sol";
import "../library/SnarkVerifier.sol";
import "../interface/IPrivacyTokenPool.sol";


contract PrivacyTokenPool is
    IPrivacyTokenPool,
    IncrementalMerkleTree,
    ReentrancyGuard
{
    using Bn254 for bytes;
    using SafeERC20 for IERC20;

    // double spend records
    mapping(bytes32 => bool) public usedNullifiers;
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    SnarkVerifier.VerifierKey public vk;

    constructor(
        address poseidon,
        SnarkVerifier.VerifierKey memory _vk
    ) IncrementalMerkleTree(poseidon)
    {
        vk = _vk;
    }

    /*
        Deposit any asset and any amount.
    */
    function deposit(
        bytes32 commitment,
        address token,
        uint256 amount
    ) external payable nonReentrant returns (uint256) {
        if (token == address(0)) revert PrivacyTokenPool__ZeroAddress();
        bytes32 assetMetadata = bytes32(abi.encodePacked(token, amount).snarkHash());
        bytes32 leaf = hasher.poseidon([commitment, assetMetadata]);
        uint256 leafIndex = insert(leaf);

        emit Deposit(
            commitment,
            leaf,
            token,
            amount,
            leafIndex,
            block.timestamp
        );

        if (token == ETH) {
            if (msg.value != amount) revert PrivacyTokenPool__MsgValueInvalid();
        } else {
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }
        return leafIndex;
    }

    /*
        Withdraw using zkProof.
    */
    function withdraw(
        bytes32 root,
        bytes32[] calldata nullifiers,
        SnarkVerifier.Proof calldata proof,
        address token,
        uint256 amount,
        address recipient,
        bytes32 newLeaf
    ) external nonReentrant {
        if (nullifiers.length != 3) revert PrivacyTokenPool__InvalidNullifiers();
        for (uint idx = 0; idx < nullifiers.length; idx++) {
            if (usedNullifiers[nullifiers[idx]]) revert PrivacyTokenPool__NoteAlreadySpent();
            usedNullifiers[nullifiers[idx]] = true;
        }
        if (!isKnownRoot(root)) revert PrivacyTokenPool__UnknownRoot();
        if (recipient == address(0) || token == address(0)) revert PrivacyTokenPool__ZeroAddress();
        uint256[] memory publicInputs = new uint256[](5);
        publicInputs[0] = uint256(root);
        publicInputs[1] = uint256(nullifiers[0]);
        publicInputs[2] = uint256(nullifiers[1]);
        publicInputs[3] = uint256(nullifiers[2]);
        publicInputs[4] = amount;
        if (!SnarkVerifier.verify(proof, vk, publicInputs)) revert PrivacyTokenPool__InvalidZKProof();
        emit Withdrawal(
            recipient,
            amount,
            nullifiers
        );

        // insert new leaf to merkle tree
        insert(newLeaf);
        if (token == ETH) {
            payable(recipient).transfer(amount);
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }
    }
}
