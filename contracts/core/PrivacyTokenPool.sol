// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./IncrementalMerkleTree.sol";
import "../library/Bn254.sol";


error PrivacyTokenPool__MsgValueInvalid();
error PrivacyTokenPool__ZeroAddress();

contract PrivacyTokenPool is IncrementalMerkleTree, ReentrancyGuard {
    using Bn254 for bytes;
    using SafeERC20 for IERC20;

    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    // emit the raw commitment, stamped leaf, plus the data to reconstruct the stamped commitment
    event Deposit(
        bytes32 indexed commitment,
        bytes32 indexed leaf,
        address indexed token,
        uint256 amount,
        uint256 leafIndex,
        uint256 timestamp
    );
    // emit the subsetRoot with each withdrawal
    event Withdrawal(
        address recipient,
        address indexed relayer,
        bytes32 indexed subsetRoot,
        bytes32 nullifier,
        uint256 fee
    );

    // double spend records
    mapping(bytes32 => bool) public nullifiers;

    constructor(address poseidon) IncrementalMerkleTree(poseidon) {}

    /*
        Deposit any asset and any amount.
    */
    function deposit(
        bytes32 commitment,
        address token,
        uint256 amount
    ) public payable nonReentrant returns (uint256) {
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
}
