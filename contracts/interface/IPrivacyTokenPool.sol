// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// https://socket.dev/npm/package/poseidon-solidity

interface IPrivacyTokenPool {
    error PrivacyTokenPool__InvalidZKProof();
    error PrivacyTokenPool__MsgValueInvalid();
    error PrivacyTokenPool__NoteAlreadySpent();
    error PrivacyTokenPool__UnknownRoot();
    error PrivacyTokenPool__ZeroAddress();
    error PrivacyTokenPool__InvalidNullifiers();

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
        address indexed recipient,
        uint256 amount,
        bytes32[] nullifier
    );

}
