// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Bn254.sol";

library TranscriptProtocol {
    using Bn254 for uint256;

    uint256 constant private FR_MASK = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    uint8 constant private DST_0 = 0;
    uint8 constant private DST_1 = 1;
    uint8 constant private DST_CHALLENGE = 2;

    struct Transcript {
        bytes32 state0;
        bytes32 state1;
        uint32 counter;
    }

    function newTranscript() internal pure returns (Transcript memory t) {
        t.state0 = bytes32(0);
        t.state1 = bytes32(0);
        t.counter = 0;
    }

    function appendUint64(Transcript memory self, uint64 value) internal pure {
        bytes32 oldState = self.state0;
        self.state0 = keccak256(abi.encodePacked(DST_0, oldState, self.state1, value));
        self.state1 = keccak256(abi.encodePacked(DST_1, oldState, self.state1, value));
    }

    function appendScalar(Transcript memory self, uint256 value) internal pure {
        bytes32 oldState = self.state0;
        self.state0 = keccak256(abi.encodePacked(DST_0, oldState, self.state1, value));
        self.state1 = keccak256(abi.encodePacked(DST_1, oldState, self.state1, value));
    }

    function appendScalarArray(Transcript memory self, uint256[] memory values) internal pure {
        for (uint256 i = 0; i < values.length; i++) {
            appendScalar(self, values[i]);
        }
    }

    function appendG1(Transcript memory self, Bn254.G1Affine memory p) internal pure {
        appendScalar(self, p.x);
        appendScalar(self, p.y);
    }

    function appendG1Array(Transcript memory self, Bn254.G1Affine[] memory ps) internal pure {
        for (uint256 i = 0; i < ps.length; i++) {
            appendG1(self, ps[i]);
        }
    }

    function challengeScalar(Transcript memory self) internal pure returns (uint256) {
        bytes32 query = keccak256(abi.encodePacked(DST_CHALLENGE, self.state0, self.state1, self.counter));
        self.counter += 1;
        return uint256(query) & FR_MASK;
    }
}