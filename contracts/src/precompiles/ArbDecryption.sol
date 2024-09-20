// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro-contracts/blob/main/LICENSE
// SPDX-License-Identifier: BUSL-1.1

pragma solidity >=0.4.21 <0.9.0;

/// @title Provides aggregators and their users methods for configuring how they participate in L1 aggregation.
/// @notice Precompiled contract that exists at 0x0000000000000000000000000000000000000094
interface ArbDecryption {

    function get() external view returns (bytes memory);
    function set(bytes calldata _pk) external returns (bool);
    function decrypt(bytes calldata privateKeyByte, bytes calldata cipherBytes, string calldata id) external view returns (bytes memory);
}