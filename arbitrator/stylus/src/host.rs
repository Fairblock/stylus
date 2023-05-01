// Copyright 2022-2023, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

use crate::env::{Escape, MaybeEscape, WasmEnv, WasmEnvMut};
use arbutil::evm;
use hex_literal::hex;
use prover::utils::Bytes20;
use prover::{programs::prelude::*, value::Value};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    {Message, Secp256k1},
};
use sha3::{Digest, Keccak256};

pub(crate) fn read_args(mut env: WasmEnvMut, ptr: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.pay_for_evm_copy(env.args.len() as u64)?;
    env.write_slice(ptr, &env.args)?;
    Ok(())
}

pub(crate) fn return_data(mut env: WasmEnvMut, ptr: u32, len: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.pay_for_evm_copy(len.into())?;
    env.outs = env.read_slice(ptr, len)?;
    Ok(())
}

pub(crate) fn evm_address_balance(mut env: WasmEnvMut, address: u32, dest: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    let address = env.read_bytes20(address)?;
    let (balance, gas_cost) = env.evm().address_balance(address);
    env.write_slice(dest, &balance.0)?;
    env.buy_gas(gas_cost)
}

pub(crate) fn evm_address_codehash(mut env: WasmEnvMut, address: u32, dest: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    let address = env.read_bytes20(address)?;
    let (hash, gas_cost) = env.evm().address_code_hash(address);
    env.write_slice(dest, &hash.0)?;
    env.buy_gas(gas_cost)
}

pub(crate) fn evm_blockhash(mut env: WasmEnvMut, block: u32, dest: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    let block = env.read_bytes32(block)?;
    let (hash, gas_cost) = env.evm().block_hash(block);
    env.write_slice(dest, &hash.0)?;
    env.buy_gas(gas_cost)
}

pub(crate) fn evm_gas_left(mut env: WasmEnvMut) -> Result<u64, Escape> {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::GASLEFT_GAS)?;
    Ok(env.gas_left())
}

pub(crate) fn evm_ink_left(mut env: WasmEnvMut) -> Result<u64, Escape> {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::GASLEFT_GAS)?;
    Ok(env.ink_left().into())
}

pub(crate) fn account_load_bytes32(mut env: WasmEnvMut, key: u32, dest: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    let key = env.read_bytes32(key)?;
    let (value, gas_cost) = env.evm().load_bytes32(key);
    env.write_slice(dest, &value.0)?;
    env.buy_gas(gas_cost)
}

pub(crate) fn account_store_bytes32(mut env: WasmEnvMut, key: u32, value: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.require_gas(evm::SSTORE_SENTRY_GAS)?; // see operations_acl_arbitrum.go

    let key = env.read_bytes32(key)?;
    let value = env.read_bytes32(value)?;
    let gas_cost = env.evm().store_bytes32(key, value)?;
    env.buy_gas(gas_cost)
}

pub(crate) fn call_contract(
    mut env: WasmEnvMut,
    contract: u32,
    calldata: u32,
    calldata_len: u32,
    value: u32,
    mut ink: u64,
    return_data_len: u32,
) -> Result<u8, Escape> {
    let mut env = WasmEnv::start(&mut env)?;
    env.pay_for_evm_copy(calldata_len.into())?;
    ink = ink.min(env.ink_left().into()); // provide no more than what the user has

    let gas = env.pricing().ink_to_gas(ink);
    let contract = env.read_bytes20(contract)?;
    let input = env.read_slice(calldata, calldata_len)?;
    let value = env.read_bytes32(value)?;

    let (outs_len, gas_cost, status) = env.evm().contract_call(contract, input, gas, value);
    env.set_return_data_len(outs_len);
    env.write_u32(return_data_len, outs_len)?;
    env.buy_gas(gas_cost)?;
    Ok(status as u8)
}

pub(crate) fn delegate_call_contract(
    mut env: WasmEnvMut,
    contract: u32,
    calldata: u32,
    calldata_len: u32,
    mut ink: u64,
    return_data_len: u32,
) -> Result<u8, Escape> {
    let mut env = WasmEnv::start(&mut env)?;
    env.pay_for_evm_copy(calldata_len.into())?;
    ink = ink.min(env.ink_left().into()); // provide no more than what the user has

    let gas = env.pricing().ink_to_gas(ink);
    let contract = env.read_bytes20(contract)?;
    let input = env.read_slice(calldata, calldata_len)?;

    let (outs_len, gas_cost, status) = env.evm().delegate_call(contract, input, gas);
    env.set_return_data_len(outs_len);
    env.write_u32(return_data_len, outs_len)?;
    env.buy_gas(gas_cost)?;
    Ok(status as u8)
}

pub(crate) fn static_call_contract(
    mut env: WasmEnvMut,
    contract: u32,
    calldata: u32,
    calldata_len: u32,
    mut ink: u64,
    return_data_len: u32,
) -> Result<u8, Escape> {
    let mut env = WasmEnv::start(&mut env)?;
    env.pay_for_evm_copy(calldata_len.into())?;
    ink = ink.min(env.ink_left().into()); // provide no more than what the user has

    let gas = env.pricing().ink_to_gas(ink);
    let contract = env.read_bytes20(contract)?;
    let input = env.read_slice(calldata, calldata_len)?;

    let (outs_len, gas_cost, status) = env.evm().static_call(contract, input, gas);
    env.set_return_data_len(outs_len);
    env.write_u32(return_data_len, outs_len)?;
    env.buy_gas(gas_cost)?;
    Ok(status as u8)
}

pub(crate) fn create1(
    mut env: WasmEnvMut,
    code: u32,
    code_len: u32,
    endowment: u32,
    contract: u32,
    revert_data_len: u32,
) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.pay_for_evm_copy(code_len.into())?;

    let code = env.read_slice(code, code_len)?;
    let endowment = env.read_bytes32(endowment)?;
    let gas = env.gas_left();

    let (result, ret_len, gas_cost) = env.evm().create1(code, endowment, gas);
    env.set_return_data_len(ret_len);
    env.write_u32(revert_data_len, ret_len)?;
    env.buy_gas(gas_cost)?;
    env.write_bytes20(contract, result?)?;
    Ok(())
}

pub(crate) fn create2(
    mut env: WasmEnvMut,
    code: u32,
    code_len: u32,
    endowment: u32,
    salt: u32,
    contract: u32,
    revert_data_len: u32,
) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.pay_for_evm_copy(code_len.into())?;

    let code = env.read_slice(code, code_len)?;
    let endowment = env.read_bytes32(endowment)?;
    let salt = env.read_bytes32(salt)?;
    let gas = env.gas_left();

    let (result, ret_len, gas_cost) = env.evm().create2(code, endowment, salt, gas);
    env.set_return_data_len(ret_len);
    env.write_u32(revert_data_len, ret_len)?;
    env.buy_gas(gas_cost)?;
    env.write_bytes20(contract, result?)?;
    Ok(())
}

pub(crate) fn read_return_data(mut env: WasmEnvMut, dest: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    let len = env.return_data_len();
    env.pay_for_evm_copy(len.into())?;

    let data = env.evm().load_return_data();
    env.write_slice(dest, &data)?;
    assert_eq!(data.len(), len as usize);
    Ok(())
}

pub(crate) fn return_data_size(mut env: WasmEnvMut) -> Result<u32, Escape> {
    let env = WasmEnv::start(&mut env)?;
    let len = env.return_data_len();
    Ok(len)
}

pub(crate) fn emit_log(mut env: WasmEnvMut, data: u32, len: u32, topics: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    let topics: u64 = topics.into();
    let length: u64 = len.into();
    if length < topics * 32 || topics > 4 {
        return Escape::logical("bad topic data");
    }
    env.buy_gas((1 + topics) * evm::LOG_TOPIC_GAS)?;
    env.buy_gas((length - topics * 32) * evm::LOG_DATA_GAS)?;

    let data = env.read_slice(data, len)?;
    env.evm().emit_log(data, topics as usize)?;
    Ok(())
}

pub(crate) fn block_basefee(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::BASEFEE_GAS)?;

    let basefee = env.evm_data().block_basefee;
    env.write_bytes32(data, basefee)?;
    Ok(())
}

pub(crate) fn block_chainid(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::CHAINID_GAS)?;

    let chainid = env.evm_data().block_chainid;
    env.write_bytes32(data, chainid)?;
    Ok(())
}

pub(crate) fn block_coinbase(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::COINBASE_GAS)?;

    let coinbase = env.evm_data().block_coinbase;
    env.write_bytes20(data, coinbase)?;
    Ok(())
}

pub(crate) fn block_difficulty(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::DIFFICULTY_GAS)?;

    let difficulty = env.evm_data().block_difficulty;
    env.write_bytes32(data, difficulty)?;
    Ok(())
}

pub(crate) fn block_gas_limit(mut env: WasmEnvMut) -> Result<u64, Escape> {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::GASLIMIT_GAS)?;
    Ok(env.evm_data().block_gas_limit)
}

pub(crate) fn block_number(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::NUMBER_GAS)?;

    let number = env.evm_data().block_number;
    env.write_bytes32(data, number)?;
    Ok(())
}

pub(crate) fn block_timestamp(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::TIMESTAMP_GAS)?;

    let timestamp = env.evm_data().block_timestamp;
    env.write_bytes32(data, timestamp)?;
    Ok(())
}

pub(crate) fn contract_address(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::ADDRESS_GAS)?;

    let address = env.evm_data().contract_address;
    env.write_bytes20(data, address)?;
    Ok(())
}

pub(crate) fn msg_sender(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::CALLER_GAS)?;

    let msg_sender = env.evm_data().msg_sender;
    env.write_bytes20(data, msg_sender)?;
    Ok(())
}

pub(crate) fn msg_value(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::CALLVALUE_GAS)?;

    let msg_value = env.evm_data().msg_value;
    env.write_bytes32(data, msg_value)?;
    Ok(())
}

pub(crate) fn tx_gas_price(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::GASPRICE_GAS)?;

    let gas_price = env.evm_data().gas_price;
    env.write_bytes32(data, gas_price)?;
    Ok(())
}

pub(crate) fn tx_ink_price(mut env: WasmEnvMut) -> Result<u64, Escape> {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::GASPRICE_GAS)?;
    Ok(env.pricing().ink_price)
}

pub(crate) fn tx_origin(mut env: WasmEnvMut, data: u32) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::ORIGIN_GAS)?;

    let origin = env.evm_data().origin;
    env.write_bytes20(data, origin)?;
    Ok(())
}

pub(crate) fn console_log_text(mut env: WasmEnvMut, ptr: u32, len: u32) -> MaybeEscape {
    let env = WasmEnv::start_free(&mut env);
    let text = env.read_slice(ptr, len)?;
    env.say(String::from_utf8_lossy(&text));
    Ok(())
}

pub(crate) fn console_log<T: Into<Value>>(mut env: WasmEnvMut, value: T) -> MaybeEscape {
    let env = WasmEnv::start_free(&mut env);
    env.say(value.into());
    Ok(())
}

pub(crate) fn console_tee<T: Into<Value> + Copy>(
    mut env: WasmEnvMut,
    value: T,
) -> Result<T, Escape> {
    let env = WasmEnv::start_free(&mut env);
    env.say(value.into());
    Ok(value)
}

pub(crate) fn lib_ecrecover_callback(
    mut env: WasmEnvMut,
    hash: u32,
    v: u32,
    r: u32,
    s: u32,
    result: u32,
) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;

    let hash = env.read_bytes32(hash)?;
    let v = env.read_bytes32(v)?;
    let r = env.read_bytes32(r)?;
    let s = env.read_bytes32(s)?;

    let data = [hash.as_slice(), v.as_slice(), r.as_slice(), s.as_slice()].concat();
    let (address, gas_cost) = env.evm().ecrecover_callback(data);
    env.buy_gas(gas_cost)?;

    env.write_bytes20(result, address)?;
    Ok(())
}

pub(crate) fn lib_ecrecover(
    mut env: WasmEnvMut,
    hash: u32,
    v: u32,
    r: u32,
    s: u32,
    result: u32,
) -> MaybeEscape {
    let mut env = WasmEnv::start(&mut env)?;
    env.buy_gas(evm::ECRECOVER_GAS)?;

    let hash = env.read_bytes32(hash)?;
    let v = env.read_bytes32(v)?;
    let r = env.read_bytes32(r)?;
    let s = env.read_bytes32(s)?;

    // Ensure v is 27 or 28
    if v[0..31] != [0; 31] {
        return Escape::logical("invalid v parameter");
    }
    let v = v[31] - 27;
    let recovery_id = RecoveryId::from_i32(v.into())?;

    const SECP256K1N: [u8; 32] =
        hex!["fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"];

    // Ensure r and s are both less than secp256kN
    if r.gt(&SECP256K1N) {
        return Escape::logical("invalid r parameter");
    }
    if s.gt(&SECP256K1N) {
        return Escape::logical("invalid s parameter");
    }
    let sig = [r.as_slice(), s.as_slice()].concat();
    let sig = RecoverableSignature::from_compact(&sig, recovery_id)?;

    let secp = Secp256k1::new();
    let msg = Message::from_slice(hash.as_ref())?;
    let key = secp.recover_ecdsa(&msg, &sig)?;
    let key = key.serialize_uncompressed();
    let key: [u8; 64] = key[1..].try_into().expect("wrong size uncompressed key");
    let mut hasher = Keccak256::new();
    hasher.update(key);
    let address: [u8; 20] = hasher.finalize()[12..]
        .try_into()
        .expect("wrong size public address");

    env.write_bytes20(result, Bytes20(address))?;
    Ok(())
}
