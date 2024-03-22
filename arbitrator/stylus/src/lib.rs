// Copyright 2022-2024, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro/blob/master/LICENSE

use arbutil::{
    evm::{
        api::DataReader,
        req::EvmApiRequestor,
        user::{UserOutcome, UserOutcomeKind},
        EvmData,
    },
    format::DebugBytes,
    Bytes32,
};
use evm_api::NativeRequestHandler;
use eyre::ErrReport;
use native::NativeInstance;
use prover::programs::{prelude::*, StylusData};
use run::RunProgram;
use std::{marker::PhantomData, mem, ptr};

pub use brotli;
pub use prover;

pub mod env;
mod evm_api;
pub mod host;
pub mod native;
pub mod run;

#[cfg(test)]
mod test;

#[cfg(all(test, feature = "benchmark"))]
mod benchmarks;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct GoSliceData {
    /// Points to data owned by Go.
    ptr: *const u8,
    /// The length in bytes.
    len: usize,
}

/// The data we're pointing to is owned by Go and has a lifetime no shorter than the current program.
unsafe impl Send for GoSliceData {}

impl GoSliceData {
    pub fn null() -> Self {
        Self {
            ptr: ptr::null(),
            len: 0,
        }
    }

    fn slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl DataReader for GoSliceData {
    fn slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[repr(C)]
pub struct RustSlice<'a> {
    ptr: *const u8,
    len: usize,
    phantom: PhantomData<&'a [u8]>,
}

impl<'a> RustSlice<'a> {
    fn new(slice: &'a [u8]) -> Self {
        Self {
            ptr: slice.as_ptr(),
            len: slice.len(),
            phantom: PhantomData,
        }
    }
}

#[repr(C)]
pub struct RustBytes {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

impl RustBytes {
    unsafe fn into_vec(self) -> Vec<u8> {
        Vec::from_raw_parts(self.ptr, self.len, self.cap)
    }

    unsafe fn write(&mut self, mut vec: Vec<u8>) {
        self.ptr = vec.as_mut_ptr();
        self.len = vec.len();
        self.cap = vec.capacity();
        mem::forget(vec);
    }

    unsafe fn write_err(&mut self, err: ErrReport) -> UserOutcomeKind {
        self.write(err.debug_bytes());
        UserOutcomeKind::Failure
    }

    unsafe fn write_outcome(&mut self, outcome: UserOutcome) -> UserOutcomeKind {
        let (status, outs) = outcome.into_data();
        self.write(outs);
        status
    }
}

/// Instruments and "activates" a user wasm.
///
/// The `output` is either the serialized asm & module pair or an error string.
/// Returns consensus info such as the module hash and footprint on success.
///
/// Note that this operation costs gas and is limited by the amount supplied via the `gas` pointer.
/// The amount left is written back at the end of the call.
///
/// # Safety
///
/// `output`, `asm_len`, `module_hash`, `footprint`, and `gas` must not be null.
#[no_mangle]
pub unsafe extern "C" fn stylus_activate(
    wasm: GoSliceData,
    page_limit: u16,
    version: u16,
    debug: bool,
    output: *mut RustBytes,
    asm_len: *mut usize,
    module_hash: *mut Bytes32,
    stylus_data: *mut StylusData,
    gas: *mut u64,
) -> UserOutcomeKind {
    let wasm = wasm.slice();
    let output = &mut *output;
    let module_hash = &mut *module_hash;
    let gas = &mut *gas;

    let (asm, module, info) = match native::activate(wasm, version, page_limit, debug, gas) {
        Ok(val) => val,
        Err(err) => return output.write_err(err),
    };
    *asm_len = asm.len();
    *module_hash = module.hash();
    *stylus_data = info;

    let mut data = asm;
    data.extend(&*module.into_bytes());
    output.write(data);
    UserOutcomeKind::Success
}

/// Calls a compiled user program.
///
/// # Safety
///
/// `module` must represent a valid module produced from `stylus_activate`.
/// `output` and `gas` must not be null.
#[no_mangle]
pub unsafe extern "C" fn stylus_call(
    module: GoSliceData,
    calldata: GoSliceData,
    config: StylusConfig,
    req_handler: NativeRequestHandler,
    evm_data: EvmData,
    debug_chain: u32,
    output: *mut RustBytes,
    gas: *mut u64,
) -> UserOutcomeKind {
    let module = module.slice();
    let calldata = calldata.slice().to_vec();
    let compile = CompileConfig::version(config.version, debug_chain != 0);
    let evm_api = EvmApiRequestor::new(req_handler);
    let pricing = config.pricing;
    let output = &mut *output;
    let ink = pricing.gas_to_ink(*gas);

    // Safety: module came from compile_user_wasm and we've paid for memory expansion
    let instance = unsafe { NativeInstance::deserialize(module, compile, evm_api, evm_data) };
    let mut instance = match instance {
        Ok(instance) => instance,
        Err(error) => panic!("failed to instantiate program: {error:?}"),
    };

    let status = match instance.run_main(&calldata, config, ink) {
        Err(e) | Ok(UserOutcome::Failure(e)) => output.write_err(e.wrap_err("call failed")),
        Ok(outcome) => output.write_outcome(outcome),
    };
    let ink_left = match status {
        UserOutcomeKind::OutOfStack => 0, // take all gas when out of stack
        _ => instance.ink_left().into(),
    };
    *gas = pricing.ink_to_gas(ink_left);
    status
}

/// Frees the vector. Does nothing when the vector is null.
///
/// # Safety
///
/// Must only be called once per vec.
#[no_mangle]
pub unsafe extern "C" fn stylus_drop_vec(vec: RustBytes) {
    if !vec.ptr.is_null() {
        mem::drop(vec.into_vec())
    }
}
