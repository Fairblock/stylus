// Copyright 2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

use crate::{depth::DepthChecker, meter::Meter, start::StartMover};

use eyre::Result;
use wasmer::{imports, CompilerConfig, Instance, Module, Store, Universal};
use wasmer_compiler_singlepass::Singlepass;
use wasmparser::Operator;

use std::sync::Arc;

pub fn create(
    wasm: &[u8],
    costs: fn(&Operator) -> u64,
    start_gas: u64,
    max_depth: u32,
) -> Result<Instance> {
    let mut compiler = Singlepass::new();
    compiler.canonicalize_nans(true);
    compiler.enable_verifier();

    // add the instrumentation
    compiler.push_middleware(Arc::new(Meter::new(costs, start_gas)));
    compiler.push_middleware(Arc::new(DepthChecker::new(max_depth)));
    compiler.push_middleware(Arc::new(StartMover::new("polyglot_moved_start")));

    let engine = Universal::new(compiler).engine();
    let store = Store::new(&engine);
    let module = Module::new(&store, wasm)?;
    let imports = imports! {};
    let instance = Instance::new(&module, &imports)?;
    Ok(instance)
}
