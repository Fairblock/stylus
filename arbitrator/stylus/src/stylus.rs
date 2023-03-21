// Copyright 2022-2023, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

use crate::{
    env::{SystemStateData, WasmEnv},
    host,
};
use arbutil::{operator::OperatorCode, Color};
use eyre::{bail, eyre, ErrReport, Result};
use prover::programs::{
    counter::{Counter, CountingMachine, OP_OFFSETS},
    depth::STYLUS_STACK_LEFT,
    meter::{STYLUS_GAS_LEFT, STYLUS_GAS_STATUS},
    prelude::*,
    start::STYLUS_START,
};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use wasmer::{
    imports, AsStoreMut, Function, FunctionEnv, Global, Instance, Module, Store, TypedFunction,
    Value,
};

pub struct NativeInstance {
    pub instance: Instance,
    pub store: Store,
    pub env: FunctionEnv<WasmEnv>,
}

impl NativeInstance {
    pub fn new(instance: Instance, store: Store, env: FunctionEnv<WasmEnv>) -> Self {
        Self {
            instance,
            store,
            env,
        }
    }

    pub fn new_sans_env(instance: Instance, mut store: Store) -> Self {
        let env = FunctionEnv::new(&mut store, WasmEnv::default());
        Self::new(instance, store, env)
    }

    pub fn env(&self) -> &WasmEnv {
        self.env.as_ref(&self.store)
    }

    pub fn get_global<T>(&mut self, name: &str) -> Result<T>
    where
        T: TryFrom<Value>,
        T::Error: Debug,
    {
        let store = &mut self.store.as_store_mut();
        let Ok(global) = self.instance.exports.get_global(name) else {
            bail!("global {} does not exist", name.red())
        };
        let ty = global.get(store);

        ty.try_into()
            .map_err(|_| eyre!("global {} has the wrong type", name.red()))
    }

    pub fn set_global<T>(&mut self, name: &str, value: T) -> Result<()>
    where
        T: Into<Value>,
    {
        let store = &mut self.store.as_store_mut();
        let Ok(global) = self.instance.exports.get_global(name) else {
            bail!("global {} does not exist", name.red())
        };
        global.set(store, value.into()).map_err(ErrReport::msg)
    }
}

impl Deref for NativeInstance {
    type Target = Instance;

    fn deref(&self) -> &Self::Target {
        &self.instance
    }
}

impl DerefMut for NativeInstance {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.instance
    }
}

impl MeteredMachine for NativeInstance {
    fn gas_left(&mut self) -> MachineMeter {
        let status = self.get_global(STYLUS_GAS_STATUS).unwrap();
        let mut gas = || self.get_global(STYLUS_GAS_LEFT).unwrap();

        match status {
            0 => MachineMeter::Ready(gas()),
            _ => MachineMeter::Exhausted,
        }
    }

    fn set_gas(&mut self, gas: u64) {
        self.set_global(STYLUS_GAS_LEFT, gas).unwrap();
        self.set_global(STYLUS_GAS_STATUS, 0).unwrap();
    }
}

impl CountingMachine for NativeInstance {
    fn operator_counts(&mut self) -> Result<BTreeMap<OperatorCode, u64>> {
        let mut counts = BTreeMap::new();

        for (&op, &offset) in OP_OFFSETS.lock().iter() {
            let count: u64 = self.get_global(&Counter::global_name(offset))?;
            if count != 0 {
                counts.insert(op, count);
            }
        }
        Ok(counts)
    }
}

impl DepthCheckedMachine for NativeInstance {
    fn stack_left(&mut self) -> u32 {
        self.get_global(STYLUS_STACK_LEFT).unwrap()
    }

    fn set_stack(&mut self, size: u32) {
        self.set_global(STYLUS_STACK_LEFT, size).unwrap()
    }
}

impl StartlessMachine for NativeInstance {
    fn get_start(&self) -> Result<TypedFunction<(), ()>> {
        let store = &self.store;
        let exports = &self.instance.exports;
        dbg!(&exports);
        exports
            .get_typed_function(store, STYLUS_START)
            .map_err(ErrReport::new)
    }
}

pub fn module(wasm: &[u8], config: StylusConfig) -> Result<Vec<u8>> {
    let mut store = config.store();
    let module = Module::new(&store, wasm)?;
    let imports = imports! {
        "forward" => {
            "read_args" => Function::new_typed(&mut store, |_: u32| {}),
            "return_data" => Function::new_typed(&mut store, |_: u32, _: u32| {}),
        },
    };
    Instance::new(&mut store, &module, &imports)?;

    let module = module.serialize()?;
    Ok(module.to_vec())
}

pub fn instance_from_module(
    module: Module,
    mut store: Store,
    env: WasmEnv,
) -> Result<NativeInstance> {
    let func_env = FunctionEnv::new(&mut store, env);
    let imports = imports! {
        "forward" => {
            "read_args" => Function::new_typed_with_env(&mut store, &func_env, host::read_args),
            "return_data" => Function::new_typed_with_env(&mut store, &func_env, host::return_data),
        },
    };
    let instance = Instance::new(&mut store, &module, &imports)?;
    let exports = &instance.exports;

    let expect_global = |name| -> Global { instance.exports.get_global(name).unwrap().clone() };
    // println!("exports: {:?}", &exports);
    let memory = exports.get_memory("memory")?.clone();
    println!("hi5");
    let gas_left = expect_global(STYLUS_GAS_LEFT);
    let gas_status = expect_global(STYLUS_GAS_STATUS);

    let env = func_env.as_mut(&mut store);
    env.memory = Some(memory);
    env.state = Some(SystemStateData {
        gas_left,
        gas_status,
        pricing: env.config.pricing,
    });

    Ok(NativeInstance::new(instance, store, func_env))
}

pub fn instance(path: &str, env: WasmEnv) -> Result<NativeInstance> {
    let store = env.config.store();
    let wat_or_wasm = std::fs::read(path)?;
    let module = Module::new(&store, wat_or_wasm)?;
    instance_from_module(module, store, env)
}
