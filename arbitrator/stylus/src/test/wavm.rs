// Copyright 2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

use eyre::Result;
use prover::{machine::GlobalState, programs::prelude::*, Machine};
use std::{collections::HashMap, path::Path, sync::Arc};

pub fn new_test_machine(path: &str, config: StylusConfig) -> Result<Machine> {
    let wat = std::fs::read(path)?;
    let wasm = wasmer::wat2wasm(&wat)?;
    let mut bin = prover::binary::parse(&wasm, Path::new("user"))?;
    let stylus_data = bin.instrument(&config)?;

    let wat = std::fs::read("tests/test.wat")?;
    let wasm = wasmer::wat2wasm(&wat)?;
    let lib = prover::binary::parse(&wasm, Path::new("test"))?;

    Machine::from_binaries(
        &[lib],
        bin,
        false,
        false,
        false,
        GlobalState::default(),
        HashMap::default(),
        Arc::new(|_, _| panic!("tried to read preimage")),
        Some(stylus_data),
    )
}

#[test]
fn test_gas() -> Result<()> {
    let mut config = StylusConfig::default();
    config.costs = super::expensive_add;
    config.start_gas = 10;

    let machine = &mut new_test_machine("tests/add.wat", config)?;
    let call = |mech: &mut Machine, v: u32| mech.call_function("user", "add_one", vec![v.into()]);

    assert_eq!(machine.gas_left(), MachineMeter::Ready(10));

    macro_rules! exhaust {
        ($gas:expr) => {
            machine.set_gas($gas);
            assert_eq!(machine.gas_left(), MachineMeter::Ready($gas));
            assert!(call(machine, 32).is_err());
            assert_eq!(machine.gas_left(), MachineMeter::Exhausted);
        };
    }

    exhaust!(0);
    exhaust!(50);
    exhaust!(99);

    let mut gas_left = 500;
    machine.set_gas(gas_left);
    while gas_left > 0 {
        assert_eq!(machine.gas_left(), MachineMeter::Ready(gas_left));
        assert_eq!(call(machine, 64)?, vec![65_u32.into()]);
        gas_left -= 100;
    }
    assert!(call(machine, 32).is_err());
    assert_eq!(machine.gas_left(), MachineMeter::Exhausted);
    Ok(())
}

#[test]
fn test_depth() -> Result<()> {
    // in depth.wat
    //    the `depth` global equals the number of times `recurse` is called
    //    the `recurse` function calls itself
    //    the `recurse` function has 1 parameter and 2 locals
    //    comments show that the max depth is 3 words

    let mut config = StylusConfig::default();
    config.depth = DepthParams::new(64, 16);

    let machine = &mut new_test_machine("tests/depth.wat", config)?;
    let call = |mech: &mut Machine| mech.call_function("user", "recurse", vec![0_u64.into()]);

    let program_depth: u32 = machine.get_global("depth")?.try_into()?;
    assert_eq!(program_depth, 0);
    assert_eq!(machine.stack_left(), 64);

    let mut check = |space: u32, expected: u32| -> Result<()> {
        machine.set_global("depth", 0_u32.into())?;
        machine.set_stack(space);
        assert_eq!(machine.stack_left(), space);

        assert!(call(machine).is_err());
        assert_eq!(machine.stack_left(), 0);

        let program_depth: u32 = machine.get_global("depth")?.try_into()?;
        assert_eq!(program_depth, expected);
        Ok(())
    };

    let locals = 2;
    let depth = 3;
    let fixed = 4;

    let frame_size = locals + depth + fixed;

    check(frame_size, 0)?; // should immediately exhaust (space left <= frame)
    check(frame_size + 1, 1)?;
    check(2 * frame_size, 1)?;
    check(2 * frame_size + 1, 2)?;
    check(4 * frame_size, 3)?;
    check(4 * frame_size + frame_size / 2, 4)
}

#[test]
fn test_start() -> Result<()> {
    // in start.wat
    //     the `status` global equals 10 at initialization
    //     the `start` function increments `status`
    //     by the spec, `start` must run at initialization

    fn check(machine: &mut Machine, value: u32) -> Result<()> {
        let status: u32 = machine.get_global("status")?.try_into()?;
        assert_eq!(status, value);
        Ok(())
    }

    let config = StylusConfig::default();
    let mut machine = &mut new_test_machine("tests/start.wat", config)?;
    check(machine, 10)?;

    let call = |mech: &mut Machine, name: &str| mech.call_function("user", name, vec![]);

    call(machine, "move_me")?;
    call(machine, "stylus_start")?;
    check(&mut machine, 12)
}
