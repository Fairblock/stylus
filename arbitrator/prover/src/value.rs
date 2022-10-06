// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

use crate::{binary::FloatType, console::Color, utils::Bytes32};
use digest::Digest;
use eyre::{bail, Result};
use serde::{Deserialize, Serialize};
use sha3::Keccak256;
use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
};
use wasmer::wasmparser::{FuncType, Type as WpType};
use wasmer_types::Type;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ArbValueType {
    I32,
    I64,
    F32,
    F64,
    RefNull,
    FuncRef,
    InternalRef,
}

impl ArbValueType {
    pub fn serialize(self) -> u8 {
        self as u8
    }
}

impl TryFrom<WpType> for ArbValueType {
    type Error = eyre::Error;

    fn try_from(ty: WpType) -> Result<Self> {
        use WpType::*;
        Ok(match ty {
            I32 => Self::I32,
            I64 => Self::I64,
            F32 => Self::F32,
            F64 => Self::F64,
            FuncRef => Self::FuncRef,
            ExternRef => Self::FuncRef,
            V128 => bail!("128-bit types are not supported"),
            ExnRef => bail!("Type not used in newer versions of wasmparser"),
            Func => bail!("Type not used in newer versions of wasmparser"),
            EmptyBlockType => bail!("Type not used in newer versions of wasmparser"),
        })
    }
}

impl From<ArbValueType> for WpType {
    fn from(ty: ArbValueType) -> Self {
        use ArbValueType::*;
        match ty {
            I32 => Self::I32,
            I64 => Self::I64,
            F32 => Self::F32,
            F64 => Self::F64,
            FuncRef | RefNull | InternalRef => Self::FuncRef,
        }
    }
}

impl TryFrom<Type> for ArbValueType {
    type Error = eyre::Error;

    fn try_from(ty: Type) -> Result<Self> {
        use Type::*;
        Ok(match ty {
            I32 => Self::I32,
            I64 => Self::I64,
            F32 => Self::F32,
            F64 => Self::F64,
            ExternRef => Self::FuncRef,
            FuncRef => Self::FuncRef,
            V128 => bail!("128-bit types are not supported"),
        })
    }
}

impl From<FloatType> for ArbValueType {
    fn from(ty: FloatType) -> ArbValueType {
        match ty {
            FloatType::F32 => ArbValueType::F32,
            FloatType::F64 => ArbValueType::F64,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
pub enum IntegerValType {
    I32,
    I64,
}

impl From<IntegerValType> for ArbValueType {
    fn from(ty: IntegerValType) -> ArbValueType {
        match ty {
            IntegerValType::I32 => ArbValueType::I32,
            IntegerValType::I64 => ArbValueType::I64,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramCounter {
    pub module: usize,
    pub func: usize,
    pub inst: usize,
}

impl ProgramCounter {
    pub fn serialize(self) -> Bytes32 {
        let mut b = [0u8; 32];
        b[28..].copy_from_slice(&(self.inst as u32).to_be_bytes());
        b[24..28].copy_from_slice(&(self.func as u32).to_be_bytes());
        b[20..24].copy_from_slice(&(self.module as u32).to_be_bytes());
        Bytes32(b)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Value {
    I32(u32),
    I64(u64),
    F32(f32),
    F64(f64),
    RefNull,
    FuncRef(u32),
    InternalRef(ProgramCounter),
}

impl Value {
    pub fn ty(self) -> ArbValueType {
        match self {
            Value::I32(_) => ArbValueType::I32,
            Value::I64(_) => ArbValueType::I64,
            Value::F32(_) => ArbValueType::F32,
            Value::F64(_) => ArbValueType::F64,
            Value::RefNull => ArbValueType::RefNull,
            Value::FuncRef(_) => ArbValueType::FuncRef,
            Value::InternalRef(_) => ArbValueType::InternalRef,
        }
    }

    pub fn contents_for_proof(self) -> Bytes32 {
        match self {
            Value::I32(x) => x.into(),
            Value::I64(x) => x.into(),
            Value::F32(x) => x.to_bits().into(),
            Value::F64(x) => x.to_bits().into(),
            Value::RefNull => Bytes32::default(),
            Value::FuncRef(x) => x.into(),
            Value::InternalRef(pc) => pc.serialize(),
        }
    }

    pub fn serialize_for_proof(self) -> [u8; 33] {
        let mut ret = [0u8; 33];
        ret[0] = self.ty().serialize();
        ret[1..].copy_from_slice(&*self.contents_for_proof());
        ret
    }

    pub fn is_i32_zero(self) -> bool {
        match self {
            Value::I32(0) => true,
            Value::I32(_) => false,
            _ => panic!(
                "WASM validation failed: i32.eqz equivalent called on {:?}",
                self,
            ),
        }
    }

    pub fn is_i64_zero(self) -> bool {
        match self {
            Value::I64(0) => true,
            Value::I64(_) => false,
            _ => panic!(
                "WASM validation failed: i64.eqz equivalent called on {:?}",
                self,
            ),
        }
    }

    pub fn assume_u32(self) -> u32 {
        match self {
            Value::I32(x) => x,
            _ => panic!("WASM validation failed: assume_u32 called on {:?}", self),
        }
    }

    pub fn assume_u64(self) -> u64 {
        match self {
            Value::I64(x) => x,
            _ => panic!("WASM validation failed: assume_u64 called on {:?}", self),
        }
    }

    pub fn hash(self) -> Bytes32 {
        let mut h = Keccak256::new();
        h.update(b"Value:");
        h.update(&[self.ty() as u8]);
        h.update(self.contents_for_proof());
        h.finalize().into()
    }

    pub fn default_of_type(ty: ArbValueType) -> Value {
        match ty {
            ArbValueType::I32 => Value::I32(0),
            ArbValueType::I64 => Value::I64(0),
            ArbValueType::F32 => Value::F32(0.),
            ArbValueType::F64 => Value::F64(0.),
            ArbValueType::RefNull | ArbValueType::FuncRef | ArbValueType::InternalRef => {
                Value::RefNull
            }
        }
    }

    pub fn pretty_print(&self) -> String {
        let lparem = Color::grey("(");
        let rparem = Color::grey(")");

        macro_rules! single {
            ($ty:expr, $value:expr) => {{
                format!("{}{}{}{}", Color::grey($ty), lparem, $value, rparem)
            }};
        }
        macro_rules! pair {
            ($ty:expr, $left:expr, $right:expr) => {{
                let eq = Color::grey("=");
                format!(
                    "{}{}{} {} {}{}",
                    Color::grey($ty),
                    lparem,
                    $left,
                    eq,
                    $right,
                    rparem
                )
            }};
        }
        match self {
            Value::I32(value) => {
                if (*value as i32) < 0 {
                    pair!("i32", *value as i32, value)
                } else {
                    single!("i32", *value)
                }
            }
            Value::I64(value) => {
                if (*value as i64) < 0 {
                    pair!("i64", *value as i64, value)
                } else {
                    single!("i64", *value)
                }
            }
            Value::F32(value) => single!("f32", *value),
            Value::F64(value) => single!("f64", *value),
            Value::RefNull => "null".into(),
            Value::FuncRef(func) => format!("func {}", func),
            Value::InternalRef(pc) => format!("inst {} in {}-{}", pc.inst, pc.module, pc.func),
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = self.pretty_print();
        write!(f, "{}", text)
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.ty() == other.ty() && self.contents_for_proof() == other.contents_for_proof()
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Value::I32(value as u32)
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Value::I64(value as u64)
    }
}

impl TryInto<u64> for Value {
    type Error = ();

    fn try_into(self) -> Result<u64, Self::Error> {
        match self {
            Value::I64(value) => Ok(value as u64),
            _ => Err(()),
        }
    }
}

impl TryInto<u32> for Value {
    type Error = ();

    fn try_into(self) -> Result<u32, Self::Error> {
        match self {
            Value::I32(value) => Ok(value as u32),
            _ => Err(()),
        }
    }
}

impl Eq for Value {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionType {
    pub inputs: Vec<ArbValueType>,
    pub outputs: Vec<ArbValueType>,
}

impl FunctionType {
    pub fn new(inputs: Vec<ArbValueType>, outputs: Vec<ArbValueType>) -> FunctionType {
        FunctionType { inputs, outputs }
    }

    pub fn hash(&self) -> Bytes32 {
        let mut h = Keccak256::new();
        h.update(b"Function type:");
        h.update(Bytes32::from(self.inputs.len()));
        for input in &self.inputs {
            h.update(&[*input as u8]);
        }
        h.update(Bytes32::from(self.outputs.len()));
        for output in &self.outputs {
            h.update(&[*output as u8]);
        }
        h.finalize().into()
    }
}

impl TryFrom<FuncType> for FunctionType {
    type Error = eyre::Error;

    fn try_from(func: FuncType) -> Result<Self> {
        let mut inputs = vec![];
        let mut outputs = vec![];

        for input in func.params.iter() {
            inputs.push(ArbValueType::try_from(*input)?)
        }
        for output in func.returns.iter() {
            outputs.push(ArbValueType::try_from(*output)?)
        }
        Ok(Self { inputs, outputs })
    }
}

impl TryFrom<wasmer_types::FunctionType> for FunctionType {
    type Error = eyre::Error;

    fn try_from(func: wasmer_types::FunctionType) -> Result<Self> {
        let mut inputs: Vec<ArbValueType> = vec![];
        let mut outputs = vec![];

        for input in func.params() {
            inputs.push(ArbValueType::try_from(*input)?)
        }
        for output in func.results() {
            outputs.push(ArbValueType::try_from(*output)?)
        }
        Ok(Self { inputs, outputs })
    }
}

impl Display for FunctionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut signature = "λ(".to_string();
        if !self.inputs.is_empty() {
            for arg in &self.inputs {
                signature += &format!("{}, ", arg);
            }
            signature.pop();
            signature.pop();
        }
        signature += ")";

        let output_tuple = self.outputs.len() > 2;

        if !self.outputs.is_empty() {
            signature += " -> ";
            if output_tuple {
                signature += "(";
            }
            for out in &self.outputs {
                signature += &format!("{}, ", out);
            }
            signature.pop();
            signature.pop();
            if output_tuple {
                signature += ")";
            }
        }
        write!(f, "{}", signature)
    }
}

impl Display for ArbValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ArbValueType::*;
        match self {
            I32 => write!(f, "i32"),
            I64 => write!(f, "i64"),
            F32 => write!(f, "f32"),
            F64 => write!(f, "f64"),
            RefNull => write!(f, "null"),
            FuncRef => write!(f, "func"),
            InternalRef => write!(f, "internal"),
        }
    }
}
