//! Author: [Seclususs](https://github.com/seclususs)

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct SsaVariabel {
    pub id_reg: String,
    pub versi: u32,
}

impl fmt::Display for SsaVariabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.id_reg, self.versi)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MicroOperand {
    SsaVar(SsaVariabel),
    Konstanta(u64),
    Flag(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MicroUnOp {
    Not,
    Neg,
    ExtractZeroFlag,
    ExtractSignFlag,
    ExtractCarryFlag,
    ExtractOverflowFlag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MicroBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
    TambahFloat,
    KurangFloat,
    KaliFloat,
    BagiFloat,
    VecAddI8,
    VecAddI16,
    VecAddI32,
    VecAddI64,
    VecSubI8,
    VecSubI16,
    VecSubI32,
    VecSubI64,
    VecMulI32,
    VecXor,
    VecOr,
    VecAnd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MicroAtomicOp {
    Xchg,
    Add,
    Sub,
    And,
    Or,
    Xor,
    CompareExchange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MicroExpr {
    Operand(MicroOperand),
    UnaryOp(MicroUnOp, Box<MicroExpr>),
    BinaryOp(MicroBinOp, Box<MicroExpr>, Box<MicroExpr>),
    LoadMemori(Box<MicroExpr>),
    Compare(Box<MicroExpr>, Box<MicroExpr>),
    TestBit(Box<MicroExpr>, Box<MicroExpr>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MicroInstruction {
    Assign(SsaVariabel, MicroExpr),
    StoreMemori(MicroExpr, MicroExpr),
    Jump(MicroExpr),
    JumpKondisi(MicroExpr, MicroExpr),
    Call(MicroExpr),
    Return,
    Nop,
    Syscall,
    Undefined,
    AtomicRMW {
        op: MicroAtomicOp,
        addr_mem: MicroExpr,
        nilai: MicroExpr,
        tujuan_lama: Option<SsaVariabel>,
    },
    MemoryFence,
    UpdateFlag(String, MicroExpr),
    VectorOp {
        op: MicroBinOp,
        tujuan: SsaVariabel,
        sz_elemen: u8,
        op_1: Vec<MicroOperand>,
        op_2: Vec<MicroOperand>,
    },
    Phi {
        tujuan: SsaVariabel,
        sumber: Vec<(SsaVariabel, u64)>,
    },
}