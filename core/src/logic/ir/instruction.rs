//! Author: [Seclususs](https://github.com/seclususs)

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct SsaVariabel {
    pub nama_dasar: String,
    pub versi: u32,
}

impl fmt::Display for SsaVariabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.nama_dasar, self.versi)
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
    OperasiUnary(MicroUnOp, Box<MicroExpr>),
    OperasiBiner(MicroBinOp, Box<MicroExpr>, Box<MicroExpr>),
    MuatMemori(Box<MicroExpr>),
    Bandingkan(Box<MicroExpr>, Box<MicroExpr>),
    UjiBit(Box<MicroExpr>, Box<MicroExpr>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MicroInstruction {
    Assign(SsaVariabel, MicroExpr),
    SimpanMemori(MicroExpr, MicroExpr),
    Lompat(MicroExpr),
    LompatKondisi(MicroExpr, MicroExpr),
    Panggil(MicroExpr),
    Kembali,
    Nop,
    Syscall,
    TidakTerdefinisi,
    AtomicRMW {
        op: MicroAtomicOp,
        alamat: MicroExpr,
        nilai: MicroExpr,
        tujuan_lama: Option<SsaVariabel>,
    },
    MemoryFence,
    UpdateFlag(String, MicroExpr),
    InstruksiVektor {
        op: MicroBinOp,
        tujuan: SsaVariabel,
        elemen_size: u8,
        operand_1: Vec<MicroOperand>,
        operand_2: Vec<MicroOperand>,
    },
}