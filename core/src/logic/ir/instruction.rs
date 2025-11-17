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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MicroUnOp {
    Not,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MicroBinOp {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    TambahFloat,
    KurangFloat,
    KaliFloat,
    BagiFloat,
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
    InstruksiVektor(String, Vec<MicroOperand>),
}