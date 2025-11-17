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
pub enum IrOperandSsa {
    SsaVar(SsaVariabel),
    Konstanta(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IrUnOp {
    Not,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IrBinOp {
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
pub enum IrExpressionSsa {
    Operand(IrOperandSsa),
    OperasiUnary(IrUnOp, Box<IrExpressionSsa>),
    OperasiBiner(IrBinOp, Box<IrExpressionSsa>, Box<IrExpressionSsa>),
    MuatMemori(Box<IrExpressionSsa>),
    Bandingkan(Box<IrExpressionSsa>, Box<IrExpressionSsa>),
    UjiBit(Box<IrExpressionSsa>, Box<IrExpressionSsa>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IrInstructionSsa {
    Assign(SsaVariabel, IrExpressionSsa),
    SimpanMemori(IrExpressionSsa, IrExpressionSsa),
    Dorong(IrExpressionSsa),
    Ambil(SsaVariabel),
    Lompat(IrExpressionSsa),
    LompatKondisi(IrExpressionSsa, IrExpressionSsa),
    Panggil(IrExpressionSsa),
    Kembali,
    Nop,
    Syscall,
    TidakTerdefinisi,
    InstruksiVektor(String, Vec<IrOperandSsa>),
}