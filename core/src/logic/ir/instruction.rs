use serde::Serialize;


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IrOperand {
    Register(String),
    Immediate(u64),
    Memory(Box<IrExpression>),
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
pub enum IrFlag {
    BenderaNol,
    BenderaBawa,
    BenderaLimpah,
    BenderaTanda,
    BenderaParitas,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IrExpression {
    Operand(IrOperand),
    UnaryOp(IrUnOp, Box<IrExpression>),
    BinaryOp(IrBinOp, Box<IrExpression>, Box<IrExpression>),
    Cmp(Box<IrExpression>, Box<IrExpression>),
    Test(Box<IrExpression>, Box<IrExpression>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IrInstruction {
    Set(IrOperand, IrExpression),
    Push(IrExpression),
    Pop(IrOperand),
    Jmp(IrExpression),
    JmpCond(IrExpression, IrExpression),
    Call(IrExpression),
    Ret,
    Nop,
    Syscall,
    Undefined,
    AturBendera(IrFlag, IrExpression),
    InstruksiVektor(String, Vec<IrOperand>),
}