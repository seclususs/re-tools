use serde::Serialize;


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IrOperand {
    Register(String),
    Immediate(u64),
    Memory(Box<IrExpression>),
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IrExpression {
    Operand(IrOperand),
    BinaryOp(IrBinOp, Box<IrExpression>, Box<IrExpression>),
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
}