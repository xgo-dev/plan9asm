package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

var x86ExtraScalarSpecs = []asm.OpSpec{
	// Missing widths for scalar ALU/unary/shift/rotate/mul-div/extend
	{Op: "ADCW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "adc"},
	{Op: "SBBB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "sbb"},
	{Op: "SBBW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "sbb"},
	{Op: "INCB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "inc"},
	{Op: "INCW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "inc"},
	{Op: "DECB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "dec"},
	{Op: "DECW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "dec"},
	{Op: "NEGB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "neg"},
	{Op: "NEGW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "neg"},
	{Op: "NOTB", Family: asm.FamilyALU, Width: 8, Effect: asm.EffectReadWrite, LLVMOp: "not"},
	{Op: "NOTW", Family: asm.FamilyALU, Width: 16, Effect: asm.EffectReadWrite, LLVMOp: "not"},
	{Op: "LEAW", Family: asm.FamilyMove, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "leaw"},
	{Op: "MOVBWSX", Family: asm.FamilyMove, Width: 16, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "movext"},
	{Op: "MOVBWZX", Family: asm.FamilyMove, Width: 16, SrcWidth: 8, Effect: asm.EffectWriteOnly, LLVMOp: "movext"},
	{Op: "MOVBLSX", Family: asm.FamilyMove, Width: 32, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movext"},
	{Op: "MOVBQSX", Family: asm.FamilyMove, Width: 64, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "movext"},
	{Op: "MOVWLSX", Family: asm.FamilyMove, Width: 32, SrcWidth: 16, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movext"},
	{Op: "MOVSWW", Family: asm.FamilyMove, Width: 16, SrcWidth: 16, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "movext"},
	{Op: "MOVZWW", Family: asm.FamilyMove, Width: 16, SrcWidth: 16, Effect: asm.EffectWriteOnly, LLVMOp: "movext"},

	// Shifts & rotates (8/16/32/64-bit, including carry rotates RCL/RCR)
	{Op: "ROLB", Family: asm.FamilyShift, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "rol"},
	{Op: "ROLW", Family: asm.FamilyShift, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "rol"},
	{Op: "RORB", Family: asm.FamilyShift, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "ror"},
	{Op: "RORW", Family: asm.FamilyShift, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "ror"},
	{Op: "RCLB", Family: asm.FamilyShift, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "rcl"},
	{Op: "RCLW", Family: asm.FamilyShift, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "rcl"},
	{Op: "RCLL", Family: asm.FamilyShift, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "rcl"},
	{Op: "RCLQ", Family: asm.FamilyShift, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "rcl"},
	{Op: "RCRB", Family: asm.FamilyShift, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "rcr"},
	{Op: "RCRW", Family: asm.FamilyShift, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "rcr"},
	{Op: "RCRL", Family: asm.FamilyShift, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "rcr"},
	{Op: "RCRQ", Family: asm.FamilyShift, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "rcr"},
	{Op: "SALB", Family: asm.FamilyShift, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "shl"},
	{Op: "SALW", Family: asm.FamilyShift, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "shl"},
	{Op: "SHRB", Family: asm.FamilyShift, Width: 8, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "lshr"},
	{Op: "SARB", Family: asm.FamilyShift, Width: 8, Signed: true, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "ashr"},
	{Op: "SARW", Family: asm.FamilyShift, Width: 16, Signed: true, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "ashr"},

	// Mul / Div narrow widths
	{Op: "IMULW", Family: asm.FamilyMulDiv, Width: 16, Signed: true, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "imul"},
	{Op: "IMUL3W", Family: asm.FamilyMulDiv, Width: 16, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "imul3"},
	{Op: "MULB", Family: asm.FamilyMulDiv, Width: 8, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, Implicit: asm.ImplicitAX, LLVMOp: "mul"},
	{Op: "IMULB", Family: asm.FamilyMulDiv, Width: 8, Signed: true, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, Implicit: asm.ImplicitAX, LLVMOp: "imul1"},
	{Op: "MULW", Family: asm.FamilyMulDiv, Width: 16, Effect: asm.EffectImplicit, Flags: asm.FlagsWrite, Implicit: asm.ImplicitAX | asm.ImplicitDX, LLVMOp: "mul"},
	{Op: "DIVB", Family: asm.FamilyMulDiv, Width: 8, Effect: asm.EffectImplicit, Flags: asm.FlagsClobber, Implicit: asm.ImplicitAX, LLVMOp: "div"},
	{Op: "IDIVB", Family: asm.FamilyMulDiv, Width: 8, Signed: true, Effect: asm.EffectImplicit, Flags: asm.FlagsClobber, Implicit: asm.ImplicitAX, LLVMOp: "idiv"},
	{Op: "DIVW", Family: asm.FamilyMulDiv, Width: 16, Effect: asm.EffectImplicit, Flags: asm.FlagsClobber, Implicit: asm.ImplicitAX | asm.ImplicitDX, LLVMOp: "div"},
	{Op: "IDIVW", Family: asm.FamilyMulDiv, Width: 16, Signed: true, Effect: asm.EffectImplicit, Flags: asm.FlagsClobber, Implicit: asm.ImplicitAX | asm.ImplicitDX, LLVMOp: "idiv"},

	// Bit test (all widths)
	{Op: "BTW", Family: asm.FamilyBit, Width: 16, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "bt"},
	{Op: "BTL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "bt"},
	{Op: "BTQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "bt"},
	{Op: "BTSW", Family: asm.FamilyBit, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "bts"},
	{Op: "BTSL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "bts"},
	{Op: "BTRW", Family: asm.FamilyBit, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "btr"},
	{Op: "BTRL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "btr"},
	{Op: "BTCW", Family: asm.FamilyBit, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "btc"},
	{Op: "BTCL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "btc"},
	{Op: "BTCQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "btc"},

	// Bit count / BMI1 / BMI2 / ADX
	{Op: "TZCNTW", Family: asm.FamilyBit, Width: 16, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "tzcnt", ArchFeature: "+bmi"},
	{Op: "TZCNTL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "tzcnt", ArchFeature: "+bmi"},
	{Op: "LZCNTW", Family: asm.FamilyBit, Width: 16, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "lzcnt", ArchFeature: "+lzcnt"},
	{Op: "LZCNTL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "lzcnt", ArchFeature: "+lzcnt"},
	{Op: "LZCNTQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "lzcnt", ArchFeature: "+lzcnt"},
	{Op: "POPCNTW", Family: asm.FamilyBit, Width: 16, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "popcnt", ArchFeature: "+popcnt"},
	{Op: "ANDNL", Family: asm.FamilyBit, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "andn", ArchFeature: "+bmi"},
	{Op: "ANDNQ", Family: asm.FamilyBit, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "andn", ArchFeature: "+bmi"},
	{Op: "BLSIL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "blsi", ArchFeature: "+bmi"},
	{Op: "BLSIQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "blsi", ArchFeature: "+bmi"},
	{Op: "BLSMSKL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "blsmsk", ArchFeature: "+bmi"},
	{Op: "BLSMSKQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "blsmsk", ArchFeature: "+bmi"},
	{Op: "BLSRL", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "blsr", ArchFeature: "+bmi"},
	{Op: "BLSRQ", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "blsr", ArchFeature: "+bmi"},
	{Op: "BEXTRL", Family: asm.FamilyBit, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "bextr", ArchFeature: "+bmi"},
	{Op: "BEXTRQ", Family: asm.FamilyBit, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "bextr", ArchFeature: "+bmi"},
	{Op: "BZHIL", Family: asm.FamilyBit, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "bzhi", ArchFeature: "+bmi2"},
	{Op: "BZHIQ", Family: asm.FamilyBit, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "bzhi", ArchFeature: "+bmi2"},
	{Op: "SHLXL", Family: asm.FamilyBit, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "shlx", ArchFeature: "+bmi2"},
	{Op: "SHLXQ", Family: asm.FamilyBit, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "shlx", ArchFeature: "+bmi2"},
	{Op: "SHRXL", Family: asm.FamilyBit, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "shrx", ArchFeature: "+bmi2"},
	{Op: "SHRXQ", Family: asm.FamilyBit, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "shrx", ArchFeature: "+bmi2"},
	{Op: "SARXL", Family: asm.FamilyBit, Width: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sarx", ArchFeature: "+bmi2"},
	{Op: "SARXQ", Family: asm.FamilyBit, Width: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sarx", ArchFeature: "+bmi2"},
	{Op: "RORXL", Family: asm.FamilyBit, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "rorx", ArchFeature: "+bmi2"},
	{Op: "RORXQ", Family: asm.FamilyBit, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "rorx", ArchFeature: "+bmi2"},
	{Op: "MULXL", Family: asm.FamilyMulDiv, Width: 32, ThreeOp: true, Effect: asm.EffectImplicit, Implicit: asm.ImplicitDX, LLVMOp: "mulx", ArchFeature: "+bmi2"},
	{Op: "ADCXL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "adcx", ArchFeature: "+adx"},
	{Op: "ADOXL", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectReadWrite, Flags: asm.FlagsReadWrite, LLVMOp: "adox", ArchFeature: "+adx"},

	// Flag, sign-extend, stack, hint, and system instructions
	{Op: "CLC", Family: asm.FamilySystem, Flags: asm.FlagsWrite, LLVMOp: "clc"},
	{Op: "STC", Family: asm.FamilySystem, Flags: asm.FlagsWrite, LLVMOp: "stc"},
	{Op: "CMC", Family: asm.FamilySystem, Flags: asm.FlagsReadWrite, LLVMOp: "cmc"},
	{Op: "CBW", Family: asm.FamilySystem, Width: 16, Implicit: asm.ImplicitAX, LLVMOp: "cbw"},
	{Op: "CWDE", Family: asm.FamilySystem, Width: 32, Implicit: asm.ImplicitAX, LLVMOp: "cwde"},
	{Op: "CDQE", Family: asm.FamilySystem, Width: 64, Implicit: asm.ImplicitAX, LLVMOp: "cdqe"},
	{Op: "CDQ", Family: asm.FamilySystem, Width: 32, Implicit: asm.ImplicitAX | asm.ImplicitDX, LLVMOp: "cdq"},
	{Op: "CQO", Family: asm.FamilySystem, Width: 64, Implicit: asm.ImplicitAX | asm.ImplicitDX, LLVMOp: "cqo"},
	{Op: "LEAVEQ", Family: asm.FamilySystem, Width: 64, Implicit: asm.ImplicitSP, LLVMOp: "leaveq"},
	{Op: "LEAVEL", Family: asm.FamilySystem, Width: 32, Implicit: asm.ImplicitSP, LLVMOp: "leaveq"},
	{Op: "LEAVEW", Family: asm.FamilySystem, Width: 16, Implicit: asm.ImplicitSP, LLVMOp: "leaveq"},
	{Op: "ENTER", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "PUSHFL", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "POPFL", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "RETFW", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "RETFQ", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "INB", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "INW", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "INL", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "OUTB", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "OUTW", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "OUTL", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "XACQUIRE", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "XRELEASE", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "XBEGIN", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "WAIT", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "INTO", Family: asm.FamilySystem, Effect: asm.EffectImplicit, LLVMOp: "any_nop"},
	{Op: "AAA", Family: asm.FamilySystem, Width: 8, Implicit: asm.ImplicitAX, Flags: asm.FlagsReadWrite, LLVMOp: "bcd_adj"},
	{Op: "AAS", Family: asm.FamilySystem, Width: 8, Implicit: asm.ImplicitAX, Flags: asm.FlagsReadWrite, LLVMOp: "bcd_adj"},
	{Op: "AAM", Family: asm.FamilySystem, Width: 8, Implicit: asm.ImplicitAX, Flags: asm.FlagsWrite, LLVMOp: "bcd_adj"},
	{Op: "AAD", Family: asm.FamilySystem, Width: 8, Implicit: asm.ImplicitAX, Flags: asm.FlagsWrite, LLVMOp: "bcd_adj"},
	{Op: "DAA", Family: asm.FamilySystem, Width: 8, Implicit: asm.ImplicitAX, Flags: asm.FlagsReadWrite, LLVMOp: "bcd_adj"},
	{Op: "DAS", Family: asm.FamilySystem, Width: 8, Implicit: asm.ImplicitAX, Flags: asm.FlagsReadWrite, LLVMOp: "bcd_adj"},
	{Op: "ARPL", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectReadWrite, Flags: asm.FlagsWrite, LLVMOp: "arpl"},
	{Op: "BOUNDW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectReadOnly, LLVMOp: "bound"},
	{Op: "BOUNDL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectReadOnly, LLVMOp: "bound"},
	{Op: "PUSHAW", Family: asm.FamilySystem, Width: 16, Implicit: asm.ImplicitSP, LLVMOp: "pushaw"},
	{Op: "POPAW", Family: asm.FamilySystem, Width: 16, Implicit: asm.ImplicitSP, LLVMOp: "popaw"},
	{Op: "DUFFZERO", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "DUFFCOPY", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "NOPL", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "NOPW", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "ENDBR64", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "ENDBR32", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "CLDEMOTE", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "CLFLUSH", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "CLFLUSHOPT", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "CLWB", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "RDPID", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "rdpid"},
	{Op: "RDRANDW", Family: asm.FamilyCrypto, Width: 16, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "rdrand"},
	{Op: "RDRANDL", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "rdrand"},
	{Op: "RDRANDQ", Family: asm.FamilyCrypto, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "rdrand"},
	{Op: "RDSEEDW", Family: asm.FamilyCrypto, Width: 16, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "rdseed"},
	{Op: "RDSEEDL", Family: asm.FamilyCrypto, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "rdseed"},
	{Op: "RDSEEDQ", Family: asm.FamilyCrypto, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "rdseed"},
	{Op: "RDFSBASEL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "rdfsbase"},
	{Op: "RDFSBASEQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "rdfsbase"},
	{Op: "RDGSBASEL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "rdgsbase"},
	{Op: "RDGSBASEQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "rdgsbase"},
	{Op: "WRFSBASEL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectReadOnly, LLVMOp: "wrfsbase"},
	{Op: "WRFSBASEQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectReadOnly, LLVMOp: "wrfsbase"},
	{Op: "WRGSBASEL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectReadOnly, LLVMOp: "wrgsbase"},
	{Op: "WRGSBASEQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectReadOnly, LLVMOp: "wrgsbase"},

	// Hardware / privileged / state save-restore / RTM instructions modeled via inline asm / state ops
	{Op: "CLAC", Family: asm.FamilySystem, InlineAsm: "clac"},
	{Op: "STAC", Family: asm.FamilySystem, InlineAsm: "stac"},
	{Op: "CLI", Family: asm.FamilySystem, InlineAsm: "cli"},
	{Op: "STI", Family: asm.FamilySystem, InlineAsm: "sti"},
	{Op: "CLTS", Family: asm.FamilySystem, InlineAsm: "clts"},
	{Op: "HLT", Family: asm.FamilySystem, InlineAsm: "hlt"},
	{Op: "ICEBP", Family: asm.FamilySystem, InlineAsm: ".byte 0xf1"},
	{Op: "INVD", Family: asm.FamilySystem, InlineAsm: "invd"},
	{Op: "WBINVD", Family: asm.FamilySystem, InlineAsm: "wbinvd"},
	{Op: "WBNOINVD", Family: asm.FamilySystem, InlineAsm: ".byte 0xf3, 0x0f, 0x09"},
	{Op: "INVLPG", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "INVPCID", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "any_nop"},
	{Op: "IRETW", Family: asm.FamilySystem, InlineAsm: "iretw"},
	{Op: "IRETL", Family: asm.FamilySystem, InlineAsm: "iretl"},
	{Op: "IRETQ", Family: asm.FamilySystem, InlineAsm: "iretq"},
	{Op: "MONITOR", Family: asm.FamilySystem, InlineAsm: "monitor"},
	{Op: "MWAIT", Family: asm.FamilySystem, InlineAsm: "mwait"},
	{Op: "INSB", Family: asm.FamilySystem, InlineAsm: "insb"},
	{Op: "INSW", Family: asm.FamilySystem, InlineAsm: "insw"},
	{Op: "INSL", Family: asm.FamilySystem, InlineAsm: "insl"},
	{Op: "OUTSB", Family: asm.FamilySystem, InlineAsm: "outsb"},
	{Op: "OUTSW", Family: asm.FamilySystem, InlineAsm: "outsw"},
	{Op: "OUTSL", Family: asm.FamilySystem, InlineAsm: "outsl"},
	{Op: "RDMSR", Family: asm.FamilySystem, InlineAsm: "rdmsr"},
	{Op: "WRMSR", Family: asm.FamilySystem, InlineAsm: "wrmsr"},
	{Op: "RDPKRU", Family: asm.FamilySystem, InlineAsm: "rdpkru"},
	{Op: "WRPKRU", Family: asm.FamilySystem, InlineAsm: "wrpkru"},
	{Op: "SWAPGS", Family: asm.FamilySystem, InlineAsm: "swapgs"},
	{Op: "SYSEXIT", Family: asm.FamilySystem, InlineAsm: "sysexit"},
	{Op: "SYSRET", Family: asm.FamilySystem, InlineAsm: "sysret"},
	{Op: "RSM", Family: asm.FamilySystem, InlineAsm: "rsm"},
	{Op: "UD1", Family: asm.FamilySystem, InlineAsm: "ud2"},
	{Op: "UD2", Family: asm.FamilySystem, InlineAsm: "ud2"},
	{Op: "XABORT", Family: asm.FamilySystem, LLVMOp: "any_nop"},
	{Op: "XEND", Family: asm.FamilySystem, InlineAsm: "xend"},
	{Op: "XTEST", Family: asm.FamilySystem, Flags: asm.FlagsWrite, LLVMOp: "xtest"},
	{Op: "XSETBV", Family: asm.FamilySystem, InlineAsm: "xsetbv"},
	{Op: "LDMXCSR", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "STMXCSR", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "stmxcsr"},
	{Op: "VLDMXCSR", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "VSTMXCSR", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "stmxcsr"},
	{Op: "FXSAVE", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "mem_nop"},
	{Op: "FXSAVE64", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "mem_nop"},
	{Op: "FXRSTOR", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "FXRSTOR64", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "XSAVE", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "mem_nop"},
	{Op: "XSAVE64", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "mem_nop"},
	{Op: "XSAVEC", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "mem_nop"},
	{Op: "XSAVEC64", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "mem_nop"},
	{Op: "XSAVEOPT", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "mem_nop"},
	{Op: "XSAVEOPT64", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "mem_nop"},
	{Op: "XSAVES", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "mem_nop"},
	{Op: "XSAVES64", Family: asm.FamilySystem, Effect: asm.EffectWriteOnly, LLVMOp: "mem_nop"},
	{Op: "XRSTOR", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "XRSTOR64", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "XRSTORS", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "XRSTORS64", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "mem_nop"},
	{Op: "LFSW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "load_seg"},
	{Op: "LFSL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "load_seg"},
	{Op: "LFSQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "load_seg"},
	{Op: "LGSW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "load_seg"},
	{Op: "LGSL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "load_seg"},
	{Op: "LGSQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "load_seg"},
	{Op: "LSSW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "load_seg"},
	{Op: "LSSL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "load_seg"},
	{Op: "LSSQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "load_seg"},
	{Op: "SLDT", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "store_zero"},
	{Op: "SLDTW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "store_zero"},
	{Op: "SLDTL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "store_zero"},
	{Op: "SLDTQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "store_zero"},
	{Op: "SMSW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "store_zero"},
	{Op: "SMSWW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "store_zero"},
	{Op: "SMSWL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "store_zero"},
	{Op: "SMSWQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "store_zero"},
	{Op: "STR", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "store_zero"},
	{Op: "STRW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, LLVMOp: "store_zero"},
	{Op: "STRL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "store_zero"},
	{Op: "STRQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "store_zero"},
	{Op: "RDPMC", Family: asm.FamilySystem, InlineAsm: "rdpmc"},
	{Op: "RETFL", Family: asm.FamilySystem, LLVMOp: "any_nop"},
	{Op: "SYSENTER", Family: asm.FamilySystem, InlineAsm: "sysenter"},
	{Op: "SYSENTER64", Family: asm.FamilySystem, InlineAsm: "sysenter"},
	{Op: "SYSEXIT64", Family: asm.FamilySystem, InlineAsm: "sysexit"},
	{Op: "UMONITOR", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "any_nop"},
	{Op: "VERR", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "any_nop"},
	{Op: "VERW", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, Flags: asm.FlagsWrite, LLVMOp: "any_nop"},
	{Op: "LARW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "any_nop"},
	{Op: "LARL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "any_nop"},
	{Op: "LARQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "any_nop"},
	{Op: "LSLW", Family: asm.FamilySystem, Width: 16, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "any_nop"},
	{Op: "LSLL", Family: asm.FamilySystem, Width: 32, Effect: asm.EffectWriteZeroUpper, Flags: asm.FlagsWrite, LLVMOp: "any_nop"},
	{Op: "LSLQ", Family: asm.FamilySystem, Width: 64, Effect: asm.EffectWriteOnly, Flags: asm.FlagsWrite, LLVMOp: "any_nop"},
}

var x86ExtraScalarTable = asm.NewOpTable(x86ExtraScalarSpecs)

// x86CondValue evaluates any Plan 9 x86 condition code suffix into an LLVM i1 SSA value.
func (c *amd64Ctx) x86CondValue(cc string) (string, bool) {
	not := func(v string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", t, v)
		return "%" + t
	}
	switch strings.ToUpper(cc) {
	case "EQ", "E", "Z":
		return c.loadFlag(c.flagsZSlot), true
	case "NE", "NZ":
		return not(c.loadFlag(c.flagsZSlot)), true
	case "LT", "L", "NGE":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", t, c.loadFlag(c.flagsSltSlot), c.loadFlag(c.flagsOFSlot))
		return "%" + t, true
	case "GE", "NL":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", t, c.loadFlag(c.flagsSltSlot), c.loadFlag(c.flagsOFSlot))
		return not("%" + t), true
	case "LE", "NG":
		lt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", lt, c.loadFlag(c.flagsSltSlot), c.loadFlag(c.flagsOFSlot))
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %s\n", t, lt, c.loadFlag(c.flagsZSlot))
		return "%" + t, true
	case "GT", "G", "NLE":
		lt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", lt, c.loadFlag(c.flagsSltSlot), c.loadFlag(c.flagsOFSlot))
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %s\n", t, lt, c.loadFlag(c.flagsZSlot))
		return not("%" + t), true
	case "CS", "LO", "B", "C", "NAE":
		return c.loadFlag(c.flagsCFSlot), true
	case "CC", "HS", "AE", "NC", "NB":
		return not(c.loadFlag(c.flagsCFSlot)), true
	case "LS", "BE", "NA":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t, c.loadFlag(c.flagsCFSlot), c.loadFlag(c.flagsZSlot))
		return "%" + t, true
	case "HI", "A", "NBE":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t, c.loadFlag(c.flagsCFSlot), c.loadFlag(c.flagsZSlot))
		return not("%" + t), true
	case "MI", "S":
		return c.loadFlag(c.flagsSltSlot), true
	case "PL", "NS":
		return not(c.loadFlag(c.flagsSltSlot)), true
	case "OS", "O":
		return c.loadFlag(c.flagsOFSlot), true
	case "OC", "NO":
		return not(c.loadFlag(c.flagsOFSlot)), true
	case "PS", "P", "PE":
		return c.loadFlag(c.flagsPFSlot), true
	case "PC", "NP", "PO":
		return not(c.loadFlag(c.flagsPFSlot)), true
	default:
		return "", false
	}
}

func (c *amd64Ctx) lowerScalarDeclarative(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	s := string(op)
	// Parameterized CMOV{W,L,Q}<cc> (48 opcodes)
	if strings.HasPrefix(s, "CMOV") && len(s) >= 7 {
		var ty asm.LLVMType
		switch s[4] {
		case 'W':
			ty = asm.I16
		case 'L':
			ty = asm.I32
		case 'Q':
			ty = asm.I64
		}
		if ty != "" {
			if cond, valid := c.x86CondValue(s[5:]); valid {
				if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
					return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
				}
				srcV, err := c.evalIntSized(ins.Args[0], ty)
				if err != nil {
					return true, false, err
				}
				dstV, err := c.evalIntSized(ins.Args[1], ty)
				if err != nil {
					return true, false, err
				}
				sel := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", sel, cond, ty, srcV, ty, dstV)
				return true, false, c.storeRegSized(ins.Args[1].Reg, ty, "%"+sel)
			}
		}
	}
	// Parameterized SET<cc> (all 16 x86 conditions)
	if strings.HasPrefix(s, "SET") && len(s) >= 4 {
		if cond, valid := c.x86CondValue(s[3:]); valid {
			if len(ins.Args) != 1 {
				return true, false, fmt.Errorf("amd64 %s expects 1 dst operand: %q", op, ins.Raw)
			}
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i8\n", z, cond)
			switch ins.Args[0].Kind {
			case asm.OpReg:
				return true, false, c.storeRegSized(ins.Args[0].Reg, asm.I8, "%"+z)
			case asm.OpMem:
				p, ptrType, err := c.ptrFromMem(ins.Args[0].Mem)
				if err != nil {
					return true, false, err
				}
				fmt.Fprintf(c.b, "  store i8 %%%s, %s %s, align 1\n", z, ptrType, p)
				return true, false, nil
			case asm.OpFP:
				return true, false, c.storeFPResult(ins.Args[0].FPOffset, asm.I8, "%"+z)
			case asm.OpSym:
				p, err := c.ptrFromSB(ins.Args[0].Sym)
				if err != nil {
					return true, false, err
				}
				fmt.Fprintf(c.b, "  store i8 %%%s, ptr %s, align 1\n", z, p)
				return true, false, nil
			default:
				return true, false, fmt.Errorf("amd64 %s unsupported dst: %q", op, ins.Raw)
			}
		}
	}

	spec, found := x86ExtraScalarTable.Lookup(op)
	if !found {
		return false, false, nil
	}
	switch spec.Family {
	case asm.FamilyNOP:
		return true, false, nil
	case asm.FamilyMove:
		return true, false, c.lowerX86ExtraMove(spec, ins)
	case asm.FamilyALU:
		return true, false, c.lowerX86ExtraALU(spec, ins)
	case asm.FamilyShift:
		return true, false, c.lowerX86ExtraShift(spec, ins)
	case asm.FamilyMulDiv:
		return true, false, c.lowerX86ExtraMulDiv(spec, ins)
	case asm.FamilyBit:
		return true, false, c.lowerX86ExtraBit(spec, ins)
	case asm.FamilyCrypto, asm.FamilySystem:
		return true, false, c.lowerX86ExtraSystem(spec, ins)
	}
	return false, false, nil
}

func x86LLVMIntType(bits uint16) asm.LLVMType {
	switch bits {
	case 8:
		return asm.I8
	case 16:
		return asm.I16
	case 32:
		return asm.I32
	default:
		return asm.I64
	}
}

func (c *amd64Ctx) lowerX86ExtraMove(spec asm.OpSpec, ins asm.Instr) error {
	switch spec.LLVMOp {
	case "leaw":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 LEAW expects mem, reg: %q", ins.Raw)
		}
		var addr string
		var err error
		switch ins.Args[0].Kind {
		case asm.OpMem:
			addr, err = c.addrFromMem(ins.Args[0].Mem)
		case asm.OpSym:
			p, perr := c.ptrFromSB(ins.Args[0].Sym)
			if perr != nil {
				return perr
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, p)
			addr = "%" + t
		default:
			return fmt.Errorf("amd64 LEAW unsupported src: %q", ins.Raw)
		}
		if err != nil {
			return err
		}
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", tr, addr)
		return c.storeRegSized(ins.Args[1].Reg, asm.I16, "%"+tr)

	case "movext":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, dstReg: %q", spec.Op, ins.Raw)
		}
		srcTy := x86LLVMIntType(spec.SrcWidth)
		dstTy := x86LLVMIntType(spec.Width)
		sv, err := c.evalIntSized(ins.Args[0], srcTy)
		if err != nil {
			return err
		}
		out := sv
		if srcTy != dstTy {
			t := c.newTmp()
			ext := "zext"
			if spec.Signed {
				ext = "sext"
			}
			fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", t, ext, srcTy, sv, dstTy)
			out = "%" + t
		}
		return c.storeRegSized(ins.Args[1].Reg, dstTy, out)
	}
	return fmt.Errorf("amd64: unhandled move %s", spec.Op)
}

func (c *amd64Ctx) lowerX86ExtraALU(spec asm.OpSpec, ins asm.Instr) error {
	ty := x86LLVMIntType(spec.Width)
	switch spec.LLVMOp {
	case "inc", "dec", "neg", "not":
		if len(ins.Args) != 1 {
			return fmt.Errorf("amd64 %s expects 1 operand: %q", spec.Op, ins.Raw)
		}
		cur, storeDst, err := c.loadIntDestination(ins.Args[0], ty)
		if err != nil {
			return err
		}
		res := c.newTmp()
		switch spec.LLVMOp {
		case "inc":
			fmt.Fprintf(c.b, "  %%%s = add %s %s, 1\n", res, ty, cur)
		case "dec":
			fmt.Fprintf(c.b, "  %%%s = sub %s %s, 1\n", res, ty, cur)
		case "neg":
			fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", res, ty, cur)
		case "not":
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", res, ty, cur)
		}
		if err := storeDst("%" + res); err != nil {
			return err
		}
		if spec.Flags == asm.FlagsWrite {
			switch spec.LLVMOp {
			case "inc":
				c.setIncDecFlagsSized(ty, cur, "%"+res, false)
			case "dec":
				c.setIncDecFlagsSized(ty, cur, "%"+res, true)
			case "neg":
				c.setNegFlagsSized(ty, cur, "%"+res)
			}
		}
		return nil

	case "adc", "sbb", "adcx", "adox":
		if len(ins.Args) != 2 {
			return fmt.Errorf("amd64 %s expects src, dst: %q", spec.Op, ins.Raw)
		}
		srcV, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		dstV, storeDst, err := c.loadIntDestination(ins.Args[1], ty)
		if err != nil {
			return err
		}
		flagSlot := c.flagsCFSlot
		if spec.LLVMOp == "adox" {
			flagSlot = c.flagsOFSlot
		}
		cf := c.loadFlag(flagSlot)
		wBits := spec.Width * 2
		wTy := fmt.Sprintf("i%d", wBits)
		dw, sw, cw := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", dw, ty, dstV, wTy)
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", sw, ty, srcV, wTy)
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", cw, cf, wTy)
		var outW, cout string
		if spec.LLVMOp == "sbb" {
			subtr, diff, bor := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", subtr, wTy, sw, cw)
			fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", diff, wTy, dw, subtr)
			fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %%%s\n", bor, wTy, dw, subtr)
			outW, cout = "%"+diff, "%"+bor
		} else {
			t0, sum, sh, c1 := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", t0, wTy, dw, sw)
			fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", sum, wTy, t0, cw)
			fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n", sh, wTy, sum, spec.Width)
			fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", c1, wTy, sh)
			outW, cout = "%"+sum, "%"+c1
		}
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", res, wTy, outW, ty)
		if err := storeDst("%" + res); err != nil {
			return err
		}
		switch spec.LLVMOp {
		case "adc":
			c.setAddCarryFlagsSized(ty, dstV, srcV, cf, "%"+res)
		case "sbb":
			c.setSubBorrowFlagsSized(ty, dstV, srcV, cf, "%"+res)
		default:
			fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", cout, flagSlot)
		}
		return nil
	}
	return fmt.Errorf("amd64: unhandled ALU %s", spec.Op)
}

func (c *amd64Ctx) lowerX86ExtraShift(spec asm.OpSpec, ins asm.Instr) error {
	ty := x86LLVMIntType(spec.Width)
	var cntOp, dstOp asm.Operand
	switch len(ins.Args) {
	case 1:
		cntOp = asm.Operand{Kind: asm.OpImm, Imm: 1}
		dstOp = ins.Args[0]
	case 2:
		cntOp = ins.Args[0]
		dstOp = ins.Args[1]
	default:
		return fmt.Errorf("amd64 %s expects 1 or 2 operands: %q", spec.Op, ins.Raw)
	}
	cur, storeDst, err := c.loadIntDestination(dstOp, ty)
	if err != nil {
		return err
	}
	cntRaw, err := c.evalIntSized(cntOp, ty)
	if err != nil {
		return err
	}
	mask := uint64(spec.Width - 1)
	if spec.Width < 32 {
		mask = 31
	}
	immCount := int64(-1)
	if cntOp.Kind == asm.OpImm {
		immCount = cntOp.Imm & int64(mask)
	}
	cntM := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", cntM, ty, cntRaw, mask)
	cntM64 := "%" + cntM
	if ty != asm.I64 {
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", z, ty, cntM)
		cntM64 = "%" + z
	}
	cnt := "%" + cntM
	if spec.Width < 32 && (spec.LLVMOp == "rol" || spec.LLVMOp == "ror") {
		rem := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = urem %s %%%s, %d\n", rem, ty, cntM, spec.Width)
		cnt = "%" + rem
	}
	switch spec.LLVMOp {
	case "ashr", "shl", "lshr":
		var resVal string
		if spec.Width < 32 {
			// On x86, 8/16-bit shift counts are masked by 31; counts >= width zero-fill
			// (for SHL/SHR) or sign-fill (for SAR) without invoking LLVM poison.
			inRange, safeAmt, shifted := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %d\n", inRange, ty, cntM, spec.Width)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %d\n", safeAmt, inRange, ty, cntM, ty, spec.Width-1)
			fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", shifted, spec.LLVMOp, ty, cur, safeAmt)
			resVal = "%" + shifted
			if spec.LLVMOp != "ashr" {
				out := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s 0\n", out, inRange, ty, shifted, ty)
				resVal = "%" + out
			}
		} else {
			res := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", res, spec.LLVMOp, ty, cur, cnt)
			resVal = "%" + res
		}
		if err := storeDst(resVal); err != nil {
			return err
		}
		c.setShiftFlagsSized(ty, int(spec.Width), spec.LLVMOp, cur, resVal, cntM64, immCount)
		return nil
	case "rol", "ror":
		intr := "fshl"
		if spec.LLVMOp == "ror" {
			intr = "fshr"
		}
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s, %s %s, %s %s)\n", res, ty, intr, ty, ty, cur, ty, cur, ty, cnt)
		if err := storeDst("%" + res); err != nil {
			return err
		}
		c.setRotateFlagsSized(ty, int(spec.Width), spec.LLVMOp == "rol", "%"+res, cntM64, immCount)
		return nil
	case "rcl", "rcr":
		// Rotate through carry across (Width + 1) bits.
		extBits := spec.Width + 1
		eTy := fmt.Sprintf("i%d", extBits)
		cf := c.loadFlag(c.flagsCFSlot)
		cfE, vE, cntE, cntMod := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", cfE, cf, eTy)
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", vE, ty, cur, eTy)
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", cntE, ty, cnt, eTy)
		fmt.Fprintf(c.b, "  %%%s = urem %s %%%s, %d\n", cntMod, eTy, cntE, extBits)
		cfPos, pack := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %d\n", cfPos, eTy, cfE, spec.Width)
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", pack, eTy, vE, cfPos)
		intr := "fshl"
		if spec.LLVMOp == "rcr" {
			intr = "fshr"
		}
		rot, outV, cfSh, newCF := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %%%s, %s %%%s, %s %%%s)\n", rot, eTy, intr, eTy, eTy, pack, eTy, pack, eTy, cntMod)
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", outV, eTy, rot, ty)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n", cfSh, eTy, rot, spec.Width)
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to i1\n", newCF, eTy, cfSh)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newCF, c.flagsCFSlot)
		// Effective rotate-through-carry count 0 leaves OF untouched; count 1 defines OF.
		isZero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", isZero, eTy, cntMod)
		msb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", msb, ty, outV)
		var newOFVal string
		if spec.LLVMOp == "rcl" {
			ofTmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, %%%s\n", ofTmp, msb, newCF)
			newOFVal = "%" + ofTmp
		} else {
			sh2, b2, bit2, ofTmp := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n", sh2, ty, outV, spec.Width-2)
			fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", b2, ty, sh2)
			fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", bit2, ty, b2)
			fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, %%%s\n", ofTmp, msb, bit2)
			newOFVal = "%" + ofTmp
		}
		oldOF := c.loadFlag(c.flagsOFSlot)
		selOF := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %s, i1 %s\n", selOF, isZero, oldOF, newOFVal)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selOF, c.flagsOFSlot)
		return storeDst("%" + outV)
	}
	return fmt.Errorf("amd64: unhandled shift %s", spec.Op)
}

func (c *amd64Ctx) lowerX86ExtraMulDiv(spec asm.OpSpec, ins asm.Instr) error {
	ty := x86LLVMIntType(spec.Width)
	switch spec.LLVMOp {
	case "imul":
		if len(ins.Args) == 1 {
			// 1-operand IMULW: DX:AX = AX * src
			src, err := c.evalIntSized(ins.Args[0], asm.I16)
			if err != nil {
				return err
			}
			ax, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}, asm.I16)
			if err != nil {
				return err
			}
			a32, b32, prod, lo, sh, hi := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", a32, ax)
			fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", b32, src)
			fmt.Fprintf(c.b, "  %%%s = mul i32 %%%s, %%%s\n", prod, a32, b32)
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i16\n", lo, prod)
			fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, 16\n", sh, prod)
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i16\n", hi, sh)
			if err := c.storeRegSized(asm.AX, asm.I16, "%"+lo); err != nil {
				return err
			}
			if err := c.storeRegSized(asm.DX, asm.I16, "%"+hi); err != nil {
				return err
			}
			c.setSignedMulFlags(asm.I16, asm.I32, "%"+lo, "%"+prod)
			return nil
		}
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 IMULW expects 1 or 2 operands: %q", ins.Raw)
		}
		src, err := c.evalIntSized(ins.Args[0], asm.I16)
		if err != nil {
			return err
		}
		dst, err := c.evalIntSized(ins.Args[1], asm.I16)
		if err != nil {
			return err
		}
		a32, b32, prod, res := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", a32, dst)
		fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", b32, src)
		fmt.Fprintf(c.b, "  %%%s = mul i32 %%%s, %%%s\n", prod, a32, b32)
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i16\n", res, prod)
		if err := c.storeRegSized(ins.Args[1].Reg, asm.I16, "%"+res); err != nil {
			return err
		}
		c.setSignedMulFlags(asm.I16, asm.I32, "%"+res, "%"+prod)
		return nil

	case "imul3":
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 IMUL3W expects $imm, src, dstReg: %q", ins.Raw)
		}
		imm, err := c.evalIntSized(ins.Args[0], asm.I16)
		if err != nil {
			return err
		}
		src, err := c.evalIntSized(ins.Args[1], asm.I16)
		if err != nil {
			return err
		}
		a32, b32, prod, res := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", a32, src)
		fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", b32, imm)
		fmt.Fprintf(c.b, "  %%%s = mul i32 %%%s, %%%s\n", prod, a32, b32)
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i16\n", res, prod)
		if err := c.storeRegSized(ins.Args[2].Reg, asm.I16, "%"+res); err != nil {
			return err
		}
		c.setSignedMulFlags(asm.I16, asm.I32, "%"+res, "%"+prod)
		return nil

	case "mul", "imul1":
		if len(ins.Args) != 1 {
			return fmt.Errorf("amd64 %s expects 1 operand: %q", spec.Op, ins.Raw)
		}
		src, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		ax, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}, ty)
		if err != nil {
			return err
		}
		wTy := x86LLVMIntType(spec.Width * 2)
		ext := "zext"
		if spec.Signed {
			ext = "sext"
		}
		aW, bW, prod := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", aW, ext, ty, ax, wTy)
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", bW, ext, ty, src, wTy)
		fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", prod, wTy, aW, bW)
		lo, sh, hi := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", lo, wTy, prod, ty)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n", sh, wTy, prod, spec.Width)
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", hi, wTy, sh, ty)
		if spec.Width == 8 {
			if err := c.storeRegSized(asm.AX, asm.I16, "%"+prod); err != nil {
				return err
			}
		} else {
			if err := c.storeRegSized(asm.AX, ty, "%"+lo); err != nil {
				return err
			}
			if err := c.storeRegSized(asm.DX, ty, "%"+hi); err != nil {
				return err
			}
		}
		if spec.Signed {
			c.setSignedMulFlags(ty, wTy, "%"+lo, "%"+prod)
		} else {
			c.setUnsignedMulFlags(ty, "%"+hi)
		}
		return nil

	case "div", "idiv":
		if len(ins.Args) != 1 {
			return fmt.Errorf("amd64 %s expects 1 divisor operand: %q", spec.Op, ins.Raw)
		}
		wTy := x86LLVMIntType(spec.Width * 2)
		divS, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		ext, divOp, remOp := "zext", "udiv", "urem"
		if spec.Signed {
			ext, divOp, remOp = "sext", "sdiv", "srem"
		}
		divW := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", divW, ext, ty, divS, wTy)
		var numerW string
		if spec.Width == 8 {
			ax16, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}, asm.I16)
			if err != nil {
				return err
			}
			numerW = ax16
		} else {
			ax16, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}, asm.I16)
			if err != nil {
				return err
			}
			dx16, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.DX}, asm.I16)
			if err != nil {
				return err
			}
			lo32, hi32, hiSh, comb := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i32\n", lo32, ax16)
			fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i32\n", hi32, dx16)
			fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, 16\n", hiSh, hi32)
			fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", comb, hiSh, lo32)
			numerW = "%" + comb
		}
		zero, safeDiv, qW, rW, q, r := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, wTy, divW)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 1, %s %%%s\n", safeDiv, zero, wTy, wTy, divW)
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", qW, divOp, wTy, numerW, safeDiv)
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", rW, remOp, wTy, numerW, safeDiv)
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", q, wTy, qW, ty)
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", r, wTy, rW, ty)
		if spec.Width == 8 {
			if err := c.storeRegSized(asm.AL, asm.I8, "%"+q); err != nil {
				return err
			}
			return c.storeRegSized(asm.AH, asm.I8, "%"+r)
		}
		if err := c.storeRegSized(asm.AX, asm.I16, "%"+q); err != nil {
			return err
		}
		return c.storeRegSized(asm.DX, asm.I16, "%"+r)

	case "mulx":
		// Plan 9 MULXL src, hiReg, loReg => hi:lo = EDX * src
		if len(ins.Args) != 3 || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 MULXL expects src, hiReg, loReg: %q", ins.Raw)
		}
		src, err := c.evalIntSized(ins.Args[0], asm.I32)
		if err != nil {
			return err
		}
		dx, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.DX}, asm.I32)
		if err != nil {
			return err
		}
		a64, b64, prod, lo, sh, hi := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", a64, src)
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", b64, dx)
		fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", prod, a64, b64)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", lo, prod)
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", sh, prod)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi, sh)
		if err := c.storeRegSized(ins.Args[1].Reg, asm.I32, "%"+hi); err != nil {
			return err
		}
		return c.storeRegSized(ins.Args[2].Reg, asm.I32, "%"+lo)
	}
	return fmt.Errorf("amd64: unhandled mul/div %s", spec.Op)
}

func (c *amd64Ctx) lowerX86ExtraBit(spec asm.OpSpec, ins asm.Instr) error {
	ty := x86LLVMIntType(spec.Width)
	switch spec.LLVMOp {
	case "bt", "bts", "btr", "btc":
		if len(ins.Args) != 2 {
			return fmt.Errorf("amd64 %s expects bit, dst: %q", spec.Op, ins.Raw)
		}
		bitRaw, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		amt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", amt, ty, bitRaw, spec.Width-1)
		cur, storeDst, err := c.loadIntDestination(ins.Args[1], ty)
		if err != nil {
			return err
		}
		sh, one, bit, cf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", sh, ty, cur, amt)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", bit, ty, sh)
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", cf, ty, bit)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		if spec.LLVMOp == "bt" {
			return nil
		}
		fmt.Fprintf(c.b, "  %%%s = shl %s 1, %%%s\n", one, ty, amt)
		res := c.newTmp()
		switch spec.LLVMOp {
		case "bts":
			fmt.Fprintf(c.b, "  %%%s = or %s %s, %%%s\n", res, ty, cur, one)
		case "btr":
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, -1\n", m, ty, one)
			fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", res, ty, cur, m)
		case "btc":
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", res, ty, cur, one)
		}
		return storeDst("%" + res)

	case "tzcnt", "lzcnt", "popcnt":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, dstReg: %q", spec.Op, ins.Raw)
		}
		src, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		out := c.newTmp()
		switch spec.LLVMOp {
		case "tzcnt":
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.cttz.%s(%s %s, i1 false)\n", out, ty, ty, ty, src)
		case "lzcnt":
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.%s(%s %s, i1 false)\n", out, ty, ty, ty, src)
		case "popcnt":
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctpop.%s(%s %s)\n", out, ty, ty, ty, src)
		}
		if err := c.storeRegSized(ins.Args[1].Reg, ty, "%"+out); err != nil {
			return err
		}
		if spec.LLVMOp == "popcnt" {
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zf, ty, src)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsPFSlot)
			return nil
		}
		zf, cf := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zf, ty, out)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", cf, ty, src)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		return nil

	case "blsi", "blsmsk", "blsr":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects src, dstReg: %q", spec.Op, ins.Raw)
		}
		src, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		t0, out := c.newTmp(), c.newTmp()
		switch spec.LLVMOp {
		case "blsi":
			fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", t0, ty, src)
			fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", out, ty, src, t0)
		case "blsmsk":
			fmt.Fprintf(c.b, "  %%%s = sub %s %s, 1\n", t0, ty, src)
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", out, ty, src, t0)
		case "blsr":
			fmt.Fprintf(c.b, "  %%%s = sub %s %s, 1\n", t0, ty, src)
			fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", out, ty, src, t0)
		}
		if err := c.storeRegSized(ins.Args[1].Reg, ty, "%"+out); err != nil {
			return err
		}
		sf, cf := c.newTmp(), c.newTmp()
		if spec.LLVMOp == "blsmsk" {
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsZSlot)
		} else {
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zf, ty, out)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		}
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", sf, ty, out)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
		if spec.LLVMOp == "blsi" {
			fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, 0\n", cf, ty, src)
		} else {
			fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", cf, ty, src)
		}
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		return nil

	case "andn", "shlx", "shrx", "sarx", "rorx", "bzhi", "bextr":
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects 3 operands: %q", spec.Op, ins.Raw)
		}
		a, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		b, err := c.evalIntSized(ins.Args[1], ty)
		if err != nil {
			return err
		}
		var out, bzhiCF string
		switch spec.LLVMOp {
		case "andn":
			// Plan 9 ANDN src1(rm), src2(vvvv), dst => (~src2) & src1
			inv, res := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inv, ty, b)
			fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", res, ty, inv, a)
			out = "%" + res
		case "shlx", "shrx", "sarx":
			// Plan 9 SHLX count, src, dst
			llvmOp := map[string]string{"shlx": "shl", "shrx": "lshr", "sarx": "ashr"}[spec.LLVMOp]
			m, res := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", m, ty, a, spec.Width-1)
			fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", res, llvmOp, ty, b, m)
			out = "%" + res
		case "rorx":
			m, res := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", m, ty, a, spec.Width-1)
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fshr.%s(%s %s, %s %s, %s %%%s)\n", res, ty, ty, ty, b, ty, b, ty, m)
			out = "%" + res
		case "bzhi":
			// Plan 9 BZHI index, src, dst => zero bits >= (index & 0xff)
			idx, ge, safeIdx, sh, mask, res := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and %s %s, 255\n", idx, ty, a)
			fmt.Fprintf(c.b, "  %%%s = icmp uge %s %%%s, %d\n", ge, ty, idx, spec.Width)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 0, %s %%%s\n", safeIdx, ge, ty, ty, idx)
			fmt.Fprintf(c.b, "  %%%s = shl %s 1, %%%s\n", sh, ty, safeIdx)
			fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, 1\n", mask, ty, sh)
			masked := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", masked, ty, b, mask)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %%%s\n", res, ge, ty, b, ty, masked)
			out = "%" + res
			bzhiCF = "%" + ge
		case "bextr":
			// Plan 9 BEXTR ctrl, src, dst: start = ctrl&0xff, len = (ctrl>>8)&0xff
			start, lenSh, lenV, startGe, safeSt, shifted, lenGe, safeLen, sh1, mask, masked, res := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and %s %s, 255\n", start, ty, a)
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, 8\n", lenSh, ty, a)
			fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 255\n", lenV, ty, lenSh)
			fmt.Fprintf(c.b, "  %%%s = icmp uge %s %%%s, %d\n", startGe, ty, start, spec.Width)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 0, %s %%%s\n", safeSt, startGe, ty, ty, start)
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", shifted, ty, b, safeSt)
			sVal := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 0, %s %%%s\n", sVal, startGe, ty, ty, shifted)
			fmt.Fprintf(c.b, "  %%%s = icmp uge %s %%%s, %d\n", lenGe, ty, lenV, spec.Width)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 0, %s %%%s\n", safeLen, lenGe, ty, ty, lenV)
			fmt.Fprintf(c.b, "  %%%s = shl %s 1, %%%s\n", sh1, ty, safeLen)
			fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, 1\n", mask, ty, sh1)
			fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", masked, ty, sVal, mask)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %%%s\n", res, lenGe, ty, sVal, ty, masked)
			out = "%" + res
		}
		if err := c.storeRegSized(ins.Args[2].Reg, ty, out); err != nil {
			return err
		}
		switch spec.LLVMOp {
		case "andn":
			zf, sf := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zf, ty, out)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", sf, ty, out)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		case "bzhi":
			zf, sf := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zf, ty, out)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", sf, ty, out)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
			fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", bzhiCF, c.flagsCFSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		case "bextr":
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zf, ty, out)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		}
		return nil
	}
	return fmt.Errorf("amd64: unhandled bit op %s", spec.Op)
}

func (c *amd64Ctx) lowerX86ExtraSystem(spec asm.OpSpec, ins asm.Instr) error {
	if spec.InlineAsm != "" && spec.LLVMOp == "" {
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", spec.InlineAsm, "~{memory}")
		return nil
	}
	switch spec.LLVMOp {
	case "any_nop":
		return nil
	case "mem_nop":
		if len(ins.Args) < 1 {
			return fmt.Errorf("amd64 %s expects memory operand: %q", spec.Op, ins.Raw)
		}
		return nil
	case "clc":
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		return nil
	case "stc":
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.flagsCFSlot)
		return nil
	case "cmc":
		cf := c.loadFlag(c.flagsCFSlot)
		inv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", inv, cf)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", inv, c.flagsCFSlot)
		return nil
	case "cbw":
		al, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AL}, asm.I8)
		if err != nil {
			return err
		}
		se := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i8 %s to i16\n", se, al)
		return c.storeRegSized(asm.AX, asm.I16, "%"+se)
	case "cwde":
		ax, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}, asm.I16)
		if err != nil {
			return err
		}
		se := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", se, ax)
		return c.storeRegSized(asm.AX, asm.I32, "%"+se)
	case "cdqe":
		ax, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}, asm.I32)
		if err != nil {
			return err
		}
		se := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", se, ax)
		return c.storeReg(asm.AX, "%"+se)
	case "cdq":
		ax, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}, asm.I32)
		if err != nil {
			return err
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, 31\n", sh, ax)
		return c.storeRegSized(asm.DX, asm.I32, "%"+sh)
	case "cqo":
		ax, err := c.loadReg(asm.AX)
		if err != nil {
			return err
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, 63\n", sh, ax)
		return c.storeReg(asm.DX, "%"+sh)
	case "leaveq":
		bp, err := c.loadReg(asm.BP)
		if err != nil {
			return err
		}
		if err := c.storeRegUnchecked(asm.SP, bp); err != nil {
			return err
		}
		return c.storeReg(asm.BP, c.popI64())
	case "bcd_adj":
		ax, err := c.loadReg(asm.AX)
		if err != nil {
			return err
		}
		al := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", al, ax)
		ahSh, ah := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 8\n", ahSh, ax)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i8\n", ah, ahSh)
		switch spec.Op {
		case "AAA", "AAS":
			low, gt9 := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, 15\n", low, al)
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i8 %%%s, 9\n", gt9, low)
			opAL, opAH := "add", "add"
			if spec.Op == "AAS" {
				opAL, opAH = "sub", "sub"
			}
			adjAL, adjAH, nAL, nAH := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s i8 %%%s, 6\n", adjAL, opAL, al)
			fmt.Fprintf(c.b, "  %%%s = %s i8 %%%s, 1\n", adjAH, opAH, ah)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 %%%s\n", nAL, gt9, adjAL, al)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 %%%s\n", nAH, gt9, adjAH, ah)
			lo4, zAL, zAH, shAH, ax16 := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, 15\n", lo4, nAL)
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", zAL, lo4)
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", zAH, nAH)
			fmt.Fprintf(c.b, "  %%%s = shl i16 %%%s, 8\n", shAH, zAH)
			fmt.Fprintf(c.b, "  %%%s = or i16 %%%s, %%%s\n", ax16, shAH, zAL)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", gt9, c.flagsCFSlot)
			return c.storeRegSized(asm.AX, asm.I16, "%"+ax16)
		case "AAM":
			base := int64(10)
			if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpImm && ins.Args[0].Imm != 0 {
				base = ins.Args[0].Imm & 0xff
			}
			q, r, zQ, zR, shQ, ax16, zf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = udiv i8 %%%s, %d\n", q, al, base)
			fmt.Fprintf(c.b, "  %%%s = urem i8 %%%s, %d\n", r, al, base)
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", zQ, q)
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", zR, r)
			fmt.Fprintf(c.b, "  %%%s = shl i16 %%%s, 8\n", shQ, zQ)
			fmt.Fprintf(c.b, "  %%%s = or i16 %%%s, %%%s\n", ax16, shQ, zR)
			fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, 0\n", zf, r)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			return c.storeRegSized(asm.AX, asm.I16, "%"+ax16)
		case "AAD":
			base := int64(10)
			if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpImm {
				base = ins.Args[0].Imm & 0xff
			}
			mul, sum, ax16, zf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i8 %%%s, %d\n", mul, ah, base)
			fmt.Fprintf(c.b, "  %%%s = add i8 %%%s, %%%s\n", sum, mul, al)
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i16\n", ax16, sum)
			fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, 0\n", zf, sum)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			return c.storeRegSized(asm.AX, asm.I16, "%"+ax16)
		default: // DAA, DAS
			opStr := "add"
			if spec.Op == "DAS" {
				opStr = "sub"
			}
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", cf, c.flagsCFSlot)
			lo4, gt9, adj1, al1 := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, 15\n", lo4, al)
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i8 %%%s, 9\n", gt9, lo4)
			fmt.Fprintf(c.b, "  %%%s = %s i8 %%%s, 6\n", adj1, opStr, al)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 %%%s\n", al1, gt9, adj1, al)
			gt99, needHi, adj2, al2, zf := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i8 %%%s, 153\n", gt99, al)
			fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", needHi, gt99, cf)
			fmt.Fprintf(c.b, "  %%%s = %s i8 %%%s, 96\n", adj2, opStr, al1)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 %%%s\n", al2, needHi, adj2, al1)
			fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, 0\n", zf, al2)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", needHi, c.flagsCFSlot)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			return c.storeRegSized(asm.AL, asm.I8, "%"+al2)
		}
	case "arpl":
		if len(ins.Args) != 2 {
			return fmt.Errorf("amd64 ARPL expects src, dst: %q", ins.Raw)
		}
		src, err := c.evalIntSized(ins.Args[0], asm.I16)
		if err != nil {
			return err
		}
		dst, err := c.evalIntSized(ins.Args[1], asm.I16)
		if err != nil {
			return err
		}
		sRpl, dRpl, lt, hi, repl, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i16 %s, 3\n", sRpl, src)
		fmt.Fprintf(c.b, "  %%%s = and i16 %s, 3\n", dRpl, dst)
		fmt.Fprintf(c.b, "  %%%s = icmp ult i16 %%%s, %%%s\n", lt, dRpl, sRpl)
		fmt.Fprintf(c.b, "  %%%s = and i16 %s, -4\n", hi, dst)
		fmt.Fprintf(c.b, "  %%%s = or i16 %%%s, %%%s\n", repl, hi, sRpl)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 %%%s, i16 %s\n", out, lt, repl, dst)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", lt, c.flagsZSlot)
		if ins.Args[1].Kind == asm.OpReg {
			return c.storeRegSized(ins.Args[1].Reg, asm.I16, "%"+out)
		}
		p, pty, err := c.ptrFromMem(ins.Args[1].Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i16 %%%s, %s %s, align 1\n", out, pty, p)
		return nil
	case "bound":
		if len(ins.Args) != 2 || !isX86MemOp(ins.Args[1]) {
			return fmt.Errorf("amd64 %s expects reg, mem: %q", spec.Op, ins.Raw)
		}
		ty := x86LLVMIntType(spec.Width)
		if _, err := c.evalIntSized(ins.Args[0], ty); err != nil {
			return err
		}
		p, pty, err := c.resolveMemPtr(ins.Args[1])
		if err != nil {
			return err
		}
		lo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", lo, ty, pty, p)
		return nil
	case "pushaw":
		if len(ins.Args) != 0 {
			return fmt.Errorf("amd64 PUSHAW takes no operands: %q", ins.Raw)
		}
		for _, r := range []asm.Reg{asm.AX, asm.CX, asm.DX, asm.BX, asm.SP, asm.BP, asm.SI, asm.DI} {
			v, err := c.loadReg(r)
			if err != nil {
				return err
			}
			c.pushI64(v)
		}
		return nil
	case "popaw":
		if len(ins.Args) != 0 {
			return fmt.Errorf("amd64 POPAW takes no operands: %q", ins.Raw)
		}
		for _, r := range []asm.Reg{asm.DI, asm.SI, asm.BP, asm.SP, asm.BX, asm.DX, asm.CX, asm.AX} {
			v := c.popI64()
			if r == asm.SP {
				continue
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", tr, v)
			if err := c.storeRegSized(r, asm.I16, "%"+tr); err != nil {
				return err
			}
		}
		return nil
	case "rdpid":
		if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpReg {
			return fmt.Errorf("amd64 RDPID expects dstReg: %q", ins.Raw)
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 asm sideeffect %q, %q()\n", t, "rdpid $0", "=r,~{memory}")
		return c.storeReg(ins.Args[0].Reg, "%"+t)
	case "rdrand", "rdseed":
		if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects dstReg: %q", spec.Op, ins.Raw)
		}
		ty := x86LLVMIntType(spec.Width)
		res := c.newTmp()
		val, okv := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call { %s, i32 } @llvm.x86.%s.%d()\n", res, ty, spec.LLVMOp, spec.Width)
		fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i32 } %%%s, 0\n", val, ty, res)
		fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i32 } %%%s, 1\n", okv, ty, res)
		cf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne i32 %%%s, 0\n", cf, okv)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsPFSlot)
		return c.storeRegSized(ins.Args[0].Reg, ty, "%"+val)
	case "rdfsbase", "rdgsbase":
		if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects dstReg: %q", spec.Op, ins.Raw)
		}
		ty := x86LLVMIntType(spec.Width)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q()\n", t, ty, spec.LLVMOp+" $0", "=r,~{memory}")
		return c.storeRegSized(ins.Args[0].Reg, ty, "%"+t)
	case "wrfsbase", "wrgsbase":
		if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects srcReg: %q", spec.Op, ins.Raw)
		}
		ty := x86LLVMIntType(spec.Width)
		v, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s)\n", spec.LLVMOp+" $0", "r,~{memory}", ty, v)
		return nil
	case "xtest":
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsPFSlot)
		return nil
	case "stmxcsr":
		if len(ins.Args) != 1 || !isX86MemOp(ins.Args[0]) {
			return fmt.Errorf("amd64 %s expects mem: %q", spec.Op, ins.Raw)
		}
		p, ptrType, err := c.resolveMemPtr(ins.Args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i32 8064, %s %s, align 1\n", ptrType, p)
		return nil
	case "load_seg":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("amd64 %s expects mem, dstReg: %q", spec.Op, ins.Raw)
		}
		ty := x86LLVMIntType(spec.Width)
		v, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return err
		}
		return c.storeRegSized(ins.Args[1].Reg, ty, v)
	case "store_zero":
		if len(ins.Args) != 1 {
			return fmt.Errorf("amd64 %s expects 1 dst operand: %q", spec.Op, ins.Raw)
		}
		ty := x86LLVMIntType(spec.Width)
		_, storeDst, err := c.loadIntDestination(ins.Args[0], ty)
		if err != nil {
			return err
		}
		return storeDst("0")
	}
	return fmt.Errorf("amd64: unhandled system op %s", spec.Op)
}
