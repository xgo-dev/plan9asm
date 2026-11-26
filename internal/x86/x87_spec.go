package x86

import (
	"github.com/xgo-dev/plan9asm/internal/asm"
)

// x87_spec.go is the single source of truth for x87 instruction metadata and
// stack semantics shared between the LLVM IR lowerers (lower_x87.go,
// lower_x87_ext.go) and the static ABI0 effect checker (effects.go).

// x87ConstSpec describes an x87 push-constant instruction in exact IEEE-754
// 80-bit extended representation (significand as signed int64, sign+exp as u16).
// Both lowerX87Ext and CheckABI0ResultInitWithSigs dispatch through x87ConstSpecs.
type x87ConstSpec struct {
	Op      asm.Op
	Sig     string
	SignExp string
}

var x87ConstSpecList = []x87ConstSpec{
	{Op: "FLD1", Sig: "9223372036854775808", SignExp: "16383"},    // 0x8000000000000000, 0x3fff (+1.0)
	{Op: "FLDZ", Sig: "0", SignExp: "0"},                          // 0x0000000000000000, 0x0000 (+0.0)
	{Op: "FLDPI", Sig: "-3958705157555305931", SignExp: "16384"},  // 0xc90fdaa22168c235, 0x4000 (pi)
	{Op: "FLDL2E", Sig: "-5140230975865229124", SignExp: "16383"}, // 0xb8aa3b295c17f0bc, 0x3fff (log2(e))
	{Op: "FLDL2T", Sig: "-3127054724296373506", SignExp: "16384"}, // 0xd49a784bcd1b8afe, 0x4000 (log2(10))
	{Op: "FLDLG2", Sig: "-7340697496662837351", SignExp: "16381"}, // 0x9a209a84fbcff799, 0x3ffd (log10(2))
	{Op: "FLDLN2", Sig: "-5660435428506895956", SignExp: "16382"}, // 0xb17217f7d1cf79ac, 0x3ffe (ln(2))
}

var x87ConstSpecs = func() map[asm.Op]x87ConstSpec {
	m := make(map[asm.Op]x87ConstSpec, len(x87ConstSpecList))
	for _, s := range x87ConstSpecList {
		m[s.Op] = s
	}
	return m
}()

type x87ArithSpec struct {
	Op       asm.Op
	llvmOp   string // fadd, fsub, fmul, fdiv
	rev      bool   // reverse operand order (FSUBR / FDIVR)
	pop      bool   // pop stack after store
	memKind  string // f64, f32, i32, i16
	memBytes int64  // byte width when source is memory
}

var x87ArithSpecList = []x87ArithSpec{
	{Op: "FADDD", llvmOp: "fadd", memKind: "f64", memBytes: 8},
	{Op: "FADDDP", llvmOp: "fadd", pop: true, memKind: "f64", memBytes: 8},
	{Op: "FADDF", llvmOp: "fadd", memKind: "f32", memBytes: 4},
	{Op: "FADDL", llvmOp: "fadd", memKind: "i32", memBytes: 4},
	{Op: "FADDW", llvmOp: "fadd", memKind: "i16", memBytes: 2},
	{Op: "FSUBD", llvmOp: "fsub", memKind: "f64", memBytes: 8},
	{Op: "FSUBDP", llvmOp: "fsub", pop: true, memKind: "f64", memBytes: 8},
	{Op: "FSUBF", llvmOp: "fsub", memKind: "f32", memBytes: 4},
	{Op: "FSUBL", llvmOp: "fsub", memKind: "i32", memBytes: 4},
	{Op: "FSUBW", llvmOp: "fsub", memKind: "i16", memBytes: 2},
	{Op: "FSUBRD", llvmOp: "fsub", rev: true, memKind: "f64", memBytes: 8},
	{Op: "FSUBRDP", llvmOp: "fsub", rev: true, pop: true, memKind: "f64", memBytes: 8},
	{Op: "FSUBRF", llvmOp: "fsub", rev: true, memKind: "f32", memBytes: 4},
	{Op: "FSUBRL", llvmOp: "fsub", rev: true, memKind: "i32", memBytes: 4},
	{Op: "FSUBRW", llvmOp: "fsub", rev: true, memKind: "i16", memBytes: 2},
	{Op: "FMULD", llvmOp: "fmul", memKind: "f64", memBytes: 8},
	{Op: "FMULDP", llvmOp: "fmul", pop: true, memKind: "f64", memBytes: 8},
	{Op: "FMULF", llvmOp: "fmul", memKind: "f32", memBytes: 4},
	{Op: "FMULL", llvmOp: "fmul", memKind: "i32", memBytes: 4},
	{Op: "FMULW", llvmOp: "fmul", memKind: "i16", memBytes: 2},
	{Op: "FDIVD", llvmOp: "fdiv", memKind: "f64", memBytes: 8},
	{Op: "FDIVDP", llvmOp: "fdiv", pop: true, memKind: "f64", memBytes: 8},
	{Op: "FDIVF", llvmOp: "fdiv", memKind: "f32", memBytes: 4},
	{Op: "FDIVL", llvmOp: "fdiv", memKind: "i32", memBytes: 4},
	{Op: "FDIVW", llvmOp: "fdiv", memKind: "i16", memBytes: 2},
	{Op: "FDIVRD", llvmOp: "fdiv", rev: true, memKind: "f64", memBytes: 8},
	{Op: "FDIVRDP", llvmOp: "fdiv", rev: true, pop: true, memKind: "f64", memBytes: 8},
	{Op: "FDIVRF", llvmOp: "fdiv", rev: true, memKind: "f32", memBytes: 4},
	{Op: "FDIVRL", llvmOp: "fdiv", rev: true, memKind: "i32", memBytes: 4},
	{Op: "FDIVRW", llvmOp: "fdiv", rev: true, memKind: "i16", memBytes: 2},
}

var x87ArithSpecs = func() map[asm.Op]x87ArithSpec {
	m := make(map[asm.Op]x87ArithSpec, len(x87ArithSpecList))
	for _, s := range x87ArithSpecList {
		m[s.Op] = s
	}
	return m
}()

type x87CmpSpec struct {
	Op       asm.Op
	memKind  string // f64, f32, i32, i16
	memBytes int64
	pops     int
	eflags   bool
}

var x87CmpSpecList = []x87CmpSpec{
	{Op: "FCOMD", memKind: "f64", memBytes: 8, pops: 0},
	{Op: "FCOMDP", memKind: "f64", memBytes: 8, pops: 1},
	{Op: "FCOMDPP", memKind: "f64", memBytes: 8, pops: 2},
	{Op: "FCOMF", memKind: "f32", memBytes: 4, pops: 0},
	{Op: "FCOMFP", memKind: "f32", memBytes: 4, pops: 1},
	{Op: "FCOML", memKind: "i32", memBytes: 4, pops: 0},
	{Op: "FCOMLP", memKind: "i32", memBytes: 4, pops: 1},
	{Op: "FCOMW", memKind: "i16", memBytes: 2, pops: 0},
	{Op: "FCOMWP", memKind: "i16", memBytes: 2, pops: 1},
	{Op: "FCOMI", memKind: "f64", memBytes: 8, pops: 0, eflags: true},
	{Op: "FCOMIP", memKind: "f64", memBytes: 8, pops: 1, eflags: true},
	{Op: "FUCOM", memKind: "f64", memBytes: 8, pops: 0},
	{Op: "FUCOMP", memKind: "f64", memBytes: 8, pops: 1},
	{Op: "FUCOMPP", memKind: "f64", memBytes: 8, pops: 2},
	{Op: "FUCOMI", memKind: "f64", memBytes: 8, pops: 0, eflags: true},
	{Op: "FUCOMIP", memKind: "f64", memBytes: 8, pops: 1, eflags: true},
}

var x87CmpSpecs = func() map[asm.Op]x87CmpSpec {
	m := make(map[asm.Op]x87CmpSpec, len(x87CmpSpecList))
	for _, s := range x87CmpSpecList {
		m[s.Op] = s
	}
	return m
}()

// x87UnsupportedReasons maps x87 opcodes whose exact architectural semantics
// are intentionally not modeled (transcendentals, partial remainders, full x87
// environment/tag-word save/restore, and FXAM tag classification) to the
// diagnostic reason returned by lowering. Kept out of switch case clauses and
// OpSpec literals so static op scanners do not report them as supported.
var x87UnsupportedReasons = map[asm.Op]string{
	"FXAM":    "exact x87 tag-word Empty/Denormal/Unsupported classification is not modeled",
	"FLDENV":  "full x87 environment/tag-word/pointer state is not modeled",
	"FSTENV":  "full x87 environment/tag-word/pointer state is not modeled",
	"FSAVE":   "full x87 environment/tag-word/pointer state is not modeled",
	"FRSTOR":  "full x87 environment/tag-word/pointer state is not modeled",
	"F2XM1":   "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FYL2X":   "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FYL2XP1": "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FSIN":    "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FCOS":    "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FSINCOS": "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FPTAN":   "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FPATAN":  "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FPREM":   "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FPREM1":  "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FSCALE":  "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
	"FXTRACT": "exact 80-bit x87 transcendental/remainder and status-flag semantics are not modeled",
}

// x87MoveKind describes the exact architectural x87 stack effect of an
// FMOV*/FMOV*P/FBLD/FBSTP instruction, matching Go's cmd/internal/obj/x86
// encoding table (yfmvd / yfmvdp / yfmvf / yfmvx / yfmvp).
type x87MoveKind uint8

const (
	x87MoveNone x87MoveKind = iota
	// x87MovePushReg: FMOVD Fi, F0 (including F0, F0) -> Go encodes D9 C0+i
	// (FLD ST(i)), pushing a copy of ST(SrcIdx) onto ST(0).
	x87MovePushReg
	// x87MoveStoreReg: FMOVD F0, Fi (i > 0) -> Go encodes DD D0+i (FST ST(i)),
	// overwriting ST(DstIdx) with ST(SrcIdx) without pushing or popping.
	x87MoveStoreReg
	// x87MoveStorePopReg: FMOVDP F0, Fi -> Go encodes DD D8+i (FSTP ST(i)),
	// overwriting ST(DstIdx) with ST(SrcIdx) BEFORE popping ST(0).
	x87MoveStorePopReg
	// x87MovePushMem: FMOV{D,F,L,W,V,X,B} mem, F0 or FBLD mem -> loads value
	// from memory and pushes it onto ST(0).
	x87MovePushMem
	// x87MoveLoadMemToReg: synthetic non-F0 memory load (FMOV* mem, Fi with i>0)
	// overwrites ST(DstIdx) in place without pushing.
	x87MoveLoadMemToReg
	// x87MoveStoreMem: FMOV{D,F,L,W} F0, mem -> stores ST(SrcIdx) to memory
	// without popping.
	x87MoveStoreMem
	// x87MoveStorePopMem: FMOV{D,F,L,W,V,X,B}P F0, mem or FBSTP mem -> stores
	// ST(SrcIdx) to memory, then pops ST(0).
	x87MoveStorePopMem
	// x87MoveMemToMem: non-x87 fallback form (mem -> mem).
	x87MoveMemToMem
)

type x87MovePlan struct {
	Kind     x87MoveKind
	SrcIdx   int
	DstIdx   int
	MemArg   int
	MemBytes int64
	Pop      bool
}

func x87MoveMemBytes(op asm.Op) (memBytes int64, pop bool, ok bool) {
	switch op {
	case "FMOVD":
		return 8, false, true
	case "FMOVDP":
		return 8, true, true
	case "FMOVF":
		return 4, false, true
	case "FMOVFP":
		return 4, true, true
	case "FMOVL":
		return 4, false, true
	case "FMOVLP":
		return 4, true, true
	case "FMOVW":
		return 2, false, true
	case "FMOVWP":
		return 2, true, true
	case "FMOVV":
		return 8, false, true
	case "FMOVVP":
		return 8, true, true
	case "FMOVX":
		return 10, false, true
	case "FMOVXP":
		return 10, true, true
	case "FMOVB", "FBLD":
		return 10, false, true
	case "FMOVBP", "FBSTP":
		return 10, true, true
	default:
		return 0, false, false
	}
}

// classifyX87Move classifies an x87 move/load/store instruction into its exact
// stack plan so both lowering (lower_x87*.go) and ABI0 checking (effects.go)
// execute identical push/store/pop semantics.
func classifyX87Move(op asm.Op, args []asm.Operand) x87MovePlan {
	memBytes, pop, ok := x87MoveMemBytes(op)
	if !ok {
		return x87MovePlan{}
	}
	if op == "FBLD" {
		if len(args) != 1 {
			return x87MovePlan{}
		}
		return x87MovePlan{Kind: x87MovePushMem, DstIdx: 0, MemArg: 0, MemBytes: 10}
	}
	if op == "FBSTP" {
		if len(args) != 1 {
			return x87MovePlan{}
		}
		return x87MovePlan{Kind: x87MoveStorePopMem, SrcIdx: 0, MemArg: 0, MemBytes: 10, Pop: true}
	}
	if len(args) != 2 {
		return x87MovePlan{}
	}
	srcIdx, srcIsF := x87OperandReg(args[0])
	dstIdx, dstIsF := x87OperandReg(args[1])
	if srcIsF && dstIsF {
		if pop {
			return x87MovePlan{Kind: x87MoveStorePopReg, SrcIdx: srcIdx, DstIdx: dstIdx, MemArg: -1, MemBytes: memBytes, Pop: true}
		}
		if dstIdx == 0 {
			// Go's Plan 9 assembler encodes `FMOVD Fi, F0` (including F0, F0)
			// as D9 C0+i (`FLD ST(i)`), which pushes ST(i) onto the x87 stack.
			return x87MovePlan{Kind: x87MovePushReg, SrcIdx: srcIdx, DstIdx: 0, MemArg: -1, MemBytes: memBytes}
		}
		// Go's Plan 9 assembler encodes `FMOVD F0, Fi` (i > 0) as DD D0+i (`FST ST(i)`).
		return x87MovePlan{Kind: x87MoveStoreReg, SrcIdx: srcIdx, DstIdx: dstIdx, MemArg: -1, MemBytes: memBytes}
	}
	if srcIsF {
		kind := x87MoveStoreMem
		if pop {
			kind = x87MoveStorePopMem
		}
		return x87MovePlan{Kind: kind, SrcIdx: srcIdx, DstIdx: -1, MemArg: 1, MemBytes: memBytes, Pop: pop}
	}
	if dstIsF {
		if dstIdx == 0 {
			return x87MovePlan{Kind: x87MovePushMem, SrcIdx: -1, DstIdx: 0, MemArg: 0, MemBytes: memBytes}
		}
		return x87MovePlan{Kind: x87MoveLoadMemToReg, SrcIdx: -1, DstIdx: dstIdx, MemArg: 0, MemBytes: memBytes}
	}
	return x87MovePlan{Kind: x87MoveMemToMem, SrcIdx: -1, DstIdx: -1, MemArg: 1, MemBytes: memBytes, Pop: pop}
}

// x87OpCategory categorizes every instruction accepted by isX87Op(op) so the
// checker cannot silently omit any x87 opcode supported by the lowerer.
type x87OpCategory uint8

const (
	x87CatUnknown      x87OpCategory = iota
	x87CatConst                      // push constant (FLD1, FLDZ, FLDPI, FLDL2E, FLDL2T, FLDLG2, FLDLN2)
	x87CatMove                       // FMOV*, FMOV*P, FBLD, FBSTP
	x87CatSwap                       // FXCHD
	x87CatArith                      // x87ArithSpecs
	x87CatCmp                        // x87CmpSpecs
	x87CatFCMOV                      // FCMOV*
	x87CatUnaryInPlace               // FABS, FCHS, FSQRT, FRNDINT
	x87CatStatusTest                 // FTST
	x87CatFree                       // FFREE
	x87CatRotateUp                   // FINCSTP
	x87CatRotateDown                 // FDECSTP
	x87CatInit                       // FINIT
	x87CatNop                        // FCLEX, FNOP
	x87CatControlStore               // FSTCW, FSTSW
	x87CatControlLoad                // FLDCW
	x87CatUnsupported                // unmodeled/approximate transcendentals, partial remainders, incomplete env/tag-word ops
)

func classifyX87Op(op asm.Op) x87OpCategory {
	if _, ok := x87ConstSpecs[op]; ok {
		return x87CatConst
	}
	if _, _, ok := x87MoveMemBytes(op); ok {
		return x87CatMove
	}
	if _, ok := x87ArithSpecs[op]; ok {
		return x87CatArith
	}
	if _, ok := x87CmpSpecs[op]; ok {
		return x87CatCmp
	}
	if isX87FCMOVOp(op) {
		return x87CatFCMOV
	}
	switch op {
	case "FXCHD":
		return x87CatSwap
	case "FABS", "FCHS", "FSQRT", "FRNDINT":
		return x87CatUnaryInPlace
	case "FTST":
		return x87CatStatusTest
	case "FFREE":
		return x87CatFree
	case "FINCSTP":
		return x87CatRotateUp
	case "FDECSTP":
		return x87CatRotateDown
	case "FINIT":
		return x87CatInit
	case "FCLEX", "FNOP":
		return x87CatNop
	case "FSTCW", "FSTSW":
		return x87CatControlStore
	case "FLDCW":
		return x87CatControlLoad
	}
	if _, ok := x87UnsupportedReasons[op]; ok {
		return x87CatUnsupported
	}
	return x87CatUnknown
}
