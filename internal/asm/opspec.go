package asm

import (
	"sort"
	"strings"
)

// OpFamily classifies an instruction's lowering template, analogous to
// Go cmd/internal/obj's optab classes but targeting LLVM IR emission.
type OpFamily uint16

const (
	FamilyUnknown OpFamily = iota
	FamilyNOP
	FamilyMove
	FamilyALU        // scalar integer add/sub/and/or/xor/neg/not
	FamilyShift      // scalar shift/rotate
	FamilyMulDiv     // scalar mul/imul/div/idiv
	FamilyBit        // bsf/bsr/tzcnt/lzcnt/popcnt/bswap/bt/bmi
	FamilyCMov       // conditional move / setcc / csel
	FamilyCompare    // cmp/test/comi/fcmp
	FamilyBranch     // jmp/jcc/call/ret
	FamilyFP         // scalar floating-point arithmetic/convert/sqrt
	FamilyVecBinOp   // packed SIMD binary op (add/sub/mul/and/or/xor/min/max/avg/cmp)
	FamilyVecUnary   // packed SIMD unary op (abs/sqrt/not/neg/broadcast/convert)
	FamilyVecShift   // packed SIMD shift (logical/arithmetic/byte/variable)
	FamilyVecShuffle // packed SIMD shuffle/permute/unpack/blend/align/insert/extract
	FamilyVecFMA     // fused multiply-add (FMA3/NEON FMLA)
	FamilyCrypto     // AES/SHA/CLMUL/CRC32
	FamilyAtomic     // lock/cmpxchg/ldxr/stxr/lse atomics
	FamilyString     // movs/stos/scas/cmps
	FamilyX87        // legacy x87 FPU
	FamilySyscall    // syscall/svc/swi
	FamilySystem     // cpuid/xgetbv/rdtsc/mrs/msr/fence
)

// RegEffect describes how an instruction reads and writes its destination operand
// for ABI0 result initialization and liveness analysis.
type RegEffect uint8

const (
	EffectNone           RegEffect = iota
	EffectWriteOnly                // overwrites destination without reading it (MOV, V-3op, LOAD)
	EffectReadWrite                // reads destination and writes result back (2-op ADD/SUB/PADDD/MUL)
	EffectReadOnly                 // reads operands only, updates flags or memory (CMP, TEST, STORE)
	EffectWriteZeroUpper           // overwrites low lanes and zeroes upper vector/register lanes
	EffectPreserveUpper            // writes low lanes while preserving upper vector/register lanes
	EffectImplicit                 // touches architecture-specific implicit regs (MUL/DIV/CMPXCHG/CPUID/SYSCALL)
)

// FlagEffect describes how an instruction interacts with architectural condition flags.
type FlagEffect uint8

const (
	FlagsNone      FlagEffect = iota
	FlagsWrite                // defines condition flags
	FlagsRead                 // consumes condition flags
	FlagsReadWrite            // both reads and updates flags
	FlagsClobber              // leaves flags undefined
)

// OpSpec is a single declarative instruction descriptor (modeled after Go's
// cmd/internal/obj optab entries, adapted for LLVM IR lowering and ABI0 checking).
// One OpSpec row drives opcode discovery, ABI0 effect analysis, and parameterized
// LLVM IR lowering without per-instruction boilerplate files.
type OpSpec struct {
	Op          Op
	Family      OpFamily
	Width       uint16     // total operand bit width (8, 16, 32, 64, 128, 256, 512; 0 = inferred)
	LaneBits    uint8      // SIMD lane width in bits (8, 16, 32, 64; 0 = scalar)
	Signed      bool       // signed integer semantics where applicable
	Float       bool       // floating-point semantics
	Saturating  bool       // saturating arithmetic semantics
	ThreeOp     bool       // non-destructive 3-operand form (VEX/EVEX/ARM64)
	Effect      RegEffect  // destination read/write behavior for ABI0 tracking
	Flags       FlagEffect // condition-flag interaction
	LLVMOp      string     // LLVM IR opcode ("add", "fadd", ...) or intrinsic ("llvm.x86.aesni.aesenc")
	ArchFeature string     // optional LLVM target feature attribute ("+avx2", "+aes", "+crc")
}

// OpTable indexes declarative OpSpecs for an architecture backend.
type OpTable struct {
	specs map[Op]OpSpec
}

// NewOpTable constructs an immutable lookup table from one or more spec slices.
func NewOpTable(groups ...[]OpSpec) *OpTable {
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	m := make(map[Op]OpSpec, total)
	for _, g := range groups {
		for _, s := range g {
			m[Op(strings.ToUpper(string(s.Op)))] = s
		}
	}
	return &OpTable{specs: m}
}

// Lookup returns the OpSpec for op (case-insensitive).
func (t *OpTable) Lookup(op Op) (OpSpec, bool) {
	if t == nil {
		return OpSpec{}, false
	}
	s, ok := t.specs[Op(strings.ToUpper(string(op)))]
	return s, ok
}

// SupportedOps returns all registered opcodes in deterministic sorted order.
func (t *OpTable) SupportedOps() []Op {
	if t == nil {
		return nil
	}
	out := make([]Op, 0, len(t.specs))
	for op := range t.specs {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Len returns the number of registered opcodes.
func (t *OpTable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.specs)
}
