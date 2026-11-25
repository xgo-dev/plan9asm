package asm

import "errors"

// ErrProbeNeedsContext reports that an instruction or source construct requires
// additional function/package context rather than isolated probing.
var ErrProbeNeedsContext = errors.New("instruction probe needs function context")

type LLVMType string

const (
	Void LLVMType = "void"
	I1   LLVMType = "i1"
	I8   LLVMType = "i8"
	I16  LLVMType = "i16"
	I32  LLVMType = "i32"
	I64  LLVMType = "i64"
	Ptr  LLVMType = "ptr"
)

type FuncSig struct {
	Name  string
	Args  []LLVMType
	Ret   LLVMType // use Void for void-return
	Attrs string   // optional function attributes group (e.g. "#0")

	// WASMContext is the physical closure-environment parameter carried in
	// WebAssembly's CTXT pseudo-register. It precedes Args in the LLVM entry but
	// is not part of the Go function signature, so FrameSlot.Index continues to
	// address Args without an offset. The zero value means that the entry does
	// not consume an incoming CTXT value.
	WASMContext LLVMType

	// WASMNative keeps the function's declared WebAssembly signature when
	// Options.WASMABI selects the official Go stack ABI. It is used for the
	// small set of runtime exports and assembly helpers that intentionally do
	// not use the resumable (PC_B) -> unwind convention.
	WASMNative bool

	// ArgRegs optionally specifies which architectural registers correspond to
	// Args for arm64 asm that passes values in non-sequential registers.
	//
	// When empty, args are assumed to map to R0..R7 in order (ABIInternal-ish).
	ArgRegs []Reg

	// Frame provides a minimal stack-frame model for resolving name+off(FP)
	// references in Go/Plan9 assembly into LLVM function args/returns.
	Frame FrameLayout

	// FrameLease optionally carries a live-owner validation hook attached by
	// GoAMD64FrameSource.BindFixedLocal so revoked/stale leases are rejected.
	FrameLease func() error
}

// WASMABI selects the physical ABI used for WebAssembly Plan 9 assembly.
type WASMABI uint8

const (
	WASMABIDirect WASMABI = iota
	WASMABIGo
)

func (a WASMABI) Valid() bool { return a == WASMABIDirect || a == WASMABIGo }

type FrameLayout struct {
	Params  []FrameSlot
	Results []FrameSlot
}

type FrameSlot struct {
	Offset int64
	Type   LLVMType
	Index  int // index into LLVM function arguments (for Params) or results tuple (for Results)
	// Field is the index of the extracted field within the argument aggregate.
	// When Field < 0, the slot refers directly to %arg(Index).
	Field int
	// Fields holds a multi-level extractvalue path for nested structs/arrays.
	Fields []int
	// Name optionally preserves the Go result parameter name.
	Name string
}

// X87Mode selects how explicit x87 instructions in 386 Plan 9 assembly are lowered.
type X87Mode uint8

const (
	X87Auto X87Mode = iota
	X87Hardware
	X87Software
)

func (m X87Mode) Valid() bool {
	return m >= X87Auto && m <= X87Software
}

type Options struct {
	TargetTriple string

	// ResolveSym maps the TEXT symbol (with (SB) trimmed) into the final linker
	// symbol name to emit in LLVM IR. If nil, the symbol is used as-is.
	ResolveSym func(sym string) string

	// Sigs maps resolved symbol name -> signature.
	Sigs map[string]FuncSig

	// Goarch is used for arch-specific translations (e.g. x86 CPUID / 386).
	Goarch string

	// WASMABI selects the WebAssembly physical ABI.
	WASMABI WASMABI

	// X87Mode controls explicit x87 instruction lowering for GOARCH=386.
	X87Mode X87Mode

	// AnnotateSource emits source asm lines as IR comments before lowering each
	// instruction, for translation debugging.
	AnnotateSource bool

	// VolatileGlobals records resolved global symbol names that represent mutable
	// Go package variables and must be loaded with LLVM volatile semantics.
	VolatileGlobals map[string]bool
}
