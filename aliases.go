package plan9asm

import (
	"fmt"
	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/native"
	"github.com/xgo-dev/plan9asm/internal/preprocess"
	"github.com/xgo-dev/plan9asm/internal/wasm"
	"github.com/xgo-dev/plan9asm/internal/x86"
)

// Core IR & ABI types re-exported from internal/asm so root package plan9asm
// stays a thin, 100% API-compatible façade over modular architecture backends.
type (
	Arch        = asm.Arch
	Reg         = asm.Reg
	Op          = asm.Op
	OperandKind = asm.OperandKind
	ShiftOp     = asm.ShiftOp
	ExtendOp    = asm.ExtendOp
	MemRef      = asm.MemRef
	Operand     = asm.Operand
	Instr       = asm.Instr
	DataStmt    = asm.DataStmt
	GloblStmt   = asm.GloblStmt
	File        = asm.File
	Func        = asm.Func

	LLVMType    = asm.LLVMType
	FuncSig     = asm.FuncSig
	FrameLayout = asm.FrameLayout
	FrameSlot   = asm.FrameSlot
	WASMABI     = asm.WASMABI
	X87Mode     = asm.X87Mode
	Options     = asm.Options

	InstructionDescriptor = asm.InstructionDescriptor

	NativeOptions = native.Options
	NativeData    = native.Data

	AssemblyPreprocessOptions   = preprocess.AssemblyPreprocessOptions
	AssemblyCPPObservation      = preprocess.AssemblyCPPObservation
	AssemblyCPPObservedSource   = preprocess.AssemblyCPPObservedSource
	AssemblyCPPObservedPosition = preprocess.AssemblyCPPObservedPosition
	AssemblyCPPObservedToken    = preprocess.AssemblyCPPObservedToken
	AssemblyCPPOutputToken      = preprocess.AssemblyCPPOutputToken
	AssemblyCPPEvent            = preprocess.AssemblyCPPEvent
)

var ErrProbeNeedsContext = asm.ErrProbeNeedsContext

const (
	ArchAMD64 = asm.ArchAMD64
	ArchARM   = asm.ArchARM
	ArchARM64 = asm.ArchARM64
	ArchWASM  = asm.ArchWASM

	AX = asm.AX
	BX = asm.BX
	CX = asm.CX
	DX = asm.DX
	SI = asm.SI
	DI = asm.DI
	SP = asm.SP
	BP = asm.BP
	PC = asm.PC
	FS = asm.FS
	GS = asm.GS
	AL = asm.AL
	AH = asm.AH
	BL = asm.BL
	BH = asm.BH
	CL = asm.CL
	CH = asm.CH
	DL = asm.DL
	DH = asm.DH
	ZR = asm.ZR

	OpTEXT   = asm.OpTEXT
	OpRET    = asm.OpRET
	OpLABEL  = asm.OpLABEL
	OpMOVQ   = asm.OpMOVQ
	OpADDQ   = asm.OpADDQ
	OpSUBQ   = asm.OpSUBQ
	OpXORQ   = asm.OpXORQ
	OpMOVL   = asm.OpMOVL
	OpCPUID  = asm.OpCPUID
	OpXGETBV = asm.OpXGETBV
	OpBYTE   = asm.OpBYTE
	OpWORD   = asm.OpWORD
	OpMRS    = asm.OpMRS
	OpMOVD   = asm.OpMOVD

	OpInvalid   = asm.OpInvalid
	OpImm       = asm.OpImm
	OpReg       = asm.OpReg
	OpFP        = asm.OpFP
	OpFPAddr    = asm.OpFPAddr
	OpMem       = asm.OpMem
	OpSym       = asm.OpSym
	OpLabel     = asm.OpLabel
	OpIdent     = asm.OpIdent
	OpRegShift  = asm.OpRegShift
	OpRegExtend = asm.OpRegExtend
	OpRegList   = asm.OpRegList

	ShiftLeft   = asm.ShiftLeft
	ShiftRight  = asm.ShiftRight
	ShiftArith  = asm.ShiftArith
	ShiftRotate = asm.ShiftRotate

	ExtendUXTB = asm.ExtendUXTB
	ExtendUXTH = asm.ExtendUXTH
	ExtendUXTW = asm.ExtendUXTW
	ExtendUXTX = asm.ExtendUXTX
	ExtendSXTB = asm.ExtendSXTB
	ExtendSXTH = asm.ExtendSXTH
	ExtendSXTW = asm.ExtendSXTW
	ExtendSXTX = asm.ExtendSXTX

	Void = asm.Void
	I1   = asm.I1
	I8   = asm.I8
	I16  = asm.I16
	I32  = asm.I32
	I64  = asm.I64
	Ptr  = asm.Ptr

	WASMABIDirect = asm.WASMABIDirect
	WASMABIGo     = asm.WASMABIGo

	X87Auto     = asm.X87Auto
	X87Hardware = asm.X87Hardware
	X87Software = asm.X87Software
)

// Parse parses Plan 9 assembly source for arch.
func Parse(arch Arch, src string) (*File, error) {
	return asm.Parse(arch, src)
}

// DescribeInstruction classifies an instruction without claiming lowering support.
func DescribeInstruction(arch Arch, goarch string, ins Instr) InstructionDescriptor {
	return asm.DescribeInstruction(arch, goarch, ins)
}

// InstructionFamily groups opcodes by architectural function.
func InstructionFamily(arch Arch, op string) string {
	return asm.InstructionFamily(arch, op)
}

// ProbeInstruction runs one instruction through the real lowering pipeline.
func ProbeInstruction(arch Arch, goarch string, ins Instr) error {
	if arch == ArchAMD64 {
		switch ins.Op {
		case asm.OpBYTE, asm.OpWORD, asm.OpLONG, asm.OpQUAD:
			return fmt.Errorf("%w: x86 raw directives require their entire contiguous instruction stream", ErrProbeNeedsContext)
		}
	}
	return asm.ProbeInstructionWith(arch, goarch, ins, func(file *File, opt Options) (string, error) {
		if arch == ArchAMD64 {
			prepared, err := x86.PrepareFile(file, goarch, opt.TargetTriple)
			if err != nil {
				return "", err
			}
			file = prepared
		}
		return translateIRText(file, opt)
	})
}

// InferWASMAssemblyFuncSig derives a direct WebAssembly signature for fn.
func InferWASMAssemblyFuncSig(fn Func, resolved string) (FuncSig, error) {
	return wasm.InferAssemblyFuncSig(fn, resolved)
}

// ForeignNativeFunctions returns symbols defined as foreign native entries in src.
func ForeignNativeFunctions(src []byte, goarch string) map[string]bool {
	return native.ForeignNativeFunctions(src, goarch)
}

// ForeignARM64Functions is the Darwin/ARM64 compatibility routing helper.
func ForeignARM64Functions(src []byte) map[string]bool {
	return native.ForeignARM64Functions(src)
}

// SupportsNativeTarget reports implemented native instruction/object-format pairs.
func SupportsNativeTarget(goos, goarch string) bool {
	return native.SupportsNativeTarget(goos, goarch)
}

// TranslateNativeSource translates checked Plan 9 source directly to native assembly.
func TranslateNativeSource(src []byte, opts NativeOptions) (string, []NativeData, error) {
	return native.TranslateNativeSource(src, opts)
}

// TranslateNativeARM64Source is the Darwin/ARM64 compatibility entry point.
func TranslateNativeARM64Source(src []byte, imports map[string]string, pkgPath string) (string, []NativeData, error) {
	return native.TranslateNativeARM64Source(src, imports, pkgPath)
}

// TranslateNativeModule translates checked Plan 9 source into an owned LLVM module.
func TranslateNativeModule(ctx llvm.Context, src []byte, opts NativeOptions) (llvm.Module, error) {
	return native.TranslateNativeModule(ctx, src, opts)
}

// PreprocessAssemblySource runs the strict Go Plan 9 assembly preprocessor.
func PreprocessAssemblySource(src string, opt AssemblyPreprocessOptions) (string, error) {
	return preprocess.PreprocessAssemblySource(src, opt)
}

// ObserveAssemblyCPP executes the strict preprocessor and records an observation.
func ObserveAssemblyCPP(src string, opt AssemblyPreprocessOptions) (AssemblyCPPObservation, error) {
	return preprocess.ObserveAssemblyCPP(src, opt)
}

// ObserveAssemblyCPPOutput executes the strict preprocessor and retains output tokens.
func ObserveAssemblyCPPOutput(src string, opt AssemblyPreprocessOptions) (AssemblyCPPObservation, []AssemblyCPPOutputToken, error) {
	return preprocess.ObserveAssemblyCPPOutput(src, opt)
}

// GoAssemblerDefines returns the predefined macros cmd/go passes to cmd/asm.
func GoAssemblerDefines(goos, goarch string) []string {
	return preprocess.GoAssemblerDefines(goos, goarch)
}

// GoAssemblerDefinesWithEnv returns predefined cmd/asm macros using explicit env.
func GoAssemblerDefinesWithEnv(goos, goarch string, env map[string]string) []string {
	return preprocess.GoAssemblerDefinesWithEnv(goos, goarch, env)
}

// GoAssemblerDefinesForEnvironment returns predefined cmd/asm macros for an observed environment.
func GoAssemblerDefinesForEnvironment(goos, goarch string, environment map[string]string) ([]string, error) {
	return preprocess.GoAssemblerDefinesForEnvironment(goos, goarch, environment)
}
