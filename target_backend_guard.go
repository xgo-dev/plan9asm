package plan9asm

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/llvm"
)

// Goarch selects the source encoder/ABI rules. It is not a backend selector:
// portable lowering may legitimately target a different LLVM architecture.
func validateBackendSourceGoarch(file *File, options Options) error {
	if file == nil || options.Goarch == "" {
		return nil
	}
	valid := true
	switch file.Arch {
	case ArchAMD64:
		valid = options.Goarch == "amd64" || options.Goarch == "386"
	case ArchARM:
		valid = options.Goarch == "arm"
	case ArchARM64:
		valid = options.Goarch == "arm64"
	case ArchWASM:
		valid = options.Goarch == "wasm"
	}
	if !valid {
		return fmt.Errorf("%w: source architecture %q conflicts with Goarch %q",
			ErrProbeNeedsContext, file.Arch, options.Goarch)
	}
	return nil
}

// validateTranslatedBackend checks the actual returned module, including early
// native-source returns. Keep target-independent source lowering portable.
func validateTranslatedBackend(file *File, options Options, module llvm.Module) error {
	requestedTriple := module.Target()
	// Match the backend LLVM22 will actually select, including omitted or
	// reordered fields. Keep the request and source-owner options unchanged.
	triple := llvmNormalizedTargetTriple(requestedTriple)
	architecture, _, _ := strings.Cut(triple, "-")
	// LLVM's x86 intrinsic namespace is target-specific. Check intrinsic IDs
	// and actual uses: ordinary names and unused declarations stay portable.
	goarch := options.Goarch
	if goarch == "" && file != nil && file.Arch == ArchAMD64 {
		goarch = "amd64" // The same source-mode default as translateIR.
	}
	if !x86ScalarFloatIntegerNativeTarget(goarch, triple) {
		mxcsrTarget := x86ScalarFloatIntegerNativeTarget("amd64", triple) ||
			x86ScalarFloatIntegerNativeTarget("386", triple)
		for function := module.FirstFunction(); !function.IsNil(); function = llvm.NextFunction(function) {
			if function.IntrinsicID() != 0 && !function.FirstUse().IsNil() &&
				strings.HasPrefix(function.Name(), "llvm.x86.") {
				// LLVM 22 maps these two intrinsics to an i32 memory operand
				// in either x86 mode (X86InstrSSE.td). Source pointer width
				// does not constrain the control register; other families do.
				if mxcsrTarget && (function.Name() == "llvm.x86.sse.ldmxcsr" ||
					function.Name() == "llvm.x86.sse.stmxcsr") {
					continue
				}
				return fmt.Errorf("%w: x86 intrinsic %q requires its matching x86 LLVM target, got %q",
					ErrProbeNeedsContext, function.Name(), requestedTriple)
			}
		}
	}
	if err := validateTranslatedNativeBackend(file, goarch, triple, module); err != nil {
		return err
	}
	if architecture == "wasm32" || architecture == "wasm64" {
		for function := module.FirstFunction(); !function.IsNil(); function = llvm.NextFunction(function) {
			for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
				// A BasicBlock is not an ordinary LLVM constant operand. Its
				// constant users are BlockAddress values, whether those addresses
				// are nested in expressions, aggregates, aliases or instructions.
				// Inspect their actual def-use edges rather than printed names,
				// source annotations or the spelling of a particular lowerer.
				for use := block.AsValue().FirstUse(); !use.IsNil(); use = use.NextUse() {
					if !use.User().IsAConstant().IsNil() {
						return fmt.Errorf("%w: LLVM target %q cannot represent blockaddress in %q",
							ErrProbeNeedsContext, requestedTriple, function.Name())
					}
				}
			}
		}
	}
	if arm64ScalarConversionNativeTarget(triple) {
		return nil
	}
	if file != nil && file.Arch == ArchARM64 {
		// Reuse the complete named/raw family classifier even when a caller
		// supplies custom attributes. Raw literal-pool words are data, not SVE
		// instructions. Pure scalable-vector operations also need this check;
		// they need not contain an llvm.aarch64 intrinsic call.
		view := arm64NativeTargetCodeView(file)
		for _, function := range view.Funcs {
			features := inferFuncTargetFeaturesForGOARCH(view.Arch, options.Goarch, function)
			for _, feature := range strings.Split(features, ",") {
				if strings.HasPrefix(feature, "+sve") {
					return fmt.Errorf("%w: ARM64 SVE requires an explicit AArch64 LLVM target, got %q",
						ErrProbeNeedsContext, requestedTriple)
				}
			}
		}
	}
	// Declarations in an architecture prelude are not executed requirements.
	// An actually referenced target intrinsic must nevertheless stay on its
	// backend, including any future lowering not yet in the source classifier.
	for function := module.FirstFunction(); !function.IsNil(); function = llvm.NextFunction(function) {
		if strings.HasPrefix(function.Name(), "llvm.aarch64.sve.") && !function.FirstUse().IsNil() {
			return fmt.Errorf("%w: used ARM64 SVE intrinsic %q requires an AArch64 LLVM target, got %q",
				ErrProbeNeedsContext, function.Name(), requestedTriple)
		}
	}
	return nil
}

func validateTranslatedNativeBackend(file *File, goarch, triple string, module llvm.Module) error {
	if file != nil {
		// Normal native requests need no instruction walk. Reuse the same
		// source-mode and endian boundaries as the typed family validators.
		switch file.Arch {
		case ArchAMD64:
			if x86ScalarFloatIntegerNativeTarget(goarch, triple) {
				return nil
			}
		case ArchARM:
			if armWordFloatNativeTarget(triple) {
				return nil
			}
		case ArchARM64:
			if arm64ScalarConversionNativeTarget(triple) {
				return nil
			}
		case ArchWASM:
			architecture, _, _ := strings.Cut(triple, "-")
			if architecture == "wasm32" {
				return nil
			}
		}
	}
	if llvmModuleHasAssembly(module) {
		return fmt.Errorf("%w: used module assembly requires its matching source LLVM target, got %q",
			ErrProbeNeedsContext, module.Target())
	}
	var scalableVectorKind llvm.TypeKind
	if file != nil && file.Arch == ArchAMD64 {
		scalableVectorKind = llvmScalableVectorKind(module.Context())
	}
	for function := module.FirstFunction(); !function.IsNil(); function = llvm.NextFunction(function) {
		for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
			for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
				if file != nil && file.Arch == ArchAMD64 && x86InstructionUsesSegmentMemory(instruction, scalableVectorKind) {
					return fmt.Errorf("%w: used x86 FS/GS segment memory in %q requires its matching source-mode LLVM target, got %q",
						ErrProbeNeedsContext, function.Name(), module.Target())
				}
				for index := 0; index < instruction.OperandsCount(); index++ {
					assembly := instruction.Operand(index).IsAInlineAsm()
					if assembly.IsNil() {
						continue
					}
					info := assembly.InlineAsmInfo()
					if info.Assembly == "" {
						// Existing memory and generic-register compiler barriers
						// compile on x86, ARM64 and WASM without source registers.
						switch info.Constraints {
						case "", "~{memory}", "r", "=r,0":
							continue
						}
					}
					return fmt.Errorf("%w: used native inline assembly in %q requires its matching source LLVM target, got %q",
						ErrProbeNeedsContext, function.Name(), module.Target())
				}
			}
		}
	}
	return nil
}

// Inspect memory address roles, not pointer-valued results, stored values,
// declarations, unused constants or address calculations. Native requests
// return before this walk. Calls with unknown effects conservatively consume
// their pointer arguments; explicit LLVM memory(none) transport does not.
func x86InstructionUsesSegmentMemory(instruction llvm.Value, scalableVectorKind llvm.TypeKind) bool {
	first, end := 0, 1
	switch instruction.InstructionOpcode() {
	case llvm.Load, llvm.VAArg:
	case llvm.Store:
		first, end = 1, 2
	case llvm.Call, llvm.Invoke:
		kind := llvm.AttributeKindID("memory")
		if attribute := instruction.GetCallSiteEnumAttribute(-1, kind); !attribute.IsNil() && attribute.GetEnumValue() == 0 {
			return false
		}
		if callee := instruction.CalledValue().IsAFunction(); !callee.IsNil() {
			if attribute := callee.GetEnumFunctionAttribute(kind); !attribute.IsNil() && attribute.GetEnumValue() == 0 {
				return false
			}
		}
		end = llvmCallArgumentCount(instruction)
		if end > 2 && !instruction.IsAMemIntrinsic().IsNil() {
			if length := instruction.Operand(2).IsAConstantInt(); !length.IsNil() && length.IsNull() {
				return false // A constant-zero transfer performs no source or destination access.
			}
		}
	default:
		if !llvmInstructionIsAtomicMemory(instruction) {
			return false
		}
	}
	for index := first; index < end; index++ {
		typ := instruction.Operand(index).Type()
		if typ.TypeKind() == llvm.VectorTypeKind || typ.TypeKind() == scalableVectorKind {
			typ = typ.ElementType()
		}
		if typ.TypeKind() == llvm.PointerTypeKind {
			if space := typ.PointerAddressSpace(); space == 256 || space == 257 {
				return true
			}
		}
	}
	return false
}
