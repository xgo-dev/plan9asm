package plan9asm

import "strings"

// ARM64ClosureTransport is the physical LLVM transport of a required context.
// It is independent of Go's R26 source register and ordinary argument banks.
type ARM64ClosureTransport uint8

const (
	ARM64ClosureNest ARM64ClosureTransport = iota + 1
	ARM64ClosureSwiftSelf
)

// ARM64ClosureABI describes an explicitly supplied, immutable Go funcval
// carrier. Its first word is this entry's code pointer and its second word is
// one captured uint64. It is not a third Go parameter or an ABI0 FP slot.
//
// The producer must establish the entry identity, carrier layout and lifetime.
// A signature alone does not authorize direct calls or address-taking: source
// edges without a matching producer remain Context. Nil is the default.
type ARM64ClosureABI struct {
	ContextRegister Reg
	EntrySymbol     string
	CodeOffset      int64
	CodeType        LLVMType
	CaptureOffset   int64
	CaptureType     LLVMType
	Transport       ARM64ClosureTransport
}

func (abi ARM64ClosureABI) llvmAttribute() string {
	if abi.Transport == ARM64ClosureSwiftSelf {
		return "swiftself"
	}
	return "nest"
}

func validateARM64ClosureABI(sig FuncSig, triple string) error {
	abi := sig.ARM64ClosureABI
	if abi == nil {
		return nil
	}
	if abi.ContextRegister != "R26" || abi.EntrySymbol != sig.Name || abi.EntrySymbol == "" ||
		abi.CodeOffset != 0 || abi.CodeType != Ptr || abi.CaptureOffset != 8 || abi.CaptureType != I64 {
		return arm64GoABIContext("%q needs an exact typed closure carrier and entry identity", sig.Name)
	}
	if err := arm64ValidateGoRegisterABI(sig); err != nil {
		return err
	}
	lower := strings.ToLower(triple)
	if !strings.HasPrefix(lower, "aarch64-") && !strings.HasPrefix(lower, "arm64-") {
		return arm64GoABIContext("%q closure transport needs an explicit ARM64 target", sig.Name)
	}
	want := ARM64ClosureNest
	for _, platform := range []string{"apple", "darwin", "android", "windows", "win32", "mingw"} {
		if strings.Contains(lower, platform) {
			want = ARM64ClosureSwiftSelf
		}
	}
	if abi.Transport != want {
		return arm64GoABIContext("%q closure transport does not match target %q", sig.Name, triple)
	}
	return nil
}

// This first carrier boundary is deliberately read-only and bounded. It does
// not infer an environment from arbitrary R26 use or give ordinary pointer
// operands a noalias promise. The complete original and normalized functions
// must both satisfy the same gate, including unreachable instructions.
func validateARM64ClosureSource(fn Func, sig FuncSig) error {
	if sig.ARM64ClosureABI == nil {
		return nil
	}
	if fn.arm64PrivateTailSource != nil {
		return validateARM64PrivateTailClosureSource(fn, sig)
	}
	if !strings.HasSuffix(fn.Sym, "<ABIInternal>") {
		return arm64GoABIContext("%q required closure entry needs a source ABIInternal selector", sig.Name)
	}
	seen := false
	for _, original := range fn.Instrs {
		ins := arm64ControlDecode(original)
		if ins.Op == "WORD" || ins.Op == "DWORD" {
			return arm64GoABIContext("%q closure carrier has unproved raw effects", sig.Name)
		}
		captureRead := ins.Op == "MOVD" && len(ins.Args) == 2 &&
			ins.Args[0].Kind == OpMem && ins.Args[0].Mem.Base == "R26" &&
			ins.Args[0].Mem.Off == sig.ARM64ClosureABI.CaptureOffset &&
			ins.Args[0].Mem.Sym == "" && ins.Args[0].Mem.OffRaw == "" &&
			ins.Args[0].Mem.Index == "" && ins.Args[0].Mem.Segment == "" &&
			ins.Args[1].Kind == OpReg && ins.Args[1].Reg != "R26"
		for i, arg := range ins.Args {
			if captureRead && i == 0 {
				seen = true
				continue
			}
			if arg.Reg == "R26" || arg.ShiftReg == "R26" || arg.Mem.Base == "R26" || arg.Mem.Index == "R26" {
				return arm64GoABIContext("%q closure context may not be changed, exposed or read outside its capture cell", sig.Name)
			}
			for _, reg := range arg.RegList {
				if reg == "R26" {
					return arm64GoABIContext("%q closure context escapes through a register list", sig.Name)
				}
			}
			if arg.Kind == OpMem || arg.Kind == OpFP || arg.Kind == OpFPAddr ||
				(arg.Kind == OpSym && strings.HasPrefix(arg.Sym, "$")) {
				return arm64GoABIContext("%q closure entry has memory/address effects without a carrier alias contract", sig.Name)
			}
			if arg.Kind == OpSym {
				if _, _, memory := parseSBRef(arg.Sym); memory && !arm64ClosureDirectControlTarget(ins, i) {
					return arm64GoABIContext("%q closure entry has symbol memory effects without a carrier alias contract", sig.Name)
				}
			}
		}
	}
	if !seen {
		return arm64GoABIContext("%q closure contract has no source-bound capture read", sig.Name)
	}
	return nil
}

func arm64ClosureDirectControlTarget(ins Instr, index int) bool {
	if index != 0 || len(ins.Args) != 1 {
		return false
	}
	switch ins.Op {
	case "B", "JMP", "RET", "BL", "CALL":
		return true
	}
	return false
}

func validateARM64ClosureFile(file *File, opt Options, resolve func(string) string) error {
	if file == nil {
		return nil // The common parsed-file gate reports this invalid input.
	}
	required := false
	for _, sig := range opt.Sigs {
		if sig.ARM64ClosureABI == nil {
			continue
		}
		required = true
		if file.Arch != ArchARM64 || opt.Goarch != "arm64" {
			return arm64GoABIContext("required ARM64 closure carrier used for another architecture")
		}
		if err := validateARM64ClosureABI(sig, opt.TargetTriple); err != nil {
			return err
		}
	}
	if !required {
		return nil
	}
	checkReference := func(symbol string) error {
		symbol = strings.TrimLeft(strings.TrimSpace(symbol), "$*")
		if name, _, ok := parseSBRef(symbol); ok {
			if sig := opt.Sigs[resolve(name)]; sig.ARM64ClosureABI != nil {
				return arm64GoABIContext("%q requires a matching typed closure producer; a source reference is not a carrier", sig.Name)
			}
		}
		return nil
	}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			for _, arg := range ins.Args {
				if err := checkReference(arg.Sym); err != nil {
					return err
				}
				if err := checkReference(arg.Mem.Sym); err != nil {
					return err
				}
			}
		}
	}
	for _, data := range file.Data {
		if err := checkReference(data.Addr); err != nil {
			return err
		}
	}
	return nil
}
