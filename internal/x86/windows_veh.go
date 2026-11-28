package x86

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// Go declares its VEH entry points as zero-argument functions so their
// addresses can be registered with Windows. Windows actually passes one
// stack argument; the intermediate assembly entry uses AX and CX. Match
// the whole adapter before applying that foreign calling convention.
var vehDispatchBody = vehBody(`SUBL $40,SP
MOVL BX,28(SP)
MOVL BP,16(SP)
MOVL SI,20(SP)
MOVL DI,24(SP)
MOVL AX,0(SP)
MOVL CX,4(SP)
CALL runtime·sigtrampgo(SB)
MOVL 8(SP),AX
MOVL 24(SP),DI
MOVL 20(SP),SI
MOVL 16(SP),BP
MOVL 28(SP),BX
ADDL $40,SP
BYTE $0xc2
WORD $4
RET`)

func vehBody(body string) []asm.Instr {
	f, err := asm.Parse(asm.ArchAMD64, "TEXT sigtramp<>(SB),4,$0-0\n"+body)
	if err != nil {
		panic(err)
	}
	return f.Funcs[0].Instrs[1:]
}

func matchesVEHBody(fn asm.Func, body []asm.Instr) bool {
	if fn.Sym != "sigtramp<>" || fn.FrameSize != 0 || fn.ArgSize != 0 || len(fn.Instrs) != len(body)+1 {
		return false
	}
	for i, expected := range body {
		actual := fn.Instrs[i+1]
		if actual.Op != expected.Op || !reflect.DeepEqual(actual.Args, expected.Args) {
			return false
		}
	}
	return true
}

// AddressedFunctionCandidate returns a symbol whose address is loaded by a
// 386 MOVL. Callers check Go declarations to distinguish code from data.
func AddressedFunctionCandidate(ins asm.Instr) string {
	if ins.Op != "MOVL" || len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpSym || ins.Args[1].Kind != asm.OpReg {
		return ""
	}
	ref := ins.Args[0].Sym
	if !strings.HasPrefix(ref, "$") || !strings.HasSuffix(ref, "(SB)") {
		return ""
	}
	sym, off, ok := asm.ParseSBRef(ref[1:])
	if !ok || off != 0 {
		return ""
	}
	return sym
}

func isVEHEntry(sym string) bool {
	switch sym {
	case "runtime·exceptiontramp", "runtime·firstcontinuetramp", "runtime·lastcontinuetramp":
		return true
	}
	return false
}

// Some Go releases use an ordinary INT $3 stub for firstcontinuetramp.
func referencesVEHDispatcher(fn asm.Func) bool {
	for _, ins := range fn.Instrs {
		for _, arg := range ins.Args {
			if arg.Kind == asm.OpSym && strings.TrimPrefix(arg.Sym, "$") == "sigtramp<>(SB)" {
				return true
			}
		}
	}
	return false
}

// The file-local dispatchers have the same name across Go releases, but
// expect different registers. Bind incoming jumps to the actual source body.
func classifyVEHDispatch(file *asm.File) (legacy, known bool, err error) {
	var dispatch *asm.Func
	for i := range file.Funcs {
		if file.Funcs[i].Sym == "sigtramp<>" {
			dispatch = &file.Funcs[i]
			break
		}
	}
	legacy = dispatch != nil && matchesVEHBody(*dispatch, legacyVEHBody)
	knownDispatcher := legacy || dispatch != nil && matchesVEHBody(*dispatch, vehDispatchBody)
	for _, fn := range file.Funcs {
		if knownDispatcher && fn.Sym != "sigtramp<>" && !isVEHEntry(fn.Sym) && referencesVEHDispatcher(fn) {
			return false, false, fmt.Errorf("%s: %w: unsupported entry to Windows/386 VEH dispatcher", fn.Sym, asm.ErrProbeNeedsContext)
		}
		if !isVEHEntry(fn.Sym) || len(fn.Instrs) < 2 {
			continue
		}
		jump := fn.Instrs[len(fn.Instrs)-1]
		if jump.Op != "JMP" || len(jump.Args) != 1 || jump.Args[0].Sym != "sigtramp<>(SB)" {
			continue
		}
		body := vehDispatchBody
		if len(fn.Instrs) == 3 {
			body = legacyVEHBody
		}
		if dispatch == nil || !matchesVEHBody(*dispatch, body) {
			return false, false, fmt.Errorf("%s: %w: incompatible windows/386 VEH dispatcher", fn.Sym, asm.ErrProbeNeedsContext)
		}
	}
	return legacy, knownDispatcher, nil
}

func translateWindows386Entry(b *strings.Builder, fn asm.Func, sig asm.FuncSig, opt asm.Options) (bool, error) {
	if opt.Goarch != "386" || !matchesX86Target("386", opt.TargetTriple) || !isWindowsTriple(opt.TargetTriple) {
		return false, nil
	}
	if opt.ResolveSym == nil {
		opt.ResolveSym = func(s string) string { return s }
	}
	var code, symbol string
	switch {
	case matchesVEHBody(fn, legacyVEHBody):
		return true, emitLegacyVEH(b, sig, opt)
	case matchesVEHBody(fn, vehDispatchBody):
		if len(sig.Args) != 0 || sig.Ret != asm.Void {
			return true, fmt.Errorf("%w: unexpected VEH entry signature", asm.ErrProbeNeedsContext)
		}
		// Adapt AX,CX to the lowered Go function's cdecl arguments. The C ABI
		// preserves BX, BP, SI and DI. The native entry must clean the VEH slot.
		symbol = "runtime·sigtrampgo"
		name := opt.ResolveSym(symbol)
		cs := opt.Sigs[name]
		if len(cs.Args) != 2 || cs.Args[0] != asm.Ptr || cs.Args[1] != asm.I32 || cs.Ret != asm.I32 {
			return true, fmt.Errorf("%w: windows/386 VEH requires a (ptr, i32) -> i32 callee, got %v", asm.ErrProbeNeedsContext, cs)
		}
		code = "pushl %ebp; movl %esp, %ebp; andl $$-16, %esp; subl $$8, %esp; " +
			"pushl %ecx; pushl %eax; calll ${0:c}; movl %ebp, %esp; popl %ebp; retl $$4"
	case isVEHEntry(fn.Sym) && referencesVEHDispatcher(fn):
		if sig.Ret != asm.Void || len(sig.Args) != 0 {
			return true, fmt.Errorf("%w: unexpected VEH entry signature", asm.ErrProbeNeedsContext)
		}
		if fn.FrameSize == 0 && len(fn.Instrs) == 3 {
			mov, jump := fn.Instrs[1], fn.Instrs[2]
			if mov.Op == "MOVL" && len(mov.Args) == 2 && mov.Args[0].Kind == asm.OpSym && mov.Args[1].Reg == asm.AX && jump.Op == "JMP" && len(jump.Args) == 1 && jump.Args[0].Sym == "sigtramp<>(SB)" {
				sym := mov.Args[0].Sym
				if sym == "$runtime·exceptionhandler(SB)" || sym == "$runtime·lastcontinuehandler(SB)" || sym == "$runtime·firstcontinuehandler(SB)" {
					name := opt.ResolveSym(sym[1 : len(sym)-4])
					cs := opt.Sigs[name]
					if cs.Ret != asm.I32 || len(cs.Args) != 3 || cs.Args[0] != asm.Ptr || cs.Args[1] != asm.Ptr || cs.Args[2] != asm.Ptr {
						return true, fmt.Errorf("%w: windows/386 legacy VEH requires handler(ptr,ptr,ptr) -> i32", asm.ErrProbeNeedsContext)
					}
					dispatch := opt.ResolveSym("sigtramp<>")
					fmt.Fprintf(b, "define void %s() %s naked noinline {\n  call void asm sideeffect \"movl $$${0:c}, %%eax; jmp ${1:c}\", \"i,i,~{memory}\"(ptr %s, ptr %s)\n  unreachable\n}\n", asm.LLVMGlobal(sig.Name), sig.Attrs, asm.LLVMGlobal(asm.FuncSigSymbol(name, cs)), asm.LLVMGlobal(asm.FuncSigSymbol(dispatch, opt.Sigs[dispatch])))
					return true, nil
				}
			}
		}
		if fn.FrameSize != 0 || len(fn.Instrs) != 4 {
			return true, fmt.Errorf("%w: unrecognized Windows/386 VEH entry %s", asm.ErrProbeNeedsContext, fn.Sym)
		}
		mov, kind, jump := fn.Instrs[1], fn.Instrs[2], fn.Instrs[3]
		if mov.Op != "MOVL" || len(mov.Args) != 2 || mov.Args[0].Kind != asm.OpFP || mov.Args[0].FPOffset != 0 || mov.Args[1].Reg != asm.AX ||
			kind.Op != "MOVL" || len(kind.Args) != 2 || kind.Args[0].Kind != asm.OpImm || kind.Args[0].ImmRaw != "" || kind.Args[1].Reg != asm.CX ||
			jump.Op != "JMP" || len(jump.Args) != 1 || jump.Args[0].Sym != "sigtramp<>(SB)" {
			return true, fmt.Errorf("%w: unrecognized Windows/386 VEH entry %s", asm.ErrProbeNeedsContext, fn.Sym)
		}
		symbol = "sigtramp<>"
		code = fmt.Sprintf("movl 4(%%esp), %%eax; movl $$%d, %%ecx; jmp ${0:c}", int32(kind.Args[0].Imm))
	default:
		return false, nil
	}
	name := opt.ResolveSym(symbol)
	operand := asm.LLVMGlobal(asm.FuncSigSymbol(name, opt.Sigs[name]))
	fmt.Fprintf(b, "define void %s() %s naked noinline {\n  call void asm sideeffect %q, \"i,~{memory}\"(ptr %s)\n  unreachable\n}\n", asm.LLVMGlobal(sig.Name), sig.Attrs, code, operand)
	return true, nil
}

func isWindowsTriple(triple string) bool {
	for _, p := range strings.Split(strings.ToLower(triple), "-") {
		if strings.TrimRight(p, "0123456789.") == "windows" {
			return true
		}
	}
	return false
}
