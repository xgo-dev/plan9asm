package plan9asm

import (
	"reflect"
	"strings"
)

// This per-translation source witness narrows only the unknown-scratch
// observer check. It is not a caller-save, native ABI, memory or flags promise,
// and cannot be supplied through Options or serialized as a trusted marker.
type arm64SourceNoopCall struct {
	original Func
	resolved string
	native   *arm64ScratchBinding
}

func captureARM64SourceNoopCalls(file *File, resolve func(string) string, sigs map[string]FuncSig) map[string]arm64SourceNoopCall {
	if file.Arch != ArchARM64 {
		return nil
	}
	symbols, resolved := make(map[string]int), make(map[string]int)
	for _, fn := range file.Funcs {
		symbols[fn.Sym]++
		resolved[resolve(fn.Sym)]++
	}
	proofs := make(map[string]arm64SourceNoopCall)
	for _, fn := range file.Funcs {
		name := resolve(fn.Sym)
		sig, present := sigs[name]
		if !present || symbols[fn.Sym] != 1 || resolved[name] != 1 || sig.Name != name ||
			!arm64SourceNoopSignature(sig) || !arm64SourceNoopBody(fn) {
			continue
		}
		original := fn
		original.Instrs = append([]Instr(nil), fn.Instrs...)
		proofs[fn.Sym] = arm64SourceNoopCall{original: original, resolved: name}
	}
	return proofs
}

func arm64SourceNoopSignature(sig FuncSig) bool {
	return sig.Name != "" && sig.Ret == Void && len(sig.Args) == 0 &&
		len(sig.Frame.Params) == 0 && len(sig.Frame.Results) == 0 && len(sig.ArgRegs) == 0 &&
		sig.ARM64GoRegisterABI == nil && sig.ARM64ClosureABI == nil && sig.ARMEntry == nil &&
		sig.WASMContext == "" && !sig.WASMNative
}

// The complete source is exactly a NOSPLIT|NOFRAME zero-argument ABI0 TEXT
// and an ordinary RET. Go obj7 emits no stack-check/prologue/epilogue scratch
// for that leaf. A label, raw RET, transitive call or extra instruction is not
// inferred harmless. ABI selectors and hidden/wrapper flags keep their own
// contracts; even an empty callable signature alone proves nothing.
func arm64SourceNoopBody(fn Func) bool {
	if fn.Sym == "" || strings.Contains(fn.Sym, "<") || fn.FrameSize != 0 || fn.ArgSize != 0 ||
		len(fn.Instrs) != 2 || fn.Instrs[0].Op != OpTEXT || len(fn.Instrs[0].Args) != 0 ||
		fn.Instrs[1].Op != OpRET || len(fn.Instrs[1].Args) != 0 {
		return false
	}
	_, rest := splitOpcode(fn.Instrs[0].Raw)
	parts := strings.Split(rest, ",")
	if len(parts) != 3 || strings.LastIndex(strings.TrimSpace(parts[2]), "-") <= 1 {
		return false
	}
	expression := globlFlagName.ReplaceAllStringFunc(parts[1], func(name string) string {
		if value, ok := goTextFlagValues[name]; ok {
			return value
		}
		return name
	})
	flags, known := parseImmExpr(expression)
	if !known || flags != 4|512 { // NOSPLIT | NOFRAME, and no hidden entry effects.
		return false
	}
	// Reparse retained source independently. A changed public instruction or
	// physical-decoder marker must not borrow a matching-looking Raw string.
	parsed, err := Parse(ArchARM64, fn.Instrs[0].Raw+"\n"+fn.Instrs[1].Raw+"\n")
	return err == nil && len(parsed.Funcs) == 1 && reflect.DeepEqual(parsed.Funcs[0], fn)
}

func (proof arm64SourceNoopCall) matchesNormalized(fn Func, sig FuncSig) bool {
	if proof.native != nil {
		// The native closure is checked on complete original input before the
		// trusted normalizer. It is not a prepared-function or register-entry
		// promise; ordinary typed/machine/CFG checks still run on this body.
		return true
	}
	return sig.Name == proof.resolved && arm64SourceNoopSignature(sig) && arm64SourceNoopBody(proof.original) &&
		arm64SourceNoopBody(fn) && reflect.DeepEqual(proof.original, fn)
}

func (c *arm64Ctx) sourceCallDoesNotObserveScratch(symbol string) bool {
	proof, present := c.sourceNoopCalls[symbol]
	if !present {
		return false
	}
	if proof.native != nil {
		return proof.native.hasCall(symbol)
	}
	sig, present := c.sigs[c.resolve(symbol)]
	return present && sig.Name == c.resolve(symbol) && proof.matchesNormalized(proof.original, sig)
}
