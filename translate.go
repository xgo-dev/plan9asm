package plan9asm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

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
	//
	// This is used for intra-asm tailcalls like:
	//   B helper<>(SB)
	// where helper expects inputs in a custom register assignment.
	ArgRegs []Reg

	// Frame provides a minimal stack-frame model for resolving name+off(FP)
	// references in Go/Plan9 assembly into LLVM function args/returns.
	//
	// This is intentionally limited to the classic Go assembler convention used
	// by stdlib .s files (e.g. internal/cpu/cpu_x86.s).
	Frame FrameLayout
}

// WASMABI selects the physical ABI used for WebAssembly Plan 9 assembly.
// Direct is LLGo's existing native LLVM calling convention. Go uses the
// official linear-memory stack, mutable register globals, PC_B resume input,
// and an i32 unwind result.
type WASMABI uint8

const (
	WASMABIDirect WASMABI = iota
	WASMABIGo
)

func (a WASMABI) valid() bool { return a == WASMABIDirect || a == WASMABIGo }

type FrameLayout struct {
	Params  []FrameSlot
	Results []FrameSlot
}

type FrameSlot struct {
	Offset int64
	Type   LLVMType
	Index  int // index into LLVM function arguments (for Params) or results tuple (for Results)
	// Name is the source-level Go parameter or result name when available.
	// It lets legacy assembly with a stale numeric FP offset still identify a
	// unique named result without weakening validation for anonymous or
	// aggregate frame slots.
	Name string
	// Field is the index of the extracted field within the argument aggregate.
	// It is used for classic Go asm slots like b_base+0(FP) when the Go-level
	// parameter is passed as a struct (string/slice header).
	//
	// When Field < 0, the slot refers directly to %arg(Index).
	Field int
	// Fields carries a nested extractvalue path for arrays and structs. It is
	// empty for direct values and one-level aggregates, which continue to use
	// Field for compatibility with existing callers.
	Fields []int
}

func frameSlotFields(slot FrameSlot) []int {
	if len(slot.Fields) != 0 {
		return slot.Fields
	}
	if slot.Field >= 0 {
		return []int{slot.Field}
	}
	return nil
}

func frameSlotExtractSuffix(slot FrameSlot) string {
	fields := frameSlotFields(slot)
	if len(fields) == 0 {
		return ""
	}
	parts := make([]string, len(fields))
	for i, field := range fields {
		parts[i] = fmt.Sprintf("%d", field)
	}
	return ", " + strings.Join(parts, ", ")
}

// X87Mode selects how explicit x87 instructions in 386 Plan 9 assembly are
// lowered. Hand-written assembly may use x87 mnemonics regardless of GO386;
// the Go-supported Pentium MMX-or-newer baseline has an x87 unit, so the
// default emits hardware instructions. Software mode is reserved for custom
// targets that explicitly cannot execute x87 instructions.
type X87Mode uint8

const (
	X87Auto X87Mode = iota
	X87Hardware
	X87Software
)

func (m X87Mode) valid() bool {
	return m >= X87Auto && m <= X87Software
}

type Options struct {
	TargetTriple string

	// X86TailGroups identifies closed, assembly-only continuation groups. Their
	// helpers have no callable Go/native entry: the caller must establish that
	// their addresses are used only for jumps within the group's root. The
	// group's every indirect JMP must target one of its named helpers. No
	// helper address may escape to other code or be read as machine-code bytes.
	// helpers are folded into that root's CFG, preserving its entire machine
	// state and FP frame. Ordinary TEXT tail calls must not use this option.
	X86TailGroups []X86TailGroup

	// ResolveSym maps the TEXT symbol (with (SB) trimmed) into the final linker
	// symbol name to emit in LLVM IR. If nil, the symbol is used as-is.
	ResolveSym func(sym string) string

	// Sigs maps resolved symbol name -> signature.
	Sigs map[string]FuncSig

	// Goarch is used for a few arch-specific translations (e.g. x86 CPUID).
	Goarch string

	// WASMABI selects the WebAssembly physical ABI. Its zero value preserves
	// the direct ABI used by existing plan9asm callers.
	WASMABI WASMABI

	// X87Mode controls explicit x87 instruction lowering for GOARCH=386. Auto
	// uses hardware, matching the Go 386 target contract. Software retains the
	// portable LLVM fallback for custom targets without x87 hardware.
	X87Mode X87Mode

	// AnnotateSource emits source asm lines as IR comments before lowering each
	// instruction, for translation debugging.
	AnnotateSource bool
}

// Translate converts a parsed Plan 9 asm File into LLVM IR text (`.ll`).
//
// The generated text is produced from an llvm.Module to keep textual emission
// consistent with the LLVM printer.
func Translate(file *File, opt Options) (string, error) {
	mod, err := TranslateModule(file, opt)
	if err != nil {
		return "", err
	}
	defer mod.Dispose()
	return mod.String(), nil
}

// translateIRText builds textual LLVM IR prior to module parsing.
func translateIRText(file *File, opt Options) (string, error) {
	if file == nil {
		return "", fmt.Errorf("nil file")
	}
	if !opt.X87Mode.valid() {
		return "", fmt.Errorf("invalid x87 mode %d", opt.X87Mode)
	}
	if len(file.Funcs) == 0 && len(file.Data) == 0 && len(file.Globl) == 0 {
		return "", fmt.Errorf("empty file")
	}
	file, err := normalizeX86RawFile(file, opt.Goarch)
	if err != nil {
		return "", err
	}
	file, err = coalesceX86Continuations(file, opt)
	if err != nil {
		return "", err
	}

	resolve := opt.ResolveSym
	if resolve == nil {
		resolve = func(s string) string { return s }
	}
	if !opt.WASMABI.valid() {
		return "", fmt.Errorf("invalid wasm ABI %d", opt.WASMABI)
	}
	if file.Arch == ArchWASM && opt.WASMABI == WASMABIDirect {
		for _, fn := range file.Funcs {
			if !wasmNeedsIncomingContext(fn) {
				continue
			}
			name := resolve(fn.Sym)
			sig, ok := opt.Sigs[name]
			if !ok || sig.WASMContext != "" {
				continue
			}
			sig.WASMContext = Ptr
			opt.Sigs[name] = sig
		}
	}

	var b strings.Builder
	b.WriteString("; Generated by llgo internal/plan9asm (prototype)\n")
	if opt.TargetTriple != "" {
		fmt.Fprintf(&b, "target triple = %q\n\n", opt.TargetTriple)
	}
	// Keep translate.go as the cross-platform pipeline entry.
	// Architecture-specific declarations live in arch-specific files.
	emitArchPrelude(&b, file, resolve, opt.Goarch, opt.WASMABI)

	emitExternSBGlobals(&b, file, resolve, opt.Sigs)

	if len(file.Data) != 0 || len(file.Globl) != 0 {
		if err := emitDataGlobals(&b, file, resolve); err != nil {
			return "", err
		}
		b.WriteString("\n")
	}

	emitExternFuncDecls(&b, file, resolve, opt.Sigs, opt.WASMABI)

	attrRegistry := newFeatureAttrRegistry()
	for i := range file.Funcs {
		fn := &file.Funcs[i]
		name := resolve(fn.Sym)
		sig, ok := opt.Sigs[name]
		if !ok {
			return "", fmt.Errorf("missing signature for %q", name)
		}
		if sig.Name == "" {
			sig.Name = name
		}
		if sig.Name != name {
			return "", fmt.Errorf("signature name mismatch: %q vs %q", sig.Name, name)
		}
		if sig.Ret == "" {
			return "", fmt.Errorf("missing return type for %q", name)
		}
		if file.Arch == ArchAMD64 && fn.X86RawText != nil {
			if err := emitX86AddressSensitiveRawText(&b, *fn, sig); err != nil {
				return "", fmt.Errorf("%s: %w", name, err)
			}
			b.WriteString("\n")
			continue
		}
		if file.Arch == ArchAMD64 && amd64IsRelocationAnchor(*fn, sig) {
			if err := emitX86RelocationAnchor(&b, *fn, sig, resolve, opt.Sigs); err != nil {
				return "", fmt.Errorf("%s: %w", name, err)
			}
			b.WriteString("\n")
			continue
		}
		if err := validateResolvedImmediates(file.Arch, *fn); err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		if file.Arch == ArchAMD64 {
			if err := validateAMD64ScalarAddSubFunction(opt.Goarch, *fn); err != nil {
				return "", fmt.Errorf("%s: %w", name, err)
			}
		}
		if sig.Attrs == "" {
			sig.Attrs = attrRegistry.ref(inferFuncTargetFeaturesForGOARCH(file.Arch, opt.Goarch, *fn))
		}
		// ARM is a fully supported target. Always use its architecture-aware CFG
		// lowerer so even straight-line functions receive the same operand-form
		// validation; the legacy linear prototype silently accepts unknown forms.
		if file.Arch == ArchARM {
			if err := translateFuncARM(&b, *fn, sig, resolve, opt.Sigs, opt.AnnotateSource); err != nil {
				return "", fmt.Errorf("%s: %w", name, err)
			}
			b.WriteString("\n")
			continue
		}
		if file.Arch == ArchARM64 && funcNeedsARM64CFG(*fn) {
			if err := translateFuncARM64(&b, *fn, sig, resolve, opt.Sigs, opt.AnnotateSource); err != nil {
				return "", fmt.Errorf("%s: %w", name, err)
			}
			b.WriteString("\n")
			continue
		}
		// X86 is fully supported. Always use its architecture-aware CFG lowerer
		// so straight-line amd64 functions receive the same memory-width and
		// operand-form semantics as functions containing branches or vector ops.
		// The old linear prototype could silently reinterpret wide FP-frame stores
		// as numeric conversions and leave adjacent aggregate result slots unwritten.
		if file.Arch == ArchAMD64 {
			if err := translateFuncX86(&b, *fn, sig, resolve, opt.Sigs, opt.Goarch, opt.TargetTriple, opt.X87Mode, opt.AnnotateSource); err != nil {
				return "", fmt.Errorf("%s: %w", name, err)
			}
			b.WriteString("\n")
			continue
		}
		if file.Arch == ArchWASM {
			if err := translateFuncWASM(&b, *fn, sig, resolve, opt.Sigs, opt.WASMABI, opt.AnnotateSource); err != nil {
				return "", fmt.Errorf("%s: %w", name, err)
			}
			b.WriteString("\n")
			continue
		}
		if err := translateFuncLinear(&b, file.Arch, *fn, sig, opt.AnnotateSource); err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		b.WriteString("\n")
	}
	attrRegistry.emit(&b)
	if fileUsesX86NonTemporalMetadata(file) {
		b.WriteString("!0 = !{i32 1}\n\n")
	}
	return b.String(), nil
}

func validateResolvedImmediates(arch Arch, fn Func) error {
	if arch != ArchARM && arch != ArchWASM {
		return nil
	}
	for _, ins := range fn.Instrs {
		for _, arg := range ins.Args {
			if arch == ArchARM && arg.Kind == OpImm && arg.ImmRaw != "" {
				return fmt.Errorf("unresolved symbolic immediate %q", arg.ImmRaw)
			}
			if arch == ArchWASM && arg.Kind == OpMem && arg.Mem.OffRaw != "" {
				return fmt.Errorf("unresolved wasm memory offset %q", arg.Mem.OffRaw)
			}
		}
	}
	return nil
}

func emitExternFuncDecls(b *strings.Builder, file *File, resolve func(string) string, sigs map[string]FuncSig, wasmABI WASMABI) {
	defined := map[string]bool{}
	for i := range file.Funcs {
		defined[resolve(file.Funcs[i].Sym)] = true
	}

	// Deterministic order for tests/debugging.
	names := make([]string, 0, len(sigs))
	for name := range sigs {
		if defined[name] || file.isX86Continuation(name, resolve) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		sig := sigs[name]
		if sig.Ret == "" {
			continue
		}
		if file.Arch == ArchWASM && wasmABI == WASMABIGo && !sig.WASMNative {
			fmt.Fprintf(b, "declare i32 %s(i32)\n", llvmGlobal(funcSigSymbol(name, sig)))
			continue
		}
		fmt.Fprintf(b, "declare %s %s(", sig.Ret, llvmGlobal(funcSigSymbol(name, sig)))
		argIndex := 0
		if sig.WASMContext != "" {
			b.WriteString(string(sig.WASMContext))
			argIndex++
		}
		for _, t := range sig.Args {
			if argIndex > 0 {
				b.WriteString(", ")
			}
			b.WriteString(string(t))
			argIndex++
		}
		b.WriteString(")")
		if sig.Attrs != "" {
			b.WriteString(" " + sig.Attrs)
		}
		b.WriteString("\n")
	}
	if len(names) != 0 {
		b.WriteString("\n")
	}
}

func funcSigSymbol(resolved string, sig FuncSig) string {
	if sig.Name != "" {
		return sig.Name
	}
	return resolved
}

func emitExternSBGlobals(b *strings.Builder, file *File, resolve func(string) string, sigs map[string]FuncSig) {
	resolveSBBase := func(base string) string {
		base = strings.TrimSpace(base)
		if base == "" {
			return ""
		}
		if strings.Contains(base, "·") || strings.Contains(base, "/") || strings.Contains(base, ".") {
			return resolve(base)
		}
		return resolve("·" + base)
	}

	// Collect base symbols of SB refs with numeric offsets. These are almost always
	// global variables whose address is computed via GEP in the lowering.
	need := map[string]bool{}
	defined := map[string]bool{}

	// Anything in DATA/GLOBL will be defined in this module.
	for _, g := range file.Globl {
		defined[resolveSBBase(g.Sym)] = true
	}
	for _, d := range file.Data {
		defined[resolveSBBase(d.Sym)] = true
	}
	for _, fn := range file.Funcs {
		defined[resolve(fn.Sym)] = true
	}

	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			opName := strings.ToUpper(string(ins.Op))
			for _, arg := range ins.Args {
				if arg.Kind != OpSym {
					continue
				}
				s := strings.TrimSpace(arg.Sym)
				indirect := strings.HasPrefix(s, "*")
				if indirect {
					s = strings.TrimSpace(strings.TrimPrefix(s, "*"))
				}
				base, off, ok := parseSBRef(s)
				if !ok || base == "" {
					continue
				}
				base = strings.TrimPrefix(base, "$")
				if off == 0 && !indirect {
					// Bare symbol refs are usually global data addresses
					// (e.g. MOVQ runtime·vdsoGettimeofdaySym(SB), AX). Exclude only
					// control-flow ops that use symbol operands as branch/call targets.
					switch opName {
					case "JMP", "JE", "JEQ", "JZ", "JNE", "JNZ",
						"JL", "JLT", "JLE", "JG", "JGT", "JGE", "JS", "JNS",
						"JB", "JBE", "JA", "JAE", "JLS", "JNA",
						"JC", "JNC", "JCC", "CALL", "CALLNORESUME", "WASMCALL", "BL", "B":
						continue
					}
				}
				name := resolveSBBase(base)
				if name != "" && !defined[name] {
					if _, fn := sigs[name]; fn {
						continue
					}
					need[name] = true
				}
			}
		}
	}

	if len(need) == 0 {
		return
	}
	for name := range need {
		fmt.Fprintf(b, "%s = external global i8\n", llvmGlobal(name))
	}
	b.WriteString("\n")
}

func emitDataGlobals(b *strings.Builder, file *File, resolve func(string) string) error {
	// Merge DATA and GLOBL into resolved symbol -> bytes.
	type symData struct {
		size     int64
		bytes    map[int64][]byte // off -> payload
		readOnly bool
		local    bool
	}

	syms := map[string]*symData{}

	resolveData := func(sym string) string {
		// Heuristic: unqualified plain names in a stdlib .s are package-local.
		// Reuse ResolveSym's local-name behavior by prefixing a Plan9 middle dot.
		if strings.Contains(sym, "·") || strings.Contains(sym, "/") || strings.Contains(sym, ".") {
			return resolve(sym)
		}
		return resolve("·" + sym)
	}

	for _, g := range file.Globl {
		readOnly, err := globlReadOnly(g.Flags)
		if err != nil {
			return err
		}
		name := resolveData(g.Sym)
		sd := syms[name]
		if sd == nil {
			sd = &symData{bytes: map[int64][]byte{}}
			syms[name] = sd
		}
		if g.Size > sd.size {
			sd.size = g.Size
		}
		sd.readOnly = readOnly
		sd.local = strings.HasSuffix(g.Sym, "<>")
	}

	for _, d := range file.Data {
		name := resolveData(d.Sym)
		sd := syms[name]
		if sd == nil {
			sd = &symData{bytes: map[int64][]byte{}}
			syms[name] = sd
		}
		sd.local = strings.HasSuffix(d.Sym, "<>")
		end, err := dataStmtEnd(d)
		if err != nil {
			return err
		}
		payload, err := dataStmtPayload(d)
		if err != nil {
			return err
		}
		sd.bytes[d.Off] = payload
		if end > sd.size {
			sd.size = end
		}
	}

	if len(syms) == 0 {
		return nil
	}

	// Deterministic output order.
	names := make([]string, 0, len(syms))
	for n := range syms {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		sd := syms[name]
		if sd.size <= 0 {
			continue
		}
		buf, err := makeDataGlobal(name, sd.size)
		if err != nil {
			return err
		}
		for off, p := range sd.bytes {
			if off < 0 || off+int64(len(p)) > int64(len(buf)) {
				return fmt.Errorf("DATA %s: out of bounds off=%d len=%d size=%d", name, off, len(p), len(buf))
			}
			copy(buf[off:], p)
		}
		align := bestAlign(int64(len(buf)))
		kind := "global"
		if sd.readOnly {
			kind = "constant"
		}
		if sd.local {
			kind = "internal " + kind
		}
		fmt.Fprintf(b, "%s = %s [%d x i8] %s, align %d\n", llvmGlobal(name), kind, len(buf), llvmI8ArrayInit(buf), align)
	}
	return nil
}

// Data globals are currently materialized as byte slices and then as LLVM
// initializer arrays. Bound their size so malformed input cannot exhaust the
// translator's memory before LLVM sees it. The Go standard library's largest
// assembly global is only a few KiB.
const maxDataGlobalSize int64 = 64 << 20

func dataStmtEnd(d DataStmt) (int64, error) {
	if d.Off < 0 {
		return 0, fmt.Errorf("DATA %s: invalid offset %d", d.Sym, d.Off)
	}
	if d.Width <= 0 || d.Width > maxDataGlobalSize || d.Off > maxDataGlobalSize-d.Width {
		return 0, fmt.Errorf("DATA %s: range off=%d width=%d exceeds %d-byte limit", d.Sym, d.Off, d.Width, maxDataGlobalSize)
	}
	return d.Off + d.Width, nil
}

func makeDataGlobal(name string, size int64) ([]byte, error) {
	if size < 0 || size > maxDataGlobalSize {
		return nil, fmt.Errorf("global %s: size %d exceeds %d-byte limit", name, size, maxDataGlobalSize)
	}
	return make([]byte, size), nil
}

func dataStmtPayload(d DataStmt) ([]byte, error) {
	if d.Width <= 0 {
		return nil, fmt.Errorf("DATA %s: invalid width %d", d.Sym, d.Width)
	}
	if d.Width > maxDataGlobalSize {
		return nil, fmt.Errorf("DATA %s: width %d exceeds %d-byte limit", d.Sym, d.Width, maxDataGlobalSize)
	}
	payload := make([]byte, d.Width)
	if d.Payload != nil {
		if int64(len(d.Payload)) > d.Width {
			return nil, fmt.Errorf("DATA %s: string payload is %d bytes, exceeds width %d", d.Sym, len(d.Payload), d.Width)
		}
		copy(payload, d.Payload)
		return payload, nil
	}
	// Plan 9 asm DATA encodes integer immediates little-endian on the
	// architectures supported by this translator.
	v := d.Value
	for i := range payload {
		payload[i] = byte(v & 0xff)
		v >>= 8
	}
	return payload, nil
}

func bestAlign(size int64) int64 {
	// Conservative alignment guess good enough for stdlib constant tables.
	switch {
	case size >= 16 && size%16 == 0:
		return 16
	case size >= 8 && size%8 == 0:
		return 8
	case size >= 4 && size%4 == 0:
		return 4
	case size >= 2 && size%2 == 0:
		return 2
	default:
		return 1
	}
}

func llvmI8ArrayInit(b []byte) string {
	if len(b) == 0 {
		return "zeroinitializer"
	}
	var sb strings.Builder
	sb.WriteString("[")
	for i, v := range b {
		if i != 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "i8 %d", int(v))
	}
	sb.WriteString("]")
	return sb.String()
}

func translateFuncLinear(b *strings.Builder, arch Arch, fn Func, sig FuncSig, annotateSource bool) error {
	// Function header.
	fmt.Fprintf(b, "define %s %s(", sig.Ret, llvmGlobal(sig.Name))
	for i, t := range sig.Args {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%s %%arg%d", t, i)
	}
	b.WriteString(")")
	if sig.Attrs != "" {
		b.WriteString(" " + sig.Attrs)
	}
	b.WriteString(" {\n")
	b.WriteString("entry:\n")

	type ssaVal struct {
		typ LLVMType
		val string // either constant ("0") or SSA ("%t1")
	}

	isSSA := func(v string) bool { return strings.HasPrefix(v, "%") }

	// Register SSA values.
	reg := map[Reg]ssaVal{}
	results := make([]ssaVal, len(sig.Frame.Results))
	haveResult := make([]bool, len(sig.Frame.Results))

	// Initialize a few common arg registers for ABIInternal-style asm.
	// This is currently best-effort; the prototype primarily targets stdlib
	// asm that uses FP slots.
	switch arch {
	case ArchARM:
		if len(sig.ArgRegs) > 0 {
			for i := 0; i < len(sig.Args) && i < len(sig.ArgRegs); i++ {
				reg[sig.ArgRegs[i]] = ssaVal{typ: sig.Args[i], val: fmt.Sprintf("%%arg%d", i)}
			}
		} else {
			for i := 0; i < len(sig.Args) && i < 4; i++ {
				reg[Reg(fmt.Sprintf("R%d", i))] = ssaVal{typ: sig.Args[i], val: fmt.Sprintf("%%arg%d", i)}
			}
		}
	case ArchARM64:
		if len(sig.ArgRegs) > 0 {
			for i := 0; i < len(sig.Args) && i < len(sig.ArgRegs); i++ {
				reg[sig.ArgRegs[i]] = ssaVal{typ: sig.Args[i], val: fmt.Sprintf("%%arg%d", i)}
			}
		} else {
			for i := 0; i < len(sig.Args) && i < 8; i++ {
				reg[Reg(fmt.Sprintf("R%d", i))] = ssaVal{typ: sig.Args[i], val: fmt.Sprintf("%%arg%d", i)}
			}
		}
	case ArchAMD64:
		if len(sig.ArgRegs) > 0 {
			for i := 0; i < len(sig.Args) && i < len(sig.ArgRegs); i++ {
				reg[sig.ArgRegs[i]] = ssaVal{typ: sig.Args[i], val: fmt.Sprintf("%%arg%d", i)}
			}
		} else {
			// SysV-ish mapping (C ABI): DI, SI, DX, CX, R8, R9.
			x86 := []Reg{DI, SI, DX, CX, Reg("R8"), Reg("R9")}
			for i := 0; i < len(sig.Args) && i < len(x86); i++ {
				reg[x86[i]] = ssaVal{typ: sig.Args[i], val: fmt.Sprintf("%%arg%d", i)}
			}
		}
	}
	tmp := 0
	newTmp := func() string {
		tmp++
		return fmt.Sprintf("t%d", tmp)
	}

	emitCast := func(v ssaVal, to LLVMType) (ssaVal, error) {
		if v.typ == "" {
			return ssaVal{}, fmt.Errorf("missing type for value %q", v.val)
		}
		if v.typ == to {
			return v, nil
		}
		// Only support integer casts for now (enough for internal/cpu asm).
		switch {
		case v.typ == I64 && (to == I1 || to == I8 || to == I16):
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = trunc i64 %s to %s\n", name, v.val, to)
			return ssaVal{typ: to, val: "%" + name}, nil
		case v.typ == I64 && to == I32:
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = trunc i64 %s to i32\n", name, v.val)
			return ssaVal{typ: I32, val: "%" + name}, nil
		case (v.typ == I1 || v.typ == I8 || v.typ == I16) && to == I32:
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = zext %s %s to i32\n", name, v.typ, v.val)
			return ssaVal{typ: I32, val: "%" + name}, nil
		case v.typ == I32 && to == I64:
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = zext i32 %s to i64\n", name, v.val)
			return ssaVal{typ: I64, val: "%" + name}, nil
		case (v.typ == I1 || v.typ == I8 || v.typ == I16 || v.typ == I32) && to == I64:
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = zext %s %s to i64\n", name, v.typ, v.val)
			return ssaVal{typ: I64, val: "%" + name}, nil
		case (v.typ == I32 || v.typ == I16 || v.typ == I8) && to == I1:
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = trunc %s %s to i1\n", name, v.typ, v.val)
			return ssaVal{typ: I1, val: "%" + name}, nil
		case (v.typ == I32 || v.typ == I16) && to == I8:
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = trunc %s %s to i8\n", name, v.typ, v.val)
			return ssaVal{typ: I8, val: "%" + name}, nil
		case v.typ == I32 && to == I16:
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = trunc i32 %s to i16\n", name, v.val)
			return ssaVal{typ: I16, val: "%" + name}, nil
		case (v.typ == I1 || v.typ == I8 || v.typ == I16 || v.typ == I32 || v.typ == I64) && (to == LLVMType("float") || to == LLVMType("double")):
			srcTy := v.typ
			srcVal := v.val
			if v.typ == I1 || v.typ == I8 || v.typ == I16 {
				w := newTmp()
				fmt.Fprintf(b, "  %%%s = zext %s %s to i32\n", w, v.typ, v.val)
				srcTy = I32
				srcVal = "%" + w
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = uitofp %s %s to %s\n", name, srcTy, srcVal, to)
			return ssaVal{typ: to, val: "%" + name}, nil
		case (v.typ == LLVMType("float") || v.typ == LLVMType("double")) && (to == I1 || to == I8 || to == I16 || to == I32 || to == I64):
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = fptoui %s %s to %s\n", name, v.typ, v.val, to)
			return ssaVal{typ: to, val: "%" + name}, nil
		case v.typ == Ptr && to == I32:
			if !isSSA(v.val) {
				if v.val == "null" || v.val == "0" {
					return ssaVal{typ: I32, val: "0"}, nil
				}
				return ssaVal{}, fmt.Errorf("unsupported non-SSA ptr cast source %q", v.val)
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = ptrtoint ptr %s to i32\n", name, v.val)
			return ssaVal{typ: I32, val: "%" + name}, nil
		case v.typ == Ptr && to == I64:
			// stdlib asm often moves pointers through GPRs (e.g. MOVD ptr+0(FP), R0).
			// Linear lowering models GPRs as integer SSA values, so support ptr<->i64.
			if !isSSA(v.val) {
				if v.val == "0" || v.val == "null" {
					return ssaVal{typ: I64, val: "0"}, nil
				}
				return ssaVal{}, fmt.Errorf("unsupported non-SSA ptr cast source %q", v.val)
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = ptrtoint ptr %s to i64\n", name, v.val)
			return ssaVal{typ: I64, val: "%" + name}, nil
		case v.typ == I64 && to == Ptr:
			src := v.val
			if !isSSA(src) {
				name := newTmp()
				fmt.Fprintf(b, "  %%%s = add i64 %s, 0\n", name, src)
				src = "%" + name
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = inttoptr i64 %s to ptr\n", name, src)
			return ssaVal{typ: Ptr, val: "%" + name}, nil
		case v.typ == I32 && to == Ptr:
			src := v.val
			if !isSSA(src) {
				name := newTmp()
				fmt.Fprintf(b, "  %%%s = add i32 %s, 0\n", name, src)
				src = "%" + name
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = inttoptr i32 %s to ptr\n", name, src)
			return ssaVal{typ: Ptr, val: "%" + name}, nil
		default:
			return ssaVal{}, fmt.Errorf("unsupported cast %s -> %s", v.typ, to)
		}
	}

	zero := func(t LLVMType) (ssaVal, error) {
		switch t {
		case I1, I8, I16, I32, I64:
			return ssaVal{typ: t, val: "0"}, nil
		case Ptr:
			return ssaVal{typ: Ptr, val: "null"}, nil
		default:
			return ssaVal{typ: t, val: llvmZeroValue(t)}, nil
		}
	}

	fpParamSlot := func(off int64) (FrameSlot, bool) {
		for _, s := range sig.Frame.Params {
			if s.Offset == off {
				return s, true
			}
		}
		return FrameSlot{}, false
	}
	fpResultIndex := func(off int64) (int, LLVMType, bool) {
		for _, s := range sig.Frame.Results {
			if s.Offset == off {
				return s.Index, s.Type, true
			}
		}
		return 0, "", false
	}

	addrOfMem := func(mem MemRef) (string, error) {
		cur := "0"
		if mem.Base != "" {
			bv, ok := reg[mem.Base]
			if ok {
				cast, err := emitCast(bv, I64)
				if err != nil {
					return "", err
				}
				cur = cast.val
			}
		}
		if mem.Index != "" {
			iv := ssaVal{typ: I64, val: "0"}
			if v, ok := reg[mem.Index]; ok {
				cast, err := emitCast(v, I64)
				if err != nil {
					return "", err
				}
				iv = cast
			}
			scale := mem.Scale
			if scale == 0 {
				scale = 1
			}
			mul := newTmp()
			fmt.Fprintf(b, "  %%%s = mul i64 %s, %d\n", mul, iv.val, scale)
			add := newTmp()
			fmt.Fprintf(b, "  %%%s = add i64 %s, %%%s\n", add, cur, mul)
			cur = "%" + add
		}
		if mem.Off != 0 {
			add := newTmp()
			fmt.Fprintf(b, "  %%%s = add i64 %s, %d\n", add, cur, mem.Off)
			cur = "%" + add
		}
		return cur, nil
	}

	var valueOf func(op Operand) (ssaVal, error)
	valueOf = func(op Operand) (ssaVal, error) {
		switch op.Kind {
		case OpImm:
			if op.ImmRaw != "" {
				return ssaVal{}, fmt.Errorf("unresolved symbolic immediate %q", op.ImmRaw)
			}
			// Default immediates to i64; MOVL will cast to i32 as needed.
			return ssaVal{typ: I64, val: fmt.Sprintf("%d", op.Imm)}, nil
		case OpReg:
			v, ok := reg[op.Reg]
			if !ok {
				// Uninitialized register -> treat as 0 i64 for now.
				return ssaVal{typ: I64, val: "0"}, nil
			}
			return v, nil
		case OpRegShift:
			v, err := valueOf(Operand{Kind: OpReg, Reg: op.Reg})
			if err != nil {
				return ssaVal{}, err
			}
			if arch != ArchARM {
				return ssaVal{}, fmt.Errorf("shift operand only modeled for arm in linear lowering: %s", op)
			}
			v, err = emitCast(v, I32)
			if err != nil {
				return ssaVal{}, err
			}
			var shiftVal string
			if op.ShiftReg != "" {
				sv, err := valueOf(Operand{Kind: OpReg, Reg: op.ShiftReg})
				if err != nil {
					return ssaVal{}, err
				}
				sv, err = emitCast(sv, I32)
				if err != nil {
					return ssaVal{}, err
				}
				shiftVal = sv.val
			} else {
				shiftVal = fmt.Sprintf("%d", op.ShiftAmount)
			}
			name := newTmp()
			switch op.ShiftOp {
			case ShiftLeft:
				fmt.Fprintf(b, "  %%%s = shl i32 %s, %s\n", name, v.val, shiftVal)
			case ShiftRight:
				fmt.Fprintf(b, "  %%%s = lshr i32 %s, %s\n", name, v.val, shiftVal)
			case ShiftArith:
				fmt.Fprintf(b, "  %%%s = ashr i32 %s, %s\n", name, v.val, shiftVal)
			case ShiftRotate:
				fmt.Fprintf(b, "  %%%s = call i32 @llvm.fshr.i32(i32 %s, i32 %s, i32 %s)\n", name, v.val, v.val, shiftVal)
			default:
				return ssaVal{}, fmt.Errorf("unsupported shift op %q", op.ShiftOp)
			}
			return ssaVal{typ: I32, val: "%" + name}, nil
		case OpFP:
			slot, ok := fpParamSlot(op.FPOffset)
			if ok {
				idx := slot.Index
				if idx < 0 || idx >= len(sig.Args) {
					return ssaVal{typ: I64, val: "0"}, nil
				}
				arg := fmt.Sprintf("%%arg%d", idx)
				if fields := frameSlotFields(slot); len(fields) != 0 {
					aggTy := sig.Args[idx]
					name := newTmp()
					fmt.Fprintf(b, "  %%%s = extractvalue %s %s%s\n", name, aggTy, arg, frameSlotExtractSuffix(slot))
					return ssaVal{typ: slot.Type, val: "%" + name}, nil
				}
				return ssaVal{typ: slot.Type, val: arg}, nil
			}
			return ssaVal{typ: I64, val: "0"}, nil
		case OpMem:
			addr, err := addrOfMem(op.Mem)
			if err != nil {
				return ssaVal{typ: I64, val: "0"}, nil
			}
			p := newTmp()
			fmt.Fprintf(b, "  %%%s = inttoptr i64 %s to ptr\n", p, addr)
			ld := newTmp()
			fmt.Fprintf(b, "  %%%s = load i64, ptr %%%s\n", ld, p)
			return ssaVal{typ: I64, val: "%" + ld}, nil
		case OpSym:
			// Keep linear lowering permissive when symbol relocation is not modeled.
			_ = op
			return ssaVal{typ: I64, val: "0"}, nil
		default:
			return ssaVal{typ: I64, val: "0"}, nil
		}
	}

	setReg := func(r Reg, v ssaVal) error {
		if v.typ == "" {
			return fmt.Errorf("setReg(%s): missing type", r)
		}
		// Materialize constants into SSA to simplify later inline asm.
		if !isSSA(v.val) {
			name := newTmp()
			switch v.typ {
			case I1, I8, I16, I32, I64:
				fmt.Fprintf(b, "  %%%s = add %s %s, 0\n", name, v.typ, v.val)
				v.val = "%" + name
			case Ptr:
				if v.val == "null" {
					v.val = "null"
				} else {
					return fmt.Errorf("setReg(%s): unsupported non-SSA ptr %q", r, v.val)
				}
			default:
				fmt.Fprintf(b, "  %%%s = add i64 0, 0\n", name)
				v.val = "%" + name
				v.typ = I64
			}
		}
		reg[r] = v
		return nil
	}

	setResult := func(off int64, v ssaVal) error {
		idx, ty, ok := fpResultIndex(off)
		if !ok {
			return nil
		}
		if v.typ != ty {
			var err error
			v, err = emitCast(v, ty)
			if err != nil {
				return err
			}
		}
		results[idx] = v
		haveResult[idx] = true
		return nil
	}

	terminated := false
	for _, ins := range fn.Instrs {
		if annotateSource {
			emitIRSourceComment(b, ins.Raw)
		}
		switch ins.Op {
		case OpTEXT:
			continue
		case OpMRS:
			// ARM64: MRS <sysreg>, Rn
			src, dst := ins.Args[0], ins.Args[1]
			if src.Kind != OpIdent || dst.Kind != OpReg {
				return fmt.Errorf("MRS expects ident, reg: %q", ins.Raw)
			}
			sysreg := arm64CanonicalSysReg(src.Ident)
			if v, ok := arm64CompileSafeMRSValue(sysreg); ok {
				reg[dst.Reg] = ssaVal{typ: I64, val: v}
				continue
			}
			name := newTmp()
			// Read system register via inline asm.
			// Example: call i64 asm "mrs $0, MIDR_EL1", "=r"()
			fmt.Fprintf(b, "  %%%s = call i64 asm %q, %q()\n", name, "mrs $0, "+sysreg, "=r")
			reg[dst.Reg] = ssaVal{typ: I64, val: "%" + name}
			continue
		case OpMOVD:
			// ARM64: MOVD src, dst
			src, dst := ins.Args[0], ins.Args[1]
			v, err := valueOf(src)
			if err != nil {
				return err
			}
			v, err = emitCast(v, I64)
			if err != nil {
				return err
			}
			switch dst.Kind {
			case OpReg:
				if err := setReg(dst.Reg, v); err != nil {
					return err
				}
			case OpFP:
				if err := setResult(dst.FPOffset, v); err != nil {
					return err
				}
			default:
				continue
			}
			continue
		case "MOVW":
			if arch != ArchARM {
				continue
			}
			src, dst := ins.Args[0], ins.Args[1]
			v, err := valueOf(src)
			if err != nil {
				return err
			}
			v, err = emitCast(v, I32)
			if err != nil {
				return err
			}
			switch dst.Kind {
			case OpReg:
				if err := setReg(dst.Reg, v); err != nil {
					return err
				}
			case OpFP:
				if err := setResult(dst.FPOffset, v); err != nil {
					return err
				}
			default:
				continue
			}
			continue
		case "MOVB", "MOVBU":
			if arch != ArchARM {
				continue
			}
			src, dst := ins.Args[0], ins.Args[1]
			v, err := valueOf(src)
			if err != nil {
				return err
			}
			v, err = emitCast(v, I8)
			if err != nil {
				return err
			}
			switch dst.Kind {
			case OpReg:
				if err := setReg(dst.Reg, v); err != nil {
					return err
				}
			case OpFP:
				if err := setResult(dst.FPOffset, v); err != nil {
					return err
				}
			default:
				continue
			}
			continue
		case OpMOVQ:
			src, dst := ins.Args[0], ins.Args[1]
			v, err := valueOf(src)
			if err != nil {
				return err
			}
			v, err = emitCast(v, I64)
			if err != nil {
				return err
			}
			switch dst.Kind {
			case OpReg:
				if err := setReg(dst.Reg, v); err != nil {
					return err
				}
			case OpFP:
				if err := setResult(dst.FPOffset, v); err != nil {
					return err
				}
			default:
				continue
			}

		case OpADDQ, OpSUBQ, OpXORQ:
			src, dst := ins.Args[0], ins.Args[1]
			if dst.Kind != OpReg {
				return fmt.Errorf("%s dst must be register in prototype: %s", ins.Op, dst.String())
			}
			lhs, err := valueOf(dst)
			if err != nil {
				return err
			}
			var rhs ssaVal
			if (ins.Op == OpADDQ || ins.Op == OpSUBQ) && src.Kind == OpImm {
				rhs = ssaVal{typ: I64, val: fmt.Sprintf("%d", amd64ScalarAddSubImmediateInt64(src.Imm, 64))}
			} else {
				rhs, err = valueOf(src)
				if err != nil {
					return err
				}
			}
			lhs, err = emitCast(lhs, I64)
			if err != nil {
				return err
			}
			rhs, err = emitCast(rhs, I64)
			if err != nil {
				return err
			}
			name := newTmp()
			switch ins.Op {
			case OpADDQ:
				fmt.Fprintf(b, "  %%%s = add i64 %s, %s\n", name, lhs.val, rhs.val)
			case OpSUBQ:
				fmt.Fprintf(b, "  %%%s = sub i64 %s, %s\n", name, lhs.val, rhs.val)
			case OpXORQ:
				fmt.Fprintf(b, "  %%%s = xor i64 %s, %s\n", name, lhs.val, rhs.val)
			}
			reg[dst.Reg] = ssaVal{typ: I64, val: "%" + name}
		case "ADD", "SUB", "AND", "ORR", "EOR", "RSB":
			if arch != ArchARM {
				continue
			}
			var lhs, rhs ssaVal
			var dst Operand
			switch len(ins.Args) {
			case 2:
				dst = ins.Args[1]
				if dst.Kind != OpReg {
					return fmt.Errorf("%s dst must be register: %s", ins.Op, ins.Raw)
				}
				var err error
				lhs, err = valueOf(dst)
				if err != nil {
					return err
				}
				rhs, err = valueOf(ins.Args[0])
				if err != nil {
					return err
				}
			case 3:
				dst = ins.Args[2]
				if dst.Kind != OpReg {
					return fmt.Errorf("%s dst must be register: %s", ins.Op, ins.Raw)
				}
				var err error
				lhs, err = valueOf(ins.Args[1])
				if err != nil {
					return err
				}
				rhs, err = valueOf(ins.Args[0])
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("%s expects 2 or 3 operands: %s", ins.Op, ins.Raw)
			}
			var err error
			lhs, err = emitCast(lhs, I32)
			if err != nil {
				return err
			}
			rhs, err = emitCast(rhs, I32)
			if err != nil {
				return err
			}
			name := newTmp()
			switch strings.ToUpper(string(ins.Op)) {
			case "ADD":
				fmt.Fprintf(b, "  %%%s = add i32 %s, %s\n", name, lhs.val, rhs.val)
			case "SUB":
				fmt.Fprintf(b, "  %%%s = sub i32 %s, %s\n", name, lhs.val, rhs.val)
			case "AND":
				fmt.Fprintf(b, "  %%%s = and i32 %s, %s\n", name, lhs.val, rhs.val)
			case "ORR":
				fmt.Fprintf(b, "  %%%s = or i32 %s, %s\n", name, lhs.val, rhs.val)
			case "EOR":
				fmt.Fprintf(b, "  %%%s = xor i32 %s, %s\n", name, lhs.val, rhs.val)
			case "RSB":
				fmt.Fprintf(b, "  %%%s = sub i32 %s, %s\n", name, rhs.val, lhs.val)
			}
			reg[dst.Reg] = ssaVal{typ: I32, val: "%" + name}
			continue

		case OpMOVL:
			src, dst := ins.Args[0], ins.Args[1]
			v, err := valueOf(src)
			if err != nil {
				return err
			}
			v, err = emitCast(v, I32)
			if err != nil {
				return err
			}
			switch dst.Kind {
			case OpReg:
				if err := setReg(dst.Reg, v); err != nil {
					return err
				}
			case OpFP:
				if err := setResult(dst.FPOffset, v); err != nil {
					return err
				}
			default:
				continue
			}

		case OpCPUID:
			// x86: CPUID reads EAX/ECX and writes EAX/EBX/ECX/EDX.
			eax := reg[AX]
			if eax.typ == "" {
				z, _ := zero(I32)
				eax = z
			} else {
				var err error
				eax, err = emitCast(eax, I32)
				if err != nil {
					return err
				}
			}
			ecx := reg[CX]
			if ecx.typ == "" {
				z, _ := zero(I32)
				ecx = z
			} else {
				var err error
				ecx, err = emitCast(ecx, I32)
				if err != nil {
					return err
				}
			}
			if !isSSA(eax.val) {
				if err := setReg(AX, eax); err != nil {
					return err
				}
				eax = reg[AX]
			}
			if !isSSA(ecx.val) {
				if err := setReg(CX, ecx); err != nil {
					return err
				}
				ecx = reg[CX]
			}
			call := newTmp()
			// Return 4x i32 in EAX/EBX/ECX/EDX.
			fmt.Fprintf(b, "  %%%s = call { i32, i32, i32, i32 } asm sideeffect %q, %q(i32 %s, i32 %s)\n",
				call,
				"cpuid",
				"={ax},={bx},={cx},={dx},{ax},{cx},~{dirflag},~{fpsr},~{flags}",
				eax.val, ecx.val)
			ext := func(i int) string {
				n := newTmp()
				fmt.Fprintf(b, "  %%%s = extractvalue { i32, i32, i32, i32 } %%%s, %d\n", n, call, i)
				return "%" + n
			}
			reg[AX] = ssaVal{typ: I32, val: ext(0)}
			reg[BX] = ssaVal{typ: I32, val: ext(1)}
			reg[CX] = ssaVal{typ: I32, val: ext(2)}
			reg[DX] = ssaVal{typ: I32, val: ext(3)}

		case OpXGETBV:
			// x86: XGETBV reads ECX and writes EAX/EDX.
			ecx := reg[CX]
			if ecx.typ == "" {
				z, _ := zero(I32)
				ecx = z
			} else {
				var err error
				ecx, err = emitCast(ecx, I32)
				if err != nil {
					return err
				}
			}
			if !isSSA(ecx.val) {
				if err := setReg(CX, ecx); err != nil {
					return err
				}
				ecx = reg[CX]
			}
			call := newTmp()
			fmt.Fprintf(b, "  %%%s = call { i32, i32 } asm sideeffect %q, %q(i32 %s)\n",
				call,
				"xgetbv",
				"={ax},={dx},{cx},~{dirflag},~{fpsr},~{flags}",
				ecx.val)
			eaxN := newTmp()
			edxN := newTmp()
			fmt.Fprintf(b, "  %%%s = extractvalue { i32, i32 } %%%s, 0\n", eaxN, call)
			fmt.Fprintf(b, "  %%%s = extractvalue { i32, i32 } %%%s, 1\n", edxN, call)
			reg[AX] = ssaVal{typ: I32, val: "%" + eaxN}
			reg[DX] = ssaVal{typ: I32, val: "%" + edxN}

		case OpRET:
			// Return value comes either from explicit result slots (name+off(FP))
			// or, as a fallback, from the arch return register for scalar returns.
			switch {
			case sig.Ret == Void:
				b.WriteString("  ret void\n")
			case len(sig.Frame.Results) > 1:
				// Aggregate return.
				cur := "undef"
				last := ""
				for _, slot := range sig.Frame.Results {
					i := slot.Index
					v := ssaVal{typ: slot.Type, val: "0"}
					if haveResult[i] {
						v = results[i]
					} else {
						z, err := zero(slot.Type)
						if err != nil {
							return err
						}
						v = z
					}
					if v.typ != slot.Type {
						var err error
						v, err = emitCast(v, slot.Type)
						if err != nil {
							return err
						}
					}
					if !isSSA(v.val) {
						// insertvalue accepts constants, but normalize to SSA for consistency.
						name := newTmp()
						fmt.Fprintf(b, "  %%%s = add %s %s, 0\n", name, v.typ, v.val)
						v.val = "%" + name
					}
					name := newTmp()
					fmt.Fprintf(b, "  %%%s = insertvalue %s %s, %s %s, %d\n", name, sig.Ret, cur, slot.Type, v.val, i)
					cur = "%" + name
					last = cur
				}
				fmt.Fprintf(b, "  ret %s %s\n", sig.Ret, last)
			default:
				// Scalar return.
				var v ssaVal
				if len(sig.Frame.Results) == 1 && haveResult[0] {
					v = results[0]
				} else if rv, ok := reg[archReturnReg(arch)]; ok {
					v = rv
				} else {
					z, err := zero(sig.Ret)
					if err != nil {
						return err
					}
					v = z
				}
				if v.typ != sig.Ret {
					var err error
					v, err = emitCast(v, sig.Ret)
					if err != nil {
						return err
					}
				}
				fmt.Fprintf(b, "  ret %s %s\n", sig.Ret, v.val)
			}
			terminated = true

		case OpBYTE:
			// Ignore raw machine bytes for now (prototype).
			continue
		default:
			// Keep linear lowering permissive for legacy/x86 stubs.
			continue
		}
		if terminated {
			break
		}
	}
	if !terminated {
		if sig.Ret == Void {
			b.WriteString("  ret void\n")
		} else {
			fmt.Fprintf(b, "  ret %s %s\n", sig.Ret, llvmZeroValue(sig.Ret))
		}
	}

	b.WriteString("}\n")
	return nil
}

func archReturnReg(arch Arch) Reg {
	if arch == ArchARM || arch == ArchARM64 {
		return Reg("R0")
	}
	return AX
}

var llvmIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func llvmGlobal(name string) string {
	// LLVM requires quoting if name contains special characters (like / or .).
	if llvmIdentRe.MatchString(name) {
		return "@" + name
	}
	return "@\"" + strings.ReplaceAll(name, "\"", "\\\"") + "\""
}
