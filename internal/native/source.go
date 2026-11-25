package native

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// Data describes a Go global whose storage is supplied by native assembly.
type Data struct {
	Name string
	Size uint32
}

// ForeignNativeFunctions identifies files containing only file-local TEXT symbols.
func ForeignNativeFunctions(src []byte, goarch string) map[string]bool {
	f, err := asm.Parse(asm.Arch(goarch), string(src))
	if err != nil || len(f.Funcs) == 0 {
		return nil
	}
	result := make(map[string]bool)
	for _, fn := range f.Funcs {
		if !strings.HasSuffix(fn.Sym, "<>") {
			return nil
		}
		result[strings.TrimSuffix(fn.Sym, "<>")] = true
	}
	return result
}

// Options selects a bounded physical-register backend. It does not describe
// Go ABI entries: callers must already obey the target native calling convention.
type Options struct {
	GOOS, GOARCH string
	PackagePath  string
	// Bare imports name external machine entries. A ·name key binds an
	// external package-global address for memory operands, never CALL/JMP.
	Imports map[string]string
	// CodeEntries binds source-native, bare TEXT address tokens to distinct
	// object symbols. It is not a Go/C signature.
	CodeEntries map[string]string
}

// SupportsNativeTarget reports implemented instruction/object-format pairs.
func SupportsNativeTarget(goos, goarch string) bool {
	return (goos == "darwin" || goos == "linux") && (goarch == "arm64" || goarch == "amd64")
}

// TranslateNativeSource translates checked Plan 9 source directly to native
// assembly, without Go object files or signature inference.
func TranslateNativeSource(src []byte, opts Options) (string, []Data, error) {
	f, ep, data, err := prepareNativeSource(src, opts)
	if err != nil {
		return "", nil, err
	}
	e := *ep
	var out strings.Builder
	for i, fn := range f.Funcs {
		if err := e.functionLabels(fn, i); err != nil {
			return "", nil, err
		}
		out.WriteString(".text\n.p2align 2\n")
		if _, bound := opts.CodeEntries[fn.Sym]; bound {
			fmt.Fprintf(&out, ".globl %s\n", e.funcs[fn.Sym])
		}
		fmt.Fprintf(&out, "%s:\n", e.funcs[fn.Sym])
		if opts.GOOS == "linux" {
			fmt.Fprintf(&out, ".type %s, @function\n", e.funcs[fn.Sym])
		}
		if err := e.functionBody(&out, fn); err != nil {
			return "", nil, err
		}
		if opts.GOOS == "linux" {
			fmt.Fprintf(&out, ".size %s, .-%s\n", e.funcs[fn.Sym], e.funcs[fn.Sym])
		}
	}
	for _, g := range f.Globl {
		flags, _ := nativeFlags(g.Flags, "RODATA", "NOPTR")
		if flags["RODATA"] {
			if opts.GOOS == "darwin" {
				out.WriteString(".section __DATA_CONST,__const\n")
			} else {
				out.WriteString(".section .data.rel.ro,\"aw\",@progbits\n")
			}
		} else {
			out.WriteString(".data\n")
		}
		label := strconv.Quote(e.globals[g.Sym])
		fmt.Fprintf(&out, ".p2align 3\n.globl %s\n%s:\n", label, label)
		values, _ := e.dataValues(f, g)
		pos := int64(0)
		for _, d := range values {
			if d.Off > pos {
				fmt.Fprintf(&out, ".zero %d\n", d.Off-pos)
			}
			if d.Addr != "" {
				target, err := e.symbol(d.Addr, true)
				if err != nil {
					return "", nil, err
				}
				fmt.Fprintf(&out, ".quad %s\n", target)
			} else {
				directive := map[int64]string{1: ".byte", 2: ".short", 4: ".long", 8: ".quad"}[d.Width]
				mask := ^uint64(0)
				if d.Width < 8 {
					mask = (uint64(1) << (8 * d.Width)) - 1
				}
				fmt.Fprintf(&out, "%s %#x\n", directive, d.Value&mask)
			}
			pos = d.Off + d.Width
		}
		if pos < g.Size {
			fmt.Fprintf(&out, ".zero %d\n", g.Size-pos)
		}
	}
	if opts.GOOS == "linux" {
		out.WriteString(".section .note.GNU-stack,\"\",@progbits\n")
	}
	return out.String(), data, nil
}

type nativeFramePlan struct {
	local  int64
	saveBP bool
}

func (p nativeFramePlan) prologue(out *strings.Builder) {
	if p.saveBP {
		out.WriteString("\tpushq %rbp\n\tmovq %rsp, %rbp\n")
	}
	if p.local != 0 {
		fmt.Fprintf(out, "\tsubq $%d, %%rsp\n", p.local)
	}
}

func (p nativeFramePlan) epilogue(out *strings.Builder) {
	if p.local != 0 {
		fmt.Fprintf(out, "\taddq $%d, %%rsp\n", p.local)
	}
	if p.saveBP {
		out.WriteString("\tpopq %rbp\n")
	}
}

func nativeTextFrame(fn asm.Func, target Options) (nativeFramePlan, error) {
	var plan nativeFramePlan
	parts := strings.Split(fn.Instrs[0].Raw, ",")
	if len(parts) != 3 || !strings.HasPrefix(strings.TrimSpace(parts[2]), "$") {
		return plan, fmt.Errorf("native TEXT requires a complete fixed frame: %s", fn.Sym)
	}
	frameSpec := strings.TrimPrefix(strings.TrimSpace(parts[2]), "$")
	framePart, argPart, hasArgs := strings.Cut(frameSpec, "-")
	frameSize, ok := asm.ParseImmExpr(strings.TrimSpace(framePart))
	if !ok {
		return plan, fmt.Errorf("native TEXT requires constant frame size: %s", fn.Sym)
	}
	var argSize uint64
	if hasArgs {
		argSize, ok = asm.ParseImmExpr(strings.TrimSpace(argPart))
		if !ok {
			return plan, fmt.Errorf("native TEXT requires constant argument size: %s", fn.Sym)
		}
	}
	if target.GOARCH == "arm64" && (argSize != 0 || frameSize != 0) {
		return plan, fmt.Errorf("native ARM64 TEXT requires zero Go frame: %s", fn.Sym)
	}
	if argSize != 0 || frameSize > 2147483639 || frameSize%8 != 0 {
		return plan, fmt.Errorf("native TEXT requires aligned fixed locals and zero Go arguments: %s", fn.Sym)
	}
	flags, err := nativeFlags(parts[1], "NOSPLIT", "NOFRAME")
	if err != nil || !flags["NOSPLIT"] {
		return plan, fmt.Errorf("native TEXT requires exact NOSPLIT/frame flags: %s", fn.Sym)
	}
	if target.GOARCH != "amd64" {
		for _, ins := range fn.Instrs {
			if (ins.Op == "CALL" || ins.Op == "BL") && !flags["NOFRAME"] {
				return plan, fmt.Errorf("native ARM64 non-leaf TEXT requires NOFRAME: %s", fn.Sym)
			}
		}
		return plan, nil
	}
	plan.local = int64(frameSize)
	hasCall := false
	var stackDelta int64
	for _, ins := range fn.Instrs {
		op := string(ins.Op)
		if op == "CALL" {
			hasCall = true
		}
		switch op {
		case "PUSHQ", "PUSHFQ":
			stackDelta += 8
		case "POPQ", "POPFQ":
			stackDelta -= 8
		case "ADJSP":
			if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpImm || ins.Args[0].ImmRaw != "" {
				return plan, fmt.Errorf("native ADJSP requires constant immediate: %s", ins.Raw)
			}
			stackDelta += ins.Args[0].Imm
		case "RET":
			if stackDelta != 0 {
				return plan, fmt.Errorf("native TEXT has unbalanced PUSH/POP: %s", fn.Sym)
			}
		}
	}
	plan.saveBP = !flags["NOFRAME"] && (plan.local != 0 || hasCall)
	return plan, nil
}

func validateNativeCodeBindings(f *asm.File, opts Options) error {
	seen := make(map[string]bool, len(opts.CodeEntries))
	for source, object := range opts.CodeEntries {
		if !nativeName.MatchString(source) || !nativeCodeObjectName.MatchString(object) || strings.HasPrefix(object, "__plan9_native_") {
			return fmt.Errorf("unsupported native code entry binding %q -> %q", source, object)
		}
		if seen[object] {
			return fmt.Errorf("duplicate native code entry object %q", object)
		}
		seen[object] = true
		if _, imported := opts.Imports[source]; imported {
			return fmt.Errorf("native code entry collides with import identity %q", source)
		}
		for _, alias := range opts.Imports {
			if object == alias {
				return fmt.Errorf("native code entry collides with native import %q", object)
			}
		}
		found := false
		for _, fn := range f.Funcs {
			found = found || fn.Sym == source
		}
		if !found {
			return fmt.Errorf("native code entry has no source TEXT %q", source)
		}
		for _, g := range f.Globl {
			if object == opts.PackagePath+"."+strings.TrimPrefix(g.Sym, "·") {
				return fmt.Errorf("native code entry collides with DATA %q", object)
			}
		}
	}
	return nil
}

func prepareNativeSource(src []byte, opts Options) (*asm.File, *nativeEmitter, []Data, error) {
	if !SupportsNativeTarget(opts.GOOS, opts.GOARCH) {
		return nil, nil, nil, fmt.Errorf("unsupported native target %s/%s", opts.GOOS, opts.GOARCH)
	}
	imports, pkgPath := opts.Imports, opts.PackagePath

	clean, err := nativeSource(src, opts.GOARCH)
	if err != nil {
		return nil, nil, nil, err
	}
	f, err := asm.Parse(asm.Arch(opts.GOARCH), clean)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(f.Funcs) == 0 && len(f.Globl) == 0 {
		return nil, nil, nil, fmt.Errorf("native assembly requires TEXT or GLOBL")
	}
	if err := validateNativeCodeBindings(f, opts); err != nil {
		return nil, nil, nil, err
	}
	e := nativeEmitter{target: opts, funcs: map[string]string{}, globals: map[string]string{}, imports: imports}
	for name, alias := range imports {
		function := nativeName.MatchString(name) && nativeName.MatchString(alias)
		data := strings.HasPrefix(name, "·") && nativeName.MatchString(strings.TrimPrefix(name, "·")) && nativeDataObjectName.MatchString(alias)
		if !function && !data {
			return nil, nil, nil, fmt.Errorf("unsupported native import %q -> %q", name, alias)
		}
	}
	for i, fn := range f.Funcs {
		name := strings.TrimSuffix(fn.Sym, "<>")
		object, bound := opts.CodeEntries[fn.Sym]
		if !bound && (name == fn.Sym || !nativeName.MatchString(name)) {
			return nil, nil, nil, fmt.Errorf("native TEXT must be file-local: %s", fn.Sym)
		}
		if bound && (!nativeName.MatchString(fn.Sym) || len(fn.Instrs) < 2) {
			return nil, nil, nil, fmt.Errorf("native code entry requires complete bare TEXT: %s", fn.Sym)
		}
		if _, ok := e.funcs[fn.Sym]; ok {
			return nil, nil, nil, fmt.Errorf("duplicate native TEXT %s", fn.Sym)
		}
		e.funcs[fn.Sym] = fmt.Sprintf("Lnative_func_%d", i)
		if bound {
			e.funcs[fn.Sym] = strconv.Quote(e.prefix() + object)
		}
		if _, err := nativeTextFrame(fn, opts); err != nil {
			return nil, nil, nil, err
		}
	}
	var data []Data
	for _, g := range f.Globl {
		name := strings.TrimPrefix(g.Sym, "·")
		if name == g.Sym || !nativeName.MatchString(name) {
			return nil, nil, nil, fmt.Errorf("native GLOBL must name a package global: %s", g.Sym)
		}
		if _, ok := e.globals[g.Sym]; ok {
			return nil, nil, nil, fmt.Errorf("duplicate native GLOBL %s", g.Sym)
		}
		if g.Size <= 0 || g.Size > 64<<20 {
			return nil, nil, nil, fmt.Errorf("unsupported native GLOBL size %d", g.Size)
		}
		if _, err := nativeFlags(g.Flags, "RODATA", "NOPTR"); err != nil {
			return nil, nil, nil, err
		}
		e.globals[g.Sym] = e.prefix() + pkgPath + "." + name
		data = append(data, Data{Name: pkgPath + "." + name, Size: uint32(g.Size)})
	}
	for _, d := range f.Data {
		if _, ok := e.globals[d.Sym]; !ok {
			return nil, nil, nil, fmt.Errorf("native DATA has no GLOBL: %s", d.Sym)
		}
	}
	for _, g := range f.Globl {
		if _, err := e.dataValues(f, g); err != nil {
			return nil, nil, nil, err
		}
	}
	return f, &e, data, nil
}

var nativeName = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]*$`)
var nativeCodeObjectName = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9.]*$`)
var nativeDataObjectName = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9./-]*$`)
var nativePseudoRegister = regexp.MustCompile(`\b(?:SP|FP|g|G|R18_PLATFORM|R18|R31|W[0-9]+)\b`)
var nativeAMD64PseudoRegister = regexp.MustCompile(`\b(?:FP|g|G)\b`)
var flagTokenRe = regexp.MustCompile(`\b[A-Z][A-Z0-9_]*\b`)

var goTextFlagValues = map[string]string{
	"NOPROF":        "1",
	"DUPOK":         "2",
	"NOSPLIT":       "4",
	"RODATA":        "8",
	"NOPTR":         "16",
	"WRAPPER":       "32",
	"NEEDCTXT":      "64",
	"LOCAL":         "128",
	"REFLECTMETHOD": "256",
	"NOFRAME":       "512",
	"TOPFRAME":      "2048",
	"ABIWRAPPER":    "4096",
}

func nativeSource(src []byte, goarch string) (string, error) {
	var b strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		line, _, _ = strings.Cut(line, "//")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if line != `#include "textflag.h"` {
				return "", fmt.Errorf("unsupported native preprocessor directive: %s", line)
			}
			continue
		}
		if strings.Contains(line, "/*") || strings.ContainsAny(line, "\"\\") {
			return "", fmt.Errorf("unsupported native source syntax: %s", line)
		}
		if (goarch == "arm64" && nativePseudoRegister.MatchString(line)) || (goarch == "amd64" && nativeAMD64PseudoRegister.MatchString(line)) {
			return "", fmt.Errorf("unsupported native register or Go stack operand: %s", line)
		}
		for _, stmt := range asm.SplitSemicolons(line) {
			if strings.Contains(stmt, ":") && (!strings.HasSuffix(stmt, ":") || !nativeName.MatchString(strings.TrimSuffix(stmt, ":"))) {
				return "", fmt.Errorf("unsupported native label or segment syntax: %s", stmt)
			}
			op, rest := asm.SplitOpcode(stmt)
			if op != "TEXT" && op != "GLOBL" && op != "DATA" && !(goarch == "amd64" && op == "ADJSP") {
				for _, raw := range asm.SplitTopLevelCSV(rest) {
					raw = strings.TrimSpace(raw)
					if !strings.HasPrefix(raw, "$") && strings.HasSuffix(raw, ")") && !strings.HasSuffix(raw, "(SB)") {
						i := strings.LastIndex(raw, "(")
						if goarch == "amd64" && i >= 0 && strings.HasSuffix(raw[:i], ")") {
							base := strings.LastIndex(raw[:i], "(")
							if base >= 0 {
								if _, register := asm.ParseReg(strings.TrimSpace(raw[base+1 : i-1])); register {
									i = base
								}
							}
						}
						if i >= 0 {
							offset := strings.TrimSpace(raw[:i])
							if offset != "" {
								if _, ok := asm.ParseImmExpr(offset); !ok {
									return "", fmt.Errorf("native memory requires a constant offset: %s", raw)
								}
							}
						}
					}
				}
			}
			if op == "GLOBL" {
				parts := strings.Split(rest, ",")
				if len(parts) != 3 {
					return "", fmt.Errorf("invalid native GLOBL")
				}
				if _, ok := nativeInteger(strings.TrimSpace(parts[2])); !ok {
					return "", fmt.Errorf("native GLOBL requires a constant integer size")
				}
			}
			if op == "DATA" {
				_, rhs, ok := strings.Cut(rest, ",")
				rhs = strings.TrimSpace(rhs)
				if !ok {
					return "", fmt.Errorf("invalid native DATA")
				}
				if _, ok := nativeInteger(rhs); !ok && !(strings.HasPrefix(rhs, "$") && strings.HasSuffix(rhs, "(SB)")) {
					return "", fmt.Errorf("unsupported native DATA initializer: %s", rhs)
				}
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func nativeInteger(s string) (uint64, bool) {
	if !strings.HasPrefix(s, "$") {
		return 0, false
	}
	return asm.ParseImmExpr(strings.TrimPrefix(s, "$"))
}

func nativeFlags(s string, allowed ...string) (map[string]bool, error) {
	if len(s) > 4096 {
		return nil, fmt.Errorf("native flags exceed expression bound")
	}
	bits := make(map[string]uint64, len(allowed))
	var mask uint64
	for _, name := range allowed {
		bit, ok := asm.ParseImmExpr(goTextFlagValues[name])
		if !ok {
			return nil, fmt.Errorf("unregistered native flag %q", name)
		}
		bits[name], mask = bit, mask|bit
	}
	expr := flagTokenRe.ReplaceAllStringFunc(s, func(name string) string {
		if value, ok := goTextFlagValues[name]; ok {
			return value
		}
		return name
	})
	value, ok := asm.ParseImmExpr(expr)
	if !ok || value&^mask != 0 {
		return nil, fmt.Errorf("unsupported native flags %q", s)
	}
	flags := make(map[string]bool, len(allowed))
	for name, bit := range bits {
		if value&bit != 0 {
			flags[name] = true
		}
	}
	return flags, nil
}

type nativeEmitter struct {
	symbolOperand                   func(string, bool) (string, error)
	target                          Options
	funcs, globals, imports, labels map[string]string
}

func (e *nativeEmitter) prefix() string {
	if e.target.GOOS == "darwin" {
		return "_"
	}
	return ""
}

func (e *nativeEmitter) symbol(s string, data bool) (string, error) {
	if e.symbolOperand != nil {
		return e.symbolOperand(s, data)
	}
	if !strings.HasSuffix(s, "(SB)") {
		return "", fmt.Errorf("unsupported native symbol %s", s)
	}
	name := strings.TrimSuffix(s, "(SB)")
	if label, ok := e.funcs[name]; ok {
		return label, nil
	}
	if data {
		if label, ok := e.globals[name]; ok {
			return strconv.Quote(label), nil
		}
	}
	if alias, ok := e.imports[name]; ok {
		if strings.HasPrefix(name, "·") && !data {
			return "", fmt.Errorf("native data binding is not a callable entry: %s", s)
		}
		return strconv.Quote(e.prefix() + alias), nil
	}
	return "", fmt.Errorf("undeclared foreign symbol or unsupported native reference %s", s)
}

func (e *nativeEmitter) branch(o asm.Operand, external bool) (string, error) {
	if external && o.Kind == asm.OpSym {
		return e.symbol(o.Sym, false)
	}
	name := o.Ident
	if o.Kind == asm.OpLabel {
		name = o.Sym
	}
	if label, ok := e.labels[name]; ok {
		return label, nil
	}
	return "", fmt.Errorf("undefined native branch label %s", o.String())
}

func (e *nativeEmitter) functionLabels(fn asm.Func, i int) error {
	e.labels = map[string]string{}
	for _, ins := range fn.Instrs {
		if ins.Op == asm.OpLABEL {
			name := ins.Args[0].Sym
			if !nativeName.MatchString(name) {
				return fmt.Errorf("unsupported native label %s", name)
			}
			if _, ok := e.labels[name]; ok {
				return fmt.Errorf("duplicate native label %s", name)
			}
			e.labels[name] = fmt.Sprintf("Lnative_%d_label_%d", i, len(e.labels))
		}
	}
	return nil
}

func nativeFunctionEnd(op asm.Op, arch string) (trap string, valid bool) {
	switch op {
	case asm.OpRET, "JMP", "B":
		return "", true
	case "CALL", "BL":
		if arch == "amd64" {
			return "\tud2\n", true
		}
		if arch == "arm64" {
			return "\tbrk #0\n", true
		}
	}
	return "", false
}

func (e *nativeEmitter) functionBody(out *strings.Builder, fn asm.Func) error {
	plan, err := nativeTextFrame(fn, e.target)
	if err != nil {
		return err
	}
	for _, ins := range fn.Instrs {
		var ierr error
		if e.target.GOARCH == "arm64" {
			ierr = (&nativeARM64{e}).instruction(out, ins)
		} else {
			ierr = (&nativeAMD64{nativeEmitter: e, frame: plan}).instruction(out, ins)
		}
		if ierr != nil {
			return fmt.Errorf("native %s: %s: %w", fn.Sym, ins.Raw, ierr)
		}
	}
	trap, _ := nativeFunctionEnd(fn.Instrs[len(fn.Instrs)-1].Op, e.target.GOARCH)
	out.WriteString(trap)
	return nil
}

func (e *nativeEmitter) dataValues(f *asm.File, g asm.GloblStmt) ([]asm.DataStmt, error) {
	var values []asm.DataStmt
	for _, d := range f.Data {
		if d.Sym == g.Sym {
			values = append(values, d)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Off < values[j].Off })
	pos := int64(0)
	for _, d := range values {
		if d.Off < pos || d.Width <= 0 || d.Off > g.Size || d.Width > g.Size-d.Off {
			return nil, fmt.Errorf("overlapping or out-of-bounds native DATA for %s", g.Sym)
		}
		if d.Addr != "" {
			if d.Width != 8 {
				return nil, fmt.Errorf("native address DATA requires width 8")
			}
			if _, err := e.symbol(d.Addr, true); err != nil {
				return nil, err
			}
		} else {
			if d.Payload != nil {
				return nil, fmt.Errorf("native string DATA is unsupported")
			}
			if d.Width != 1 && d.Width != 2 && d.Width != 4 && d.Width != 8 {
				return nil, fmt.Errorf("unsupported native DATA width %d", d.Width)
			}
		}
		pos = d.Off + d.Width
	}
	return values, nil
}
