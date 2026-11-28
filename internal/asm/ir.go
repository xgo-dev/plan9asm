package asm

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var llvmIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// LLVMGlobal formats a linker symbol name as an LLVM global identifier.
func LLVMGlobal(name string) string {
	if llvmIdentRe.MatchString(name) {
		return "@" + name
	}
	return "@\"" + strings.ReplaceAll(name, "\"", "\\\"") + "\""
}

// LLVMBlockName sanitizes a Plan 9 label into a valid LLVM basic-block label.
func LLVMBlockName(src string) string {
	if src == "" {
		return "bb"
	}
	var out []byte
	for i := 0; i < len(src); i++ {
		ch := src[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			out = append(out, ch)
			continue
		}
		out = append(out, '_')
	}
	s := string(out)
	if s == "" {
		return "bb"
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "bb_" + s
	}
	if s == "entry" {
		s = "bb_entry"
	}
	return s
}

// FuncSigSymbol returns the effective symbol name for sig.
func FuncSigSymbol(resolved string, sig FuncSig) string {
	if sig.Name != "" {
		return sig.Name
	}
	return resolved
}

// EmitIRSourceComment appends Plan 9 source assembly lines as LLVM IR comments.
func EmitIRSourceComment(b *strings.Builder, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\t", " "))
		if line == "" {
			continue
		}
		fmt.Fprintf(b, "  ; s: %s\n", line)
	}
}

// FormatLLVMFloat64Literal renders v as an LLVM double literal.
func FormatLLVMFloat64Literal(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Sprintf("0x%016X", math.Float64bits(v))
	}
	s := strconv.FormatFloat(v, 'e', -1, 64)
	if i := strings.IndexByte(s, 'e'); i >= 0 {
		if !strings.Contains(s[:i], ".") {
			return s[:i] + ".0" + s[i:]
		}
		return s
	}
	if !strings.Contains(s, ".") {
		return s + ".0"
	}
	return s
}

// ParseLiteralStructFields splits an anonymous LLVM struct type "{ T1, T2 }" into its field types.
func ParseLiteralStructFields(ty LLVMType) (fields []LLVMType, ok bool) {
	s := strings.TrimSpace(string(ty))
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil, false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}"))
	if inner == "" {
		return nil, false
	}
	parts := strings.Split(inner, ",")
	fields = make([]LLVMType, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, false
		}
		fields = append(fields, LLVMType(p))
	}
	return fields, true
}

// LiteralFieldsAllScalar reports whether every field in fields is an LLVM scalar int or ptr.
func LiteralFieldsAllScalar(fields []LLVMType) bool {
	for _, ty := range fields {
		switch ty {
		case Ptr, I1, I8, I16, I32, I64:
		default:
			return false
		}
	}
	return true
}

// LLVMZeroValue returns the canonical LLVM zero constant literal for ty.
func LLVMZeroValue(ty LLVMType) string {
	switch string(ty) {
	case "ptr":
		return "null"
	case "i1":
		return "false"
	case "i8", "i16", "i32", "i64":
		return "0"
	case "float", "double":
		return "0.000000e+00"
	default:
		return "zeroinitializer"
	}
}

// ParseSBRef parses a Plan 9 static-base symbol reference like "r2r1<>+0(SB)" or "runtime·memequal(SB)".
func ParseSBRef(sym string) (base string, off int64, ok bool) {
	sym = strings.TrimSpace(sym)
	if strings.HasSuffix(sym, "(SB)") {
		s := strings.TrimSpace(strings.TrimSuffix(sym, "(SB)"))
		if s == "" {
			return "", 0, false
		}
		base, off = SplitSymPlusOff(s)
		return base, off, true
	}
	if strings.IndexAny(sym, " \t,") >= 0 {
		return "", 0, false
	}
	if _, ok := ParseMem(sym); ok {
		return "", 0, false
	}
	base, off = SplitSymPlusOff(sym)
	if strings.TrimSpace(base) == "" {
		return "", 0, false
	}
	return base, off, true
}

// EmitTLSOffset computes a Go local-exec relocation from actual TLS storage.
func EmitTLSOffset(b *strings.Builder, tmp func() string, symbol string, bits int) string {
	addr, tp := tmp(), tmp()
	a, t, offset := tmp(), tmp(), tmp()
	fmt.Fprintf(b, "  %%%s = call ptr @llvm.threadlocal.address.p0(ptr %s)\n", addr, LLVMGlobal(symbol))
	fmt.Fprintf(b, "  %%%s = call ptr @llvm.thread.pointer()\n", tp)
	fmt.Fprintf(b, "  %%%s = ptrtoint ptr %%%s to i%d\n", a, addr, bits)
	fmt.Fprintf(b, "  %%%s = ptrtoint ptr %%%s to i%d\n", t, tp, bits)
	fmt.Fprintf(b, "  %%%s = sub i%d %%%s, %%%s\n", offset, bits, a, t)
	return "%" + offset
}
