package asm

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/preprocess"
)

// ErrEmptyFile means the preprocessed source contains no TEXT, DATA or GLOBL.
var ErrEmptyFile = errors.New("no TEXT directive found")

// File is a parsed Plan 9 asm source file (subset).
type File struct {
	// SourceGoVersion selects version-dependent assembler ABI conventions.
	// An empty value uses the toolchain that built the translator.
	SourceGoVersion string
	Arch            Arch
	Funcs           []Func
	// UnlinkedPrelude records instructions before the first TEXT.
	UnlinkedPrelude []string

	// Data and Globl capture a minimal subset of the Plan 9 DATA/GLOBL directives
	// used by some stdlib asm (e.g. hash/crc32/crc32_amd64.s).
	//
	// These are emitted as LLVM globals by the translator so loads like:
	//   MOVOA r2r1<>+0(SB), X0
	// can be translated without relying on an overlay/alt package.
	Data  []DataStmt
	Globl []GloblStmt
}

type Func struct {
	// Sym is the symbol name from the TEXT directive with (SB) trimmed.
	// It may contain the Plan 9 middle dot (·).
	Sym string

	// FrameSize and ArgSize retain the numeric $frame-args values from TEXT.
	// WebAssembly's Go ABI uses FrameSize to address FP operands through the
	// linear-memory stack and to restore SP on return. A missing -args suffix
	// leaves ArgSize at zero.
	FrameSize int64
	ArgSize   int64

	Instrs []Instr
}

// Parse parses a subset of Go/Plan 9 assembly syntax.
//
// Currently supported:
//   - TEXT directives (function start)
//   - MOVQ/ADDQ/SUBQ/XORQ/MOVL, CPUID, XGETBV, BYTE, RET
//   - Operands: immediate ($imm), register (AX/BX/CX/DX), and name+off(FP)
//
// Also supported at a minimal level:
//   - #include is ignored
//   - #define NAME <body> with optional single-line continuation via '\' and
//     macro invocation when the entire statement is just NAME.
func Parse(arch Arch, src string) (*File, error) {
	pp, err := preprocess.Preprocess(src)
	if err != nil {
		return nil, err
	}
	return ParsePreprocessed(arch, pp)
}

// ParsePreprocessed parses assembly source that has already been preprocessed
// by PreprocessAssembly, without running the legacy macro expander a second time.
func ParsePreprocessed(arch Arch, pp string) (*File, error) {
	f := &File{Arch: arch}

	sc := bufio.NewScanner(strings.NewReader(pp))
	lineno := 0
	var cur *Func
	for sc.Scan() {
		lineno++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		for _, stmt := range SplitSemicolons(line) {
			if stmt == "" {
				continue
			}
			if strings.HasSuffix(stmt, ":") {
				if cur == nil {
					return nil, fmt.Errorf("line %d: label outside TEXT: %q", lineno, stmt)
				}
				lbl := strings.TrimSpace(strings.TrimSuffix(stmt, ":"))
				if lbl == "" {
					return nil, fmt.Errorf("line %d: empty label: %q", lineno, stmt)
				}
				cur.Instrs = append(cur.Instrs, Instr{
					Op:   OpLABEL,
					Args: []Operand{{Kind: OpLabel, Sym: lbl}},
					Raw:  stmt,
				})
				continue
			}
			// Support one or more "label: label2: INSTR ..." prefixes on one statement
			// (C-preprocessed macros can emit stacked labels without whitespace, e.g. "loop1done:loop4:TESTQ BX,BX").
			for {
				c := strings.IndexByte(stmt, ':')
				if c < 0 {
					break
				}
				left := strings.TrimSpace(stmt[:c])
				right := strings.TrimSpace(stmt[c+1:])
				if left == "" || strings.ContainsAny(left, " \t,\"'$()+-*/") {
					break
				}
				if cur == nil {
					return nil, fmt.Errorf("line %d: label outside TEXT: %q", lineno, stmt)
				}
				cur.Instrs = append(cur.Instrs, Instr{
					Op:   OpLABEL,
					Args: []Operand{{Kind: OpLabel, Sym: left}},
					Raw:  left + ":",
				})
				stmt = right
				if stmt == "" {
					break
				}
			}
			if stmt == "" {
				continue
			}

			opStr, rest := SplitOpcode(stmt)
			op := Op(strings.ToUpper(opStr))
			if arch == ArchWASM {
				// Go's wasm assembler distinguishes low-level WebAssembly Call
				// and Return from the high-level Go ABI CALL and RET pseudos by
				// spelling. Preserve that distinction after normalization.
				switch opStr {
				case "Call":
					op = "WASMCALL"
				case "Return":
					op = "WASMRETURN"
				}
			}
			switch op {
			case OpTEXT:
				// TEXT name(SB), flags, $frame-args
				parts := strings.Split(rest, ",")
				if len(parts) < 1 {
					return nil, fmt.Errorf("line %d: invalid TEXT: %q", lineno, stmt)
				}
				sym := strings.TrimSpace(parts[0])
				if !strings.HasSuffix(sym, "(SB)") {
					return nil, fmt.Errorf("line %d: TEXT symbol must end with (SB): %q", lineno, sym)
				}
				sym = strings.TrimSpace(strings.TrimSuffix(sym, "(SB)"))
				if sym == "" {
					return nil, fmt.Errorf("line %d: empty TEXT symbol: %q", lineno, stmt)
				}
				frameSize, argSize, err := parseTEXTFrame(parts)
				if err != nil {
					return nil, fmt.Errorf("line %d: %v", lineno, err)
				}
				f.Funcs = append(f.Funcs, Func{Sym: sym, FrameSize: frameSize, ArgSize: argSize})
				cur = &f.Funcs[len(f.Funcs)-1]
				cur.Instrs = append(cur.Instrs, Instr{Op: OpTEXT, Raw: stmt})
				continue

			case "DATA":
				// Be permissive: some stdlib asm emits DATA while parser still
				// tracks the previous TEXT as current.
				ds, err := ParseDATAStmt(arch, rest)
				if err != nil {
					return nil, fmt.Errorf("line %d: %v", lineno, err)
				}
				f.Data = append(f.Data, ds)
				continue

			case "GLOBL":
				// Be permissive: some stdlib asm emits data symbols while parser
				// still tracks the previous TEXT as current.
				gs, err := parseGLOBLStmt(rest)
				if err != nil {
					return nil, fmt.Errorf("line %d: %v", lineno, err)
				}
				f.Globl = append(f.Globl, gs)
				continue

			case OpCPUID, OpXGETBV:
				if cur == nil {
					return nil, fmt.Errorf("line %d: %s outside TEXT: %q", lineno, op, stmt)
				}
				if strings.TrimSpace(rest) != "" {
					return nil, fmt.Errorf("line %d: %s takes no operands: %q", lineno, op, stmt)
				}
				cur.Instrs = append(cur.Instrs, Instr{Op: op, Raw: stmt})
				continue

			case OpBYTE, OpWORD:
				if cur == nil {
					return nil, fmt.Errorf("line %d: %s outside TEXT: %q", lineno, op, stmt)
				}
				args, err := parseOperandsCSV(arch, op, rest)
				if err != nil {
					return nil, fmt.Errorf("line %d: %v", lineno, err)
				}
				if len(args) != 1 || args[0].Kind != OpImm {
					return nil, fmt.Errorf("line %d: %s expects single immediate operand: %q", lineno, op, stmt)
				}
				cur.Instrs = append(cur.Instrs, Instr{Op: op, Args: args, Raw: stmt})
				continue

			case OpRET:
				if cur == nil {
					return nil, fmt.Errorf("line %d: RET outside TEXT: %q", lineno, stmt)
				}
				if strings.TrimSpace(rest) != "" {
					// A symbol operand is a tail call; register operands retain the
					// architecture-specific return behavior.
					args, err := parseOperandsCSV(arch, op, rest)
					if err != nil {
						return nil, fmt.Errorf("line %d: %v", lineno, err)
					}
					cur.Instrs = append(cur.Instrs, Instr{Op: op, Args: args, Raw: stmt})
					continue
				}
				cur.Instrs = append(cur.Instrs, Instr{Op: OpRET, Raw: stmt})
				continue

			default:
				if cur == nil {
					return nil, fmt.Errorf("line %d: instruction outside TEXT: %q", lineno, stmt)
				}
				// For now, parse unknown opcodes as generic instructions. The translator
				// is responsible for rejecting unsupported ones.
				args, err := parseOperandsCSV(arch, op, rest)
				if err != nil {
					return nil, fmt.Errorf("line %d: %v", lineno, err)
				}
				// funcdata.h expands NO_LOCAL_POINTERS to this exact directive.
				// Other stack map symbols still require runtime metadata support.
				if arch == ArchWASM && op == "FUNCDATA" && len(args) == 2 &&
					args[0].Kind == OpImm && args[0].ImmRaw == "" && args[0].Imm == 1 &&
					args[1].Kind == OpSym && args[1].Sym == "no_pointers_stackmap(SB)" {
					op, args = "NO_LOCAL_POINTERS", nil
				}
				cur.Instrs = append(cur.Instrs, Instr{Op: op, Args: args, Raw: stmt})
				continue
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(f.Funcs) == 0 && len(f.Data) == 0 && len(f.Globl) == 0 {
		return nil, ErrEmptyFile
	}
	return f, nil
}

func parseTEXTFrame(parts []string) (frameSize, argSize int64, err error) {
	if len(parts) < 2 {
		return 0, 0, nil
	}
	spec := strings.TrimSpace(parts[len(parts)-1])
	if !strings.HasPrefix(spec, "$") {
		return 0, 0, nil
	}
	spec = strings.TrimSpace(strings.TrimPrefix(spec, "$"))
	frameText, argText := spec, ""
	if i := strings.LastIndex(spec, "-"); i > 0 {
		frameText, argText = strings.TrimSpace(spec[:i]), strings.TrimSpace(spec[i+1:])
	}
	frame, ok := ParseImmExpr(frameText)
	if !ok {
		return 0, 0, fmt.Errorf("unresolved TEXT frame size %q", frameText)
	}
	if argText == "" {
		return int64(frame), 0, nil
	}
	args, ok := ParseImmExpr(argText)
	if !ok {
		return 0, 0, fmt.Errorf("unresolved TEXT argument size %q", argText)
	}
	return int64(frame), int64(args), nil
}

func ParseDATAStmt(arch Arch, rest string) (DataStmt, error) {
	// DATA sym+off(SB)/width, $value
	lhs, rhs, ok := strings.Cut(rest, ",")
	if !ok {
		return DataStmt{}, fmt.Errorf("invalid DATA: %q", "DATA "+rest)
	}
	lhs = strings.TrimSpace(lhs)
	rhs = strings.TrimSpace(rhs)
	if lhs == "" || rhs == "" {
		return DataStmt{}, fmt.Errorf("invalid DATA: %q", "DATA "+rest)
	}

	// lhs: sym+off(SB)/width
	widthAt := strings.LastIndexByte(lhs, '/')
	if widthAt < 0 {
		return DataStmt{}, fmt.Errorf("DATA missing /width: %q", "DATA "+rest)
	}
	symPart, widthStr := lhs[:widthAt], lhs[widthAt+1:]
	width, err := parseWidth(arch, widthStr)
	if err != nil || width <= 0 {
		return DataStmt{}, fmt.Errorf("DATA invalid width %q: %q", widthStr, "DATA "+rest)
	}

	symPart = strings.TrimSpace(symPart)
	if !strings.HasSuffix(symPart, "(SB)") {
		return DataStmt{}, fmt.Errorf("DATA symbol must end with (SB): %q", "DATA "+rest)
	}
	symPart = strings.TrimSuffix(symPart, "(SB)")
	symPart = strings.TrimSpace(symPart)
	if symPart == "" {
		return DataStmt{}, fmt.Errorf("DATA empty symbol: %q", "DATA "+rest)
	}

	sym, off, err := ParseDataSymbol(symPart)
	if err != nil {
		return DataStmt{}, err
	}

	ds := DataStmt{Sym: sym, Off: off, Width: width, usePointerWidth: strings.EqualFold(strings.TrimSpace(widthStr), "PTRSIZE")}
	expr, immediate := strings.CutPrefix(rhs, "$")
	if !immediate {
		return DataStmt{}, fmt.Errorf("DATA requires an immediate value: %q", rhs)
	}
	switch {
	case strings.HasPrefix(expr, "\""):
		str, err := strconv.Unquote(expr)
		if err != nil || int64(len(str)) > width {
			return DataStmt{}, fmt.Errorf("invalid DATA string of width %d: %q", width, rhs)
		}
		ds.Payload = []byte(str)
	case strings.HasSuffix(expr, "(SB)"):
		ds.Addr = expr
	default:
		if value, ok := ParseImmExpr(expr); ok {
			switch width {
			case 1, 2, 4, 8:
				ds.Value = value
			default:
				return DataStmt{}, fmt.Errorf("invalid DATA width %d for integer", width)
			}
		} else if value, ok := ParseImmFloatExpr(expr); ok {
			ds.floatLiteral = true
			switch width {
			case 4:
				ds.Value = uint64(math.Float32bits(float32(value)))
			case 8:
				ds.Value = math.Float64bits(value)
			default:
				return DataStmt{}, fmt.Errorf("invalid DATA width %d for float", width)
			}
		} else {
			return DataStmt{}, fmt.Errorf("DATA invalid or unresolved immediate %q: %q", rhs, "DATA "+rest)
		}
	}
	return ds, nil
}

func parseWidth(arch Arch, s string) (int64, error) {
	s = strings.TrimSpace(s)
	switch strings.ToUpper(s) {
	case "PTRSIZE":
		switch arch {
		case ArchAMD64, ArchARM64, ArchWASM:
			return 8, nil
		default:
			return 4, nil
		}
	}
	return parseInt(s)
}

func parseGLOBLStmt(rest string) (GloblStmt, error) {
	// GLOBL sym(SB), flags, $size  OR  GLOBL sym(SB), $size
	parts := strings.Split(rest, ",")
	if len(parts) != 2 && len(parts) != 3 {
		return GloblStmt{}, fmt.Errorf("invalid GLOBL: %q", "GLOBL "+rest)
	}
	symPart := strings.TrimSpace(parts[0])
	flags := ""
	sizePart := strings.TrimSpace(parts[1])
	if len(parts) == 3 {
		flags = strings.TrimSpace(parts[1])
		sizePart = strings.TrimSpace(parts[2])
	}
	if !strings.HasSuffix(symPart, "(SB)") {
		return GloblStmt{}, fmt.Errorf("GLOBL symbol must end with (SB): %q", "GLOBL "+rest)
	}
	sym := strings.TrimSpace(strings.TrimSuffix(symPart, "(SB)"))
	if sym == "" {
		return GloblStmt{}, fmt.Errorf("GLOBL empty symbol: %q", "GLOBL "+rest)
	}
	sym, off, err := ParseDataSymbol(sym)
	if err != nil {
		return GloblStmt{}, err
	}
	if off != 0 {
		return GloblStmt{}, fmt.Errorf("GLOBL symbol must not be offset from SB: %q", symPart)
	}
	expr, immediate := strings.CutPrefix(sizePart, "$")
	if immediate {
		if n, ok := ParseImmExpr(expr); ok && int64(n) >= 0 {
			return GloblStmt{Sym: sym, Flags: flags, Size: int64(n)}, nil
		} else if !ok && strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
			// Keep the declaration visible to source inventory. Object emission
			// requires the caller's generated assembly header to resolve its size.
			return GloblStmt{Sym: sym, Flags: flags, Size: -1}, nil
		}
	}
	return GloblStmt{}, fmt.Errorf("GLOBL invalid size %q: %q", sizePart, "GLOBL "+rest)
}

// ParseDataSymbol separates a package-qualified symbol and its assembler addend.
func ParseDataSymbol(s string) (string, int64, error) {
	s = strings.TrimSpace(s)
	// Operators in a package path precede the assembler symbol separator.
	nameAt := strings.LastIndex(s, "·")
	if nameAt >= 0 {
		nameAt += len("·")
	} else {
		nameAt = strings.LastIndexByte(s, '/') + 1
	}
	if i := strings.IndexAny(s[nameAt:], "+-"); i >= 0 {
		i += nameAt
		base := strings.TrimSpace(s[:i])
		if delta, ok := ParseImmExpr(s[i:]); base != "" && ok {
			return base, int64(delta), nil
		}
		return base, 0, fmt.Errorf("unresolved DATA address %q: %w", s, ErrProbeNeedsContext)
	}
	return s, 0, nil
}

func SplitSymPlusOff(s string) (sym string, off int64) {
	// Best-effort parse for forms like:
	//   name+0
	//   name-8
	// If offset parsing fails, treat the entire string as a symbol name.
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	// Prefer the last '+' or '-' as the separator.
	sep := strings.LastIndexAny(s, "+-")
	if sep <= 0 || sep == len(s)-1 {
		return s, 0
	}
	n, err := parseInt(s[sep:])
	if err != nil {
		return s, 0
	}
	return strings.TrimSpace(s[:sep]), n
}

func parseInt(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty int")
	}
	// Accept 0x... too.
	return strconv.ParseInt(s, 0, 64)
}

func parseOperandsCSV(arch Arch, op Op, s string) ([]Operand, error) {
	if s == "" {
		return nil, nil
	}
	parts := SplitTopLevelCSV(s)
	out := make([]Operand, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Decimal floating literals carry binary64 bits in ParseOperand.
		// F32Const instead encodes the rounded IEEE binary32 payload.
		if arch == ArchWASM && op == "F32CONST" && strings.HasPrefix(part, "$") {
			expr := strings.TrimSpace(part[1:])
			if _, integer := ParseImmExpr(expr); !integer {
				value, err := strconv.ParseFloat(expr, 32)
				ok := err == nil
				if !ok {
					value, ok = ParseImmFloatExpr(expr)
				}
				if ok {
					out = append(out, Operand{Kind: OpImm, Imm: int64(math.Float32bits(float32(value)))})
					continue
				}
			}
		}
		legacy := []string{part}
		if arch == ArchAMD64 && op == "SHLL" {
			legacy = splitLegacyColonOperand(part)
		}
		for _, item := range legacy {
			op, err := parseOperandForArch(arch, item)
			if err != nil {
				return nil, err
			}
			out = append(out, op)
		}
	}
	// Go 1.20 and 1.21 accepted SHA1C/M/P Vm, Rn, Vd and encoded Rn's
	// register number in the SIMD Sn field. Normalize before register use
	// analysis so the legacy spelling reads the same vector slot as Vn.
	if arch == ArchARM64 && len(out) == 3 && (op == "SHA1C" || op == "SHA1M" || op == "SHA1P") &&
		out[0].Kind == OpReg && out[2].Kind == OpReg && plainARM64Vector(out[0].Reg) && plainARM64Vector(out[2].Reg) && out[1].Kind == OpReg {
		r := string(out[1].Reg)
		if r == "ZR" {
			out[1].Reg = Reg("V31")
		} else if strings.HasPrefix(r, "R") {
			if n, err := strconv.Atoi(r[1:]); err == nil && n >= 0 && n <= 31 {
				out[1].Reg = Reg(fmt.Sprintf("V%d", n))
			}
		}
	}
	// Direct branches treat a bare token as a label even when it also looks like
	// an architecture register (for example amd64 JL V1 and ARM BEQ X7 in Go
	// 1.23's math/big assembly). Indirect branch and call opcodes stay outside
	// this rule because their bare register operands are meaningful.
	if branchRegisterTokenIsLabel(arch, op) && len(out) == 1 && out[0].Kind == OpReg {
		out[0] = Operand{Kind: OpIdent, Ident: strings.TrimSpace(s)}
	}
	return out, nil
}

func plainARM64Vector(r Reg) bool {
	if !strings.HasPrefix(string(r), "V") {
		return false
	}
	n, err := strconv.Atoi(string(r[1:]))
	return err == nil && n >= 0 && n <= 31
}

// Go's ARM assembler accepts decimal R(n) and F(n) wherever an operand
// takes a register, including both registers of a shifted operand.
var armNumberedRegister = regexp.MustCompile(`(?:^|[[:space:]($\[,<>@+\-])([RF])[[:space:]]*\([[:space:]]*([0-9]+)[[:space:]]*\)`)

func normalizeARMNumberedRegisters(s string) (string, error) {
	matches := armNumberedRegister.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s, nil
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		n, err := strconv.ParseUint(s[m[4]:m[5]], 10, 4)
		if err != nil {
			return "", fmt.Errorf("invalid ARM register %q", s[m[2]:m[1]])
		}
		b.WriteString(s[last:m[3]])
		b.WriteString(strconv.FormatUint(n, 10))
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

func parseOperandForArch(arch Arch, s string) (Operand, error) {
	if arch == ArchARM && strings.Contains(s, "(") {
		var err error
		s, err = normalizeARMNumberedRegisters(s)
		if err != nil {
			return Operand{}, err
		}
	}
	if arch == ArchWASM {
		if reg, ok := parseWASMReg(s); ok {
			return Operand{Kind: OpReg, Reg: reg}, nil
		}
		if !strings.HasPrefix(strings.TrimSpace(s), "$") {
			if mem, matched, err := ParseWASMMem(s); matched {
				if err != nil {
					return Operand{}, err
				}
				return Operand{Kind: OpMem, Mem: mem}, nil
			}
		}
	}
	op, err := ParseOperand(s)
	if err == nil && arch == ArchARM64 {
		preserveARM64PhysicalStackPointer(s, &op)
	}
	return op, err
}

func preserveARM64PhysicalStackPointer(source string, op *Operand) {
	source = strings.TrimSpace(source)
	switch op.Kind {
	case OpReg:
		if strings.EqualFold(source, "RSP") {
			op.Reg = Reg("RSP")
		}
	case OpMem:
		if strings.Contains(strings.ToUpper(source), "(RSP)") {
			if op.Mem.Base == SP {
				op.Mem.Base = Reg("RSP")
			}
			if op.Mem.Index == SP {
				op.Mem.Index = Reg("RSP")
			}
		}
	}
}

func ParseWASMMem(s string) (mem MemRef, matched bool, err error) {
	s = strings.TrimSpace(s)
	open := strings.LastIndexByte(s, '(')
	if open < 0 || !strings.HasSuffix(s, ")") {
		return MemRef{}, false, nil
	}
	base, ok := parseWASMReg(strings.TrimSpace(s[open+1 : len(s)-1]))
	if !ok {
		return MemRef{}, false, nil
	}
	offset := strings.TrimSpace(s[:open])
	if offset == "" {
		return MemRef{Base: base}, true, nil
	}
	if n, parseErr := strconv.ParseInt(offset, 0, 64); parseErr == nil {
		return MemRef{Base: base, Off: n}, true, nil
	}
	if n, ok := ParseImmExpr(offset); ok {
		return MemRef{Base: base, Off: int64(n)}, true, nil
	}
	return MemRef{Base: base, OffRaw: offset}, true, nil
}

var wasmRegisterPrefixes = [...]struct {
	name string
	max  int
}{
	{name: "R", max: 15},
	{name: "F", max: 31},
	{name: "V", max: 15},
}

func parseWASMReg(s string) (Reg, bool) {
	name := strings.TrimSpace(s)
	upper := strings.ToUpper(name)
	switch upper {
	case "SP", "CTXT", "G", "RET0", "RET1", "RET2", "RET3", "PAUSE", "PC_B":
		return Reg(upper), true
	}
	for _, prefix := range wasmRegisterPrefixes {
		if !strings.HasPrefix(upper, prefix.name) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(upper, prefix.name))
		if err == nil && 0 <= n && n <= prefix.max {
			return Reg(upper), true
		}
	}
	return "", false
}

func branchRegisterTokenIsLabel(arch Arch, op Op) bool {
	name := NormalizeInstructionOpcode(op)
	switch arch {
	case ArchAMD64:
		return (strings.HasPrefix(name, "J") && name != "JMP") || strings.HasPrefix(name, "LOOP")
	case ArchARM:
		return isARMBranchOpcode(name) && name != "BL" && name != "BX" && name != "BLX" && name != "RET"
	case ArchARM64:
		return isARM64BranchOpcode(name) && name != "BL" && name != "BR" && name != "BLR" && name != "RET" && name != "ERET"
	default:
		return false
	}
}

// Go's x86 assembler retains an old three-operand spelling where left:right
// means right, left. For example R11:AX in SHLL CX, R11:AX is equivalent to
// SHLL CX, AX, R11. Keep this in the parser so official assembler testdata can
// describe the canonical three-operand form.
func splitLegacyColonOperand(s string) []string {
	par := 0
	brk := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			par++
		case ')':
			if par > 0 {
				par--
			}
		case '[':
			brk++
		case ']':
			if brk > 0 {
				brk--
			}
		case ':':
			if par == 0 && brk == 0 {
				left := strings.TrimSpace(s[:i])
				right := strings.TrimSpace(s[i+1:])
				if left != "" && right != "" {
					return []string{right, left}
				}
			}
		}
	}
	return []string{s}
}

func SplitOpcode(stmt string) (op, rest string) {
	opEnd := strings.IndexAny(stmt, " \t")
	if opEnd < 0 {
		return stmt, ""
	}
	return strings.TrimSpace(stmt[:opEnd]), strings.TrimSpace(stmt[opEnd:])
}

func SplitSemicolons(line string) []string {
	parts := strings.Split(line, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}
