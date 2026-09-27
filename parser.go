package plan9asm

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// File is a parsed Plan 9 asm source file (subset).
type File struct {
	Arch             Arch
	Funcs            []Func
	x86Continuations map[string]x86Continuation
	// UnlinkedPrelude records instructions before the first TEXT. Go assembles
	// them into no named function, so they cannot affect any translated symbol.
	// Corpus verification checks the same source with Go's assembler first.
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

	// X86RawText retains a byte-exact, address-sensitive raw TEXT body. It is
	// populated only when another source instruction takes the body's address
	// (including symbol+offset patching), so ordinary BYTE-encoded instructions
	// still go through semantic decoding and validation.
	X86RawText []byte
	// X86RawAlign retains a leading PCALIGN on an address-sensitive raw body.
	// Go aligns the function itself when PCALIGN precedes its first byte.
	X86RawAlign int64

	x86ContinuationAddresses map[string]x86Continuation
	x86IndirectLabels        []string
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
	return ParseWithDefines(arch, src, nil)
}

// ParseWithDefines parses assembly with the same predefined symbols cmd/go
// supplies to cmd/asm (for example GOOS_windows or GOARM64_LSE).
func ParseWithDefines(arch Arch, src string, defines []string) (*File, error) {
	f := &File{Arch: arch}

	pp, err := preprocessWithDefines(src, defines)
	if err != nil {
		return nil, err
	}

	sc := bufio.NewScanner(strings.NewReader(pp))
	// A short nested macro can expand beyond 64 KiB on one logical line.
	// Bound the scanner by the actual expanded input, including its final EOF.
	sc.Buffer(nil, len(pp)+1)
	lineno := 0
	var cur *Func
	for sc.Scan() {
		lineno++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		for _, stmt := range splitSemicolons(line) {
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
			// Support "label: INSTR ..." on one statement.
			if c := strings.IndexByte(stmt, ':'); c >= 0 {
				left := strings.TrimSpace(stmt[:c])
				right := strings.TrimSpace(stmt[c+1:])
				if left != "" && right != "" && !strings.ContainsAny(left, " \t") {
					if cur == nil {
						return nil, fmt.Errorf("line %d: label outside TEXT: %q", lineno, stmt)
					}
					cur.Instrs = append(cur.Instrs, Instr{
						Op:   OpLABEL,
						Args: []Operand{{Kind: OpLabel, Sym: left}},
						Raw:  left + ":",
					})
					stmt = right
				}
			}

			opStr, rest := splitOpcode(stmt)
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
			if cur == nil && op != OpTEXT && op != "DATA" && op != "GLOBL" {
				f.UnlinkedPrelude = append(f.UnlinkedPrelude, stmt)
				continue
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
				// Early Plan 9 assembly commonly spelled function definitions as
				// TEXT ·name+0(SB). The zero is a symbol offset, not part of the
				// linker name; current Go still accepts this legacy form.
				if base, off := splitSymPlusOff(sym); base != sym && off == 0 {
					sym = base
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
				ds, err := parseDATAStmt(arch, rest)
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
				cur.Instrs = append(cur.Instrs, Instr{Op: op, Args: args, Raw: stmt})
				continue
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(f.Funcs) == 0 && len(f.Data) == 0 && len(f.Globl) == 0 {
		return nil, fmt.Errorf("no TEXT directive found")
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
	frame, ok := parseImmExpr(frameText)
	if !ok {
		return 0, 0, fmt.Errorf("unresolved TEXT frame size %q", frameText)
	}
	if argText == "" {
		return int64(frame), 0, nil
	}
	args, ok := parseImmExpr(argText)
	if !ok {
		return 0, 0, fmt.Errorf("unresolved TEXT argument size %q", argText)
	}
	return int64(frame), int64(args), nil
}

func parseDATAStmt(arch Arch, rest string) (DataStmt, error) {
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
	symPart, widthStr, ok := strings.Cut(lhs, "/")
	if !ok {
		return DataStmt{}, fmt.Errorf("DATA missing /width: %q", "DATA "+rest)
	}
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

	sym, off := splitSymPlusOff(symPart)

	val, ok := parseImm(rhs)
	var payload []byte
	var addr string
	if !ok {
		trimRHS := strings.TrimSpace(rhs)
		if strings.HasPrefix(trimRHS, "$\"") {
			str, err := strconv.Unquote(strings.TrimPrefix(trimRHS, "$"))
			if err == nil && int64(len(str)) <= width {
				payload = []byte(str)
				ok = true
			}
		}
	}
	if !ok {
		// Accept symbol-address initializers (e.g. $runtime·main(SB)) even when
		// relocation details are not modeled; encode as zero placeholder.
		if strings.HasPrefix(strings.TrimSpace(rhs), "$") {
			if sym, symOK := parseSym(strings.TrimPrefix(strings.TrimSpace(rhs), "$")); symOK {
				addr = sym
				val = 0
				ok = true
			}
		}
	}
	if !ok {
		return DataStmt{}, fmt.Errorf("DATA invalid immediate %q: %q", rhs, "DATA "+rest)
	}
	return DataStmt{Sym: sym, Off: off, Width: width, Value: uint64(val), Payload: payload, Addr: addr}, nil
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
	// GLOBL sym(SB), $size
	// GLOBL sym(SB), flags, $size
	parts := strings.Split(rest, ",")
	if len(parts) != 2 && len(parts) != 3 {
		return GloblStmt{}, fmt.Errorf("invalid GLOBL: %q", "GLOBL "+rest)
	}
	symPart := strings.TrimSpace(parts[0])
	flags := ""
	sizePartIndex := 1
	if len(parts) == 3 {
		flags = strings.TrimSpace(parts[1])
		sizePartIndex = 2
	}
	sizePart := strings.TrimSpace(parts[sizePartIndex])
	if !strings.HasSuffix(symPart, "(SB)") {
		return GloblStmt{}, fmt.Errorf("GLOBL symbol must end with (SB): %q", "GLOBL "+rest)
	}
	sym := strings.TrimSpace(strings.TrimSuffix(symPart, "(SB)"))
	if sym == "" {
		return GloblStmt{}, fmt.Errorf("GLOBL empty symbol: %q", "GLOBL "+rest)
	}
	sz, ok := parseImm(sizePart)
	if (!ok || sz < 0) && strings.HasPrefix(sizePart, "$(") && strings.HasSuffix(sizePart, ")") {
		// Some platform asm uses symbolic struct-size macros in GLOBL sizes
		// (e.g. $(machTimebaseInfo__size)). We don't evaluate include-time
		// macros here, so keep a conservative non-zero placeholder size.
		sz, ok = 64, true
	}
	if !ok || sz < 0 {
		return GloblStmt{}, fmt.Errorf("GLOBL invalid size %q: %q", sizePart, "GLOBL "+rest)
	}
	return GloblStmt{Sym: sym, Flags: flags, Size: int64(sz)}, nil
}

func splitSymPlusOff(s string) (sym string, off int64) {
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
	parts := splitTopLevelCSV(s)
	out := make([]Operand, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		legacy := []string{part}
		if arch == ArchAMD64 && (op == "SHLL" || op == "SHLQ" || op == "SHRL" || op == "SHRQ") {
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
	// Direct branches treat a bare token as a label even when it also looks like
	// an architecture register (for example amd64 JL V1 and ARM BEQ X7 in Go
	// 1.23's math/big assembly). Indirect branch and call opcodes stay outside
	// this rule because their bare register operands are meaningful.
	if branchRegisterTokenIsLabel(arch, op) && len(out) == 1 && out[0].Kind == OpReg {
		out[0] = Operand{Kind: OpIdent, Ident: strings.TrimSpace(s)}
	}
	return out, nil
}

func parseOperandForArch(arch Arch, s string) (Operand, error) {
	if arch == ArchAMD64 || arch == ArchARM || arch == ArchARM64 {
		operand := strings.TrimSpace(s)
		// Go's shared parser accepts '*' on register and register-memory
		// operands, not just x86. Reuse architecture-specific normalization
		// (g, R(n), RSP) while preserving symbol/immediate indirection.
		if strings.HasPrefix(operand, "*") {
			indirect := strings.TrimSpace(operand[1:])
			if !strings.HasPrefix(indirect, "*") {
				parsed, err := parseOperandForArch(arch, indirect)
				if err == nil && (parsed.Kind == OpReg || parsed.Kind == OpMem) {
					return parsed, nil
				}
			}
		}
	}
	s = normalizeGoGRegister(arch, s)
	if arch == ArchARM || arch == ArchARM64 {
		s = normalizeARMParenthesizedRegisters(arch, s)
	}
	if arch == ArchARM {
		if memory, ok := parseARMShiftMemory(s); ok {
			return Operand{Kind: OpMem, Mem: memory}, nil
		}
	}
	if arch == ArchAMD64 {
		x86Operand := strings.TrimSpace(s)
		reg := Reg(strings.ToUpper(x86Operand))
		switch reg {
		case ES, CS, SS, DS:
			return Operand{Kind: OpReg, Reg: reg}, nil
		}
		if _, _, ok := x86MachineRegister(reg); ok {
			return Operand{Kind: OpReg, Reg: reg}, nil
		}
	}
	if arch == ArchWASM {
		if reg, ok := parseWASMReg(s); ok {
			return Operand{Kind: OpReg, Reg: reg}, nil
		}
		if !strings.HasPrefix(strings.TrimSpace(s), "$") {
			if mem, matched, err := parseWASMMem(s); matched {
				if err != nil {
					return Operand{}, err
				}
				return Operand{Kind: OpMem, Mem: mem}, nil
			}
		}
	}
	op, err := parseOperand(s)
	if err != nil {
		return Operand{}, err
	}
	if arch == ArchARM64 {
		preserveARM64PhysicalStackPointer(s, &op)
	}
	return op, nil
}

// Go's frontend assigns a different physical register to g on each ISA.
// Normalize only register positions, including an
// address immediate or indirect branch. A symbol such as g(SB) stays intact.
// The shared x86 parser also serves 386; its operand validators reject R14.
func normalizeGoGRegister(arch Arch, source string) string {
	if !strings.Contains(source, "g") {
		return source
	}
	register := ""
	switch arch {
	case ArchAMD64:
		register = "R14"
	case ArchARM:
		register = "R10"
	case ArchARM64:
		register = "R28"
	default:
		return source
	}
	s := strings.TrimSpace(source)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") ||
		strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && strings.Contains(s, ",") {
		parts := splitTopLevelCSV(s[1 : len(s)-1])
		for i, part := range parts {
			ends := strings.SplitN(part, "-", 2)
			for j, end := range ends {
				ends[j] = normalizeGoGRegisterExpression(strings.TrimSpace(end), register)
			}
			parts[i] = strings.Join(ends, "-")
		}
		return s[:1] + strings.Join(parts, ",") + s[len(s)-1:]
	}
	if strings.HasPrefix(s, "*") && strings.TrimSpace(s[1:]) == "g" {
		return "*" + register
	}
	s = normalizeGoGRegisterExpression(s, register)
	// ARM writes a shifted register offset before the base, g<<2(R1).
	// Only a parsed register shift is eligible: g(SB), named FP slots and
	// ordinary symbolic displacement expressions must not be renamed.
	if arch == ArchARM && strings.HasSuffix(s, ")") {
		if open := strings.LastIndexByte(s, '('); open > 0 {
			prefix := strings.TrimSpace(s[:open])
			marker := ""
			if strings.HasPrefix(prefix, "$") {
				marker, prefix = "$", strings.TrimSpace(prefix[1:])
			}
			if _, _, _, _, ok := parseRegShift(prefix); ok {
				s = marker + normalizeGoGRegisterExpression(prefix, register) + s[open:]
			}
		}
	}
	for start := 0; start < len(s); {
		open := strings.IndexByte(s[start:], '(')
		if open < 0 {
			break
		}
		open += start
		end := strings.IndexByte(s[open+1:], ')')
		if end < 0 {
			break
		}
		end += open + 1
		inner := strings.TrimSpace(s[open+1 : end])
		replacement := normalizeGoGRegisterExpression(inner, register)
		if scale := strings.IndexByte(inner, '*'); scale >= 0 && strings.TrimSpace(inner[:scale]) == "g" {
			replacement = register + inner[scale:]
		}
		if replacement != inner {
			s = s[:open+1] + replacement + s[end:]
			end = open + 1 + len(replacement)
		}
		start = end + 1
	}
	return s
}

// Rewrite only the register terminals in a recognized register expression.
// This preserves symbols, constant expressions, and an explicitly written R28.
func normalizeGoGRegisterExpression(source, register string) string {
	if source == "g" {
		return register
	}
	if _, shift, _, _, ok := parseRegShift(source); ok {
		at := strings.Index(source, string(shift))
		left, right := strings.TrimSpace(source[:at]), strings.TrimSpace(source[at+len(shift):])
		if left == "g" {
			left = register
		}
		if right == "g" {
			right = register
		}
		return left + string(shift) + right
	}
	if _, _, _, ok := parseRegExtendShift(source); ok {
		if dot := strings.IndexByte(source, '.'); strings.TrimSpace(source[:dot]) == "g" {
			return register + source[dot:]
		}
	}
	if _, _, ok := parseRegExtend(source); ok {
		if dot := strings.IndexByte(source, '.'); strings.TrimSpace(source[:dot]) == "g" {
			return register + source[dot:]
		}
	}
	return source
}

// normalizeARMParenthesizedRegisters implements the numeric register-prefix
// syntax accepted by Go's ARM assemblers, such as R(3), F(7), and V(16).
// Keeping this architecture-specific prevents a symbol such as SPR(269) from
// being mistaken for an ARM general-purpose register.
func normalizeARMParenthesizedRegisters(arch Arch, source string) string {
	limits := map[string]int{}
	switch arch {
	case ArchARM:
		limits = map[string]int{"R": 15, "F": 15}
	case ArchARM64:
		limits = map[string]int{"R": 30, "F": 31, "V": 31, "Z": 31, "P": 15, "PN": 15}
	default:
		return source
	}
	prefixes := []string{"PN", "R", "F", "V", "Z", "P"}
	var out strings.Builder
	for i := 0; i < len(source); {
		matched := false
		for _, prefix := range prefixes {
			endPrefix := i + len(prefix)
			if endPrefix >= len(source) || !strings.EqualFold(source[i:endPrefix], prefix) || source[endPrefix] != '(' {
				continue
			}
			if i > 0 && isIdentifierByte(source[i-1]) {
				continue
			}
			close := strings.IndexByte(source[endPrefix+1:], ')')
			if close < 0 {
				continue
			}
			close += endPrefix + 1
			numberText := strings.TrimSpace(source[endPrefix+1 : close])
			number, err := strconv.Atoi(numberText)
			limit, validPrefix := limits[prefix]
			if err != nil || !validPrefix || number < 0 || number > limit {
				continue
			}
			out.WriteString(prefix)
			out.WriteString(strconv.Itoa(number))
			i = close + 1
			matched = true
			break
		}
		if matched {
			continue
		}
		out.WriteByte(source[i])
		i++
	}
	return out.String()
}

func isIdentifierByte(ch byte) bool {
	return ch == '_' || ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
}

// Go's arm64 assembler distinguishes the hardware stack pointer RSP from the
// pseudo stack pointer SP. parseReg historically canonicalizes both to SP, so
// restore the distinction here where the source spelling is still available.
// This matters for exact optab validation: (RSP) is a C_ZOREG address, while a
// named local+0(SP) address is C_ZAUTO, and RSP in a paired data operand
// encodes register 31 (the zero register) rather than a writable stack pointer.
func preserveARM64PhysicalStackPointer(source string, op *Operand) {
	source = strings.TrimSpace(source)
	switch op.Kind {
	case OpReg:
		if strings.EqualFold(source, "RSP") {
			op.Reg = Reg("RSP")
		}
	case OpMem:
		if op.Mem.Base == SP && op.Mem.OffRaw == "" && strings.HasSuffix(strings.ToUpper(source), "(SP)") {
			prefix := strings.TrimSpace(source[:len(source)-len("(SP)")])
			if offset, ok := parseNamedStackConstantOffset(prefix); ok && offset == op.Mem.Off {
				// The generic parser evaluated the displacement. ARM64's
				// optabs also need the source name to distinguish C_ZAUTO
				// from a plain register-relative SP address.
				op.Mem.OffRaw = prefix
			}
		}
		if strings.Contains(strings.ToUpper(source), "(RSP)") {
			if op.Mem.Base == SP {
				op.Mem.Base = Reg("RSP")
			}
			if op.Mem.Index == SP {
				op.Mem.Index = Reg("RSP")
			}
		}
	case OpRegList:
		if len(source) < 2 {
			return
		}
		inner := strings.TrimSpace(strings.Trim(source, "()[]"))
		parts := splitTopLevelCSV(inner)
		index := 0
		for _, part := range parts {
			regs, ok := expandRegRange(strings.TrimSpace(part))
			if !ok {
				return
			}
			if len(regs) == 1 && strings.EqualFold(strings.TrimSpace(part), "RSP") && index < len(op.RegList) {
				op.RegList[index] = Reg("RSP")
			}
			index += len(regs)
		}
	}
}

// ARM shifted offsets can contain parenthesized constant expressions. Retain
// the complete shift before the final base group, including unresolved macros;
// the typed address validator, not the generic symbol fallback, checks it.
func parseARMShiftMemory(s string) (MemRef, bool) {
	s = strings.TrimSpace(s)
	open := strings.LastIndexByte(s, '(')
	if open <= 0 || !strings.HasSuffix(s, ")") {
		return MemRef{}, false
	}
	base, ok := parseReg(strings.TrimSpace(s[open+1 : len(s)-1]))
	if !ok || !isARMGeneralReg(base) {
		return MemRef{}, false
	}
	prefix := strings.TrimSpace(s[:open])
	for _, shift := range []ShiftOp{ShiftRotate, ShiftArith, ShiftLeft, ShiftRight} {
		if i := strings.Index(prefix, string(shift)); i > 0 {
			if reg, ok := parseReg(strings.TrimSpace(prefix[:i])); ok && isARMGeneralReg(reg) {
				return MemRef{Base: base, OffRaw: prefix}, true
			}
		}
	}
	return MemRef{}, false
}

func parseWASMMem(s string) (mem MemRef, matched bool, err error) {
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
	if n, ok := parseImmExpr(offset); ok {
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
	name := normalizeInstructionOpcode(op)
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

func splitOpcode(stmt string) (op, rest string) {
	opEnd := strings.IndexAny(stmt, " \t")
	if opEnd < 0 {
		return stmt, ""
	}
	return strings.TrimSpace(stmt[:opEnd]), strings.TrimSpace(stmt[opEnd:])
}

func splitSemicolons(line string) []string {
	parts := strings.Split(line, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}
