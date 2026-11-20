package plan9asm

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"text/scanner"
)

// File is a parsed Plan 9 asm source file (subset).
type File struct {
	Arch                 Arch
	Funcs                []Func
	x86Continuations     map[string]x86Continuation
	x86ContinuationGraph *x86ContinuationGraph
	x86DirectTails       *x86DirectTailGraph // request-local whole-source continuation graph
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
	x86ContinuationFlow      *x86ContinuationFlow
	x86SourceStack           *x86SourceStackProof // recomputed final source ABI0 stack proof
	x86SourceStackFailure    string               // diagnostic only; never authorizes an effect or return
	x86FixedLocal            *x86FixedLocalProof
	// Set only by the closed same-file Go binding proof, never by a guessed
	// helper FuncSig. The ABI0 root's GP/NZCV entry is otherwise unspecified.
	arm64PrivateRegisterEntry  bool
	arm64PrivateUnexposedFrame bool                    // original source proof retained across audited helper coalescing
	arm64PrivateTailSource     *arm64PrivateTailSource // complete, immutable zero-frame continuation source
	arm64PrivateCallSource     *arm64PrivateCallSource // sealed original CALL bodies and exact prepared CFG
	arm64ABI0TailSource        *arm64ABI0TailSource
	arm64PrivateSourceAdded    int                 // resource accounting only, never a machine-state permission
	x86RawReplay               *x86RawReplaySource // immutable raw source/replay identity, never a capability
	x86DirectTailRoot          *x86DirectTailRoot
	x86ResultFlowBudget        *x86ResultFlowBudget // request-local combined proof accounting only
	x86BoolCalls               *x86ABI0BoolCallPlan // private complete-source logical CALL plan only
	x86BoolReadonlyInputs      bool                 // private callee replay; never entry/native authority
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
	pp, err := preprocessWithDefines(src, defines)
	if err != nil {
		return nil, err
	}
	return parsePreprocessedAssembly(arch, pp)
}

// parsePreprocessedAssembly consumes the caller's complete expanded source.
// In particular it cannot silently ignore an active include or apply another
// macro environment to identifiers left by the actual preprocessor.
func parsePreprocessedAssembly(arch Arch, pp string) (*File, error) {
	f := &File{Arch: arch}

	sc := bufio.NewScanner(strings.NewReader(pp))
	// A short nested macro can expand beyond 64 KiB on one logical line.
	// Bound the scanner by the actual expanded input, including its final EOF.
	sc.Buffer(nil, len(pp)+1)
	lineno := 0
	var cur *Func
	var pendingLabels []assemblyLabelPrefix
	labels := make(map[string]bool)
	flushLabels := func() error {
		for _, label := range pendingLabels {
			if labels[label.name] {
				return fmt.Errorf("line %d: label %q multiply defined", lineno, label.name)
			}
			labels[label.name] = true
			if cur == nil {
				f.UnlinkedPrelude = append(f.UnlinkedPrelude, label.raw)
				continue
			}
			cur.Instrs = append(cur.Instrs, Instr{
				Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: label.name}}, Raw: label.raw,
			})
		}
		pendingLabels = nil
		return nil
	}
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
			for {
				label, found := statementLabelPrefix(arch, stmt)
				if !found {
					break
				}
				pendingLabels = append(pendingLabels, label)
				stmt = label.rest
			}
			if stmt == "" {
				continue
			}

			head, err := parseAssemblyOpcode(arch, stmt)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", lineno, err)
			}
			opStr, rest := head.name, head.rest
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
			if op != OpTEXT && op != "DATA" && op != "GLOBL" {
				if err := flushLabels(); err != nil {
					return nil, err
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
				labels = make(map[string]bool)
				if err := flushLabels(); err != nil {
					return nil, err
				}
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

// cmd/asm's line grammar admits zero or more pending identifier labels before
// an instruction. Suffix tokens precede the colon on non-wasm architectures,
// but do not change the label's original identifier. Operand/string colons
// never enter this role. DATA/GLOBL and EOF do not consume pending labels.
type assemblyLabelPrefix struct {
	name, raw, rest string
}

func statementLabelPrefix(arch Arch, statement string) (assemblyLabelPrefix, bool) {
	colon := strings.IndexByte(statement, ':')
	if colon < 0 {
		return assemblyLabelPrefix{}, false
	}
	reader := newPPGoReader("<label-prefix>", statement[:colon])
	word, err := reader.next()
	if err != nil || word.kind != scanner.Ident {
		return assemblyLabelPrefix{}, false
	}
	for {
		token, err := reader.next()
		if err != nil {
			return assemblyLabelPrefix{}, false
		}
		if token.kind == scanner.EOF {
			return assemblyLabelPrefix{word.text, strings.TrimSpace(statement[:colon+1]), strings.TrimSpace(statement[colon+1:])}, true
		}
		if token.kind != '.' || arch != ArchAMD64 && arch != ArchARM && arch != ArchARM64 {
			return assemblyLabelPrefix{}, false
		}
		suffix, err := reader.next()
		if err != nil || suffix.kind != scanner.Ident {
			return assemblyLabelPrefix{}, false
		}
	}
}

func parseTEXTFrame(parts []string) (frameSize, argSize int64, err error) {
	spec, err := parseTEXTFrameSpec(parts)
	return spec.frameSize, spec.argSize, err
}

type textFrameSpec struct {
	frameSize, argSize int64
	argsSpecified      bool
}

// Keep Go's omitted argument-size state distinct from an explicit zero. The
// public numeric fields retain their historical zero value; source-sensitive
// consumers can recover this distinction from the retained original TEXT.
func parseTEXTFrameSpec(parts []string) (textFrameSpec, error) {
	var result textFrameSpec
	if len(parts) < 2 {
		return result, nil
	}
	spec := strings.TrimSpace(parts[len(parts)-1])
	if !strings.HasPrefix(spec, "$") {
		return result, nil
	}
	spec = strings.TrimSpace(strings.TrimPrefix(spec, "$"))
	frameText, argText := spec, ""
	if i := strings.LastIndex(spec, "-"); i > 0 {
		result.argsSpecified = true
		frameText, argText = strings.TrimSpace(spec[:i]), strings.TrimSpace(spec[i+1:])
	}
	frame, ok := parseImmExpr(frameText)
	if !ok {
		return result, fmt.Errorf("unresolved TEXT frame size %q", frameText)
	}
	result.frameSize = int64(frame)
	if !result.argsSpecified {
		return result, nil
	}
	args, ok := parseImmExpr(argText)
	if !ok {
		return result, fmt.Errorf("unresolved TEXT argument size %q", argText)
	}
	result.argSize = int64(args)
	return result, nil
}

func parseDATAStmt(arch Arch, rest string) (DataStmt, error) {
	// DATA sym+off(SB)/width, $value
	parts := splitTopLevelCSV(rest)
	if len(parts) != 2 {
		return DataStmt{}, fmt.Errorf("invalid DATA: %q", "DATA "+rest)
	}
	lhs, rhs := parts[0], parts[1]
	if lhs == "" || rhs == "" {
		return DataStmt{}, fmt.Errorf("invalid DATA: %q", "DATA "+rest)
	}

	// lhs: sym+off(SB)/width
	widthSeparator := strings.LastIndexByte(lhs, '/')
	if widthSeparator < 0 {
		return DataStmt{}, fmt.Errorf("DATA missing /width: %q", "DATA "+rest)
	}
	symPart, widthStr := lhs[:widthSeparator], lhs[widthSeparator+1:]
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

	sym, off, concrete := parseSymbolOffset(symPart)
	if !concrete || strings.ContainsAny(sym, "\"'`") {
		return DataStmt{}, fmt.Errorf("DATA unresolved or malformed displacement: %q", "DATA "+rest)
	}

	// DATA's width applies to the value's type, not to a generic immediate
	// bit pattern. cmd/asm converts a FLOAT leaf to float32 before writing
	// four bytes; truncating the low bits of float64 would silently corrupt it.
	expression := strings.TrimSpace(strings.TrimPrefix(rhs, "$"))
	val, integerError := strconv.ParseUint(expression, 0, 64)
	ok := integerError == nil
	if !ok {
		val, ok = parseImmExpr(expression)
	}
	ok = ok && strings.HasPrefix(rhs, "$")
	if ok && width != 1 && width != 2 && width != 4 && width != 8 {
		return DataStmt{}, fmt.Errorf("DATA integer requires width 1, 2, 4 or 8: %q", rest)
	}
	if !ok && strings.HasPrefix(rhs, "$") {
		if value, floating := parseGoFloatLiteral(expression); floating {
			switch width {
			case 4:
				val = uint64(math.Float32bits(float32(value)))
			case 8:
				val = math.Float64bits(value)
			default:
				return DataStmt{}, fmt.Errorf("DATA float requires width 4 or 8: %q", rest)
			}
			ok = true
		}
	}
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
		// Preserve symbol-address initializers for relocation-aware lowering.
		// Value is not a byte payload for an address initializer.
		if strings.HasPrefix(rhs, "$") && strings.HasSuffix(rhs, "(SB)") {
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
	return DataStmt{Sym: sym, Off: off, Width: width, Value: val, Payload: payload, Addr: addr}, nil
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
	parts := splitTopLevelCSV(rest)
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
	// cmd/asm evaluates the symbol displacement before requiring it to be
	// zero. Keep a zero expression out of the declaration's identity so DATA
	// and GLOBL name the same object. A declaration cannot retain an
	// unresolved expression as a different, phantom storage identity.
	var off int64
	var concrete bool
	sym, off, concrete = parseSymbolOffset(sym)
	if !concrete || strings.ContainsAny(sym, "\"'`") {
		return GloblStmt{}, fmt.Errorf("GLOBL unresolved or malformed symbol displacement: %q", "GLOBL "+rest)
	}
	if off != 0 {
		return GloblStmt{}, fmt.Errorf("GLOBL symbol must not be offset from SB: %q", "GLOBL "+rest)
	}
	if !strings.HasPrefix(sizePart, "$") {
		return GloblStmt{}, fmt.Errorf("GLOBL size must be an immediate: %q", sizePart)
	}
	expression := strings.TrimSpace(strings.TrimPrefix(sizePart, "$"))
	sz, ok := parseImmExpr(expression)
	if !ok && memoryOffsetExpressionNeedsContext(expression) {
		// Retain generated layout syntax for inventory, never a guessed
		// zero or 64-byte allocation. Both lowering paths reject SizeRaw.
		return GloblStmt{Sym: sym, Flags: flags, SizeRaw: sizePart}, nil
	}
	if !ok || int64(sz) < 0 {
		return GloblStmt{}, fmt.Errorf("GLOBL invalid size %q: %q", sizePart, "GLOBL "+rest)
	}
	return GloblStmt{Sym: sym, Flags: flags, Size: int64(sz)}, nil
}

func splitSymPlusOff(s string) (sym string, off int64) {
	s = strings.TrimSpace(s)
	if name, offset, concrete := parseSymbolOffset(s); concrete {
		return name, offset
	}
	return s, 0
}

// Separate the first explicit displacement outside quoted tokens. A later
// parseable suffix cannot repair an invalid earlier expression. The public
// query keeps unresolved input verbatim; DATA/GLOBL consumers require concrete.
func parseSymbolOffset(s string) (name string, offset int64, concrete bool) {
	s = strings.TrimSpace(s)
	var quote byte
	for index := 0; index < len(s); index++ {
		character := s[index]
		if quote != 0 {
			if character == '\\' && quote != '`' && index+1 < len(s) {
				index++
			} else if character == quote {
				quote = 0
			}
			continue
		}
		switch character {
		case '\'', '"', '`':
			quote = character
		case '+', '-':
			if index == 0 {
				return "", 0, false
			}
			name = strings.TrimSpace(s[:index])
			value, valid := parseImmExpr(s[index:])
			return name, int64(value), name != "" && valid
		}
	}
	return s, 0, s != "" && quote == 0
}

// SplitSymbolOffset parses a Go assembly symbol and its constant-expression
// displacement. An unparseable displacement leaves the input unchanged so
// callers can report the original symbol in their own context.
func SplitSymbolOffset(s string) (sym string, off int64) {
	return splitSymPlusOff(s)
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
		if arch == ArchAMD64 {
			if operand, matched := parseX86BranchIdentifier(op, part); matched {
				out = append(out, operand)
				continue
			}
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
	// ARM direct branches treat a bare token as a label even when the shared
	// parser recognizes it as another architecture's register, such as BEQ X7.
	// x86 uses its complete source namespace before generic operand parsing.
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
	if arch == ArchAMD64 {
		x86Operand := strings.TrimSpace(s)
		address := strings.HasPrefix(x86Operand, "$")
		body := strings.TrimSpace(strings.TrimPrefix(x86Operand, "$"))
		if memory, matched, err := parseX86SymbolIndexedMemory(body); matched {
			if err != nil {
				// Preserve the old shared parser's g index spelling, but do
				// not normalize a new unscaled Reg or address-immediate g
				// annotation into a Go-valid ignored 386 register.
				normalized := normalizeGoGRegister(arch, body)
				if !address && errors.Is(err, ErrProbeNeedsContext) && normalized != body && x86SymbolGIndex.MatchString(body) {
					if legacy, ok := parseMem(normalized); ok &&
						strings.HasSuffix(legacy.Sym, "(SB)") && legacy.Base == "" && legacy.Index == "R14" {
						return Operand{Kind: OpMem, Mem: legacy}, nil
					}
				}
				return Operand{}, err
			}
			operand := Operand{Kind: OpMem, Mem: memory}
			if address {
				return Operand{Kind: OpSym, Sym: "$" + operand.String()}, nil
			}
			return operand, nil
		}
	}
	if arch == ArchAMD64 && strings.HasPrefix(strings.TrimSpace(s), "$") {
		original := strings.TrimSpace(s)
		normalized := normalizeGoGRegister(arch, original)
		if normalized != original {
			body := strings.TrimSpace(strings.TrimPrefix(normalized, "$"))
			if _, matched, err := parseX86SourceRegisterMemory(body); matched {
				if err != nil {
					return Operand{}, err
				}
				// This parser also serves 386. Preserve the original g token
				// until the source row knows its actual architecture; an
				// ignored R14 annotation is legal in 386 constant classes.
				return Operand{Kind: OpSym, Sym: original}, nil
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
		if !strings.HasPrefix(x86Operand, "$") {
			if pseudo := x86SymbolPseudoGroup.FindStringSubmatch(x86Operand); pseudo != nil && pseudo[1] != "SP" {
				return parseOperand(s) // Keep unindexed SB/FP and PC branch roles.
			}
			if memory, matched, err := parseX86SourceRegisterMemorySyntax(x86Operand, true); matched {
				if err != nil {
					return Operand{}, err
				}
				if x86SourceMemoryHasSegment(memory) {
					// Preserve the independent, existing segment/TLS operand
					// model. A lexical group is not a native-address contract.
					return parseOperand(s)
				}
				return Operand{Kind: OpMem, Mem: memory}, nil
			}
		}
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
// The shared x86 parser also serves 386. Unnamed address immediates retain
// their original g spelling for mode qualification before constant rewriting.
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
	head, err := parseAssemblyOpcode(ArchAMD64, stmt)
	if err != nil {
		// Source inspectors cannot admit an invalid header by dropping tokens.
		// Parse reports the lexical error through its architecture-aware path.
		return stmt, ""
	}
	return head.name, head.rest
}

type assemblyOpcodeHead struct {
	name, rest string
}

// cmd/asm accepts Ident ('.' Ident)* on ARM and x86 before the first
// operand. Spaces, comments and CPP origins do not delimit that grammar.
// Keep original operand bytes; only the opcode/suffix tokens are canonicalized.
func parseAssemblyOpcode(arch Arch, statement string) (assemblyOpcodeHead, error) {
	reader := newPPGoReader("<opcode>", statement)
	word, err := reader.next()
	if err != nil {
		return assemblyOpcodeHead{}, err
	}
	if word.kind != scanner.Ident {
		return assemblyOpcodeHead{}, fmt.Errorf("instruction expected identifier, found %q", word.text)
	}
	head := assemblyOpcodeHead{name: word.text}
	for {
		token, err := reader.next()
		if err != nil {
			return assemblyOpcodeHead{}, err
		}
		if token.kind == scanner.EOF {
			return head, nil
		}
		if token.kind != '.' {
			head.rest = strings.TrimSpace(statement[reader.scanner.Position.Offset:])
			return head, nil
		}
		if arch != ArchAMD64 && arch != ArchARM && arch != ArchARM64 {
			return assemblyOpcodeHead{}, fmt.Errorf("instruction suffix is not supported on %s", arch)
		}
		suffix, err := reader.next()
		if err != nil {
			return assemblyOpcodeHead{}, err
		}
		if suffix.kind != scanner.Ident {
			return assemblyOpcodeHead{}, fmt.Errorf("instruction suffix expected identifier, found %q", suffix.text)
		}
		head.name += "." + suffix.text
	}
}

func splitSemicolons(line string) []string {
	// cmd/asm scans complete string and character tokens. A separator inside
	// either token is payload, including after an escaped quote/backslash.
	// Do not repair a malformed quoted token by splitting its remainder.
	var out []string
	var quote byte
	start := 0
	for index := 0; index < len(line); index++ {
		value := line[index]
		if quote != 0 {
			if value == '\\' && index+1 < len(line) {
				index++
			} else if value == quote {
				quote = 0
			}
			continue
		}
		switch value {
		case '"', '\'':
			quote = value
		case ';':
			out = append(out, strings.TrimSpace(line[start:index]))
			start = index + 1
		}
	}
	out = append(out, strings.TrimSpace(line[start:]))
	return out
}
