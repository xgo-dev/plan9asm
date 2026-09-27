package plan9asm

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

func normalizeX86RawFile(file *File, goarch string) (*File, error) {
	if file == nil || file.Arch != ArchAMD64 {
		return file, nil
	}
	normalized := *file
	normalized.Funcs = append([]Func(nil), file.Funcs...)
	normalized.Data = append([]DataStmt(nil), file.Data...)
	usedSymbols := make(map[string]bool)
	for _, fn := range file.Funcs {
		usedSymbols[fn.Sym] = true
	}
	for _, datum := range file.Data {
		usedSymbols[datum.Sym] = true
	}
	for _, global := range file.Globl {
		usedSymbols[global.Sym] = true
	}
	if err := preserveAddressSensitiveX86RawText(&normalized); err != nil {
		return nil, err
	}
	for i := range normalized.Funcs {
		if normalized.Funcs[i].X86RawText != nil {
			continue
		}
		if x86HasTerminalRawTail(normalized.Funcs[i]) &&
			x86RawTailLayoutObserved(&normalized, normalized.Funcs[i].Sym) {
			return nil, fmt.Errorf("%s: address-observed raw tail after RET cannot be omitted safely", normalized.Funcs[i].Sym)
		}
		fn, err := decodeX86RawDirectives(normalized.Funcs[i], goarch)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", normalized.Funcs[i].Sym, err)
		}
		hasLiteral := false
		for _, ins := range fn.Instrs {
			if ins.x86RIPLiteral {
				hasLiteral = true
				break
			}
		}
		if hasLiteral && x86RawTailLayoutObserved(&normalized, fn.Sym) {
			return nil, fmt.Errorf("%s: address-observed RIP-relative raw literal cannot be folded safely", fn.Sym)
		}
		addressSymbols := make(map[int]string)
		for j := range fn.Instrs {
			ins := &fn.Instrs[j]
			if len(ins.x86RIPAddressData) == 0 {
				continue
			}
			addressArg := -1
			for index, arg := range ins.Args {
				if arg.Kind == OpSym && arg.Sym == "·__plan9asm_raw_address_pending(SB)" {
					addressArg = index
					break
				}
			}
			if addressArg < 0 {
				continue
			}
			name := addressSymbols[ins.x86RIPAddressGroup]
			if name == "" {
				stem := fmt.Sprintf("·__plan9asm_raw_address_%x_%d", sha256.Sum256([]byte(fn.Sym)), ins.x86RIPAddressGroup)
				name = stem
				for suffix := 1; usedSymbols[name]; suffix++ {
					name = fmt.Sprintf("%s_%d", stem, suffix)
				}
				usedSymbols[name] = true
				addressSymbols[ins.x86RIPAddressGroup] = name
				normalized.Data = append(normalized.Data, DataStmt{
					Sym: name, Width: int64(len(ins.x86RIPAddressData)),
					Payload: ins.x86RIPAddressData,
				})
			}
			address := name
			if ins.x86RIPAddressOff != 0 {
				address += fmt.Sprintf("+%d", ins.x86RIPAddressOff)
			}
			ins.Args[addressArg].Sym = address + "(SB)"
			ins.Raw = strings.Replace(ins.Raw, "·__plan9asm_raw_address_pending(SB)", ins.Args[addressArg].Sym, 1)
		}
		for j := range fn.Instrs {
			ins := &fn.Instrs[j]
			if len(ins.x86RIPLiteralData) == 0 {
				continue
			}
			// Bounded-module translation normalizes again after partitioning.
			// Keep the payload for constant-specialized lowerers without
			// materializing a second global on that pass.
			literalArg := -1
			for index, arg := range ins.Args {
				if arg.Kind == OpSym && arg.Sym == "·__plan9asm_raw_literal_pending(SB)" {
					literalArg = index
					break
				}
			}
			if literalArg < 0 {
				continue
			}
			stem := fmt.Sprintf("·__plan9asm_raw_literal_%x_%d", sha256.Sum256([]byte(fn.Sym)), j)
			name := stem
			for suffix := 1; usedSymbols[name]; suffix++ {
				name = fmt.Sprintf("%s_%d", stem, suffix)
			}
			usedSymbols[name] = true
			normalized.Data = append(normalized.Data, DataStmt{
				Sym: name, Width: int64(len(ins.x86RIPLiteralData)),
				Payload: ins.x86RIPLiteralData,
			})
			ins.Args[literalArg].Sym = name + "(SB)"
			ins.Raw = strings.Replace(ins.Raw, "·__plan9asm_raw_literal_pending(SB)", ins.Args[literalArg].Sym, 1)
		}
		normalized.Funcs[i] = fn
	}
	return &normalized, nil
}

func x86HasTerminalRawTail(fn Func) bool {
	start := len(fn.Instrs)
	for start > 0 && isX86RawDirective(fn.Instrs[start-1]) {
		start--
	}
	return start > 0 && start < len(fn.Instrs) && fn.Instrs[start-1].Op == OpRET
}

func x86RawTailLayoutObserved(file *File, symbol string) bool {
	target := strings.TrimSuffix(symbol, "<>")
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			for _, operand := range ins.Args {
				if fn.Sym == symbol && operand.Kind == OpMem && operand.Mem.Base == PC {
					return true
				}

				ref := ""
				switch operand.Kind {
				case OpSym:
					ref = operand.Sym
				case OpMem:
					ref = operand.Mem.Sym
				}
				if ref == "" {
					continue
				}
				ref = strings.TrimSpace(strings.TrimPrefix(ref, "*"))
				base, offset, ok := parseSBRef(ref)
				if !ok || strings.TrimSuffix(strings.TrimPrefix(base, "$"), "<>") != target {
					continue
				}
				if offset != 0 || !isX86DirectControlTransfer(ins.Op) {
					return true
				}
			}
		}
	}
	for _, datum := range file.Data {
		base, _, ok := parseSBRef(datum.Addr)
		if ok && strings.TrimSuffix(base, "<>") == target {
			return true
		}
	}
	return false
}

func isX86DirectControlTransfer(op Op) bool {
	return op == OpCALL || op == OpJMP || op == OpRET || isAMD64ConditionalBranch(op)
}

// NormalizeRawFileForTranslation performs the whole-file raw-byte analysis
// before a compile-only caller partitions functions into bounded modules.
// Address-sensitive TEXT bodies must be identified while all references are
// still visible. TranslateModuleInContext may safely normalize the result
// again after partitioning.
func NormalizeRawFileForTranslation(file *File, goarch string) (*File, error) {
	return normalizeX86RawFile(file, goarch)
}

// preserveAddressSensitiveX86RawText identifies raw-only TEXT bodies whose
// exact byte layout is observed elsewhere in the same source file. Typical
// examples are boot trampolines patched through symbol+offset references and
// TEXT-backed descriptor/data tables. Decoding such a body into LLVM
// operations would make the referenced byte offsets false even when the
// instruction semantics happened to match.
//
// Raw-only bodies that are merely called or jumped to are deliberately not
// selected: those remain on the normal semantic decoder path.
func preserveAddressSensitiveX86RawText(file *File) error {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	candidates := make(map[string]int)
	encoded := make(map[int][]byte)
	alignments := make(map[int]int64)
	for index := range file.Funcs {
		fn := &file.Funcs[index]
		candidateName := strings.TrimSuffix(fn.Sym, "<>")
		if fn.X86RawText != nil {
			candidates[candidateName] = index
			encoded[index] = append([]byte(nil), fn.X86RawText...)
			alignments[index] = fn.X86RawAlign
			continue
		}
		var code []byte
		hasRaw := false
		rawOnly := true
		var alignment int64
		for _, ins := range fn.Instrs {
			if ins.Op == OpTEXT {
				continue
			}
			if ins.Op == "PCALIGN" && !hasRaw {
				if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
					rawOnly = false
					break
				}
				value := ins.Args[0].Imm
				if value < 8 || value > 2048 || value&(value-1) != 0 {
					rawOnly = false
					break
				}
				if value > alignment {
					alignment = value
				}
				continue
			}
			if !isX86RawDirective(ins) {
				rawOnly = false
				break
			}
			part, err := x86RawDirectiveBytes(ins)
			if err != nil {
				return fmt.Errorf("%s: %w", fn.Sym, err)
			}
			code = append(code, part...)
			hasRaw = true
		}
		if !rawOnly || !hasRaw {
			continue
		}
		candidates[candidateName] = index
		encoded[index] = code
		alignments[index] = alignment
	}
	if len(candidates) == 0 {
		return nil
	}

	addressed := make(map[int]bool)
	markSymbol := func(symbol string) {
		base, _, ok := parseSBRef(strings.TrimSpace(strings.TrimPrefix(symbol, "*")))
		if !ok {
			return
		}
		base = strings.TrimSuffix(base, "<>")
		if index, exists := candidates[base]; exists {
			addressed[index] = true
		}
	}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			op := Op(strings.ToUpper(string(ins.Op)))
			if op == OpCALL || op == OpJMP || op == OpRET || isAMD64ConditionalBranch(op) {
				continue
			}
			for _, operand := range ins.Args {
				switch operand.Kind {
				case OpSym:
					markSymbol(operand.Sym)
				case OpMem:
					if operand.Mem.Sym != "" {
						markSymbol(operand.Mem.Sym)
					}
				}
			}
		}
	}
	for index := range addressed {
		file.Funcs[index].X86RawText = append([]byte(nil), encoded[index]...)
		file.Funcs[index].X86RawAlign = alignments[index]
	}
	return nil
}

// decodeX86RawDirectives replaces consecutive BYTE/WORD/LONG/QUAD directives
// with the Plan 9 instructions represented by those bytes. The decoder and
// syntax printer come from Go's architecture tables; the resulting instruction
// still has to pass the ordinary plan9asm operand-form and semantic lowerers.
// This is deliberately not an opaque inline-assembly escape hatch.
func decodeX86RawDirectives(fn Func, goarch string) (Func, error) {
	mode := 64
	if goarch == "386" {
		mode = 32
	} else if goarch != "" && goarch != "amd64" {
		return fn, fmt.Errorf("raw x86 directives require GOARCH 386 or amd64, got %q", goarch)
	}

	knownLabels := make(map[string]bool)
	for _, ins := range fn.Instrs {
		if ins.Op == OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == OpLabel {
			knownLabels[ins.Args[0].Sym] = true
		}
	}

	var normalized []Instr
	for i := 0; i < len(fn.Instrs); {
		if !isX86RawDirective(fn.Instrs[i]) {
			normalized = append(normalized, fn.Instrs[i])
			i++
			continue
		}

		start := i
		var code []byte
		var rawLines []string
		opaque := make(map[int]x86RawDecodedInstruction)
		for i < len(fn.Instrs) {
			if isX86RawDirective(fn.Instrs[i]) {
				encoded, err := x86RawDirectiveBytes(fn.Instrs[i])
				if err != nil {
					return fn, err
				}
				code = append(code, encoded...)
				rawLines = append(rawLines, fn.Instrs[i].Raw)
				i++
				continue
			}
			// Keep a run of named SSE constant reads in the same physical
			// layout only when raw bytes resume after it. Go's encoder lengths
			// are checked against the official assembler in tests.
			end := i
			for end < len(fn.Instrs) {
				if _, ok := x86RawMixedSSESymbolReadSize(fn.Instrs[end]); !ok {
					break
				}
				end++
			}
			if end == i || end == len(fn.Instrs) || !isX86RawDirective(fn.Instrs[end]) {
				break
			}
			for i < end {
				ins := fn.Instrs[i]
				length, _ := x86RawMixedSSESymbolReadSize(ins)
				opaque[len(code)] = x86RawDecodedInstruction{length: length, instrs: []Instr{ins}}
				code = append(code, make([]byte, length)...)
				rawLines = append(rawLines, ins.Raw)
				i++
			}
		}
		// Go appends BYTE/WORD/LONG/QUAD after a final RET to the previous
		// TEXT, even when GLOBL declarations intervene. Without a following
		// source label, the tail has no control-flow entry and is not an
		// executable instruction stream. Generated tables can therefore
		// contain arbitrary bytes, including apparent branches. Keep labeled
		// tails on the normal decoder path so reachable code never disappears.
		if i == len(fn.Instrs) && start > 0 && fn.Instrs[start-1].Op == OpRET {
			continue
		}
		rawGroup := strings.Join(rawLines, "; ")
		if mode == 64 {
			if target, ok := x86RawRetpolineTarget(code); ok {
				normalized = append(normalized, Instr{
					Op:   OpJMP,
					Args: []Operand{{Kind: OpReg, Reg: target}},
					Raw:  fmt.Sprintf("JMP %s /* decoded retpoline from %s */", target, rawGroup),
				})
				continue
			}
		}
		decoded, err := decodeX86RawDirectiveGroupWithOpaque(code, mode, start, rawGroup, knownLabels, opaque)
		if err != nil {
			return fn, err
		}
		normalized = append(normalized, decoded...)
	}
	fn.Instrs = normalized
	return fn, nil
}

type x86RawDecodedInstruction struct {
	length int
	instrs []Instr
}

// decodeX86RawDirectiveGroup follows every reachable path through one raw
// directive group. Internal relative JMP/Jcc targets become synthetic source
// labels, so backward edges and both short and near conditional branches keep
// their control-flow semantics. Bytes skipped by all reachable paths remain
// uninterpreted, which permits the embedded signatures and constant data used
// by generated assembly. Any edge outside the group or into an instruction is
// still rejected rather than being guessed from final linked layout.
func decodeX86RawDirectiveGroup(code []byte, mode, start int, rawGroup string, knownLabels map[string]bool) ([]Instr, error) {
	return decodeX86RawDirectiveGroupWithOpaque(code, mode, start, rawGroup, knownLabels, nil)
}

func decodeX86RawDirectiveGroupWithOpaque(
	code []byte, mode, start int, rawGroup string,
	knownLabels map[string]bool, opaque map[int]x86RawDecodedInstruction,
) ([]Instr, error) {
	decodedByOffset := make(map[int]x86RawDecodedInstruction)
	labels := make(map[int]string)
	addressTargets := make(map[int]int)
	var literalRanges []x86RawLiteralRange
	recordLiteral := func(offset int, literal x86RawLiteralRange) {
		literal.source = offset
		literalRanges = append(literalRanges, literal)
	}
	owners := make([]int, len(code))
	for i := range owners {
		owners[i] = -1
	}
	for offset, named := range opaque {
		if named.length <= 0 || offset < 0 || offset+named.length > len(code) {
			return nil, fmt.Errorf("invalid named x86 source span at byte %d: %q", offset, rawGroup)
		}
		for current := offset; current < offset+named.length; current++ {
			if owners[current] != -1 {
				return nil, fmt.Errorf("overlapping named x86 source spans at byte %d: %q", current, rawGroup)
			}
			owners[current] = offset
		}
	}
	queue := []int{0}
	queued := map[int]bool{0: true}

	labelFor := func(target int) string {
		if label := labels[target]; label != "" {
			return label
		}
		base := fmt.Sprintf("raw_jcc_%d_%d", start, target)
		label := base
		for suffix := 2; knownLabels[label]; suffix++ {
			label = fmt.Sprintf("%s_%d", base, suffix)
		}
		knownLabels[label] = true
		labels[target] = label
		return label
	}
	enqueue := func(target int) error {
		if target < 0 || target > len(code) {
			return fmt.Errorf("raw x86 PC-relative target byte %d at instruction %d is outside directive group: %q", target, start, rawGroup)
		}
		if target < len(code) && owners[target] >= 0 && owners[target] != target {
			return fmt.Errorf("raw x86 PC-relative target byte %d at instruction %d is not an instruction boundary: %q", target, start, rawGroup)
		}
		labelFor(target)
		if !queued[target] {
			queued[target] = true
			queue = append(queue, target)
		}
		return nil
	}
	markInstruction := func(offset, length int) error {
		if length <= 0 || offset+length > len(code) {
			return fmt.Errorf("raw x86 instruction at instruction %d byte %d has invalid length %d: %q", start, offset, length, rawGroup)
		}
		for current := offset; current < offset+length; current++ {
			if owners[current] >= 0 && owners[current] != offset {
				return fmt.Errorf("raw x86 instruction at instruction %d byte %d overlaps instruction at byte %d: %q", start, offset, owners[current], rawGroup)
			}
		}
		for current := offset; current < offset+length; current++ {
			owners[current] = offset
		}
		return nil
	}
	annotate := func(instrs []Instr) []Instr {
		for i := range instrs {
			instrs[i].Raw = fmt.Sprintf("%s /* decoded from %s */", instrs[i].Raw, rawGroup)
		}
		return instrs
	}

	for len(queue) != 0 {
		blockStart := queue[0]
		queue = queue[1:]
		if blockStart == len(code) {
			continue
		}
		if owners[blockStart] >= 0 && owners[blockStart] != blockStart {
			return nil, fmt.Errorf("raw x86 PC-relative target byte %d at instruction %d is not an instruction boundary: %q", blockStart, start, rawGroup)
		}
		for offset := blockStart; offset < len(code); {
			if _, exists := decodedByOffset[offset]; exists {
				break
			}
			if owners[offset] >= 0 && owners[offset] != offset {
				return nil, fmt.Errorf("raw x86 reachable byte %d at instruction %d is inside instruction at byte %d: %q", offset, start, owners[offset], rawGroup)
			}
			if named, ok := opaque[offset]; ok {
				decodedByOffset[offset] = named
				offset += named.length
				continue
			}
			if instruction, length, ok, err := decodedX86ExtendedPrefetchInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 extended prefetch at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok := decodedX86AMDSystemManagementInstruction(code[offset:]); ok {
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}

			if instruction, length, ok, err := decodedX86SegmentMoveInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 segment-register move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if syntax, length, ok := decodedX86RandomInstruction(code[offset:], mode); ok {
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instrs, err := parseDecodedX86Instruction(syntax)
				if err != nil {
					return nil, fmt.Errorf("parse decoded raw x86 instruction %q at instruction %d byte %d: %w", syntax, start, offset, err)
				}
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: annotate(instrs)}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86CacheLineWritebackInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 cache-line writeback at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawBlockBroadcastRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX block broadcast literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawBlockBroadcastInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX block broadcast at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawVBROADCAST128RIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VBROADCAST128 literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VBROADCAST128Instruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VBROADCAST128 at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawVMOVIntegerLiteral(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VMOVD/VMOVQ literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VMOVQInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VMOVQ at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86MaskMoveInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 KMOV at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86MaskVectorMoveInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 mask/vector move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawEVEXPackedIntegerMoveRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX packed integer move literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86EVEXPackedIntegerMoveInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX packed integer move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawPackedMoveRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed move literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedMoveInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawGatherInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 gather at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawScatterInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scatter at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawQwordPermuteInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 qword permute at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawPackedSignInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed sign at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ExplicitMaskMoveInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 explicit mask move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawScalarMoveRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar move literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ScalarMoveInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawDuplicateMoveRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 duplicate move literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86DuplicateMoveInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 duplicate move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawFloatLogicalRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 floating logical literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawEVEXFloatLogicalInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX floating logical instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXPackedFloatLogicalInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEX packed floating logical instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86FloatingUnpackInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 floating unpack at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86InLaneFloatingPermuteInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 in-lane floating permute at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawMaskBlendRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 mask blend literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawMaskBlendInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 mask blend at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawVariableBlendRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 variable blend literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VariableBlendInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 variable blend at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawImmediatePackedBlendRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 immediate packed blend literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawCLMULRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 carryless multiply literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawCLMULInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 carryless multiply at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ImmediatePackedBlendInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 immediate packed blend at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawBinaryFloatRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 binary floating literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXBinaryFloatInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEX binary floating instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawPackedWidenConversionRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed widening conversion literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedWidenConversionInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed widening conversion at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ScalarFloatToIntegerInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar float-to-integer instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ScalarIntegerFloatInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar integer-to-float instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ScalarPrecisionConvertInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar precision conversion at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawQQToFloatRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 QWORD-to-float literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawQQToFloatInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 QWORD-to-float conversion at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86SameWidthConversionInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 same-width packed conversion at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedDoubleDwordInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed double/dword conversion at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedPrecisionConvertInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed precision conversion at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawScalarHalfConversionRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar FP16 literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ScalarHalfConversionInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar FP16 conversion at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawFP16ConversionRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 FP16 conversion literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedHalfConversionInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed half conversion at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawBF16RIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 BF16 literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawBF16Instruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 BF16 at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86MinimumPositionInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 minimum-position instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawMinMaxRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed integer min/max literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedIntegerMinMaxInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed integer min/max at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86SingleSourceNarrowInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 single-source narrowing at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawVariableShiftRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 per-lane variable shift literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PerLaneVariableShiftInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 per-lane shift at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawMaskCompareRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 mask compare literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawMaskCompareInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 mask compare at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawPackedCompareRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed integer compare literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedIntegerCompareInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed integer compare at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawVectorBitCountInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 vector bit count at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawVectorHighLowMoveInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 vector high/low move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawVectorHalfMemoryInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 vector half memory move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawKLogicalInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 K-register operation at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawMaskShiftInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 mask shift at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawPackedTestMaskInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed test mask at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawPackedSADInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed SAD at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawScalarFlagCompareRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar flag compare literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ScalarFlagCompareInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar flag compare at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXVectorTestInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEX vector test at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXMoveMaskInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEX move mask at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawVectorFloatCompareRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 vector floating compare literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VectorFloatCompareInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 vector floating compare instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXHorizontalIntegerInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 horizontal integer at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawHorizontalFloatRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 horizontal floating literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXHorizontalFloatInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEX horizontal floating instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawPackedLogicalRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed logical literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXPackedIntegerLogicalInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEX packed integer logical instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86EVEXPackedLogicalInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX packed logical instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawPackedMADDRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEX packed multiply-add literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86EVEXPackedMADDInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX packed multiply-add at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXPackedMADDInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEX packed multiply-add instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawFMA3RIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 FMA3 literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXFMA3Instruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEX FMA3 instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXTRACT128Instruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEXTRACT128 instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXNonTemporalMoveInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VEX non-temporal move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86InsertPSInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 INSERTPS/VINSERTPS at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedScalarExtractInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed scalar extract at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VPERMQInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VPERMQ at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VINSERT128Instruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VINSERT128 at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86EVEXPackedInsertInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX packed insert at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawScalarFloatBroadcastLiteral(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar float broadcast literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ScalarBroadcastInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar broadcast at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawPackedBroadcastLiteral(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed broadcast literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VEXPackedBroadcastInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed broadcast at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedAlignRightInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed align-right at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86Permute128Instruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 128-bit lane permute at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VSHUFPSInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VSHUFPS at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedShuffleInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed shuffle at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86Shuffle128BitBlocksInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VSHUFF/VSHUFI block shuffle at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawVPSHUFBRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VPSHUFB literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VPSHUFBInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VPSHUFB at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedExtendInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed extending move at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawPackedArithmeticRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed integer arithmetic literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedIntegerArithmeticInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed integer arithmetic at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawVariableRotateRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 variable rotate literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawVariableRotateInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 variable rotate at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedImmediateRotateInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed immediate rotate at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawImmediateThreeVectorRIPData(
				code, offset, mode, 0x03, decodedX86VectorAlignInstruction, "vector align",
			); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 vector align literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VectorAlignInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VALIGN at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawImmediateThreeVectorRIPData(
				code, offset, mode, 0x25, decodedX86TernaryLogicInstruction, "ternary logic",
			); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 ternary logic literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86TernaryLogicInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 ternary logic at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86FunnelShiftInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 funnel shift at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedUniformShiftInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed uniform shift at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawIndexedPermuteRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 indexed permute literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86IndexedPermuteInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 indexed permute at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedCompressInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed compress at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedExpandInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed expand at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86IFMAInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 IFMA at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86GFNIInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 GFNI at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VPINSRInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VPINSR at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86EVEXVPINSRInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX VPINSR at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawEVEXUnpackRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX packed unpack literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86EVEXPackedUnpackInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX packed unpack at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VPUNPCKInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VPUNPCK at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VNNIInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VNNI at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VariableDwordPermuteInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VPERMD/VPERMPS at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawEVEXVariableDwordPermuteRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX variable dword permute literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86EVEXVariableDwordPermuteInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 EVEX variable dword permute at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86SHAInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 SHA at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawBZHIInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 BZHI at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86BMI2ShiftInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 BMI2 variable shift at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ParallelBitsInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 parallel bits at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86BLSInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 BLS at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86ANDNInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 ANDN at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86MULXInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 MULX at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RORXInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 RORX at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86DwordToQwordMultiplyInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 dword-to-qword multiply at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawPackedAbsRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VPABS literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawScaledRoundRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scaled round literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawVEXRoundRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VROUND literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawVectorByteShiftRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 vector byte shift literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawVectorByteShiftInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 vector byte shift at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawScaledRoundInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scaled round at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawVEXRoundInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VROUND at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86RawPackedAbsInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 VPABS at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86VectorPackedSaturatingNarrowInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed saturating narrow at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}
			if instruction, length, literal, ok, err := decodeX86RawPackedMultiplyRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed multiply literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}
			if instruction, length, ok, err := decodedX86PackedMultiplyInstruction(code[offset:], mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 packed multiply at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}

			if instruction, length, ok, err := decodedX86ScalarPortIOInstruction(code[offset:]); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 scalar port I/O at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				offset += length
				continue
			}

			if instruction, length, literal, ok, err := decodeX86RawLegacySIMDMoveRIPData(code, offset, mode); ok {
				if err != nil {
					return nil, fmt.Errorf("decode raw x86 legacy SIMD move literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
				}
				if err := markInstruction(offset, length); err != nil {
					return nil, err
				}
				instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
				decodedByOffset[offset] = x86RawDecodedInstruction{length: length, instrs: []Instr{instruction}}
				recordLiteral(offset, literal)
				offset += length
				continue
			}

			inst, err := x86asm.Decode(code[offset:], mode)
			if err != nil || inst.Len <= 0 || inst.Op == 0 {
				if err == nil {
					if inst.Len <= 0 {
						err = fmt.Errorf("decoder consumed zero bytes")
					} else {
						err = fmt.Errorf("incomplete or unknown instruction")
					}
				}
				end := offset + 16
				if end > len(code) {
					end = len(code)
				}
				return nil, fmt.Errorf("decode raw x86 directive group at instruction %d byte %d (%x): %w: %q", start, offset, code[offset:end], err, rawGroup)
			}
			if err := markInstruction(offset, inst.Len); err != nil {
				return nil, err
			}
			syntax, err := decodedX86GoSyntax(inst, code[offset:offset+inst.Len])
			if err != nil {
				return nil, fmt.Errorf("convert decoded raw x86 instruction at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
			}
			opName := strings.Fields(syntax)[0]
			op := Op(strings.ToUpper(opName))
			if inst.PCRel != 0 {
				if instruction, literal, ok, err := decodeX86RawLegacyScalarRIPData(code, offset, inst, syntax); ok {
					if err != nil {
						return nil, fmt.Errorf("decode raw x86 legacy scalar literal at instruction %d byte %d: %w: %q", start, offset, err, rawGroup)
					}
					instruction.Raw = fmt.Sprintf("%s /* decoded from %s */", instruction.Raw, rawGroup)
					decodedByOffset[offset] = x86RawDecodedInstruction{length: inst.Len, instrs: []Instr{instruction}}
					recordLiteral(offset, literal)
					offset += inst.Len
					continue
				}
				if mode == 64 && inst.Op == x86asm.LEA {
					mem, ok := inst.Args[1].(x86asm.Mem)
					if ok && mem.Base == x86asm.RIP {
						target := offset + inst.Len + int(mem.Disp)
						if target < 0 || target >= len(code) {
							return nil, fmt.Errorf("raw x86 local address target byte %d at instruction %d is outside directive group: %q", target, start, rawGroup)
						}
						instrs, err := parseDecodedX86Instruction(syntax)
						if err != nil || len(instrs) != 1 || len(instrs[0].Args) != 2 {
							return nil, fmt.Errorf("parse decoded raw x86 local address %q at instruction %d byte %d: %v", syntax, start, offset, err)
						}
						instrs[0].Args[0] = Operand{Kind: OpSym, Sym: "·__plan9asm_raw_address_pending(SB)"}
						instrs[0].Raw = fmt.Sprintf("%s ·__plan9asm_raw_address_pending(SB), %s /* decoded from %s */", op, instrs[0].Args[1], rawGroup)
						decodedByOffset[offset] = x86RawDecodedInstruction{length: inst.Len, instrs: instrs}
						addressTargets[offset] = target
						offset += inst.Len
						continue
					}
				}
				target, ok := x86RawRelativeTarget(inst, offset)
				isJump := op == OpJMP
				isConditional := isAMD64ConditionalBranch(op)
				if !ok || (!isJump && !isConditional) {
					return nil, fmt.Errorf("raw x86 PC-relative instruction %q at instruction %d byte %d cannot be mapped safely to source labels: %q", syntax, start, offset, rawGroup)
				}
				if err := enqueue(target); err != nil {
					return nil, fmt.Errorf("raw x86 branch at byte %d: %w", offset, err)
				}
				label := labelFor(target)
				branch := Instr{Op: op, Args: []Operand{{Kind: OpIdent, Ident: label}}, Raw: fmt.Sprintf("%s %s /* decoded from %s */", op, label, rawGroup)}
				decodedByOffset[offset] = x86RawDecodedInstruction{length: inst.Len, instrs: []Instr{branch}}
				if isConditional {
					if err := enqueue(offset + inst.Len); err != nil {
						return nil, fmt.Errorf("raw x86 conditional fallthrough at byte %d: %w", offset, err)
					}
				}
				break
			}
			if inst.Op == x86asm.JMP {
				return nil, fmt.Errorf("raw x86 indirect jump at instruction %d byte %d cannot be mapped safely: %q", start, offset, rawGroup)
			}
			instrs, err := parseDecodedX86Instruction(syntax)
			if err != nil {
				return nil, fmt.Errorf("parse decoded raw x86 instruction %q at instruction %d byte %d: %w", syntax, start, offset, err)
			}
			decodedByOffset[offset] = x86RawDecodedInstruction{length: inst.Len, instrs: annotate(instrs)}
			offset += inst.Len
			if inst.Op == x86asm.RET {
				break
			}
		}
	}

	for _, literal := range literalRanges {
		for offset := literal.first; offset < literal.last; offset++ {
			if owners[offset] >= 0 {
				return nil, fmt.Errorf("RIP-relative literal byte %d overlaps reachable instruction at byte %d: %q", offset, owners[offset], rawGroup)
			}
		}
	}
	if len(addressTargets) != 0 {
		first := len(code)
		for _, target := range addressTargets {
			if target < first {
				first = target
			}
		}
		// Only a fully unreachable suffix after a decoded RET can be moved to
		// a shared global. Addressing executable bytes or a separately folded
		// literal would lose source-relative pointer identity.
		retBeforeSuffix := false
		for offset, decoded := range decodedByOffset {
			if offset >= first {
				continue
			}
			for _, ins := range decoded.instrs {
				if ins.Op == OpRET {
					retBeforeSuffix = true
				}
			}
		}
		if !retBeforeSuffix {
			return nil, fmt.Errorf("raw x86 local address data at byte %d has no preceding RET: %q", first, rawGroup)
		}
		for offset := first; offset < len(code); offset++ {
			if owners[offset] >= 0 {
				return nil, fmt.Errorf("raw x86 local address byte %d overlaps reachable instruction: %q", offset, rawGroup)
			}
		}
		for _, literal := range literalRanges {
			if literal.last <= first {
				continue
			}
			if literal.first < first {
				return nil, fmt.Errorf("raw x86 local address overlaps the middle of a folded literal: %q", rawGroup)
			}
			decoded := decodedByOffset[literal.source]
			for index := range decoded.instrs {
				ins := &decoded.instrs[index]
				for arg := range ins.Args {
					if ins.Args[arg].Kind != OpSym || ins.Args[arg].Sym != "·__plan9asm_raw_literal_pending(SB)" {
						continue
					}
					ins.Args[arg].Sym = "·__plan9asm_raw_address_pending(SB)"
					ins.Raw = strings.Replace(ins.Raw, "·__plan9asm_raw_literal_pending(SB)", ins.Args[arg].Sym, 1)
					// An address escape may permit writes to this pool. Force a
					// runtime load rather than specializing from its initial bytes.
					ins.x86RIPLiteralData = nil
					ins.x86RIPAddressData = code[first:]
					ins.x86RIPAddressOff = literal.first - first
					ins.x86RIPAddressGroup = start
				}
			}
			decodedByOffset[literal.source] = decoded
		}
		for offset, target := range addressTargets {
			decoded := decodedByOffset[offset]
			decoded.instrs[0].x86RIPLiteral = true
			decoded.instrs[0].x86RIPAddressData = code[first:]
			decoded.instrs[0].x86RIPAddressOff = target - first
			decoded.instrs[0].x86RIPAddressGroup = start
			decodedByOffset[offset] = decoded
		}
	}

	offsets := make([]int, 0, len(decodedByOffset))
	for offset := range decodedByOffset {
		offsets = append(offsets, offset)
	}
	sort.Ints(offsets)
	result := make([]Instr, 0, len(offsets)+len(labels))
	for _, offset := range offsets {
		if label := labels[offset]; label != "" {
			result = append(result, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: label}}, Raw: label + ":"})
		}
		result = append(result, decodedByOffset[offset].instrs...)
	}
	if label := labels[len(code)]; label != "" {
		result = append(result, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: label}}, Raw: label + ":"})
	}
	return result, nil
}

// decodedX86SegmentMoveInstruction recognizes the complete 8C/8E segment
// register move family represented by Go 1.27's ymovtab. Go spells these
// operations MOVW even though x86 disassemblers often print register forms as
// MOVL or MOVQ according to the encoded general-register destination width.
func decodedX86SegmentMoveInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segmentOverride := Reg("")
	addressOverride := false
	rex := byte(0)
	for i < len(code) {
		switch code[i] {
		case 0x64:
			rex = 0
			segmentOverride = FS
			i++
		case 0x65:
			rex = 0
			segmentOverride = GS
			i++
		case 0x66:
			rex = 0
			i++
		case 0x67:
			rex = 0
			addressOverride = true
			i++
		default:
			if mode == 64 && code[i] >= 0x40 && code[i] <= 0x4f {
				rex = code[i]
				i++
				continue
			}
			goto opcode
		}
	}

opcode:
	if i >= len(code) || (code[i] != 0x8c && code[i] != 0x8e) || len(code) < i+2 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	modRM := code[i+1]
	segmentNumber := int(modRM>>3&7) + int(rex>>2&1)*8
	segmentNames := [...]Reg{ES, CS, SS, DS, FS, GS}
	if segmentNumber >= len(segmentNames) {
		return Instr{}, 0, true, fmt.Errorf("reserved segment-register encoding %d", segmentNumber)
	}
	bExt := int(rex & 1)
	xExt := int(rex>>1) & 1
	other, consumed, decodeErr := decodedX86RMSource(code[i+1:], mode, bExt, xExt, segmentOverride, 1)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	segment := Operand{Kind: OpReg, Reg: segmentNames[segmentNumber]}
	args := []Operand{segment, other}
	if code[i] == 0x8e {
		args[0], args[1] = args[1], args[0]
	}
	return Instr{
		Op:   "MOVW",
		Args: args,
		Raw:  fmt.Sprintf("MOVW %s, %s", args[0].String(), args[1].String()),
	}, i + 1 + consumed, true, nil
}

// decodedX86MaskMoveInstruction recognizes Go 1.27's complete VEX-encoded
// KMOVB/W/D/Q family. x/arch v0.14 does not decode opmask registers and can
// split these bytes into unrelated legacy instructions, so recover all four
// _ykmovb operand rows before consulting the generic decoder.
func decodedX86MaskMoveInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	var vexLength, rExt, xExt, bExt int
	var vexBits byte
	switch {
	case len(code) >= i+3 && code[i] == 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
	default:
		return Instr{}, 0, false, nil
	}
	opcodeIndex := i + vexLength
	if len(code) <= opcodeIndex || code[opcodeIndex] < 0x90 || code[opcodeIndex] > 0x93 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if vexBits&0x04 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.L must be zero")
	}
	if vexBits&0x78 != 0x78 {
		return Instr{}, 0, true, fmt.Errorf("VEX.vvvv must be 1111")
	}

	opcode := code[opcodeIndex]
	pp := vexBits & 3
	width64 := vexLength == 3 && vexBits&0x80 != 0
	width := ""
	if opcode == 0x90 || opcode == 0x91 {
		switch {
		case !width64 && pp == 1:
			width = "B"
		case !width64 && pp == 0:
			width = "W"
		case width64 && pp == 1:
			width = "D"
		case width64 && pp == 0:
			width = "Q"
		}
	} else {
		switch {
		case !width64 && pp == 1:
			width = "B"
		case !width64 && pp == 0:
			width = "W"
		case !width64 && pp == 3:
			width = "D"
		case width64 && pp == 3:
			width = "Q"
		}
	}
	if width == "" {
		return Instr{}, 0, true, fmt.Errorf("invalid VEX.W/pp combination")
	}

	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	mod := modRM >> 6
	regNumber := int(modRM>>3&7) + rExt*8
	rmNumber := int(modRM&7) + bExt*8
	kReg := func(number int) (Operand, error) {
		if number < 0 || number > 7 {
			return Operand{}, fmt.Errorf("invalid opmask register K%d", number)
		}
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", number))}, nil
	}
	gpReg := func(number int) (Operand, error) {
		reg, valid := decodedX86GeneralRegister(number)
		if !valid || mode == 32 && number >= 8 {
			return Operand{}, fmt.Errorf("invalid general register %d", number)
		}
		return Operand{Kind: OpReg, Reg: reg}, nil
	}

	var src, dst Operand
	consumed := 1
	switch opcode {
	case 0x90: // K-or-memory -> K
		dst, err = kReg(regNumber)
		if err != nil {
			return Instr{}, 0, true, err
		}
		if mod == 3 {
			src, err = kReg(rmNumber)
		} else {
			src, consumed, err = decodedX86VEXRMSource(code[modRMIndex:], mode, bExt, xExt, segment)
		}
	case 0x91: // K -> memory
		if mod == 3 {
			return Instr{}, 0, true, fmt.Errorf("opcode 91 requires a memory destination")
		}
		src, err = kReg(regNumber)
		if err == nil {
			dst, consumed, err = decodedX86VEXRMSource(code[modRMIndex:], mode, bExt, xExt, segment)
		}
	case 0x92: // GP -> K
		if mod != 3 {
			return Instr{}, 0, true, fmt.Errorf("opcode 92 requires a general-register source")
		}
		dst, err = kReg(regNumber)
		if err == nil {
			src, err = gpReg(rmNumber)
		}
	case 0x93: // K -> GP
		if mod != 3 {
			return Instr{}, 0, true, fmt.Errorf("opcode 93 requires a general-register destination")
		}
		src, err = kReg(rmNumber)
		if err == nil {
			dst, err = gpReg(regNumber)
		}
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	op := Op("KMOV" + width)
	instruction = Instr{
		Op:   op,
		Args: []Operand{src, dst},
		Raw:  fmt.Sprintf("%s %s, %s", op, src.String(), dst.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

// decodedX86EVEXPackedIntegerMoveInstruction recognizes the complete EVEX
// family behind Go 1.27's shared _yvmovdqa32 table. x/arch v0.14 cannot
// decode these encodings, including the raw VMOVDQU32 loads emitted by
// github.com/minio/sha256-simd. Decode all six opcodes and all twelve table
// rows before consulting the generic decoder.
func decodedX86EVEXPackedIntegerMoveInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	return decodedX86EVEXPackedMoveInstruction(code, mode, "packed integer move", func(pp byte, width64 bool, opcode byte) (Op, bool, bool) {
		store := opcode == 0x7f
		if opcode != 0x6f && !store {
			return "", false, false
		}
		switch {
		case pp == 1 && !width64:
			return "VMOVDQA32", store, true
		case pp == 1 && width64:
			return "VMOVDQA64", store, true
		case pp == 3 && !width64:
			return "VMOVDQU8", store, true
		case pp == 3 && width64:
			return "VMOVDQU16", store, true
		case pp == 2 && !width64:
			return "VMOVDQU32", store, true
		case pp == 2 && width64:
			return "VMOVDQU64", store, true
		default:
			return "", false, false
		}
	})
}

type decodedX86EVEXMoveMatcher func(pp byte, width64 bool, opcode byte) (op Op, store bool, ok bool)

func decodedX86EVEXPackedMoveInstruction(code []byte, mode int, family string, match decodedX86EVEXMoveMatcher) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+6 || code[i] != 0x62 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	if p0&0x0f != 1 || p1&0x04 == 0 || p1&0x78 != 0x78 || p2&0x08 == 0 {
		return Instr{}, 0, false, nil
	}
	pp := p1 & 3
	width64 := p1&0x80 != 0
	op, store, matched := match(pp, width64, opcode)
	if !matched {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if p2&0x10 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.b is not valid for %s", family)
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorPrefix := [...]string{"X", "Y", "Z"}[vectorBits]
	disp8Scale := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if zeroing && store && code[i+5]>>6 != 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing is invalid for a memory store")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	regNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	reg := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, regNumber))}
	rm, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}

	args := []Operand{rm, reg}
	if store {
		args[0], args[1] = reg, rm
	}
	if maskNumber != 0 {
		mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))}
		args = []Operand{args[0], mask, args[1]}
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	instruction = Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}
	return instruction, modRMIndex + consumed, true, nil
}

func decodedX86EVEXRMOperand(code []byte, mode, bExt, xExt int, segment Reg, vectorPrefix string, disp8Scale int) (Operand, int, error) {
	if len(code) == 0 {
		return Operand{}, 0, fmt.Errorf("missing ModRM byte")
	}
	if code[0]>>6 == 3 {
		number := int(code[0]&7) + bExt*8 + xExt*16
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, number))}, 1, nil
	}
	return decodedX86RMSource(code, mode, bExt, xExt, segment, disp8Scale)
}

func x86RawRelativeTarget(inst x86asm.Inst, offset int) (int, bool) {
	for _, arg := range inst.Args {
		if relative, ok := arg.(x86asm.Rel); ok {
			return offset + inst.Len + int(relative), true
		}
	}
	return 0, false
}

// decodedX86VMOVQInstruction recognizes the complete Go 1.27 _yvmovd and
// _yvmovq families. VMOVD has the X-to-GP/memory and reverse forms; VMOVQ
// additionally has two X-to-X encodings. Recover every VEX and EVEX form
// before consulting the generic decoder, which can split the raw VMOVD bytes
// emitted by Weaviate into a relative branch. Raw AVX512-FP16 VMOVW uses the
// same operand grammar with a two-byte transfer and a distinct opcode map.
func decodedX86VMOVQInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXVMOVDQInstruction(code, i, mode, segment, addressOverride)
	}
	if len(code) < i+3 {
		return Instr{}, 0, false, nil
	}

	var rExt, xExt, bExt, vexLength int
	var vexBits byte
	switch code[i] {
	case 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
	case 0xc4:
		if len(code) < i+4 || code[i+1]&0x1f != 1 {
			return Instr{}, 0, false, nil
		}
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
	default:
		return Instr{}, 0, false, nil
	}
	opcodeIndex := i + vexLength
	if len(code) <= opcodeIndex {
		return Instr{}, 0, false, nil
	}

	opcode := code[opcodeIndex]
	pp := vexBits & 3
	width64 := vexLength == 3 && vexBits&0x80 != 0
	type vmovqDirection int
	const (
		xToGeneral vmovqDirection = iota
		xToVector
		generalToX
		vectorToX
	)
	op := Op("")
	direction := xToGeneral
	switch {
	case opcode == 0x7e && pp == 1 && !width64:
		op = "VMOVD"
		direction = xToGeneral
	case opcode == 0x6e && pp == 1 && !width64:
		op = "VMOVD"
		direction = generalToX
	case opcode == 0x7e && pp == 1 && width64:
		op = "VMOVQ"
		direction = xToGeneral
	case opcode == 0xd6 && pp == 1 && !width64:
		op = "VMOVQ"
		direction = xToVector
	case opcode == 0x6e && pp == 1 && width64:
		op = "VMOVQ"
		direction = generalToX
	case opcode == 0x7e && pp == 2 && !width64:
		op = "VMOVQ"
		direction = vectorToX
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexBits&0x7c != 0x78 {
		return Instr{}, 0, true, fmt.Errorf("VEX.vvvv must be 1111 and VEX.L must be zero")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	vectorNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || vectorNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	vector := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", vectorNumber))}
	rmVector := direction == xToVector || direction == vectorToX
	rm, consumed, decodeErr := decodedX86VEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, rmVector)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	if mode == 32 && width64 && rm.Kind == OpReg {
		return Instr{}, 0, true, fmt.Errorf("64-bit general register is unavailable in 32-bit mode")
	}

	args := []Operand{vector, rm}
	if direction == generalToX || direction == vectorToX {
		args[0], args[1] = rm, vector
	}
	instruction = Instr{
		Op:   op,
		Args: args,
		Raw:  fmt.Sprintf("%s %s, %s", op, args[0].String(), args[1].String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

func decodedX86EVEXVMOVDQInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+5 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	wordMove := p0&0x0f == 5 && p1&3 == 1 && (opcode == 0x6e || opcode == 0x7e)
	if p0&0x0f != 1 && !wordMove {
		return Instr{}, 0, false, nil
	}
	if p1&0x04 == 0 || p1&0x78 != 0x78 || p2 != 0x08 {
		if wordMove {
			return Instr{}, 0, true, fmt.Errorf("VMOVW requires reserved vvvv, fixed 128-bit length, and no mask or broadcast")
		}
		return Instr{}, 0, false, nil
	}
	pp := p1 & 3
	width64 := p1&0x80 != 0
	type vmovdqDirection int
	const (
		xToGeneral vmovdqDirection = iota
		xToVector
		generalToX
		vectorToX
	)
	op := Op("")
	direction := xToGeneral
	switch {
	case wordMove:
		op = "VMOVW"
		if opcode == 0x6e {
			direction = generalToX
		}
	case opcode == 0x7e && pp == 1 && !width64:
		op = "VMOVD"
		direction = xToGeneral
	case opcode == 0x6e && pp == 1 && !width64:
		op = "VMOVD"
		direction = generalToX
	case opcode == 0x7e && pp == 1 && width64:
		op = "VMOVQ"
		direction = xToGeneral
	case opcode == 0xd6 && pp == 1 && width64:
		op = "VMOVQ"
		direction = xToVector
	case opcode == 0x6e && pp == 1 && width64:
		op = "VMOVQ"
		direction = generalToX
	case opcode == 0x7e && pp == 2 && width64:
		op = "VMOVQ"
		direction = vectorToX
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	modRMIndex := i + 5
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	vectorNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	rmVector := direction == xToVector || direction == vectorToX
	if mode == 32 && (vectorNumber >= 8 || rmVector && modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	if modRM>>6 == 3 && !rmVector && xExt != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.X cannot extend a general register")
	}
	vector := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", vectorNumber))}
	transferBytes := 4
	if wordMove {
		transferBytes = 2
	} else if op == "VMOVQ" {
		transferBytes = 8
	}
	var rm Operand
	var consumed int
	var decodeErr error
	if rmVector {
		rm, consumed, decodeErr = decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X", transferBytes)
	} else {
		rm, consumed, decodeErr = decodedX86RMSource(code[modRMIndex:], mode, bExt, xExt, segment, transferBytes)
	}
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	if mode == 32 && op == "VMOVQ" && rm.Kind == OpReg && !rmVector {
		return Instr{}, 0, true, fmt.Errorf("64-bit general register is unavailable in 32-bit mode")
	}
	args := []Operand{vector, rm}
	if direction == generalToX || direction == vectorToX {
		args[0], args[1] = rm, vector
	}
	instruction = Instr{
		Op:         op,
		Args:       args,
		Raw:        fmt.Sprintf("%s %s, %s", op, args[0].String(), args[1].String()),
		x86Encoded: wordMove,
	}
	return instruction, modRMIndex + consumed, true, nil
}

func decodedX86VEXRMOperand(code []byte, mode, bExt, xExt int, segment Reg, vectorRegister bool) (Operand, int, error) {
	if len(code) == 0 {
		return Operand{}, 0, fmt.Errorf("missing ModRM byte")
	}
	if code[0]>>6 != 3 || !vectorRegister {
		return decodedX86VEXRMSource(code, mode, bExt, xExt, segment)
	}
	number := int(code[0]&7) + bExt*8
	if mode == 32 && number >= 8 {
		return Operand{}, 0, fmt.Errorf("extended vector register in 32-bit mode")
	}
	return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", number))}, 1, nil
}

// decodedX86VEXNonTemporalMoveInstruction recognizes the complete VEX.128 and
// VEX.256 non-temporal vector-move family before x/arch's generic decoder.
// x/arch v0.14 loses the VEX.L register width for VMOVNTDQ/VMOVNTDQA and can
// decode VMOVNTPD/VMOVNTPS as legacy integer subtraction. EVEX forms are not
// handled here because the generic decoder preserves their X/Y/Z widths.
func decodedX86VEXNonTemporalMoveInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+3 {
		return Instr{}, 0, false, nil
	}

	var rExt, xExt, bExt, vexLength, opcodeMap int
	var vexBits byte
	switch code[i] {
	case 0xc5:
		vexLength = 2
		opcodeMap = 1
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
	case 0xc4:
		if len(code) < i+4 {
			return Instr{}, 0, false, nil
		}
		vexLength = 3
		opcodeMap = int(code[i+1] & 0x1f)
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
	default:
		return Instr{}, 0, false, nil
	}
	opcodeIndex := i + vexLength
	if len(code) <= opcodeIndex {
		return Instr{}, 0, false, nil
	}

	opcode := code[opcodeIndex]
	prefix := vexBits & 3
	load := false
	op := Op("")
	switch {
	case opcodeMap == 1 && opcode == 0xe7 && prefix == 1:
		op = "VMOVNTDQ"
	case opcodeMap == 1 && opcode == 0x2b && prefix == 1:
		op = "VMOVNTPD"
	case opcodeMap == 1 && opcode == 0x2b && prefix == 0:
		op = "VMOVNTPS"
	case opcodeMap == 2 && opcode == 0x2a && prefix == 1:
		op = "VMOVNTDQA"
		load = true
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexLength == 3 && vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	if vexBits&0x78 != 0x78 {
		return Instr{}, 0, true, fmt.Errorf("VEX.vvvv must be 1111")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	if modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("register r/m operand is absent from Go 1.27's %s table", op)
	}
	vectorNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || vectorNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	vector := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, vectorNumber))}
	memory, consumed, decodeErr := decodedX86VEXRMSource(code[modRMIndex:], mode, bExt, xExt, segment)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	args := []Operand{vector, memory}
	if load {
		args[0], args[1] = memory, vector
	}
	instruction = Instr{
		Op:   op,
		Args: args,
		Raw:  fmt.Sprintf("%s %s, %s", op, args[0].String(), args[1].String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

// decodedX86VINSERT128Instruction recognizes the complete VEX
// VINSERTF128/VINSERTI128 family. x/arch v0.14 can misclassify the bytes that
// follow these instructions as PC-relative control flow.
func decodedX86VINSERT128Instruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if len(code) < i+5 || code[i] != 0xc4 || code[i+1]&0x1f != 3 {
		return Instr{}, 0, false, nil
	}
	op, recognized := map[byte]Op{0x18: "VINSERTF128", 0x38: "VINSERTI128"}[code[i+3]]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if mode != 32 && mode != 64 {
		return Instr{}, 0, true, fmt.Errorf("unsupported x86 mode %d", mode)
	}
	if mode == 32 {
		return Instr{}, 0, true, fmt.Errorf("386 %s exceeds the Go assembler frontend's operand limit", op)
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	vex0, vexBits := code[i+1], code[i+2]
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	if vexBits&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("%s requires VEX.256", op)
	}
	rExt := int(^vex0>>7) & 1
	xExt := int(^vex0>>6) & 1
	bExt := int(^vex0>>5) & 1
	modRMIndex := i + 4
	modRM := code[modRMIndex]
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(modRM>>3&7) + rExt*8
	firstSource, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Y%d", secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Y%d", destinationNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{immediate, firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s, %s", op, immediate.String(), firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, immediateIndex + 1, true, nil
}

// decodedX86EVEXPackedInsertInstruction recognizes every EVEX row in Go
// 1.27's _yvinsertf32x4 and _yvinsertf32x8 tables. The floating and integer
// spellings share their encodings apart from the opcode, while EVEX.W selects
// 32- or 64-bit lane names. This includes Y/Z output widths, register and
// memory insert sources, and optional merge/zero masks.
func decodedX86EVEXPackedInsertInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if len(code) < i+5 || code[i] != 0x62 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	if p0&0x0f != 3 || p1&3 != 1 {
		return Instr{}, 0, false, nil
	}
	integer := opcode == 0x38 || opcode == 0x3a
	wideInsert := opcode == 0x1a || opcode == 0x3a
	if opcode != 0x18 && opcode != 0x1a && !integer {
		return Instr{}, 0, false, nil
	}
	ok = true
	if mode == 32 {
		return Instr{}, 0, true, fmt.Errorf("EVEX packed vector inserts are unavailable in 32-bit mode")
	}
	if p1&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX fixed bit must be one")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if p2&0x10 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.b is unavailable for packed vector inserts")
	}
	vectorBits := p2 >> 5 & 3
	if wideInsert {
		if vectorBits != 2 {
			return Instr{}, 0, true, fmt.Errorf("wide packed vector insert requires a Z output")
		}
	} else if vectorBits != 1 && vectorBits != 2 {
		return Instr{}, 0, true, fmt.Errorf("packed vector insert requires a Y or Z output")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	insertBytes := 16
	sourceName := "X"
	laneBits := 32
	if p1&0x80 != 0 {
		laneBits = 64
	}
	if wideInsert {
		insertBytes = 32
		sourceName = "Y"
	}
	stem := "VINSERTF"
	if integer {
		stem = "VINSERTI"
	}
	op := Op(fmt.Sprintf("%s%dX%d", stem, laneBits, insertBytes*8/laneBits))
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}

	modRMIndex := i + 5
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	secondNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	first, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, sourceName, insertBytes)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{immediate, first, second}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, immediateIndex + 1, true, nil
}

// decodedX86VEXPackedBroadcastInstruction recognizes the complete VEX and EVEX
// VPBROADCASTB/W/D/Q family represented by Go 1.27's _yvpbroadcastb table.
// x/arch v0.14 can misclassify the VEX bytes as PC-relative branches, as
// observed in github.com/vivint/infectious, and cannot decode the EVEX
// general-register form used by github.com/JohanLindvall/haste.
func decodedX86VEXPackedBroadcastInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXPackedBroadcastInstruction(code, i, mode, segment, addressOverride)
	}
	if len(code) < i+5 || code[i] != 0xc4 || code[i+1]&0x1f != 2 {
		return Instr{}, 0, false, nil
	}
	op, recognized := map[byte]Op{
		0x78: "VPBROADCASTB",
		0x79: "VPBROADCASTW",
		0x58: "VPBROADCASTD",
		0x59: "VPBROADCASTQ",
	}[code[i+3]]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if mode != 32 && mode != 64 {
		return Instr{}, 0, true, fmt.Errorf("unsupported x86 mode %d", mode)
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	vex0, vexBits := code[i+1], code[i+2]
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	if int(^vexBits>>3)&15 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.vvvv must be 1111")
	}
	rExt := int(^vex0>>7) & 1
	xExt := int(^vex0>>6) & 1
	bExt := int(^vex0>>5) & 1
	modRMIndex := i + 4
	modRM := code[modRMIndex]
	destinationNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	vectorName := "X"
	if vexBits&0x04 != 0 {
		vectorName = "Y"
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{source, destination},
		Raw:  fmt.Sprintf("%s %s, %s", op, source.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

func decodedX86EVEXPackedBroadcastInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+5 || code[i] != 0x62 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	if p0&0x0f != 2 || p1&3 != 1 {
		return Instr{}, 0, false, nil
	}
	width64 := p1&0x80 != 0
	vectorSource := false
	laneBytes := 0
	op := Op("")
	switch opcode {
	case 0x7a:
		op, laneBytes = "VPBROADCASTB", 1
	case 0x7b:
		op, laneBytes = "VPBROADCASTW", 2
	case 0x7c:
		if width64 {
			op, laneBytes = "VPBROADCASTQ", 8
		} else {
			op, laneBytes = "VPBROADCASTD", 4
		}
	case 0x78:
		op, laneBytes, vectorSource = "VPBROADCASTB", 1, true
	case 0x79:
		op, laneBytes, vectorSource = "VPBROADCASTW", 2, true
	case 0x58:
		op, laneBytes, vectorSource = "VPBROADCASTD", 4, true
	case 0x59:
		op, laneBytes, vectorSource = "VPBROADCASTQ", 8, true
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if (!vectorSource || opcode != 0x59) && opcode != 0x7c && width64 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W must be zero for %s", op)
	}
	if vectorSource && opcode == 0x59 && !width64 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W must be one for %s", op)
	}
	if p1&0x7c != 0x7c || p2&0x08 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.vvvv must be reserved")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if p2&0x10 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.b is unavailable for packed scalar broadcasts")
	}
	vectorBits := p2 >> 5 & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}

	modRMIndex := i + 5
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && destinationNumber >= 8 {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}

	var source Operand
	consumed := 0
	if vectorSource {
		if mode == 32 && modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8 {
			return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
		}
		source, consumed, err = decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X", laneBytes)
	} else {
		if modRM>>6 != 3 {
			return Instr{}, 0, true, fmt.Errorf("EVEX opcode %#x requires a general-register source", opcode)
		}
		if xExt != 0 {
			return Instr{}, 0, true, fmt.Errorf("EVEX.X cannot extend a general register")
		}
		if mode == 32 && laneBytes == 8 {
			return Instr{}, 0, true, fmt.Errorf("64-bit general register is unavailable in 32-bit mode")
		}
		source, consumed, err = decodedX86RMSource(code[modRMIndex:], mode, bExt, 0, segment, laneBytes)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	args := []Operand{source}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

// decodedX86PackedAlignRightInstruction recognizes every raw PALIGNR and
// VPALIGNR encoding represented by Go 1.27's ypalignr and
// _yvgf2p8affineinvqb tables: legacy X, VEX X/Y, and EVEX X/Y/Z with optional
// merge/zero masks. x/arch v0.14 rejects the VEX bytes used by the historical
// sha256-simd copy in github.com/ipfs/fs-repo-migrations.
func decodedX86PackedAlignRightInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	hasDataSizePrefix := false
	rex := byte(0)
	hasREX := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			rex = 0
			hasREX = false
			segment = FS
			i++
		case 0x65:
			rex = 0
			hasREX = false
			segment = GS
			i++
		case 0x66:
			rex = 0
			hasREX = false
			hasDataSizePrefix = true
			i++
		case 0x67:
			rex = 0
			hasREX = false
			addressOverride = true
			i++
		default:
			if mode == 64 && code[i] >= 0x40 && code[i] <= 0x4f {
				rex = code[i]
				hasREX = true
				i++
				continue
			}
			goto opcode
		}
	}

opcode:
	if i >= len(code) {
		return Instr{}, 0, false, nil
	}
	if code[i] == 0xc4 {
		if hasDataSizePrefix || hasREX || len(code) < i+5 || code[i+1]&0x1f != 3 || code[i+3] != 0x0f {
			return Instr{}, 0, false, nil
		}
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		if mode == 32 {
			return Instr{}, 0, true, fmt.Errorf("386 VPALIGNR exceeds the Go assembler frontend's operand limit")
		}
		vex0, vexBits := code[i+1], code[i+2]
		if vexBits&3 != 1 {
			return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
		}
		if vexBits&0x80 != 0 {
			return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
		}
		vectorName := "X"
		if vexBits&0x04 != 0 {
			vectorName = "Y"
		}
		rExt := int(^vex0>>7) & 1
		xExt := int(^vex0>>6) & 1
		bExt := int(^vex0>>5) & 1
		modRMIndex := i + 4
		modRM := code[modRMIndex]
		firstSource, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName)
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		immediateIndex := modRMIndex + consumed
		if len(code) <= immediateIndex {
			return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
		}
		secondSourceNumber := int(^vexBits>>3) & 15
		destinationNumber := int(modRM>>3&7) + rExt*8
		args := []Operand{
			{Kind: OpImm, Imm: int64(code[immediateIndex])},
			firstSource,
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondSourceNumber))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))},
		}
		rawArgs := make([]string, len(args))
		for index := range args {
			rawArgs[index] = args[index].String()
		}
		return Instr{Op: "VPALIGNR", Args: args, Raw: "VPALIGNR " + strings.Join(rawArgs, ", ")}, immediateIndex + 1, true, nil
	}
	if code[i] == 0x62 {
		if hasDataSizePrefix || hasREX || len(code) < i+6 || code[i+1]&0x0f != 3 || code[i+2]&0x07 != 5 || code[i+4] != 0x0f {
			return Instr{}, 0, false, nil
		}
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		if mode == 32 {
			return Instr{}, 0, true, fmt.Errorf("386 VPALIGNR exceeds the Go assembler frontend's operand limit")
		}
		p0, p1, p2 := code[i+1], code[i+2], code[i+3]
		if p1&0x80 != 0 {
			return Instr{}, 0, true, fmt.Errorf("EVEX.W must be zero")
		}
		vectorBits := p2 >> 5 & 3
		if vectorBits == 3 {
			return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
		}
		if p2&0x10 != 0 {
			return Instr{}, 0, true, fmt.Errorf("EVEX broadcast is absent from Go 1.27's VPALIGNR table")
		}
		vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
		vectorWidth := [...]int{16, 32, 64}[vectorBits]
		maskNumber := int(p2 & 7)
		zeroing := p2&0x80 != 0
		if zeroing && maskNumber == 0 {
			return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
		}
		rExt := int(^p0>>7) & 1
		rHighExt := int(^p0>>4) & 1
		xExt := int(^p0>>6) & 1
		bExt := int(^p0>>5) & 1
		modRMIndex := i + 5
		modRM := code[modRMIndex]
		firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, vectorWidth)
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		immediateIndex := modRMIndex + consumed
		if len(code) <= immediateIndex {
			return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
		}
		secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
		destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
		op := Op("VPALIGNR")
		args := []Operand{
			{Kind: OpImm, Imm: int64(code[immediateIndex])},
			firstSource,
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondSourceNumber))},
		}
		if maskNumber != 0 {
			args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
		}
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))})
		if zeroing {
			op += ".Z"
		}
		rawArgs := make([]string, len(args))
		for index := range args {
			rawArgs[index] = args[index].String()
		}
		return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, immediateIndex + 1, true, nil
	}

	if !hasDataSizePrefix || len(code) < i+5 || code[i] != 0x0f || code[i+1] != 0x3a || code[i+2] != 0x0f {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if hasREX && rex&0x08 != 0 {
		return Instr{}, 0, true, fmt.Errorf("REX.W is absent from Go 1.27's PALIGNR encoding")
	}
	rExt := int(rex>>2) & 1
	xExt := int(rex>>1) & 1
	bExt := int(rex & 1)
	modRMIndex := i + 3
	modRM := code[modRMIndex]
	destinationNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && (destinationNumber >= 8 || bExt != 0 || xExt != 0) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
	instruction = Instr{
		Op:   "PALIGNR",
		Args: []Operand{immediate, source, destination},
		Raw:  fmt.Sprintf("PALIGNR %s, %s, %s", immediate.String(), source.String(), destination.String()),
	}
	return instruction, immediateIndex + 1, true, nil
}

// decodedX86Permute128Instruction recognizes every raw VPERM2F128 and
// VPERM2I128 encoding represented by Go 1.27's _yvperm2f128 table: an
// immediate, Y/m256 first source, Y second source, and Y destination.
func decodedX86Permute128Instruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	hasLegacyPrefix := false
	hasREX := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			hasREX = false
			segment = FS
			i++
		case 0x65:
			hasREX = false
			segment = GS
			i++
		case 0x66:
			hasREX = false
			hasLegacyPrefix = true
			i++
		case 0x67:
			hasREX = false
			addressOverride = true
			i++
		default:
			if mode == 64 && code[i] >= 0x40 && code[i] <= 0x4f {
				hasREX = true
				i++
				continue
			}
			goto opcode
		}
	}

opcode:
	if i >= len(code) || code[i] != 0xc4 || hasLegacyPrefix || hasREX || len(code) < i+5 {
		return Instr{}, 0, false, nil
	}
	vex0, vexBits, opcode := code[i+1], code[i+2], code[i+3]
	if vex0&0x1f != 3 || (opcode != 0x06 && opcode != 0x46) {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if mode == 32 {
		return Instr{}, 0, true, fmt.Errorf("386 VPERM2F128/VPERM2I128 exceeds the Go assembler frontend's operand limit")
	}
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	if vexBits&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.L must select 256-bit vectors")
	}
	rExt := int(^vex0>>7) & 1
	xExt := int(^vex0>>6) & 1
	bExt := int(^vex0>>5) & 1
	modRMIndex := i + 4
	modRM := code[modRMIndex]
	firstSource, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "Y")
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	op := Op("VPERM2F128")
	if opcode == 0x46 {
		op = "VPERM2I128"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(modRM>>3&7) + rExt*8
	args := []Operand{
		{Kind: OpImm, Imm: int64(code[immediateIndex])},
		firstSource,
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Y%d", secondSourceNumber))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Y%d", destinationNumber))},
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, immediateIndex + 1, true, nil
}

// decodedX86InsertPSInstruction recognizes all encodings represented by Go
// 1.27's yxshuf and _yvinsertps tables: legacy INSERTPS plus VEX and EVEX
// VINSERTPS, each with an X-register or ModRM/SIB memory source. x/arch v0.14
// can consume one byte past VINSERTPS and desynchronize the rest of a raw
// directive group, as observed in github.com/racerxdl/segdsp.
func decodedX86InsertPSInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto encoding
		}
	}

encoding:
	if len(code) <= i {
		return Instr{}, 0, false, nil
	}

	if code[i] == 0x66 {
		j := i + 1
		rex := byte(0)
		if j < len(code) && code[j]&0xf0 == 0x40 {
			rex = code[j]
			j++
		}
		if len(code) < j+4 || code[j] != 0x0f || code[j+1] != 0x3a || code[j+2] != 0x21 {
			return Instr{}, 0, false, nil
		}
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		if mode == 32 && rex != 0 {
			return Instr{}, 0, true, fmt.Errorf("REX prefix in 32-bit mode")
		}
		modRMIndex := j + 3
		modRM := code[modRMIndex]
		rExt := int(rex>>2) & 1
		xExt := int(rex>>1) & 1
		bExt := int(rex) & 1
		destinationNumber := int(modRM>>3&7) + rExt*8
		if mode == 32 && destinationNumber >= 8 {
			return Instr{}, 0, true, fmt.Errorf("extended destination register in 32-bit mode")
		}
		source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		immediateIndex := modRMIndex + consumed
		if len(code) <= immediateIndex {
			return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
		}
		immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
		return Instr{
			Op:   "INSERTPS",
			Args: []Operand{immediate, source, destination},
			Raw:  fmt.Sprintf("INSERTPS %s, %s, %s", immediate.String(), source.String(), destination.String()),
		}, immediateIndex + 1, true, nil
	}

	if code[i] == 0xc4 {
		if len(code) < i+5 || code[i+1]&0x1f != 3 || code[i+3] != 0x21 {
			return Instr{}, 0, false, nil
		}
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		p0, p1 := code[i+1], code[i+2]
		if p1&0x87 != 0x01 {
			return Instr{}, 0, true, fmt.Errorf("VINSERTPS requires VEX.W0.L0.66")
		}
		modRMIndex := i + 4
		modRM := code[modRMIndex]
		rExt := int(^p0>>7) & 1
		xExt := int(^p0>>6) & 1
		bExt := int(^p0>>5) & 1
		baseNumber := int(^p1>>3) & 15
		destinationNumber := int(modRM>>3&7) + rExt*8
		if mode == 32 && (baseNumber >= 8 || destinationNumber >= 8) {
			return Instr{}, 0, true, fmt.Errorf("extended VINSERTPS register in 32-bit mode")
		}
		source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		immediateIndex := modRMIndex + consumed
		if len(code) <= immediateIndex {
			return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
		}
		immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
		base := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", baseNumber))}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
		return Instr{
			Op:   "VINSERTPS",
			Args: []Operand{immediate, source, base, destination},
			Raw:  fmt.Sprintf("VINSERTPS %s, %s, %s, %s", immediate.String(), source.String(), base.String(), destination.String()),
		}, immediateIndex + 1, true, nil
	}

	if code[i] != 0x62 || len(code) < i+6 || code[i+1]&0x0f != 3 || code[i+4] != 0x21 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if mode == 32 {
		return Instr{}, 0, true, fmt.Errorf("EVEX VINSERTPS is unavailable in 32-bit mode")
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p1&0x87 != 0x05 || p2&0xf7 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VINSERTPS requires EVEX.W0.L0.66 without mask, zeroing, or broadcast")
	}
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	baseNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	source, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X", 4)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	base := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", baseNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
	return Instr{
		Op:   "VINSERTPS",
		Args: []Operand{immediate, source, base, destination},
		Raw:  fmt.Sprintf("VINSERTPS %s, %s, %s, %s", immediate.String(), source.String(), base.String(), destination.String()),
	}, immediateIndex + 1, true, nil
}

// decodedX86PackedScalarExtractInstruction recognizes every VEX and EVEX
// encoding row shared by Go 1.27's _yvextractps and _yvpextrw tables:
// VEXTRACTPS and VPEXTRB/W/D/Q with GP-register or ModRM/SIB memory
// destinations. x/arch v0.14 does not decode VEXTRACTPS and can interpret
// bytes after other scalar extracts as instructions or PC-relative operands,
// so recover the complete family before consulting the generic decoder.
func decodedX86PackedScalarExtractInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto prefix
		}
	}

prefix:
	if len(code) <= i {
		return Instr{}, 0, false, nil
	}
	var (
		mapNumber       byte
		opcode          byte
		width64         bool
		rExt            int
		rHighExt        int
		xExt            int
		bExt            int
		modRMIndex      int
		disp8Scale      = 1
		evex            bool
		twoByteVEX      bool
		prefixValidated bool
	)
	switch code[i] {
	case 0xc4:
		if len(code) < i+4 {
			return Instr{}, 0, false, nil
		}
		mapNumber = code[i+1] & 0x1f
		opcode = code[i+3]
		width64 = code[i+2]&0x80 != 0
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		modRMIndex = i + 4
		prefixValidated = code[i+2]&0x7f == 0x79
	case 0xc5:
		if len(code) < i+3 {
			return Instr{}, 0, false, nil
		}
		mapNumber = 1
		opcode = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		modRMIndex = i + 3
		twoByteVEX = true
		prefixValidated = code[i+1]&0x7f == 0x79
	case 0x62:
		if len(code) < i+5 {
			return Instr{}, 0, false, nil
		}
		evex = true
		mapNumber = code[i+1] & 0x0f
		opcode = code[i+4]
		width64 = code[i+2]&0x80 != 0
		rExt = int(^code[i+1]>>7) & 1
		rHighExt = int(^code[i+1]>>4) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		modRMIndex = i + 5
		prefixValidated = code[i+2]&0x7f == 0x7d && code[i+3] == 0x08
	default:
		return Instr{}, 0, false, nil
	}

	var op Op
	laneBytes := 0
	expectedWidth64 := false
	switch {
	case mapNumber == 3 && opcode == 0x14:
		op, laneBytes = "VPEXTRB", 1
	case mapNumber == 3 && opcode == 0x15:
		op, laneBytes = "VPEXTRW", 2
	case mapNumber == 3 && opcode == 0x16 && !width64:
		op, laneBytes = "VPEXTRD", 4
	case mapNumber == 3 && opcode == 0x16 && width64:
		op, laneBytes, expectedWidth64 = "VPEXTRQ", 8, true
	case mapNumber == 3 && opcode == 0x17:
		op, laneBytes = "VEXTRACTPS", 4
	case mapNumber == 1 && opcode == 0xc5:
		op, laneBytes = "VPEXTRW", 2
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if !prefixValidated {
		return Instr{}, 0, true, fmt.Errorf("reserved vvvv, vector length, prefix, or EVEX mask bits are invalid")
	}
	if width64 != expectedWidth64 {
		return Instr{}, 0, true, fmt.Errorf("invalid W bit for %s", op)
	}
	if evex {
		if mode == 32 {
			return Instr{}, 0, true, fmt.Errorf("EVEX packed scalar extracts are unavailable in 32-bit mode")
		}
		disp8Scale = laneBytes
	}
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	sourceNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && sourceNumber >= 8 {
		return Instr{}, 0, true, fmt.Errorf("extended source register in 32-bit mode")
	}
	destination, consumed, decodeErr := decodedX86RMSource(code[modRMIndex:], mode, bExt, xExt, segment, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	if mapNumber == 1 && destination.Kind != OpReg {
		return Instr{}, 0, true, fmt.Errorf("VEX map-1 VPEXTRW requires a GP-register destination")
	}
	if evex && destination.Kind == OpReg && xExt != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX packed scalar extract destination is outside the GP-register class")
	}
	if twoByteVEX && destination.Kind == OpReg && bExt != 0 {
		return Instr{}, 0, true, fmt.Errorf("two-byte VEX cannot encode an extended destination register")
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	source := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", sourceNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{immediate, source, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, immediate.String(), source.String(), destination.String()),
	}
	return instruction, immediateIndex + 1, true, nil
}

// decodedX86VPERMQInstruction recognizes the complete VEX.256 immediate
// VPERMQ Y/m256, Y family. x/arch v0.14 can misclassify its trailing immediate
// as a PC-relative operand, so recover register and ModRM/SIB memory forms
// before consulting the generic decoder. EVEX forms are decoded correctly by
// x/arch and continue through the ordinary path.
func decodedX86VPERMQInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if len(code) < i+4 || code[i] != 0xc4 || code[i+1]&0x1f != 3 || code[i+3] != 0x00 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if mode != 32 && mode != 64 {
		return Instr{}, 0, true, fmt.Errorf("unsupported x86 mode %d", mode)
	}
	if code[i+2] != 0xfd {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be one, VEX.vvvv must be 1111, VEX.L must be one, and VEX.pp must be 66")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	vex1 := code[i+1]
	rExt := int(^vex1>>7) & 1
	xExt := int(^vex1>>6) & 1
	bExt := int(^vex1>>5) & 1
	modRMIndex := i + 4
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	source, consumed, err := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "Y")
	if err != nil {
		return Instr{}, 0, true, err
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Y%d", destinationNumber))}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	instruction = Instr{
		Op:   "VPERMQ",
		Args: []Operand{immediate, source, destination},
		Raw:  fmt.Sprintf("VPERMQ %s, %s, %s", immediate.String(), source.String(), destination.String()),
	}
	return instruction, immediateIndex + 1, true, nil
}

// decodedX86ScalarPrecisionConvertInstruction recognizes the complete
// CVTSS2SD/CVTSD2SS and VCVTSS2SD/VCVTSD2SS family represented by Go 1.27's
// legacy yxm and EVEX-aware _yvaddsd tables. Besides VEX and legacy forms it
// handles EVEX high X registers, memory, masks, zeroing, SAE, and all four
// embedded rounding modes. x/arch v0.14 can split VCVTSD2SS into POP/ROLL.
func decodedX86ScalarPrecisionConvertInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto encoding
		}
	}

encoding:
	if len(code) <= i {
		return Instr{}, 0, false, nil
	}

	// Legacy F2/F3 0F 5A /r forms overwrite their X destination.
	j := i
	if code[j] == 0xf2 || code[j] == 0xf3 {
		prefix := code[j]
		j++
		rex := byte(0)
		if j < len(code) && code[j]&0xf0 == 0x40 {
			rex = code[j]
			j++
		}
		if len(code) >= j+3 && code[j] == 0x0f && code[j+1] == 0x5a {
			ok = true
			if addressOverride {
				return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
			}
			if mode == 32 && rex != 0 {
				return Instr{}, 0, true, fmt.Errorf("REX prefix in 32-bit mode")
			}
			op := Op("CVTSD2SS")
			if prefix == 0xf3 {
				op = "CVTSS2SD"
			}
			modRMIndex := j + 2
			modRM := code[modRMIndex]
			rExt := int(rex>>2) & 1
			xExt := int(rex>>1) & 1
			bExt := int(rex) & 1
			destinationNumber := int(modRM>>3&7) + rExt*8
			if mode == 32 && destinationNumber >= 8 {
				return Instr{}, 0, true, fmt.Errorf("extended destination register in 32-bit mode")
			}
			source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
			if decodeErr != nil {
				return Instr{}, 0, true, decodeErr
			}
			destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
			return Instr{Op: op, Args: []Operand{source, destination}, Raw: fmt.Sprintf("%s %s, %s", op, source.String(), destination.String())}, modRMIndex + consumed, true, nil
		}
	}

	if code[i] == 0xc4 || code[i] == 0xc5 {
		var vexLength, rExt, xExt, bExt int
		var vexBits, opcode byte
		switch code[i] {
		case 0xc5:
			if len(code) < i+4 {
				return Instr{}, 0, false, nil
			}
			vexLength = 2
			vexBits = code[i+1]
			rExt = int(^vexBits>>7) & 1
			opcode = code[i+2]
		case 0xc4:
			if len(code) < i+5 || code[i+1]&0x1f != 1 {
				return Instr{}, 0, false, nil
			}
			vexLength = 3
			vexBits = code[i+2]
			rExt = int(^code[i+1]>>7) & 1
			xExt = int(^code[i+1]>>6) & 1
			bExt = int(^code[i+1]>>5) & 1
			opcode = code[i+3]
		}
		if opcode != 0x5a || (vexBits&3 != 2 && vexBits&3 != 3) {
			return Instr{}, 0, false, nil
		}
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		if vexLength == 3 && vexBits&0x80 != 0 {
			return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
		}
		if vexBits&0x04 != 0 {
			return Instr{}, 0, true, fmt.Errorf("scalar precision conversion requires VEX.128")
		}
		op := Op("VCVTSD2SS")
		if vexBits&3 == 2 {
			op = "VCVTSS2SD"
		}
		opcodeIndex := i + vexLength
		modRMIndex := opcodeIndex + 1
		modRM := code[modRMIndex]
		first, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		secondNumber := int(^vexBits>>3) & 15
		destinationNumber := int(modRM>>3&7) + rExt*8
		if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondNumber >= 8 || destinationNumber >= 8) {
			return Instr{}, 0, true, fmt.Errorf("extended VEX register in 32-bit mode")
		}
		second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", secondNumber))}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
		return Instr{Op: op, Args: []Operand{first, second, destination}, Raw: fmt.Sprintf("%s %s, %s, %s", op, first.String(), second.String(), destination.String())}, modRMIndex + consumed, true, nil
	}

	if len(code) < i+6 || code[i] != 0x62 || code[i+1]&0x0f != 1 || code[i+4] != 0x5a {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	prefix := p1 & 3
	wBit := p1&0x80 != 0
	op := Op("")
	inputBytes := 0
	supportsRounding := false
	switch prefix {
	case 3:
		op = "VCVTSD2SS"
		inputBytes = 8
		supportsRounding = true
		if !wBit {
			return Instr{}, 0, true, fmt.Errorf("VCVTSD2SS requires EVEX.W1")
		}
	case 2:
		op = "VCVTSS2SD"
		inputBytes = 4
		if wBit {
			return Instr{}, 0, true, fmt.Errorf("VCVTSS2SD requires EVEX.W0")
		}
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if p1&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX fixed bit must be one")
	}
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	embeddedControl := p2&0x10 != 0
	vectorBits := p2 >> 5 & 3
	if !embeddedControl && vectorBits != 0 {
		return Instr{}, 0, true, fmt.Errorf("scalar precision conversion requires EVEX.128")
	}
	if embeddedControl && modRM>>6 != 3 {
		return Instr{}, 0, true, fmt.Errorf("embedded rounding/SAE requires a register source")
	}
	if embeddedControl {
		if supportsRounding {
			op += Op("." + [...]string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}[vectorBits])
		} else if vectorBits == 0 {
			op += ".SAE"
		} else {
			return Instr{}, 0, true, fmt.Errorf("VCVTSS2SD supports SAE but not explicit rounding")
		}
	}
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 scalar precision conversion mask forms exceed the Go assembler frontend's operand limit")
	}
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	first, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X", inputBytes)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", secondNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
	args := []Operand{first, second}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

// decodedX86DuplicateMoveInstruction recognizes every Go 1.27 yxm and
// _yvmovddup encoding for MOVDDUP/MOVSHDUP/MOVSLDUP and their V-prefixed
// forms. This includes legacy X, VEX X/Y, and EVEX X/Y/Z register or memory
// sources with optional merge/zero masks and compressed displacements.
// x/arch v0.14 rejects the VMOVSHDUP bytes generated by segdsp.
func decodedX86DuplicateMoveInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto encoding
		}
	}

encoding:
	if len(code) <= i {
		return Instr{}, 0, false, nil
	}

	// Legacy duplicate moves use F2/F3 0F opcode /r and the ModRM.reg X
	// register as the destination.
	j := i
	if code[j] == 0xf2 || code[j] == 0xf3 {
		prefix := code[j]
		j++
		rex := byte(0)
		if j < len(code) && code[j]&0xf0 == 0x40 {
			rex = code[j]
			j++
		}
		if len(code) >= j+3 && code[j] == 0x0f {
			op := Op("")
			switch {
			case prefix == 0xf2 && code[j+1] == 0x12:
				op = "MOVDDUP"
			case prefix == 0xf3 && code[j+1] == 0x12:
				op = "MOVSLDUP"
			case prefix == 0xf3 && code[j+1] == 0x16:
				op = "MOVSHDUP"
			}
			if op != "" {
				ok = true
				if addressOverride {
					return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
				}
				if mode == 32 && rex != 0 {
					return Instr{}, 0, true, fmt.Errorf("REX prefix in 32-bit mode")
				}
				modRMIndex := j + 2
				modRM := code[modRMIndex]
				rExt := int(rex>>2) & 1
				xExt := int(rex>>1) & 1
				bExt := int(rex) & 1
				destinationNumber := int(modRM>>3&7) + rExt*8
				if mode == 32 && destinationNumber >= 8 {
					return Instr{}, 0, true, fmt.Errorf("extended destination register in 32-bit mode")
				}
				source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
				if decodeErr != nil {
					return Instr{}, 0, true, decodeErr
				}
				destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
				return Instr{Op: op, Args: []Operand{source, destination}, Raw: fmt.Sprintf("%s %s, %s", op, source.String(), destination.String())}, modRMIndex + consumed, true, nil
			}
		}
	}

	if code[i] == 0xc4 || code[i] == 0xc5 {
		var vexLength, rExt, xExt, bExt int
		var vexBits, opcode byte
		switch code[i] {
		case 0xc5:
			if len(code) < i+4 {
				return Instr{}, 0, false, nil
			}
			vexLength = 2
			vexBits = code[i+1]
			rExt = int(^vexBits>>7) & 1
			opcode = code[i+2]
		case 0xc4:
			if len(code) < i+5 || code[i+1]&0x1f != 1 {
				return Instr{}, 0, false, nil
			}
			vexLength = 3
			vexBits = code[i+2]
			rExt = int(^code[i+1]>>7) & 1
			xExt = int(^code[i+1]>>6) & 1
			bExt = int(^code[i+1]>>5) & 1
			opcode = code[i+3]
		}
		prefix := vexBits & 3
		op := Op("")
		switch {
		case prefix == 3 && opcode == 0x12:
			op = "VMOVDDUP"
		case prefix == 2 && opcode == 0x12:
			op = "VMOVSLDUP"
		case prefix == 2 && opcode == 0x16:
			op = "VMOVSHDUP"
		}
		if op == "" {
			return Instr{}, 0, false, nil
		}
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		if vexLength == 3 && vexBits&0x80 != 0 {
			return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
		}
		if vexBits&0x78 != 0x78 {
			return Instr{}, 0, true, fmt.Errorf("VEX.vvvv must be reserved")
		}
		vectorName := "X"
		if vexBits&0x04 != 0 {
			vectorName = "Y"
		}
		opcodeIndex := i + vexLength
		modRMIndex := opcodeIndex + 1
		modRM := code[modRMIndex]
		destinationNumber := int(modRM>>3&7) + rExt*8
		if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || destinationNumber >= 8) {
			return Instr{}, 0, true, fmt.Errorf("extended VEX register in 32-bit mode")
		}
		source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName)
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
		return Instr{Op: op, Args: []Operand{source, destination}, Raw: fmt.Sprintf("%s %s, %s", op, source.String(), destination.String())}, modRMIndex + consumed, true, nil
	}

	if len(code) < i+6 || code[i] != 0x62 || code[i+1]&0x0f != 1 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2, opcode := code[i+1], code[i+2], code[i+3], code[i+4]
	prefix := p1 & 3
	op := Op("")
	elementBytes := 4
	switch {
	case prefix == 3 && opcode == 0x12:
		op = "VMOVDDUP"
		elementBytes = 8
	case prefix == 2 && opcode == 0x12:
		op = "VMOVSLDUP"
	case prefix == 2 && opcode == 0x16:
		op = "VMOVSHDUP"
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if p1&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX fixed bit must be one")
	}
	double := op == "VMOVDDUP"
	if double != (p1&0x80 != 0) {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W does not match duplicate-move element width")
	}
	if p1&0x78 != 0x78 || p2&0x08 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.vvvvv must be reserved")
	}
	if p2&0x10 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast is absent from Go 1.27's duplicate-move table")
	}
	vectorBits := p2 >> 5 & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	disp8Scale := vectorWidth
	if double && vectorBits == 0 {
		disp8Scale = elementBytes
	}
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	sourceNumber := int(modRM&7) + bExt*8 + xExt*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && vectorName == "Z" {
		if modRM>>6 == 3 && sourceNumber >= 8 || destinationNumber >= 8 {
			return Instr{}, 0, true, fmt.Errorf("high Z register is unavailable in 32-bit mode")
		}
	}
	source, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{source}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

// decodedX86InLaneFloatingPermuteInstruction recognizes every encoding in Go
// 1.27's shared _yvpermilpd table: VPERMILPS/VPERMILPD immediate and
// variable-control VEX X/Y forms plus EVEX X/Y/Z, memory, scalar broadcast,
// merge-mask, and zero-mask forms. x/arch v0.14 can split a VEX immediate form
// into a fake PC-relative branch inside generated segdsp byte streams.
func decodedX86InLaneFloatingPermuteInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto encoding
		}
	}

encoding:
	if len(code) <= i {
		return Instr{}, 0, false, nil
	}
	if code[i] == 0xc4 {
		if len(code) < i+5 {
			return Instr{}, 0, false, nil
		}
		vex0, vexBits, opcode := code[i+1], code[i+2], code[i+3]
		mapNumber := vex0 & 0x1f
		immediate := mapNumber == 3 && (opcode == 0x04 || opcode == 0x05)
		variable := mapNumber == 2 && (opcode == 0x0c || opcode == 0x0d)
		if !immediate && !variable {
			return Instr{}, 0, false, nil
		}
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		if vexBits&3 != 1 {
			return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
		}
		if vexBits&0x80 != 0 {
			return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
		}
		if immediate && vexBits&0x78 != 0x78 {
			return Instr{}, 0, true, fmt.Errorf("immediate VPERMIL requires reserved VEX.vvvv")
		}
		vectorName := "X"
		if vexBits&0x04 != 0 {
			vectorName = "Y"
		}
		rExt := int(^vex0>>7) & 1
		xExt := int(^vex0>>6) & 1
		bExt := int(^vex0>>5) & 1
		modRMIndex := i + 4
		modRM := code[modRMIndex]
		destinationNumber := int(modRM>>3&7) + rExt*8
		secondNumber := int(^vexBits>>3) & 15
		if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || destinationNumber >= 8 || variable && secondNumber >= 8) {
			return Instr{}, 0, true, fmt.Errorf("extended VEX register in 32-bit mode")
		}
		first, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName)
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		double := opcode&1 != 0
		op := Op("VPERMILPS")
		if double {
			op = "VPERMILPD"
		}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
		args := make([]Operand, 0, 3)
		end := modRMIndex + consumed
		if immediate {
			if len(code) <= end {
				return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
			}
			args = append(args, Operand{Kind: OpImm, Imm: int64(code[end])}, first, destination)
			end++
		} else {
			second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondNumber))}
			args = append(args, first, second, destination)
		}
		rawArgs := make([]string, len(args))
		for index := range args {
			rawArgs[index] = args[index].String()
		}
		return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, end, true, nil
	}

	if len(code) < i+6 || code[i] != 0x62 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2, opcode := code[i+1], code[i+2], code[i+3], code[i+4]
	mapNumber := p0 & 0x0f
	immediate := mapNumber == 3 && (opcode == 0x04 || opcode == 0x05)
	variable := mapNumber == 2 && (opcode == 0x0c || opcode == 0x0d)
	if !immediate && !variable {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if p1&0x07 != 5 {
		return Instr{}, 0, true, fmt.Errorf("EVEX fixed bit and pp must select 66")
	}
	double := opcode&1 != 0
	if double != (p1&0x80 != 0) {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W does not match VPERMILPS/PD")
	}
	if immediate && (p1&0x78 != 0x78 || p2&0x08 == 0) {
		return Instr{}, 0, true, fmt.Errorf("immediate VPERMIL requires reserved EVEX.vvvvv")
	}
	vectorBits := p2 >> 5 & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	laneBytes := 4
	op := Op("VPERMILPS")
	if double {
		laneBytes = 8
		op = "VPERMILPD"
	}
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 VPERMIL mask forms exceed the Go assembler frontend's operand limit")
	}
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = laneBytes
		op += ".BCST"
	}
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	firstNumber := int(modRM&7) + bExt*8 + xExt*16
	secondNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && vectorName == "Z" {
		if modRM>>6 == 3 && firstNumber >= 8 || variable && secondNumber >= 8 || destinationNumber >= 8 {
			return Instr{}, 0, true, fmt.Errorf("high Z register is unavailable in 32-bit mode")
		}
	}
	first, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := make([]Operand, 0, 4)
	end := modRMIndex + consumed
	if immediate {
		if len(code) <= end {
			return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
		}
		args = append(args, Operand{Kind: OpImm, Imm: int64(code[end])}, first)
		end++
	} else {
		second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondNumber))}
		args = append(args, first, second)
	}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, end, true, nil
}

// decodedX86ImmediatePackedBlendInstruction recognizes the complete Go 1.27
// immediate packed-blend family: legacy PBLENDW/BLENDPS/BLENDPD X forms and
// VEX VPBLENDW/VPBLENDD/VBLENDPS/VBLENDPD X/Y forms. Every register and
// ModRM/SIB memory source is handled before x/arch's generic decoder, which
// can split VBLENDPD into unrelated scalar instructions in generated code.
func decodedX86ImmediatePackedBlendInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto encoding
		}
	}

encoding:
	if len(code) <= i {
		return Instr{}, 0, false, nil
	}

	// Legacy 66 0F 3A /r ib encodings use the ModRM.reg X register as both
	// their second source and destination.
	j := i
	if code[j] == 0x66 {
		j++
		rex := byte(0)
		if j < len(code) && code[j]&0xf0 == 0x40 {
			rex = code[j]
			j++
		}
		if len(code) >= j+4 && code[j] == 0x0f && code[j+1] == 0x3a {
			op, recognized := map[byte]Op{0x0c: "BLENDPS", 0x0d: "BLENDPD", 0x0e: "PBLENDW"}[code[j+2]]
			if recognized {
				ok = true
				if addressOverride {
					return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
				}
				if mode == 32 && rex != 0 {
					return Instr{}, 0, true, fmt.Errorf("REX prefix in 32-bit mode")
				}
				modRMIndex := j + 3
				modRM := code[modRMIndex]
				rExt := int(rex>>2) & 1
				xExt := int(rex>>1) & 1
				bExt := int(rex) & 1
				destinationNumber := int(modRM>>3&7) + rExt*8
				if mode == 32 && destinationNumber >= 8 {
					return Instr{}, 0, true, fmt.Errorf("extended destination register in 32-bit mode")
				}
				source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
				if decodeErr != nil {
					return Instr{}, 0, true, decodeErr
				}
				immediateIndex := modRMIndex + consumed
				if len(code) <= immediateIndex {
					return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
				}
				immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
				destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
				return Instr{
					Op:   op,
					Args: []Operand{immediate, source, destination},
					Raw:  fmt.Sprintf("%s %s, %s, %s", op, immediate.String(), source.String(), destination.String()),
				}, immediateIndex + 1, true, nil
			}
		}
	}

	// All vector forms are VEX.128/256.66.0F3A.W0. Go's 386 frontend
	// cannot represent their four Plan 9 operands and rejects them.
	if len(code) < i+5 || code[i] != 0xc4 || code[i+1]&0x1f != 3 {
		return Instr{}, 0, false, nil
	}
	op, recognized := map[byte]Op{
		0x02: "VPBLENDD",
		0x0c: "VBLENDPS",
		0x0d: "VBLENDPD",
		0x0e: "VPBLENDW",
	}[code[i+3]]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if mode == 32 {
		return Instr{}, 0, true, fmt.Errorf("386 %s exceeds the Go assembler frontend's operand limit", op)
	}
	vex0, vexBits := code[i+1], code[i+2]
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	vectorName := "X"
	if vexBits&0x04 != 0 {
		vectorName = "Y"
	}
	rExt := int(^vex0>>7) & 1
	xExt := int(^vex0>>6) & 1
	bExt := int(^vex0>>5) & 1
	modRMIndex := i + 4
	modRM := code[modRMIndex]
	first, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	secondNumber := int(^vexBits>>3) & 15
	destinationNumber := int(modRM>>3&7) + rExt*8
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	return Instr{
		Op:   op,
		Args: []Operand{immediate, first, second, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s, %s", op, immediate.String(), first.String(), second.String(), destination.String()),
	}, immediateIndex + 1, true, nil
}

// decodedX86FloatingUnpackInstruction recognizes every legacy yxm and
// VEX/EVEX _yvandnpd row used by UNPCKLPS/UNPCKHPS/UNPCKLPD/UNPCKHPD and
// their V-prefixed forms. This includes X/Y/Z widths, register and ModRM/SIB
// memory sources, EVEX broadcast, merge masks, zero masks, and compressed
// displacements. x/arch v0.14 can overrun VUNPCK by one byte and desynchronize
// a raw directive stream, as observed in github.com/racerxdl/segdsp.
func decodedX86FloatingUnpackInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto encoding
		}
	}

encoding:
	if len(code) <= i {
		return Instr{}, 0, false, nil
	}

	legacyPrefix := byte(0)
	j := i
	if code[j] == 0x66 {
		legacyPrefix = 1
		j++
	}
	rex := byte(0)
	if j < len(code) && code[j]&0xf0 == 0x40 {
		rex = code[j]
		j++
	}
	if len(code) >= j+3 && code[j] == 0x0f && (code[j+1] == 0x14 || code[j+1] == 0x15) {
		opcode := code[j+1]
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		if mode == 32 && rex != 0 {
			return Instr{}, 0, true, fmt.Errorf("REX prefix in 32-bit mode")
		}
		stem := "UNPCKL"
		if opcode == 0x15 {
			stem = "UNPCKH"
		}
		op := Op(stem + map[byte]string{0: "PS", 1: "PD"}[legacyPrefix])
		modRMIndex := j + 2
		modRM := code[modRMIndex]
		rExt := int(rex>>2) & 1
		xExt := int(rex>>1) & 1
		bExt := int(rex) & 1
		destinationNumber := int(modRM>>3&7) + rExt*8
		if mode == 32 && destinationNumber >= 8 {
			return Instr{}, 0, true, fmt.Errorf("extended destination register in 32-bit mode")
		}
		source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
		return Instr{
			Op:   op,
			Args: []Operand{source, destination},
			Raw:  fmt.Sprintf("%s %s, %s", op, source.String(), destination.String()),
		}, modRMIndex + consumed, true, nil
	}

	var vexLength, rExt, xExt, bExt int
	var vexBits, opcode byte
	switch {
	case len(code) >= i+3 && code[i] == 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
		opcode = code[i+2]
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		opcode = code[i+3]
	}
	if vexLength != 0 && (opcode == 0x14 || opcode == 0x15) {
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		if vexBits&3 > 1 {
			return Instr{}, 0, true, fmt.Errorf("VEX.pp does not select PS or PD floating unpack")
		}
		if vexLength == 3 && vexBits&0x80 != 0 {
			return Instr{}, 0, true, fmt.Errorf("floating unpack requires VEX.W0")
		}
		stem := "VUNPCKL"
		if opcode == 0x15 {
			stem = "VUNPCKH"
		}
		op := Op(stem + map[byte]string{0: "PS", 1: "PD"}[vexBits&3])
		opcodeIndex := i + vexLength
		modRMIndex := opcodeIndex + 1
		if len(code) <= modRMIndex {
			return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
		}
		vectorName := "X"
		if vexBits&0x04 != 0 {
			vectorName = "Y"
		}
		secondNumber := int(^vexBits>>3) & 15
		destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
		if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondNumber >= 8 || destinationNumber >= 8) {
			return Instr{}, 0, true, fmt.Errorf("extended VEX register in 32-bit mode")
		}
		first, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName)
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondNumber))}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
		return Instr{
			Op:   op,
			Args: []Operand{first, second, destination},
			Raw:  fmt.Sprintf("%s %s, %s, %s", op, first.String(), second.String(), destination.String()),
		}, modRMIndex + consumed, true, nil
	}

	if code[i] != 0x62 || len(code) < i+6 || code[i+1]&0x0f != 1 || (code[i+4] != 0x14 && code[i+4] != 0x15) {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p1&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX fixed bit must be one")
	}
	if p1&3 > 1 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.pp does not select PS or PD floating unpack")
	}
	double := p1&3 == 1
	if double != (p1&0x80 != 0) {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W and pp disagree for floating unpack")
	}
	vectorBits := p2 >> 5 & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorBytes := [...]int{16, 32, 64}[vectorBits]
	laneBytes := 4
	suffix := "PS"
	if double {
		laneBytes = 8
		suffix = "PD"
	}
	stem := "VUNPCKL"
	if code[i+4] == 0x15 {
		stem = "VUNPCKH"
	}
	op := Op(stem + suffix)
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX masking is unavailable for 386 floating unpack forms")
	}

	modRMIndex := i + 5
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	disp8Scale := vectorBytes
	if broadcast {
		disp8Scale = laneBytes
		op += ".BCST"
	}
	evexRExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	evexXExt := int(^p0>>6) & 1
	evexBExt := int(^p0>>5) & 1
	firstNumber := int(modRM&7) + evexBExt*8 + evexXExt*16
	secondNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + evexRExt*8 + rHighExt*16
	if mode == 32 && vectorName == "Z" {
		if modRM>>6 == 3 && firstNumber >= 8 || secondNumber >= 8 || destinationNumber >= 8 {
			return Instr{}, 0, true, fmt.Errorf("high Z register is unavailable in 32-bit mode")
		}
	}
	first, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, evexBExt, evexXExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{first, second}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

// decodedX86VEXPackedFloatLogicalInstruction recognizes the complete
// VEX.128/VEX.256 VANDPS/PD, VANDNPS/PD, VORPS/PD, and VXORPS/PD family.
// x/arch v0.14 can split or reject valid VEX encodings, including the raw
// VXORPS emitted by Weaviate, so recover every register and ModRM/SIB memory
// form before the generic decoder. VEX.W is ignored by these opcode rows.
func decodedX86VEXPackedFloatLogicalInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	var vexLength, rExt, xExt, bExt int
	var vexBits, opcode byte
	switch {
	case len(code) >= i+3 && code[i] == 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
		opcode = code[i+2]
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		opcode = code[i+3]
	default:
		return Instr{}, 0, false, nil
	}
	stem, recognized := map[byte]string{
		0x54: "VAND",
		0x55: "VANDN",
		0x56: "VOR",
		0x57: "VXOR",
	}[opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	suffix := ""
	switch vexBits & 3 {
	case 0:
		suffix = "PS"
	case 1:
		suffix = "PD"
	default:
		return Instr{}, 0, true, fmt.Errorf("VEX.pp does not select a packed floating logical instruction")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	opcodeIndex := i + vexLength
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	firstSource, consumed, err := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if err != nil {
		return Instr{}, 0, true, err
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	op := Op(stem + suffix)
	instruction = Instr{
		Op:   op,
		Args: []Operand{firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

// decodedX86VEXPackedIntegerLogicalInstruction recognizes the complete
// VEX.128/VEX.256 VPAND, VPANDN, VPOR, and VPXOR family described by Go
// 1.27's shared _yvaddsubpd operand table. Recover both VEX.WIG values and
// every register and ModRM/SIB memory form before the generic decoder, which
// can split or reject raw encodings emitted by ecosystem assembly.
func decodedX86VEXPackedIntegerLogicalInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	var vexLength, rExt, xExt, bExt int
	var vexBits, opcode byte
	switch {
	case len(code) >= i+3 && code[i] == 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
		opcode = code[i+2]
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		opcode = code[i+3]
	default:
		return Instr{}, 0, false, nil
	}
	op, recognized := map[byte]Op{
		0xdb: "VPAND",
		0xdf: "VPANDN",
		0xeb: "VPOR",
		0xef: "VPXOR",
	}[opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	opcodeIndex := i + vexLength
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	firstSource, consumed, err := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if err != nil {
		return Instr{}, 0, true, err
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

// decodedX86EVEXPackedLogicalInstruction recognizes every EVEX register,
// memory, broadcast, merge-mask, and zero-mask row shared by Go 1.27's
// VPANDD/Q, VPANDND/Q, VPORD/Q, and VPXORD/Q _yvblendmpd table.
func decodedX86EVEXPackedLogicalInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if len(code) < i+5 || code[i] != 0x62 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p0&0x0f != 1 || p1&3 != 1 {
		return Instr{}, 0, false, nil
	}
	stem, recognized := map[byte]string{0xdb: "VPAND", 0xdf: "VPANDN", 0xeb: "VPOR", 0xef: "VPXOR"}[code[i+4]]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX fixed bit must be one")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	vectorBits := p2 >> 5 & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorBytes := [...]int{16, 32, 64}[vectorBits]
	width := "D"
	laneBytes := 4
	if p1&0x80 != 0 {
		width = "Q"
		laneBytes = 8
	}
	op := Op(stem + width)
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX masking is unavailable for 386 packed logical forms")
	}

	modRMIndex := i + 5
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	disp8Scale := vectorBytes
	if broadcast {
		disp8Scale = laneBytes
		op += ".BCST"
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	firstNumber := int(modRM&7) + bExt*8 + xExt*16
	secondNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && vectorName == "Z" {
		if modRM>>6 == 3 && firstNumber >= 8 || secondNumber >= 8 || destinationNumber >= 8 {
			return Instr{}, 0, true, fmt.Errorf("high Z register is unavailable in 32-bit mode")
		}
	}
	first, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{first, second}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

// decodedX86VEXPackedMADDInstruction recognizes the complete VEX.128 and
// VEX.256 VPMADDWD and VPMADDUBSW family in Go 1.27's opcode tables.
// VPMADDWD is available through both two- and three-byte VEX map-1 forms;
// VPMADDUBSW uses the three-byte VEX map-2 form. VEX.W is ignored. Recover
// every register and ModRM/SIB memory form before the generic decoder, which
// can split raw VPMADDWD bytes emitted by ecosystem assembly.
func decodedX86VEXPackedMADDInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	var vexLength, opcodeMap, rExt, xExt, bExt int
	var vexBits, opcode byte
	switch {
	case len(code) >= i+3 && code[i] == 0xc5:
		vexLength = 2
		opcodeMap = 1
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
		opcode = code[i+2]
	case len(code) >= i+4 && code[i] == 0xc4:
		vexLength = 3
		opcodeMap = int(code[i+1] & 0x1f)
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		opcode = code[i+3]
	default:
		return Instr{}, 0, false, nil
	}
	op, recognized := map[[2]int]Op{
		{1, 0xf5}: "VPMADDWD",
		{2, 0x04}: "VPMADDUBSW",
	}[[2]int{opcodeMap, int(opcode)}]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	opcodeIndex := i + vexLength
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	firstSource, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

// decodedX86VEXBinaryFloatInstruction recognizes the complete VEX and EVEX
// VADD, VMUL, VSUB, VMIN, VDIV, and VMAX family for PS/PD/SS/SD, plus
// VSQRTSS/VSQRTSD, plus raw-only packed/scalar FP16 MAP5 binary forms. Packed SQRT
// has a distinct single-source grammar and is decoded by
// decodedX86SameWidthConversionInstruction. Scalar VEX forms require VEX.128;
// packed VEX forms accept both vector widths. EVEX adds X/Y/Z widths, masking,
// zeroing, packed broadcasts, rounding, and SAE.
// Recover every register and ModRM/SIB memory form before the generic decoder.
func decodedX86VEXBinaryFloatInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXBinaryFloatInstruction(code, i, mode, segment, addressOverride)
	}
	var vexLength, rExt, xExt, bExt int
	var vexBits, opcode byte
	switch {
	case len(code) >= i+3 && code[i] == 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
		opcode = code[i+2]
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		opcode = code[i+3]
	default:
		return Instr{}, 0, false, nil
	}
	stem, recognized := map[byte]string{
		0x51: "VSQRT",
		0x58: "VADD",
		0x59: "VMUL",
		0x5c: "VSUB",
		0x5d: "VMIN",
		0x5e: "VDIV",
		0x5f: "VMAX",
	}[opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	pp := vexBits & 3
	if opcode == 0x51 && pp < 2 {
		return Instr{}, 0, false, nil
	}
	suffix := [...]string{"PS", "PD", "SS", "SD"}[pp]
	scalar := pp >= 2
	if scalar && vexBits&0x04 != 0 {
		return Instr{}, 0, true, fmt.Errorf("scalar binary floating instruction requires VEX.128")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	opcodeIndex := i + vexLength
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	firstSource, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	op := Op(stem + suffix)
	instruction = Instr{
		Op:   op,
		Args: []Operand{firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

func decodedX86EVEXBinaryFloatInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+6 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	stem, recognized := map[byte]string{
		0x51: "VSQRT",
		0x58: "VADD",
		0x59: "VMUL",
		0x5c: "VSUB",
		0x5d: "VMIN",
		0x5e: "VDIV",
		0x5f: "VMAX",
	}[opcode]
	mapNumber := p0 & 0x0f
	rawHalf := mapNumber == 5 && (p1&3 == 0 || p1&3 == 2)
	rawHalfScalar := rawHalf && p1&3 == 2
	if !recognized || mapNumber != 1 && !rawHalf {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("invalid EVEX prefix")
	}
	pp := p1 & 3
	if opcode == 0x51 && pp < 2 {
		return Instr{}, 0, false, nil
	}
	width64 := p1&0x80 != 0
	wantWidth64 := pp == 1 || pp == 3
	if rawHalf {
		wantWidth64 = false
	}
	if width64 != wantWidth64 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W does not match floating element type")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	modRMIndex := i + 5
	modRM := code[modRMIndex]
	vectorBits := (p2 >> 5) & 3
	scalar := pp >= 2
	evexB := p2&0x10 != 0
	registerSource := modRM>>6 == 3
	embeddedControl := evexB && registerSource
	broadcast := evexB && !registerSource
	if broadcast && scalar {
		return Instr{}, 0, true, fmt.Errorf("scalar binary floating instruction does not support broadcast")
	}
	if !embeddedControl && vectorBits == 3 && !rawHalfScalar {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}

	vectorPrefix := "X"
	vectorWidth := 16
	switch {
	case embeddedControl && !scalar:
		vectorPrefix = "Z"
		vectorWidth = 64
	case !scalar:
		vectorPrefix = [...]string{"X", "Y", "Z"}[vectorBits]
		vectorWidth = [...]int{16, 32, 64}[vectorBits]
	}
	laneBytes := 4
	if rawHalf {
		laneBytes = 2
	} else if pp == 1 || pp == 3 {
		laneBytes = 8
	}
	disp8Scale := vectorWidth
	if scalar || broadcast {
		disp8Scale = laneBytes
	}

	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && (!rawHalf && maskNumber != 0 || rExt != 0 || rHighExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register or mask in 32-bit mode")
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}

	suffix := [...]string{"PS", "PD", "SS", "SD"}[pp]
	if rawHalf {
		suffix = "PH"
		if rawHalfScalar {
			suffix = "SH"
		}
	}
	op := Op(stem + suffix)
	if broadcast {
		op += ".BCST"
	}
	if embeddedControl {
		if stem == "VMIN" || stem == "VMAX" {
			op += ".SAE"
		} else {
			op += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[vectorBits]
		}
	}
	if zeroing {
		op += ".Z"
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	args := []Operand{firstSource, secondSource}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{
		Op: op, Args: args,
		Raw:        fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", ")),
		x86Encoded: rawHalf,
	}, modRMIndex + consumed, true, nil
}

// decodedX86ScalarIntegerFloatInstruction recognizes Go 1.27's complete
// signed and unsigned scalar integer-to-floating-point family. VEX supports
// the four signed forms; EVEX additionally supports unsigned forms, ignored
// scalar L'L encodings, and register-only embedded rounding where enabled.
func decodedX86ScalarIntegerFloatInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto prefix
		}
	}

prefix:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXScalarIntegerFloatInstruction(code, i, mode, segment, addressOverride)
	}
	if len(code) < i+4 {
		return Instr{}, 0, false, nil
	}

	var vexLength, rExt, xExt, bExt int
	var vexBits byte
	switch {
	case code[i] == 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
	case code[i] == 0xc4 && len(code) >= i+5 && code[i+1]&0x1f == 1:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
	default:
		return Instr{}, 0, false, nil
	}
	opcodeIndex := i + vexLength
	if len(code) <= opcodeIndex || code[opcodeIndex] != 0x2a {
		return Instr{}, 0, false, nil
	}
	ok = true
	pp := vexBits & 3
	if pp != 2 && pp != 3 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be F3 or F2")
	}
	if vexBits&0x04 != 0 {
		return Instr{}, 0, true, fmt.Errorf("scalar integer-to-float instruction requires VEX.128")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	passthroughNumber := int(^vexBits>>3) & 15
	destinationNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || passthroughNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	source, consumed, decodeErr := decodedX86RMSource(code[modRMIndex:], mode, bExt, xExt, segment, 1)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	width64 := vexLength == 3 && vexBits&0x80 != 0
	op := scalarIntegerFloatRawOperation(false, pp, width64)
	passthrough := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", passthroughNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
	args := []Operand{source, passthrough, destination}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s, %s, %s", op, source.String(), passthrough.String(), destination.String())}, modRMIndex + consumed, true, nil
}

func decodedX86EVEXScalarIntegerFloatInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+6 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	if p0&0x0f != 1 || opcode != 0x2a && opcode != 0x7b {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("invalid EVEX prefix")
	}
	pp := p1 & 3
	if pp != 2 && pp != 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.pp must be F3 or F2")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if p2&0x87 != 0 {
		return Instr{}, 0, true, fmt.Errorf("masking and zeroing are absent from the scalar integer-to-float table")
	}

	modRMIndex := i + 5
	modRM := code[modRMIndex]
	vectorBits := (p2 >> 5) & 3
	embeddedRounding := p2&0x10 != 0
	if !embeddedRounding && vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	if embeddedRounding && modRM>>6 != 3 {
		return Instr{}, 0, true, fmt.Errorf("embedded rounding requires a register source")
	}
	width64 := p1&0x80 != 0
	roundingEnabled := pp == 2 || width64
	if embeddedRounding && !roundingEnabled {
		return Instr{}, 0, true, fmt.Errorf("explicit rounding is absent from VCVTSI2SDL/VCVTUSI2SDL")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	passthroughNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if modRM>>6 == 3 && xExt != 0 {
		return Instr{}, 0, true, fmt.Errorf("general register source cannot use the EVEX high vector extension")
	}
	if mode == 32 && (rExt != 0 || rHighExt != 0 || xExt != 0 || bExt != 0 || passthroughNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	sourceBytes := 4
	if width64 {
		sourceBytes = 8
	}
	source, consumed, decodeErr := decodedX86RMSource(code[modRMIndex:], mode, bExt, xExt, segment, sourceBytes)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	op := scalarIntegerFloatRawOperation(opcode == 0x7b, pp, width64)
	if embeddedRounding {
		op += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[vectorBits]
	}
	passthrough := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", passthroughNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
	args := []Operand{source, passthrough, destination}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s, %s, %s", op, source.String(), passthrough.String(), destination.String())}, modRMIndex + consumed, true, nil
}

func scalarIntegerFloatRawOperation(unsigned bool, pp byte, width64 bool) Op {
	prefix := "VCVTSI2"
	if unsigned {
		prefix = "VCVTUSI2"
	}
	result := "SS"
	if pp == 3 {
		result = "SD"
	}
	source := "L"
	if width64 {
		source = "Q"
	}
	return Op(prefix + result + source)
}

// decodedX86VectorFloatCompareInstruction recognizes the complete VEX and
// EVEX VCMPPD/PS/SD/SS family. VEX writes X/Y vector results. EVEX writes K
// results and adds an optional K write mask, packed broadcast, and SAE.
func decodedX86VectorFloatCompareInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto prefix
		}
	}

prefix:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXVectorFloatCompareInstruction(code, i, mode, segment, addressOverride)
	}
	if len(code) < i+5 {
		return Instr{}, 0, false, nil
	}

	var vexLength, rExt, xExt, bExt int
	var vexBits byte
	switch {
	case code[i] == 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
	case code[i] == 0xc4 && len(code) >= i+6 && code[i+1]&0x1f == 1:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
	default:
		return Instr{}, 0, false, nil
	}
	opcodeIndex := i + vexLength
	if len(code) <= opcodeIndex || code[opcodeIndex] != 0xc2 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if mode == 32 {
		return Instr{}, 0, true, fmt.Errorf("vector floating compare is absent from Go's 386 table")
	}
	if vexLength == 3 && vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	pp := vexBits & 3
	scalar := pp >= 2
	if scalar && vexBits&0x04 != 0 {
		return Instr{}, 0, true, fmt.Errorf("scalar vector floating compare requires VEX.128")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(modRM>>3&7) + rExt*8
	firstSource, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	op := vectorFloatCompareRawOperation(pp)
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	args := []Operand{immediate, firstSource, secondSource, destination}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s, %s, %s, %s", op, immediate.String(), firstSource.String(), secondSource.String(), destination.String())}, immediateIndex + 1, true, nil
}

func decodedX86EVEXVectorFloatCompareInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+7 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p0&0x0f != 1 || code[i+4] != 0xc2 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if mode == 32 {
		return Instr{}, 0, true, fmt.Errorf("vector floating compare is absent from Go's 386 table")
	}
	if p1&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("invalid EVEX prefix")
	}
	pp := p1 & 3
	width64 := p1&0x80 != 0
	wantWidth64 := pp == 1 || pp == 3
	if width64 != wantWidth64 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W does not match floating element type")
	}
	if p2&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing is absent from vector floating compare")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	if rExt != 0 || rHighExt != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX destination is an unextended K register")
	}
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	vectorBits := (p2 >> 5) & 3
	scalar := pp >= 2
	evexB := p2&0x10 != 0
	registerSource := modRM>>6 == 3
	sae := evexB && registerSource
	broadcast := evexB && !registerSource
	if broadcast && scalar {
		return Instr{}, 0, true, fmt.Errorf("scalar vector floating compare does not support broadcast")
	}
	if !sae && vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}

	vectorPrefix := "X"
	vectorWidth := 16
	switch {
	case sae && !scalar:
		vectorPrefix = "Z"
		vectorWidth = 64
	case !scalar:
		vectorPrefix = [...]string{"X", "Y", "Z"}[vectorBits]
		vectorWidth = [...]int{16, 32, 64}[vectorBits]
	}
	laneBytes := 4
	if width64 {
		laneBytes = 8
	}
	disp8Scale := vectorWidth
	if scalar || broadcast {
		disp8Scale = laneBytes
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}

	op := vectorFloatCompareRawOperation(pp)
	if broadcast {
		op += ".BCST"
	}
	if sae {
		op += ".SAE"
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", modRM>>3&7))}
	args := []Operand{immediate, firstSource, secondSource}
	if writeMask := int(p2 & 7); writeMask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", writeMask))})
	}
	args = append(args, destination)
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, immediateIndex + 1, true, nil
}

func vectorFloatCompareRawOperation(pp byte) Op {
	return [...]Op{"VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"}[pp]
}

// decodedX86VEXHorizontalFloatInstruction recognizes the complete VEX.128 and
// VEX.256 VHADD/VHSUB/VADDSUB PS/PD family in Go 1.27's _yvaddsubpd table.
// VEX.W is ignored. Recover every register and ModRM/SIB memory form before
// the generic decoder, which can misdecode these bytes as relative branches.
func decodedX86VEXHorizontalFloatInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	var vexLength, rExt, xExt, bExt int
	var vexBits, opcode byte
	switch {
	case len(code) >= i+3 && code[i] == 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
		opcode = code[i+2]
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		opcode = code[i+3]
	default:
		return Instr{}, 0, false, nil
	}
	stem, recognized := map[byte]string{0x7c: "VHADD", 0x7d: "VHSUB", 0xd0: "VADDSUB"}[opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	suffix := ""
	switch vexBits & 3 {
	case 1:
		suffix = "PD"
	case 3:
		suffix = "PS"
	default:
		return Instr{}, 0, true, fmt.Errorf("VEX.pp does not select a horizontal floating instruction")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	opcodeIndex := i + vexLength
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	firstSource, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	op := Op(stem + suffix)
	instruction = Instr{
		Op:   op,
		Args: []Operand{firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

type decodedX86VEXFMA3Spec struct {
	stem   string
	scalar bool
}

func (spec decodedX86VEXFMA3Spec) op(width64 bool) Op {
	suffix := "PS"
	if spec.scalar {
		suffix = "SS"
	}
	if width64 {
		if spec.scalar {
			suffix = "SD"
		} else {
			suffix = "PD"
		}
	}
	return Op(spec.stem + suffix)
}

// decodedX86VEXFMA3Ops covers all 36 packed and 24 scalar FMA3 names in Go
// 1.27's _yvaddpd and _yvaddsd operand tables. VEX.W selects PS/PD or SS/SD.
var decodedX86VEXFMA3Ops = map[byte]decodedX86VEXFMA3Spec{
	0x96: {stem: "VFMADDSUB132"},
	0x97: {stem: "VFMSUBADD132"},
	0x98: {stem: "VFMADD132"},
	0x99: {stem: "VFMADD132", scalar: true},
	0x9a: {stem: "VFMSUB132"},
	0x9b: {stem: "VFMSUB132", scalar: true},
	0x9c: {stem: "VFNMADD132"},
	0x9d: {stem: "VFNMADD132", scalar: true},
	0x9e: {stem: "VFNMSUB132"},
	0x9f: {stem: "VFNMSUB132", scalar: true},
	0xa6: {stem: "VFMADDSUB213"},
	0xa7: {stem: "VFMSUBADD213"},
	0xa8: {stem: "VFMADD213"},
	0xa9: {stem: "VFMADD213", scalar: true},
	0xaa: {stem: "VFMSUB213"},
	0xab: {stem: "VFMSUB213", scalar: true},
	0xac: {stem: "VFNMADD213"},
	0xad: {stem: "VFNMADD213", scalar: true},
	0xae: {stem: "VFNMSUB213"},
	0xaf: {stem: "VFNMSUB213", scalar: true},
	0xb6: {stem: "VFMADDSUB231"},
	0xb7: {stem: "VFMSUBADD231"},
	0xb8: {stem: "VFMADD231"},
	0xb9: {stem: "VFMADD231", scalar: true},
	0xba: {stem: "VFMSUB231"},
	0xbb: {stem: "VFMSUB231", scalar: true},
	0xbc: {stem: "VFNMADD231"},
	0xbd: {stem: "VFNMADD231", scalar: true},
	0xbe: {stem: "VFNMSUB231"},
	0xbf: {stem: "VFNMSUB231", scalar: true},
}

// decodedX86VEXFMA3Instruction recognizes every VEX and EVEX FMA3 form behind
// Go 1.27's complete FMA3 table. EVEX adds X/Y/Z widths, masking, zeroing,
// packed broadcasts, and embedded rounding. x/arch v0.14 can split or reject
// raw FMA encodings emitted by generated ecosystem assembly, so recover the
// family before the generic decoder.
func decodedX86VEXFMA3Instruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXFMA3Instruction(code, i, mode, segment, addressOverride)
	}
	if len(code) < i+5 || code[i] != 0xc4 || code[i+1]&0x1f != 2 {
		return Instr{}, 0, false, nil
	}
	vex0, vexBits, opcode := code[i+1], code[i+2], code[i+3]
	spec, recognized := decodedX86VEXFMA3Ops[opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if spec.scalar && vexBits&0x04 != 0 {
		return Instr{}, 0, true, fmt.Errorf("scalar FMA3 requires VEX.128")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	rExt := int(^vex0>>7) & 1
	xExt := int(^vex0>>6) & 1
	bExt := int(^vex0>>5) & 1
	modRMIndex := i + 4
	modRM := code[modRMIndex]
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	firstSource, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	op := spec.op(vexBits&0x80 != 0)
	instruction = Instr{
		Op:   op,
		Args: []Operand{firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

func decodedX86EVEXFMA3Instruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+6 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	spec, recognized := decodedX86VEXFMA3Ops[opcode]
	half := p0&0x0f == 6
	if p0&0x0f != 2 && !half || !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x04 == 0 || p1&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.pp must be 66")
	}
	if half && p1&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("FP16 FMA3 requires EVEX.W0")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	modRMIndex := i + 5
	modRM := code[modRMIndex]
	vectorBits := (p2 >> 5) & 3
	evexB := p2&0x10 != 0
	registerSource := modRM>>6 == 3
	embeddedRounding := evexB && registerSource
	broadcast := evexB && !registerSource
	if broadcast && spec.scalar {
		return Instr{}, 0, true, fmt.Errorf("scalar FMA3 does not support broadcast")
	}
	if !embeddedRounding && vectorBits == 3 && !(half && spec.scalar) {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}

	vectorPrefix := "X"
	vectorWidth := 16
	switch {
	case embeddedRounding && !spec.scalar:
		vectorPrefix = "Z"
		vectorWidth = 64
	case !spec.scalar:
		vectorPrefix = [...]string{"X", "Y", "Z"}[vectorBits]
		vectorWidth = [...]int{16, 32, 64}[vectorBits]
	}
	laneBytes := 4
	width64 := p1&0x80 != 0
	if width64 {
		laneBytes = 8
	}
	if half {
		laneBytes = 2
	}
	disp8Scale := vectorWidth
	if spec.scalar || broadcast {
		disp8Scale = laneBytes
	}

	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && (maskNumber != 0 && !half || rExt != 0 || rHighExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register or mask in 32-bit mode")
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}

	op := spec.op(width64)
	if half {
		op = Op(spec.stem + "PH")
		if spec.scalar {
			op = Op(spec.stem + "SH")
		}
	}
	if broadcast {
		op += ".BCST"
	}
	if embeddedRounding {
		op += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[vectorBits]
	}
	if zeroing {
		op += ".Z"
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	args := []Operand{firstSource, secondSource}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", ")), x86Encoded: half}, modRMIndex + consumed, true, nil
}

// decodedX86VEXTRACT128Instruction recognizes the complete Go 1.27 vector
// lane-extract family: the VEX F128/I128 forms and all EVEX F/I 32/64-bit
// 128/256-bit block forms. x/arch v0.14 can misdecode these raw bytes as
// PC-relative control flow or reject the EVEX encodings outright.
func decodedX86VEXTRACT128Instruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXTRACTInstruction(code, i, mode, segment, addressOverride)
	}
	if len(code) < i+6 || code[i] != 0xc4 || code[i+1]&0x1f != 3 {
		return Instr{}, 0, false, nil
	}
	vex0, vexBits, opcode := code[i+1], code[i+2], code[i+3]
	op, recognized := map[byte]Op{0x19: "VEXTRACTF128", 0x39: "VEXTRACTI128"}[opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	if vexBits&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("VEXTRACT128 requires VEX.256")
	}
	if int(^vexBits>>3)&15 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.vvvv must be 1111")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	rExt := int(^vex0>>7) & 1
	xExt := int(^vex0>>6) & 1
	bExt := int(^vex0>>5) & 1
	modRMIndex := i + 4
	modRM := code[modRMIndex]
	sourceNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || sourceNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	destination, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	source := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Y%d", sourceNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{immediate, source, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, immediate.String(), source.String(), destination.String()),
	}
	return instruction, immediateIndex + 1, true, nil
}

func decodedX86EVEXTRACTInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+5 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p0&0x0f != 3 || p1&0x07 != 5 {
		return Instr{}, 0, false, nil
	}
	opcode := code[i+4]
	width64 := p1&0x80 != 0
	outputBytes := 0
	op := Op("")
	switch opcode {
	case 0x19:
		outputBytes = 16
		op = "VEXTRACTF32X4"
		if width64 {
			op = "VEXTRACTF64X2"
		}
	case 0x1b:
		outputBytes = 32
		op = "VEXTRACTF32X8"
		if width64 {
			op = "VEXTRACTF64X4"
		}
	case 0x39:
		outputBytes = 16
		op = "VEXTRACTI32X4"
		if width64 {
			op = "VEXTRACTI64X2"
		}
	case 0x3b:
		outputBytes = 32
		op = "VEXTRACTI32X8"
		if width64 {
			op = "VEXTRACTI64X4"
		}
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x78 != 0x78 || p2&0x08 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.vvvv must be reserved")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if p2&0x10 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.b is unavailable for vector extract")
	}
	vectorBits := (p2 >> 5) & 3
	if outputBytes == 16 && vectorBits != 1 && vectorBits != 2 {
		return Instr{}, 0, true, fmt.Errorf("128-bit extract requires a 256- or 512-bit source")
	}
	if outputBytes == 32 && vectorBits != 2 {
		return Instr{}, 0, true, fmt.Errorf("256-bit extract requires a 512-bit source")
	}
	sourceName := [...]string{"", "Y", "Z"}[vectorBits]
	destinationName := "X"
	if outputBytes == 32 {
		destinationName = "Y"
	}
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	if zeroing && modRM>>6 != 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing is invalid for a memory destination")
	}
	sourceNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	destinationNumber := int(modRM&7) + bExt*8 + xExt*16
	if mode == 32 && (sourceNumber >= 8 || modRM>>6 == 3 && destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	destination, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, destinationName, outputBytes)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	source := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", sourceName, sourceNumber))}
	args := []Operand{immediate, source}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, immediateIndex + 1, true, nil
}

// decodedX86VSHUFPSInstruction recognizes Go 1.27's complete shared
// VSHUFPS/VSHUFPD operand table. x/arch v0.14 rejects some extended VEX
// encodings and all EVEX forms used by generated ecosystem assembly.
func decodedX86VSHUFPSInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXPackedFloatShuffleInstruction(code, i, mode, segment, addressOverride)
	}
	var vexLength, rExt, xExt, bExt int
	var vexBits byte
	switch {
	case len(code) >= i+3 && code[i] == 0xc5 && code[i+2] == 0xc6:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1 && code[i+3] == 0xc6:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexLength == 3 && vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	op := Op("")
	switch vexBits & 3 {
	case 0:
		op = "VSHUFPS"
	case 1:
		op = "VSHUFPD"
	default:
		return Instr{}, 0, true, fmt.Errorf("VEX.pp does not select VSHUFPS or VSHUFPD")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	opcodeIndex := i + vexLength
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	firstSource, consumed, err := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{immediate, firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s, %s", op, immediate.String(), firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, immediateIndex + 1, true, nil
}

func decodedX86EVEXPackedFloatShuffleInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+7 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p0&0x0f != 1 || p1&0x04 == 0 || code[i+4] != 0xc6 {
		return Instr{}, 0, false, nil
	}
	op := Op("")
	switch {
	case p1&3 == 0 && p1&0x80 == 0:
		op = "VSHUFPS"
	case p1&3 == 1 && p1&0x80 != 0:
		op = "VSHUFPD"
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorPrefix := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = 4
		if op == "VSHUFPD" {
			disp8Scale = 8
		}
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	args := []Operand{immediate, firstSource, secondSource}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, immediateIndex + 1, true, nil
}

// decodedX86PackedShuffleInstruction recognizes the complete Go 1.27
// _yvpshufd family: VPSHUFD, VPSHUFHW, and VPSHUFLW across VEX.128,
// VEX.256, and EVEX.128/256/512, including memory, mask, zeroing, and the
// VPSHUFD broadcast forms. x/arch v0.14 can split the VEX bytes emitted by
// Weaviate into a relative branch, so recover the family before consulting
// the generic decoder.
func decodedX86PackedShuffleInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vectorPrefix
		}
	}

vectorPrefix:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXPackedShuffleInstruction(code, i, mode, segment, addressOverride)
	}

	var vexLength, rExt, xExt, bExt int
	var vexBits byte
	switch {
	case len(code) >= i+3 && code[i] == 0xc5 && code[i+2] == 0x70:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1 && code[i+3] == 0x70:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
	default:
		return Instr{}, 0, false, nil
	}
	op := map[byte]Op{1: "VPSHUFD", 2: "VPSHUFHW", 3: "VPSHUFLW"}[vexBits&3]
	if op == "" {
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexBits&0x78 != 0x78 {
		return Instr{}, 0, true, fmt.Errorf("VEX.vvvv must be reserved")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	opcodeIndex := i + vexLength
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorName := "X"
	if vexBits&0x04 != 0 {
		vectorName = "Y"
	}
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{immediate, source, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, immediate.String(), source.String(), destination.String()),
	}
	return instruction, immediateIndex + 1, true, nil
}

func decodedX86EVEXPackedShuffleInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+5 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p0&0x0f != 1 || p1&0x04 == 0 || code[i+4] != 0x70 {
		return Instr{}, 0, false, nil
	}
	op := map[byte]Op{1: "VPSHUFD", 2: "VPSHUFHW", 3: "VPSHUFLW"}[p1&3]
	if op == "" || op == "VPSHUFD" && p1&0x80 != 0 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x78 != 0x78 || p2&0x08 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.vvvv must be reserved")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 packed shuffle mask form exceeds the Go assembler frontend's operand limit")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && op != "VPSHUFD" {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast is only available for VPSHUFD")
	}
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = 4
	}
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && (destinationNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	source, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{immediate, source}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, immediateIndex + 1, true, nil
}

// decodedX86Shuffle128BitBlocksInstruction recognizes the complete EVEX-only
// Go 1.27 _yvshuff32x4 family: VSHUFF32X4, VSHUFF64X2, VSHUFI32X4, and
// VSHUFI64X2. x/arch v0.14 rejects these raw encodings, including the
// VSHUFF64X2 sequence in github.com/minio/sha256-simd.
func decodedX86Shuffle128BitBlocksInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+7 || code[i] != 0x62 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	if p0&0x0f != 3 || p1&0x07 != 5 || opcode != 0x23 && opcode != 0x43 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits != 1 && vectorBits != 2 {
		return Instr{}, 0, true, fmt.Errorf("VSHUFF/VSHUFI block shuffle requires a 256- or 512-bit vector")
	}
	vectorPrefix := [...]string{"", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{0, 32, 64}[vectorBits]
	width64 := p1&0x80 != 0
	op := Op("VSHUFF32X4")
	laneBytes := 4
	if opcode == 0x43 {
		op = "VSHUFI32X4"
	}
	if width64 {
		laneBytes = 8
		if opcode == 0x23 {
			op = "VSHUFF64X2"
		} else {
			op = "VSHUFI64X2"
		}
	}
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = laneBytes
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	args := []Operand{immediate, firstSource, secondSource}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, immediateIndex + 1, true, nil
}

// decodedX86VPSHUFBInstruction recognizes every VEX and EVEX encoding behind
// Go 1.27's _yvandnpd table. x/arch v0.14 rejects the EVEX forms used by
// github.com/minio/sha256-simd.
func decodedX86VPSHUFBInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vectorPrefix
		}
	}

vectorPrefix:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+4 {
		return Instr{}, 0, false, nil
	}
	if code[i] == 0xc4 && code[i+1]&0x1f == 2 && code[i+3] == 0x00 {
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		vex0, vex1 := code[i+1], code[i+2]
		if vex1&3 != 1 {
			return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
		}
		if vex1&0x80 != 0 {
			return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
		}
		if len(code) <= i+4 {
			return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
		}
		rExt := int(^vex0>>7) & 1
		xExt := int(^vex0>>6) & 1
		bExt := int(^vex0>>5) & 1
		vectorName := "X"
		if vex1&0x04 != 0 {
			vectorName = "Y"
		}
		modRMIndex := i + 4
		modRM := code[modRMIndex]
		dataNumber := int(^vex1>>3) & 15
		destinationNumber := int(modRM>>3&7) + rExt*8
		if mode == 32 && (dataNumber >= 8 || destinationNumber >= 8) {
			return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
		}
		control, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName)
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		data := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, dataNumber))}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
		return Instr{
			Op:   "VPSHUFB",
			Args: []Operand{control, data, destination},
			Raw:  fmt.Sprintf("VPSHUFB %s, %s, %s", control.String(), data.String(), destination.String()),
		}, modRMIndex + consumed, true, nil
	}

	if len(code) < i+5 || code[i] != 0x62 || code[i+1]&0x0f != 2 || code[i+2]&0x07 != 5 || code[i+4] != 0x00 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p1&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W must be zero")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	if p2&0x10 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.b is unavailable for VPSHUFB")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 VPSHUFB mask form exceeds the Go assembler frontend's operand limit")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	dataNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && (dataNumber >= 8 || destinationNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	control, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, vectorWidth)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	data := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, dataNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{control, data}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	op := Op("VPSHUFB")
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

type decodedX86PackedExtendProperties struct {
	op         Op
	inputBits  int
	outputBits int
}

func decodedX86PackedExtendOpcode(opcode byte) (decodedX86PackedExtendProperties, bool) {
	properties := map[byte]decodedX86PackedExtendProperties{
		0x20: {op: "VPMOVSXBW", inputBits: 8, outputBits: 16},
		0x21: {op: "VPMOVSXBD", inputBits: 8, outputBits: 32},
		0x22: {op: "VPMOVSXBQ", inputBits: 8, outputBits: 64},
		0x23: {op: "VPMOVSXWD", inputBits: 16, outputBits: 32},
		0x24: {op: "VPMOVSXWQ", inputBits: 16, outputBits: 64},
		0x25: {op: "VPMOVSXDQ", inputBits: 32, outputBits: 64},
		0x30: {op: "VPMOVZXBW", inputBits: 8, outputBits: 16},
		0x31: {op: "VPMOVZXBD", inputBits: 8, outputBits: 32},
		0x32: {op: "VPMOVZXBQ", inputBits: 8, outputBits: 64},
		0x33: {op: "VPMOVZXWD", inputBits: 16, outputBits: 32},
		0x34: {op: "VPMOVZXWQ", inputBits: 16, outputBits: 64},
		0x35: {op: "VPMOVZXDQ", inputBits: 32, outputBits: 64},
	}[opcode]
	return properties, properties.op != ""
}

// decodedX86PackedExtendInstruction recognizes all six signed and all six
// unsigned packed extending moves in Go 1.27. It covers their VEX.128/256 and
// EVEX.128/256/512 register and memory forms, including high registers,
// writemasks, zeroing, and compressed displacements. EVEX.b is deliberately
// rejected because no broadcast form exists in the Go operand tables.
func decodedX86PackedExtendInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vectorPrefix
		}
	}

vectorPrefix:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) > i && code[i] == 0x62 {
		return decodedX86EVEXPackedExtendInstruction(code, i, mode, segment, addressOverride)
	}
	if len(code) < i+4 || code[i] != 0xc4 || code[i+1]&0x1f != 2 {
		return Instr{}, 0, false, nil
	}
	vex0, vex1 := code[i+1], code[i+2]
	properties, recognized := decodedX86PackedExtendOpcode(code[i+3])
	if !recognized || vex1&3 != 1 || vex1&0x80 != 0 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if vex1&0x78 != 0x78 {
		return Instr{}, 0, true, fmt.Errorf("VEX.vvvv must be reserved")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	modRMIndex := i + 4
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	rExt := int(^vex0>>7) & 1
	xExt := int(^vex0>>6) & 1
	bExt := int(^vex0>>5) & 1
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (destinationNumber >= 8 || code[modRMIndex]>>6 == 3 && int(code[modRMIndex]&7)+bExt*8 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	destinationName := "X"
	if vex1&0x04 != 0 {
		destinationName = "Y"
	}
	source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", destinationName, destinationNumber))}
	instruction = Instr{
		Op:   properties.op,
		Args: []Operand{source, destination},
		Raw:  fmt.Sprintf("%s %s, %s", properties.op, source.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

func decodedX86EVEXPackedExtendInstruction(code []byte, i, mode int, segment Reg, addressOverride bool) (instruction Instr, length int, ok bool, err error) {
	if len(code) < i+5 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p0&0x0f != 2 || p1&0x07 != 5 {
		return Instr{}, 0, false, nil
	}
	properties, recognized := decodedX86PackedExtendOpcode(code[i+4])
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x78 != 0x78 || p2&0x08 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.vvvv must be reserved")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if p2&0x10 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.b is unavailable for packed extending moves")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	destinationName := [...]string{"X", "Y", "Z"}[vectorBits]
	destinationBytes := [...]int{16, 32, 64}[vectorBits]
	sourceBytes := destinationBytes * properties.inputBits / properties.outputBits
	sourceName := "X"
	if sourceBytes > 16 {
		sourceName = "Y"
	}
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	sourceNumber := int(modRM&7) + bExt*8 + xExt*16
	if mode == 32 && (destinationNumber >= 8 || modRM>>6 == 3 && sourceNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	source, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, sourceName, sourceBytes)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", destinationName, destinationNumber))}
	args := []Operand{source}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	op := properties.op
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

type decodedX86PackedUniformShiftProperties struct {
	op        Op
	laneBytes int
	immediate bool
}

func decodedX86PackedUniformShiftOpcode(opcode, modRM byte, evex, w bool) (decodedX86PackedUniformShiftProperties, bool) {
	laneBytes := map[byte]int{0x71: 2, 0x72: 4, 0x73: 8}[opcode]
	if laneBytes != 0 {
		direction := modRM >> 3 & 7
		if direction != 2 && direction != 4 && direction != 6 {
			return decodedX86PackedUniformShiftProperties{}, false
		}
		stem := "VPSRL"
		switch direction {
		case 4:
			if laneBytes == 8 {
				return decodedX86PackedUniformShiftProperties{}, false
			}
			stem = "VPSRA"
			if evex && w && laneBytes == 4 {
				laneBytes = 8
			}
		case 6:
			stem = "VPSLL"
		}
		suffix := map[int]string{2: "W", 4: "D", 8: "Q"}[laneBytes]
		return decodedX86PackedUniformShiftProperties{op: Op(stem + suffix), laneBytes: laneBytes, immediate: true}, true
	}
	variable := map[byte]struct {
		op        Op
		laneBytes int
	}{
		0xf1: {op: "VPSLLW", laneBytes: 2},
		0xf2: {op: "VPSLLD", laneBytes: 4},
		0xf3: {op: "VPSLLQ", laneBytes: 8},
		0xd1: {op: "VPSRLW", laneBytes: 2},
		0xd2: {op: "VPSRLD", laneBytes: 4},
		0xd3: {op: "VPSRLQ", laneBytes: 8},
		0xe1: {op: "VPSRAW", laneBytes: 2},
		0xe2: {op: "VPSRAD", laneBytes: 4},
	}
	properties, ok := variable[opcode]
	if !ok {
		return decodedX86PackedUniformShiftProperties{}, false
	}
	if evex && w && opcode == 0xe2 {
		properties.op, properties.laneBytes = "VPSRAQ", 8
	}
	return decodedX86PackedUniformShiftProperties{op: properties.op, laneBytes: properties.laneBytes}, true
}

// decodedX86PackedUniformShiftInstruction recognizes the complete Go 1.27
// immediate and XMM/m128-count grammar: six logical shifts and three
// arithmetic right shifts across VEX/EVEX X/Y/Z widths. x/arch v0.14
// misdecodes several VEX/EVEX forms used by external assembly.
func decodedX86PackedUniformShiftInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vectorPrefix
		}
	}

vectorPrefix:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+4 {
		return Instr{}, 0, false, nil
	}

	var vexBits byte
	var opcodeIndex, modRMIndex, rExt, xExt, bExt int
	isVEX := false
	vexHasW := false
	switch {
	case code[i] == 0xc5:
		vexBits = code[i+1]
		opcodeIndex = i + 2
		modRMIndex = i + 3
		rExt = int(^vexBits>>7) & 1
		isVEX = true
	case len(code) >= i+5 && code[i] == 0xc4 && code[i+1]&0x1f == 1:
		vex0 := code[i+1]
		vexBits = code[i+2]
		opcodeIndex = i + 3
		modRMIndex = i + 4
		rExt = int(^vex0>>7) & 1
		xExt = int(^vex0>>6) & 1
		bExt = int(^vex0>>5) & 1
		isVEX = true
		vexHasW = true
	}
	if isVEX {
		properties, recognized := decodedX86PackedUniformShiftOpcode(code[opcodeIndex], code[modRMIndex], false, vexHasW && vexBits&0x80 != 0)
		if !recognized {
			return Instr{}, 0, false, nil
		}
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		if vexBits&3 != 1 {
			return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
		}
		if vexHasW && vexBits&0x80 != 0 {
			return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
		}
		vectorName := "X"
		if vexBits&0x04 != 0 {
			vectorName = "Y"
		}
		modRM := code[modRMIndex]
		vvvvNumber := int(^vexBits>>3) & 15
		if properties.immediate {
			if rExt != 0 {
				return Instr{}, 0, true, fmt.Errorf("VEX.R must not extend the shift opcode selector")
			}
			if mode == 32 && vvvvNumber >= 8 {
				return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
			}
			source, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName)
			if decodeErr != nil {
				return Instr{}, 0, true, decodeErr
			}
			immediateIndex := modRMIndex + consumed
			if len(code) <= immediateIndex {
				return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
			}
			immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
			destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, vvvvNumber))}
			return Instr{
				Op:         properties.op,
				Args:       []Operand{immediate, source, destination},
				Raw:        fmt.Sprintf("%s %s, %s, %s", properties.op, immediate.String(), source.String(), destination.String()),
				x86Encoded: true,
			}, immediateIndex + 1, true, nil
		}

		destinationNumber := int(modRM>>3&7) + rExt*8
		if mode == 32 && (vvvvNumber >= 8 || destinationNumber >= 8) {
			return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
		}
		count, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X")
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		data := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, vvvvNumber))}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
		return Instr{
			Op:         properties.op,
			Args:       []Operand{count, data, destination},
			Raw:        fmt.Sprintf("%s %s, %s, %s", properties.op, count.String(), data.String(), destination.String()),
			x86Encoded: true,
		}, modRMIndex + consumed, true, nil
	}

	if len(code) < i+6 || code[i] != 0x62 || code[i+1]&0x0f != 1 || code[i+2]&0x07 != 5 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	modRMIndex = i + 5
	modRM := code[modRMIndex]
	properties, recognized := decodedX86PackedUniformShiftOpcode(code[i+4], modRM, true, p1&0x80 != 0)
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if (p1&0x80 != 0) != (properties.laneBytes == 8) {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W does not match %s", properties.op)
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	rExt = int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt = int(^p0>>6) & 1
	bExt = int(^p0>>5) & 1
	vvvvNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	broadcast := p2&0x10 != 0
	if properties.immediate {
		if p0&0x90 != 0x90 {
			return Instr{}, 0, true, fmt.Errorf("EVEX.R and EVEX.R' must not extend the shift opcode selector")
		}
		if broadcast && properties.laneBytes == 2 {
			return Instr{}, 0, true, fmt.Errorf("EVEX broadcast is unavailable for %s", properties.op)
		}
		if broadcast && modRM>>6 == 3 {
			return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
		}
		if mode == 32 && (vvvvNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
			return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
		}
		disp8Scale := vectorWidth
		if broadcast {
			disp8Scale = properties.laneBytes
		}
		source, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		immediateIndex := modRMIndex + consumed
		if len(code) <= immediateIndex {
			return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
		}
		immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, vvvvNumber))}
		args := []Operand{immediate, source}
		if maskNumber != 0 {
			args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
		}
		args = append(args, destination)
		op := properties.op
		if broadcast {
			op += ".BCST"
		}
		if zeroing {
			op += ".Z"
		}
		rawArgs := make([]string, len(args))
		for index := range args {
			rawArgs[index] = args[index].String()
		}
		return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", ")), x86Encoded: true}, immediateIndex + 1, true, nil
	}

	if broadcast {
		return Instr{}, 0, true, fmt.Errorf("EVEX.b is unavailable for the uniform-count form of %s", properties.op)
	}
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && (vvvvNumber >= 8 || destinationNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	count, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "X", 16)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	data := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, vvvvNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{count, data}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	op := properties.op
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", ")), x86Encoded: true}, modRMIndex + consumed, true, nil
}

// decodedX86TernaryLogicInstruction recognizes VPTERNLOGD/Q across the
// complete Go 1.27 _yvalignd table. x/arch v0.14 rejects the EVEX encodings
// used by github.com/minio/sha256-simd.
func decodedX86TernaryLogicInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	return decodedX86EVEXImmediateThreeVectorInstruction(code, mode, 0x25, "VPTERNLOGD", "VPTERNLOGQ", "VPTERNLOG")
}

// decodedX86VectorAlignInstruction recognizes VALIGND/Q across the complete
// Go 1.27 _yvalignd table.
func decodedX86VectorAlignInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	return decodedX86EVEXImmediateThreeVectorInstruction(code, mode, 0x03, "VALIGND", "VALIGNQ", "VALIGN")
}

// decodedX86FunnelShiftInstruction recognizes the complete Go 1.27 VBMI2
// funnel-shift family: immediate/variable, left/right, and W/D/Q lanes.
// x/arch v0.14 rejects all of these EVEX encodings.
func decodedX86FunnelShiftInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+6 || code[i] != 0x62 || code[i+2]&0x07 != 5 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	mapNumber := p0 & 0x0f
	variable := false
	switch mapNumber {
	case 2:
		variable = true
	case 3:
	default:
		return Instr{}, 0, false, nil
	}
	opcode := code[i+4]
	wBit := p1&0x80 != 0
	laneBits := 0
	left := false
	switch opcode {
	case 0x70:
		left, laneBits = true, 16
	case 0x71:
		left = true
		if wBit {
			laneBits = 64
		} else {
			laneBits = 32
		}
	case 0x72:
		laneBits = 16
	case 0x73:
		if wBit {
			laneBits = 64
		} else {
			laneBits = 32
		}
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if laneBits == 16 && !wBit {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W must be one for word funnel shifts")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if !variable && mode == 32 {
		return Instr{}, 0, true, fmt.Errorf("386 immediate funnel shifts exceed the Go assembler frontend's operand limit")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if variable && mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 variable funnel-shift mask form exceeds the Go assembler frontend's operand limit")
	}
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && laneBits == 16 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast is unavailable for word funnel shifts")
	}
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && (secondSourceNumber >= 8 || destinationNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = laneBits / 8
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	opDirection := "R"
	if left {
		opDirection = "L"
	}
	laneSuffix := map[int]string{16: "W", 32: "D", 64: "Q"}[laneBits]
	op := Op("VPSH" + opDirection + "D")
	if variable {
		op += "V"
	}
	op += Op(laneSuffix)
	args := make([]Operand, 0, 5)
	end := modRMIndex + consumed
	if !variable {
		if len(code) <= end {
			return Instr{}, 0, false, nil
		}
		args = append(args, Operand{Kind: OpImm, Imm: int64(code[end])})
		end++
	}
	args = append(args, firstSource, secondSource)
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, end, true, nil
}

// decodedX86EVEXImmediateThreeVectorInstruction implements the EVEX immediate,
// r/m, vvvv, destination shape shared by Go 1.27's _yvalignd families.
func decodedX86EVEXImmediateThreeVectorInstruction(code []byte, mode int, opcode byte, dwordOp, qwordOp Op, family string) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+7 || code[i] != 0x62 || code[i+1]&0x0f != 3 || code[i+2]&0x07 != 5 || code[i+4] != opcode {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if mode == 32 {
		return Instr{}, 0, true, fmt.Errorf("386 %s is rejected by the Go assembler frontend's operand limit", family)
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	laneBytes := 4
	op := dwordOp
	if p1&0x80 != 0 {
		laneBytes = 8
		op = qwordOp
	}
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = laneBytes
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{immediate, firstSource, secondSource}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, immediateIndex + 1, true, nil
}

// decodedX86PackedImmediateRotateInstruction recognizes all four EVEX
// immediate rotates in Go 1.27's _yvprold table. x/arch v0.14 rejects these
// raw encodings, including VPRORD in github.com/minio/sha256-simd.
func decodedX86PackedImmediateRotateInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+7 || code[i] != 0x62 || code[i+1]&0x0f != 1 || code[i+2]&0x07 != 5 || code[i+4] != 0x72 {
		return Instr{}, 0, false, nil
	}
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	selector := modRM >> 3 & 7
	if selector != 0 && selector != 1 {
		// Opcode 72 is a grouped encoding. Selectors /2 and /6 are the
		// VPSRL/VPSLL logical-shift family, and other selectors may belong to
		// decoders added later. This decoder only owns the rotate selectors.
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p0&0x90 != 0x90 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.R and EVEX.R' must not extend the rotate opcode selector")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	laneBytes := 4
	left := false
	switch selector {
	case 0:
	case 1:
		left = true
	}
	op := Op("VPRORD")
	if left {
		op = "VPROLD"
	}
	if p1&0x80 != 0 {
		laneBytes = 8
		if left {
			op = "VPROLQ"
		} else {
			op = "VPRORQ"
		}
	}
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 %s mask form exceeds the Go assembler frontend's operand limit", op)
	}

	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	broadcast := p2&0x10 != 0
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	destinationNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	if mode == 32 && (destinationNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = laneBytes
	}
	source, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{immediate, source}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, immediateIndex + 1, true, nil
}

var decodedX86PackedIntegerArithmeticOps = map[byte]struct {
	op        Op
	laneBytes int
}{
	0xfc: {op: "VPADDB", laneBytes: 1},
	0xfd: {op: "VPADDW", laneBytes: 2},
	0xfe: {op: "VPADDD", laneBytes: 4},
	0xd4: {op: "VPADDQ", laneBytes: 8},
	0xec: {op: "VPADDSB", laneBytes: 1},
	0xed: {op: "VPADDSW", laneBytes: 2},
	0xdc: {op: "VPADDUSB", laneBytes: 1},
	0xdd: {op: "VPADDUSW", laneBytes: 2},
	0xf8: {op: "VPSUBB", laneBytes: 1},
	0xf9: {op: "VPSUBW", laneBytes: 2},
	0xfa: {op: "VPSUBD", laneBytes: 4},
	0xfb: {op: "VPSUBQ", laneBytes: 8},
	0xe8: {op: "VPSUBSB", laneBytes: 1},
	0xe9: {op: "VPSUBSW", laneBytes: 2},
	0xd8: {op: "VPSUBUSB", laneBytes: 1},
	0xd9: {op: "VPSUBUSW", laneBytes: 2},
}

// decodedX86PackedIntegerArithmeticInstruction recognizes the complete
// VEX/EVEX VPADD and VPSUB families behind Go 1.27's shared _yvandnpd table.
// x/arch v0.14 rejects EVEX forms and can split VEX forms used by ecosystem
// assembly.
func decodedX86PackedIntegerArithmeticInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vectorPrefix
		}
	}

vectorPrefix:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+3 {
		return Instr{}, 0, false, nil
	}

	var vexBits byte
	var opcodeIndex, modRMIndex, rExt, xExt, bExt int
	isVEX := false
	switch {
	case code[i] == 0xc5:
		vexBits = code[i+1]
		opcodeIndex = i + 2
		modRMIndex = i + 3
		rExt = int(^vexBits>>7) & 1
		isVEX = true
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1:
		vex0 := code[i+1]
		vexBits = code[i+2]
		opcodeIndex = i + 3
		modRMIndex = i + 4
		rExt = int(^vex0>>7) & 1
		xExt = int(^vex0>>6) & 1
		bExt = int(^vex0>>5) & 1
		isVEX = true
	}
	if isVEX {
		properties, recognized := decodedX86PackedIntegerArithmeticOps[code[opcodeIndex]]
		if !recognized {
			return Instr{}, 0, false, nil
		}
		ok = true
		if addressOverride {
			return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
		}
		if vexBits&3 != 1 {
			return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
		}
		if len(code) <= modRMIndex {
			return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
		}
		vectorName := "X"
		if vexBits&0x04 != 0 {
			vectorName = "Y"
		}
		modRM := code[modRMIndex]
		secondSourceNumber := int(^vexBits>>3) & 15
		destinationNumber := int(modRM>>3&7) + rExt*8
		if mode == 32 && (secondSourceNumber >= 8 || destinationNumber >= 8) {
			return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
		}
		firstSource, consumed, decodeErr := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName)
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
		secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondSourceNumber))}
		destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
		return Instr{
			Op:   properties.op,
			Args: []Operand{firstSource, secondSource, destination},
			Raw:  fmt.Sprintf("%s %s, %s, %s", properties.op, firstSource.String(), secondSource.String(), destination.String()),
		}, modRMIndex + consumed, true, nil
	}

	if len(code) < i+5 || code[i] != 0x62 || code[i+1]&0x0f != 1 || code[i+2]&0x07 != 5 {
		return Instr{}, 0, false, nil
	}
	properties, recognized := decodedX86PackedIntegerArithmeticOps[code[i+4]]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	wBit := p1&0x80 != 0
	if wBit != (properties.laneBytes == 8) {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W does not match %s", properties.op)
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 %s mask form exceeds the Go assembler frontend's operand limit", properties.op)
	}

	rExt = int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt = int(^p0>>6) & 1
	bExt = int(^p0>>5) & 1
	modRMIndex = i + 5
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && properties.laneBytes != 4 && properties.laneBytes != 8 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast is unavailable for %s", properties.op)
	}
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && (secondSourceNumber >= 8 || destinationNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = properties.laneBytes
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{firstSource, secondSource}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	op := properties.op
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

// decodedX86IndexedPermuteInstruction recognizes the complete EVEX-only
// VPERMI2 and VPERMT2 families behind Go 1.27's shared _yvblendmpd table.
func decodedX86IndexedPermuteInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+6 || code[i] != 0x62 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	if p0&0x0f != 2 || p1&0x07 != 5 ||
		(opcode < 0x75 || opcode > 0x77) && (opcode < 0x7d || opcode > 0x7f) {
		return Instr{}, 0, false, nil
	}
	width64 := p1&0x80 != 0
	op := Op("")
	laneBytes := 0
	switch opcode {
	case 0x75:
		if width64 {
			op, laneBytes = "VPERMI2W", 2
		} else {
			op, laneBytes = "VPERMI2B", 1
		}
	case 0x76:
		if width64 {
			op, laneBytes = "VPERMI2Q", 8
		} else {
			op, laneBytes = "VPERMI2D", 4
		}
	case 0x77:
		if width64 {
			op, laneBytes = "VPERMI2PD", 8
		} else {
			op, laneBytes = "VPERMI2PS", 4
		}
	case 0x7d:
		if width64 {
			op, laneBytes = "VPERMT2W", 2
		} else {
			op, laneBytes = "VPERMT2B", 1
		}
	case 0x7e:
		if width64 {
			op, laneBytes = "VPERMT2Q", 8
		} else {
			op, laneBytes = "VPERMT2D", 4
		}
	case 0x7f:
		if width64 {
			op, laneBytes = "VPERMT2PD", 8
		} else {
			op, laneBytes = "VPERMT2PS", 4
		}
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorPrefix := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 indexed permute mask form exceeds the Go assembler operand limit")
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && laneBytes < 4 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast is unavailable for byte and word VPERMI2")
	}
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = laneBytes
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	if mode == 32 && vectorBits == 2 &&
		(destinationNumber >= 8 || secondSourceNumber >= 8 ||
			modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("386 Z register exceeds the Go assembler frontend's register class")
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	args := []Operand{firstSource, secondSource}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

// Go 1.27's _yvcompresspd and _yvexpandpd families share the same typed
// register/memory grammar, with the ModRM roles reversed for stores.
func decodedX86PackedCompressInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86PackedCompactInstruction(code, mode, true)
}

func decodedX86PackedExpandInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86PackedCompactInstruction(code, mode, false)
}

func decodedX86PackedCompactInstruction(code []byte, mode int, store bool) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+6 || code[i] != 0x62 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	if p0&0x0f != 2 || p1&0x07 != 5 {
		return Instr{}, 0, false, nil
	}
	if store && opcode != 0x63 && opcode != 0x8a && opcode != 0x8b ||
		!store && opcode != 0x62 && opcode != 0x88 && opcode != 0x89 {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x78 != 0x78 || p2&0x08 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX packed compact reserves the vvvv register field")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if p2&0x10 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast is unavailable for packed compact")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorPrefix := [...]string{"X", "Y", "Z"}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 packed compact mask form exceeds the Go assembler operand limit")
	}
	width64 := p1&0x80 != 0
	op := Op("")
	laneBytes := 0
	switch opcode {
	case 0x63:
		if width64 {
			op, laneBytes = "VPCOMPRESSW", 2
		} else {
			op, laneBytes = "VPCOMPRESSB", 1
		}
	case 0x8a:
		if width64 {
			op, laneBytes = "VCOMPRESSPD", 8
		} else {
			op, laneBytes = "VCOMPRESSPS", 4
		}
	case 0x8b:
		if width64 {
			op, laneBytes = "VPCOMPRESSQ", 8
		} else {
			op, laneBytes = "VPCOMPRESSD", 4
		}
	case 0x62:
		if width64 {
			op, laneBytes = "VPEXPANDW", 2
		} else {
			op, laneBytes = "VPEXPANDB", 1
		}
	case 0x88:
		if width64 {
			op, laneBytes = "VEXPANDPD", 8
		} else {
			op, laneBytes = "VEXPANDPS", 4
		}
	case 0x89:
		if width64 {
			op, laneBytes = "VPEXPANDQ", 8
		} else {
			op, laneBytes = "VPEXPANDD", 4
		}
	}
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	if mode == 32 && vectorBits == 2 &&
		(int(modRM>>3&7)+rExt*8+rHighExt*16 >= 8 ||
			modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("386 Z register exceeds the Go assembler frontend's register class")
	}
	regNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	reg := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, regNumber))}
	rm, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix, laneBytes)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	args := []Operand{reg}
	if !store {
		args = []Operand{rm}
	}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	if store {
		args = append(args, rm)
	} else {
		args = append(args, reg)
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

// decodedX86IFMAInstruction recognizes the complete EVEX-only
// VPMADD52HUQ/LUQ family behind Go 1.27's _yvblendmpd table. x/arch v0.14
// rejects these encodings.
func decodedX86IFMAInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+6 || code[i] != 0x62 || code[i+1]&0x0f != 2 || code[i+2]&0x07 != 5 {
		return Instr{}, 0, false, nil
	}
	op := Op("")
	switch code[i+4] {
	case 0xb4:
		op = "VPMADD52LUQ"
	case 0xb5:
		op = "VPMADD52HUQ"
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	if p1&0x80 == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W must be one for %s", op)
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits == 3 {
		return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
	}
	vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 %s mask form exceeds the Go assembler frontend's operand limit", op)
	}

	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	secondSourceNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && (secondSourceNumber >= 8 || destinationNumber >= 8 || modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = 8
	}
	firstSource, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorName, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorName, destinationNumber))}
	args := []Operand{firstSource, secondSource}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

// decodedX86VPINSRInstruction recognizes the complete VEX.128 VPINSR
// byte/word/dword/qword family, including two- and three-byte VEX encodings and
// every ModRM/SIB source. x/arch v0.14 rejects some extended-register VPINSRQ
// forms used by generated crypto assembly. EVEX forms continue through x/arch.
func decodedX86VPINSRInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	var vexLength, rExt, xExt, bExt int
	var vexBits byte
	op := Op("")
	switch {
	case len(code) >= i+3 && code[i] == 0xc5 && code[i+2] == 0xc4:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
		op = "VPINSRW"
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1 && code[i+3] == 0xc4:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		op = "VPINSRW"
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 3 && code[i+3] == 0x20:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		op = "VPINSRB"
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 3 && code[i+3] == 0x22:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		op = "VPINSRD"
		if vexBits&0x80 != 0 {
			op = "VPINSRQ"
		}
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if vexBits&0x04 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.L must be zero")
	}
	if (op == "VPINSRB" || op == "VPINSRW") && vexLength == 3 && vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero for %s", op)
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	opcodeIndex := i + vexLength
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	firstVectorNumber := int(^vexBits>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (op == "VPINSRQ" || rExt != 0 || xExt != 0 || bExt != 0 || firstVectorNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("64-bit width or extended register in 32-bit mode")
	}
	scalar, consumed, err := decodedX86VEXRMSource(code[modRMIndex:], mode, bExt, xExt, segment)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	firstVector := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", firstVectorNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{immediate, scalar, firstVector, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s, %s", op, immediate.String(), scalar.String(), firstVector.String(), destination.String()),
	}
	return instruction, immediateIndex + 1, true, nil
}

// decodedX86VPUNPCKInstruction recognizes the complete VEX.128/VEX.256
// low/high byte, word, dword, and qword unpack family. x/arch v0.14 can split
// or reject VEX encodings with extended registers, so recover every VEX
// register and ModRM/SIB memory form before the generic decoder. EVEX forms
// use the separate decodedX86EVEXPackedUnpackInstruction grammar.
func decodedX86VPUNPCKInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	var vexLength, rExt, xExt, bExt int
	var vexBits, opcode byte
	switch {
	case len(code) >= i+3 && code[i] == 0xc5:
		vexLength = 2
		vexBits = code[i+1]
		rExt = int(^vexBits>>7) & 1
		opcode = code[i+2]
	case len(code) >= i+4 && code[i] == 0xc4 && code[i+1]&0x1f == 1:
		vexLength = 3
		vexBits = code[i+2]
		rExt = int(^code[i+1]>>7) & 1
		xExt = int(^code[i+1]>>6) & 1
		bExt = int(^code[i+1]>>5) & 1
		opcode = code[i+3]
	default:
		return Instr{}, 0, false, nil
	}
	op, recognized := map[byte]Op{
		0x60: "VPUNPCKLBW",
		0x61: "VPUNPCKLWD",
		0x62: "VPUNPCKLDQ",
		0x6c: "VPUNPCKLQDQ",
		0x68: "VPUNPCKHBW",
		0x69: "VPUNPCKHWD",
		0x6a: "VPUNPCKHDQ",
		0x6d: "VPUNPCKHQDQ",
	}[opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if vexLength == 3 && vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	opcodeIndex := i + vexLength
	modRMIndex := opcodeIndex + 1
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	firstSource, consumed, err := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if err != nil {
		return Instr{}, 0, true, err
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

func decodedX86VEXVectorRMOperand(code []byte, mode, bExt, xExt int, segment Reg, vectorPrefix string) (Operand, int, error) {
	if len(code) == 0 {
		return Operand{}, 0, fmt.Errorf("missing ModRM byte")
	}
	if code[0]>>6 != 3 {
		return decodedX86VEXRMSource(code, mode, bExt, xExt, segment)
	}
	number := int(code[0]&7) + bExt*8
	if mode == 32 && number >= 8 {
		return Operand{}, 0, fmt.Errorf("extended vector register in 32-bit mode")
	}
	return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, number))}, 1, nil
}

// decodedX86VNNIInstruction recognizes the complete VEX.128/VEX.256
// AVX-VNNI dot-product family. Go's assembler exposes the equivalent named
// EVEX forms, while generated third-party assembly uses raw VEX encodings that
// x/arch v0.14 cannot decode. Recover all four opcodes and every register or
// ModRM/SIB memory source before consulting the generic decoder.
func decodedX86VNNIInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+4 || code[i] != 0xc4 || code[i+1]&0x1f != 2 {
		return Instr{}, 0, false, nil
	}
	vexBits := code[i+2]
	opcode := code[i+3]
	op, recognized := map[byte]Op{
		0x50: "VPDPBUSD",
		0x51: "VPDPBUSDS",
		0x52: "VPDPWSSD",
		0x53: "VPDPWSSDS",
	}[opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	vex1 := code[i+1]
	rExt := int(^vex1>>7) & 1
	xExt := int(^vex1>>6) & 1
	bExt := int(^vex1>>5) & 1
	modRMIndex := i + 4
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	vectorPrefix := "X"
	if vexBits&0x04 != 0 {
		vectorPrefix = "Y"
	}
	secondSourceNumber := int(^vexBits>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondSourceNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	firstSource, consumed, err := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix)
	if err != nil {
		return Instr{}, 0, true, err
	}
	secondSource := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, secondSourceNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{firstSource, secondSource, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, firstSource.String(), secondSource.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

// decodedX86VariableDwordPermuteInstruction recognizes the complete VEX.256
// VPERMD/VPERMPS family shared by Go 1.27's _yvpermd table. x/arch v0.14 can
// reject or split these encodings, so recover every register and ModRM/SIB
// memory source before consulting the generic decoder. EVEX forms continue
// through x/arch.
func decodedX86VariableDwordPermuteInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+4 || code[i] != 0xc4 || code[i+1]&0x1f != 2 {
		return Instr{}, 0, false, nil
	}
	vexBits := code[i+2]
	opcode := code[i+3]
	op, recognized := map[byte]Op{
		0x36: "VPERMD",
		0x16: "VPERMPS",
	}[opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	ok = true
	if vexBits&3 != 1 {
		return Instr{}, 0, true, fmt.Errorf("VEX.pp must be 66")
	}
	if vexBits&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
	}
	if vexBits&0x04 == 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.L must be one")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	vex1 := code[i+1]
	rExt := int(^vex1>>7) & 1
	xExt := int(^vex1>>6) & 1
	bExt := int(^vex1>>5) & 1
	modRMIndex := i + 4
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	indicesNumber := int(^vexBits>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || indicesNumber >= 8 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	data, consumed, err := decodedX86VEXVectorRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, "Y")
	if err != nil {
		return Instr{}, 0, true, err
	}
	indices := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Y%d", indicesNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Y%d", destinationNumber))}
	instruction = Instr{
		Op:   op,
		Args: []Operand{data, indices, destination},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, data.String(), indices.String(), destination.String()),
	}
	return instruction, modRMIndex + consumed, true, nil
}

// decodedX86EVEXVariableDwordPermuteInstruction covers the Y/Z EVEX forms of
// Go 1.27's shared VPERMD/VPERMPS _yvpermd table.
func decodedX86EVEXVariableDwordPermuteInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto evex
		}
	}

evex:
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+6 || code[i] != 0x62 {
		return Instr{}, 0, false, nil
	}
	p0, p1, p2 := code[i+1], code[i+2], code[i+3]
	opcode := code[i+4]
	if p0&0x0f != 2 || p1&0x07 != 5 || (opcode != 0x36 && opcode != 0x16) {
		return Instr{}, 0, false, nil
	}
	ok = true
	if p1&0x80 != 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX.W must be zero for VPERMD/VPERMPS")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	vectorBits := (p2 >> 5) & 3
	if vectorBits != 1 && vectorBits != 2 {
		return Instr{}, 0, true, fmt.Errorf("VPERMD/VPERMPS EVEX form requires Y or Z width")
	}
	vectorPrefix := [...]string{"X", "Y", "Z"}[vectorBits]
	vectorWidth := [...]int{16, 32, 64}[vectorBits]
	maskNumber := int(p2 & 7)
	zeroing := p2&0x80 != 0
	if zeroing && maskNumber == 0 {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}
	if mode == 32 && maskNumber != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 VPERMD/VPERMPS mask form exceeds the Go assembler operand limit")
	}
	rExt := int(^p0>>7) & 1
	rHighExt := int(^p0>>4) & 1
	xExt := int(^p0>>6) & 1
	bExt := int(^p0>>5) & 1
	modRMIndex := i + 5
	modRM := code[modRMIndex]
	broadcast := p2&0x10 != 0
	if broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	disp8Scale := vectorWidth
	if broadcast {
		disp8Scale = 4
	}
	data, consumed, decodeErr := decodedX86EVEXRMOperand(code[modRMIndex:], mode, bExt, xExt, segment, vectorPrefix, disp8Scale)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	indicesNumber := (int(^p1>>3) & 15) + (int(^p2>>3)&1)*16
	destinationNumber := int(modRM>>3&7) + rExt*8 + rHighExt*16
	if mode == 32 && vectorBits == 2 &&
		(indicesNumber >= 8 || destinationNumber >= 8 ||
			modRM>>6 == 3 && int(modRM&7)+bExt*8+xExt*16 >= 8) {
		return Instr{}, 0, true, fmt.Errorf("386 Z register exceeds the Go assembler frontend's register class")
	}
	indices := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, indicesNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vectorPrefix, destinationNumber))}
	args := []Operand{data, indices}
	if maskNumber != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", maskNumber))})
	}
	args = append(args, destination)
	op := Op("VPERMD")
	if opcode == 0x16 {
		op = "VPERMPS"
	}
	if broadcast {
		op += ".BCST"
	}
	if zeroing {
		op += ".Z"
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, modRMIndex + consumed, true, nil
}

// decodedX86RandomInstruction recognizes the complete register-only
// RDRAND/RDSEED/RDPID encoding family. RDPID shares RDSEED's ModRM extension
// but requires F3 and has only a 32-bit destination. x/arch v0.14 drops the
// operand from 64-bit RDRAND and cannot decode RDSEED or RDPID, so recover
// these encodings before consulting the generic decoder.
func decodedX86RandomInstruction(code []byte, mode int) (syntax string, length int, ok bool) {
	i := 0
	rdpid := len(code) > 0 && code[0] == 0xf3
	if rdpid {
		i++
	}
	bits := 32
	if len(code) > i && code[i] == 0x66 {
		bits = 16
		i++
	}
	rex := byte(0)
	if mode == 64 && len(code) > i && code[i] >= 0x40 && code[i] <= 0x4f {
		rex = code[i]
		i++
		if rex&0x08 != 0 {
			bits = 64
		}
	}
	if len(code) < i+3 || code[i] != 0x0f || code[i+1] != 0xc7 {
		return "", 0, false
	}
	modRM := code[i+2]
	if modRM>>6 != 3 {
		return "", 0, false
	}
	family := ""
	switch modRM >> 3 & 7 {
	case 6:
		if rdpid {
			return "", 0, false
		}
		family = "RDRAND"
	case 7:
		if rdpid {
			if bits != 32 {
				return "", 0, false
			}
			family = "RDPID"
		} else {
			family = "RDSEED"
		}
	default:
		return "", 0, false
	}
	register := int(modRM & 7)
	if mode == 64 && rex&0x01 != 0 {
		register += 8
	}
	registerNames := [...]string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	if rdpid {
		return fmt.Sprintf("RDPID %s", registerNames[register]), i + 3, true
	}
	width := map[int]string{16: "W", 32: "L", 64: "Q"}[bits]
	return fmt.Sprintf("%s%s %s", family, width, registerNames[register]), i + 3, true
}

// decodedX86VBROADCAST128Instruction recognizes the complete AVX2
// VBROADCASTF128/I128 m128, Y family. x/arch v0.14 misdecodes these VEX
// opcodes as legacy scalar instructions, so recover every ModRM/SIB memory
// form before consulting the generic decoder.
func decodedX86VBROADCAST128Instruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	// VEX.256.66.0F38.W0 1A/5A /r. The unused encoded vvvv field must be
	// 1111, so the complete third VEX byte is 0x7d.
	if len(code) < i+5 || code[i] != 0xc4 || code[i+1]&0x1f != 2 || code[i+2] != 0x7d ||
		(code[i+3] != 0x1a && code[i+3] != 0x5a) {
		return Instr{}, 0, false, nil
	}
	ok = true
	if mode != 32 && mode != 64 {
		return Instr{}, 0, true, fmt.Errorf("unsupported x86 mode %d", mode)
	}
	vex1 := code[i+1]
	rExt := int(^vex1>>7) & 1
	xExt := int(^vex1>>6) & 1
	bExt := int(^vex1>>5) & 1
	destinationNumber := int(code[i+4]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	source, consumed, err := decodedX86VEXRMSource(code[i+4:], mode, bExt, xExt, segment)
	if err != nil {
		return Instr{}, 0, true, err
	}
	if source.Kind != OpMem {
		return Instr{}, 0, true, fmt.Errorf("source must be m128 memory")
	}
	destination := Reg(fmt.Sprintf("Y%d", destinationNumber))
	op := Op("VBROADCASTI128")
	if code[i+3] == 0x1a {
		op = "VBROADCASTF128"
	}
	instruction = Instr{
		Op:   op,
		Args: []Operand{source, {Kind: OpReg, Reg: destination}},
		Raw:  fmt.Sprintf("%s %s, %s", op, source.String(), destination),
	}
	return instruction, i + 4 + consumed, true, nil
}

// decodedX86SHAInstruction recognizes the complete Go 1.27 Intel SHA table:
// SHA1NEXTE, SHA1MSG1/2, SHA1RNDS4, SHA256MSG1/2, and SHA256RNDS2. Older
// x/arch decoders reject some raw 0F38 encodings used by minio/sha256-simd.
func decodedX86SHAInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto rex
		}
	}

rex:
	rexPrefix := byte(0)
	if mode == 64 && i < len(code) && code[i]&0xf0 == 0x40 {
		rexPrefix = code[i]
		i++
	}
	if len(code) < i+4 || code[i] != 0x0f {
		return Instr{}, 0, false, nil
	}

	op := Op("")
	immediate := false
	switch {
	case code[i+1] == 0x38:
		switch code[i+2] {
		case 0xc8:
			op = "SHA1NEXTE"
		case 0xc9:
			op = "SHA1MSG1"
		case 0xca:
			op = "SHA1MSG2"
		case 0xcb:
			op = "SHA256RNDS2"
		case 0xcc:
			op = "SHA256MSG1"
		case 0xcd:
			op = "SHA256MSG2"
		default:
			return Instr{}, 0, false, nil
		}
	case code[i+1] == 0x3a && code[i+2] == 0xcc:
		op = "SHA1RNDS4"
		immediate = true
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	modRMIndex := i + 3
	modRM := code[modRMIndex]
	rExt := int(rexPrefix>>2) & 1
	xExt := int(rexPrefix>>1) & 1
	bExt := int(rexPrefix) & 1
	destinationNumber := int(modRM>>3&7) + rExt*8
	if mode == 32 && destinationNumber >= 8 {
		return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}

	var source Operand
	consumed := 0
	if modRM>>6 == 3 {
		sourceNumber := int(modRM&7) + bExt*8
		if mode == 32 && sourceNumber >= 8 {
			return Instr{}, 0, true, fmt.Errorf("extended vector register in 32-bit mode")
		}
		source = Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", sourceNumber))}
		consumed = 1
	} else {
		var decodeErr error
		source, consumed, decodeErr = decodedX86RMSource(code[modRMIndex:], mode, bExt, xExt, segment, 1)
		if decodeErr != nil {
			return Instr{}, 0, true, decodeErr
		}
	}

	args := []Operand{source, destination}
	end := modRMIndex + consumed
	if immediate {
		if len(code) <= end {
			return Instr{}, 0, true, fmt.Errorf("missing immediate byte")
		}
		// SHA1RNDS4 consumes only the low two bits. Normalize the raw byte to
		// Go's Yu2 operand class so the recovered instruction remains valid.
		args = []Operand{{Kind: OpImm, Imm: int64(code[end] & 3)}, source, destination}
		end++
	} else if op == "SHA256RNDS2" {
		args = []Operand{{Kind: OpReg, Reg: Reg("X0")}, source, destination}
	}
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", "))}, end, true, nil
}

// decodedX86BLSInstruction recognizes the complete BMI1 BLSI/BLSMSK/BLSR
// register and ModRM/SIB memory families. x/arch v0.14 reports these VEX.NDD
// encodings as unknown AVX opcodes, so recover them before generic decoding.
func decodedX86BLSInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if len(code) < i+5 || code[i] != 0xc4 || code[i+1]&0x1f != 2 || code[i+2]&0x07 != 0 || code[i+3] != 0xf3 {
		return Instr{}, 0, false, nil
	}
	ok = true
	vex1, vex2 := code[i+1], code[i+2]
	xExt := int(^vex1>>6) & 1
	bExt := int(^vex1>>5) & 1
	width64 := vex2&0x80 != 0
	destinationNumber := int(^vex2>>3) & 15
	modRM := code[i+4]
	family := ""
	switch modRM >> 3 & 7 {
	case 1:
		family = "BLSR"
	case 2:
		family = "BLSMSK"
	case 3:
		family = "BLSI"
	default:
		return Instr{}, 0, true, fmt.Errorf("invalid opcode extension /%d", modRM>>3&7)
	}
	if mode != 32 && mode != 64 {
		return Instr{}, 0, true, fmt.Errorf("unsupported x86 mode %d", mode)
	}
	if mode == 32 && (xExt != 0 || bExt != 0 || destinationNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended register in 32-bit mode")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	source, consumed, err := decodedX86VEXRMSource(code[i+4:], mode, bExt, xExt, segment)
	if err != nil {
		return Instr{}, 0, true, err
	}
	destination, valid := decodedX86GeneralRegister(destinationNumber)
	if !valid {
		return Instr{}, 0, true, fmt.Errorf("invalid destination register %d", destinationNumber)
	}
	op := Op(family + "L")
	if width64 && mode == 64 {
		op = Op(family + "Q")
	}
	instruction = Instr{
		Op:   op,
		Args: []Operand{source, {Kind: OpReg, Reg: destination}},
		Raw:  fmt.Sprintf("%s %s, %s", op, source.String(), destination),
	}
	return instruction, i + 4 + consumed, true, nil
}

// decodedX86MULXInstruction recognizes the complete BMI2 MULX register and
// ModRM/SIB memory family. x/arch rejects this VEX.NDD encoding even though
// Go's assembler and the semantic lowerer support MULXL/MULXQ.
func decodedX86MULXInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto vex
		}
	}

vex:
	if len(code) < i+5 || code[i] != 0xc4 || code[i+1]&0x1f != 2 || code[i+2]&0x07 != 3 || code[i+3] != 0xf6 {
		return Instr{}, 0, false, nil
	}
	ok = true
	vex1, vex2 := code[i+1], code[i+2]
	if vex2&0x04 != 0 {
		return Instr{}, 0, true, fmt.Errorf("VEX.L must be zero")
	}
	rExt := int(^vex1>>7) & 1
	xExt := int(^vex1>>6) & 1
	bExt := int(^vex1>>5) & 1
	width64 := vex2&0x80 != 0
	lowRegister := int(^vex2>>3) & 15
	modRM := code[i+4]
	highRegister := int(modRM>>3&7) + rExt*8
	if mode == 32 && (width64 || rExt != 0 || xExt != 0 || bExt != 0 || lowRegister >= 8 || highRegister >= 8) {
		return Instr{}, 0, true, fmt.Errorf("64-bit width or extended register in 32-bit mode")
	}
	if mode != 32 && mode != 64 {
		return Instr{}, 0, true, fmt.Errorf("unsupported x86 mode %d", mode)
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}

	source, consumed, err := decodedX86VEXRMSource(code[i+4:], mode, bExt, xExt, segment)
	if err != nil {
		return Instr{}, 0, true, err
	}
	low, valid := decodedX86GeneralRegister(lowRegister)
	if !valid {
		return Instr{}, 0, true, fmt.Errorf("invalid low destination register %d", lowRegister)
	}
	high, valid := decodedX86GeneralRegister(highRegister)
	if !valid {
		return Instr{}, 0, true, fmt.Errorf("invalid high destination register %d", highRegister)
	}
	op := Op("MULXL")
	if width64 {
		op = "MULXQ"
	}
	instruction = Instr{
		Op:   op,
		Args: []Operand{source, {Kind: OpReg, Reg: low}, {Kind: OpReg, Reg: high}},
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, source.String(), low, high),
	}
	return instruction, i + 4 + consumed, true, nil
}

func decodedX86VEXRMSource(code []byte, mode, bExt, xExt int, segment Reg) (Operand, int, error) {
	return decodedX86RMSource(code, mode, bExt, xExt, segment, 1)
}

func decodedX86RMSource(code []byte, mode, bExt, xExt int, segment Reg, disp8Scale int) (Operand, int, error) {
	if len(code) == 0 {
		return Operand{}, 0, fmt.Errorf("missing ModRM byte")
	}
	if disp8Scale <= 0 {
		return Operand{}, 0, fmt.Errorf("invalid disp8 scale %d", disp8Scale)
	}
	modRM := code[0]
	mod := int(modRM >> 6)
	rm := int(modRM & 7)
	if mod == 3 {
		register, ok := decodedX86GeneralRegister(rm + bExt*8)
		if !ok || mode == 32 && rm+bExt*8 >= 8 {
			return Operand{}, 0, fmt.Errorf("invalid source register")
		}
		return Operand{Kind: OpReg, Reg: register}, 1, nil
	}

	mem := MemRef{Segment: segment}
	consumed := 1
	readDisp8 := func() error {
		if len(code) < consumed+1 {
			return fmt.Errorf("truncated disp8")
		}
		mem.Off = int64(int8(code[consumed])) * int64(disp8Scale)
		consumed++
		return nil
	}
	readDisp32 := func() error {
		if len(code) < consumed+4 {
			return fmt.Errorf("truncated disp32")
		}
		mem.Off = int64(int32(binary.LittleEndian.Uint32(code[consumed : consumed+4])))
		consumed += 4
		return nil
	}

	if rm == 4 {
		if len(code) < consumed+1 {
			return Operand{}, 0, fmt.Errorf("truncated SIB byte")
		}
		sib := code[consumed]
		consumed++
		indexNumber := int(sib>>3&7) + xExt*8
		if int(sib>>3&7) != 4 || xExt != 0 {
			index, ok := decodedX86GeneralRegister(indexNumber)
			if !ok || mode == 32 && indexNumber >= 8 {
				return Operand{}, 0, fmt.Errorf("invalid SIB index register")
			}
			mem.Index = index
			mem.Scale = int64(1 << (sib >> 6))
		}
		baseBits := int(sib & 7)
		if mod == 0 && baseBits == 5 {
			if err := readDisp32(); err != nil {
				return Operand{}, 0, err
			}
		} else {
			baseNumber := baseBits + bExt*8
			base, ok := decodedX86GeneralRegister(baseNumber)
			if !ok || mode == 32 && baseNumber >= 8 {
				return Operand{}, 0, fmt.Errorf("invalid SIB base register")
			}
			mem.Base = base
		}
	} else if mod == 0 && rm == 5 {
		if mode == 64 {
			return Operand{}, 0, fmt.Errorf("RIP-relative source is not source-layout safe")
		}
		if err := readDisp32(); err != nil {
			return Operand{}, 0, err
		}
	} else {
		baseNumber := rm + bExt*8
		base, ok := decodedX86GeneralRegister(baseNumber)
		if !ok || mode == 32 && baseNumber >= 8 {
			return Operand{}, 0, fmt.Errorf("invalid base register")
		}
		mem.Base = base
	}

	switch mod {
	case 1:
		if err := readDisp8(); err != nil {
			return Operand{}, 0, err
		}
	case 2:
		if err := readDisp32(); err != nil {
			return Operand{}, 0, err
		}
	}
	return Operand{Kind: OpMem, Mem: mem}, consumed, nil
}

func decodedX86GeneralRegister(number int) (Reg, bool) {
	names := [...]Reg{AX, CX, DX, BX, SP, BP, SI, DI, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	if number < 0 || number >= len(names) {
		return "", false
	}
	return names[number], true
}

// x86RawRetpolineTarget recognizes the complete amd64 RETPOLINE(reg) byte
// family emitted by the Go runtime. Its local CALL and backward PAUSE loop are
// a speculative-execution barrier; architecturally the sequence replaces the
// temporary return address with reg and returns to it, which is an indirect
// tail jump. Requiring every fixed byte prevents arbitrary PC-relative raw
// control flow from being accepted through this path.
func x86RawRetpolineTarget(code []byte) (Reg, bool) {
	if len(code) != 14 ||
		code[0] != 0xe8 || code[1] != 0x04 || code[2] != 0 || code[3] != 0 || code[4] != 0 ||
		code[5] != 0xf3 || code[6] != 0x90 || code[7] != 0xeb || code[8] != 0xfc ||
		(code[9] != 0x48 && code[9] != 0x4c) || code[10] != 0x89 || code[11]&0xc7 != 0x04 ||
		code[12] != 0x24 || code[13] != 0xc3 {
		return "", false
	}
	register := int(code[11]>>3&7) + int(code[9]>>2&1)*8
	if register == 4 {
		return "", false
	}
	names := [...]Reg{AX, CX, DX, BX, SP, BP, SI, DI, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	return names[register], true
}

// Go's assembler omits Intel's N for these no-wait x87 encodings. Keep the
// entire control/environment alias family on the existing named lowerers.
var x86RawX87ControlAliases = map[x86asm.Op]Op{
	x86asm.FNCLEX:  "FCLEX",
	x86asm.FNINIT:  "FINIT",
	x86asm.FNSAVE:  "FSAVE",
	x86asm.FNSTCW:  "FSTCW",
	x86asm.FNSTENV: "FSTENV",
	x86asm.FNSTSW:  "FSTSW",
}

func decodedX86GoSyntax(inst x86asm.Inst, encoding []byte) (string, error) {
	for _, prefix := range inst.Prefix {
		if !prefix.IsVEX() {
			continue
		}
		// The pinned x/arch decoder recognizes only these VEX operations.
		// For other VEX bytes it can incorrectly return an ordinary legacy
		// opcode with a successful status and the wrong instruction length.
		// Family-specific decoders above must handle those encodings; never
		// let generic fallback turn a missing family into valid but wrong IR.
		switch inst.Op {
		case x86asm.VMOVDQA, x86asm.VMOVDQU, x86asm.VMOVNTDQ, x86asm.VMOVNTDQA, x86asm.VZEROUPPER:
		default:
			return "", fmt.Errorf("unrecognized VEX instruction decoded as legacy %s", inst.Op)
		}
		break
	}
	syntax := x86asm.GoSyntax(inst, 0, nil)
	replaceOp := func(op string) {
		if space := strings.IndexByte(syntax, ' '); space >= 0 {
			syntax = op + syntax[space:]
		} else {
			syntax = op
		}
	}
	if op, ok := decodedX86CacheLineWriteback(encoding); ok {
		replaceOp(op)
		return syntax, nil
	}
	if op, ok := x86RawX87ControlAliases[inst.Op]; ok {
		// The Go memory mnemonics encode the 32-bit environment layout.
		// Mapping a 66-prefixed 14/94-byte legacy layout to them would change
		// the memory footprint. Keep that unsupported format explicit.
		if inst.DataSize == 16 && (inst.Op == x86asm.FNSAVE || inst.Op == x86asm.FNSTENV) {
			return "", fmt.Errorf("raw %s uses a 16-bit environment layout not represented by Go %s", inst.Op, op)
		}
		replaceOp(string(op))
		return syntax, nil
	}

	switch inst.Op {
	case x86asm.INC, x86asm.DEC:
		bits := 0
		switch destination := inst.Args[0].(type) {
		case x86asm.Reg:
			bits = decodedX86RegisterBits(destination)
		case x86asm.Mem:
			bits = inst.MemBytes * 8
		}
		width := map[int]string{8: "B", 16: "W", 32: "L", 64: "Q"}[bits]
		if width == "" {
			return "", fmt.Errorf("raw %s has unsupported destination width %d", inst.Op, bits)
		}
		replaceOp(inst.Op.String() + width)
	case x86asm.SLDT, x86asm.STR, x86asm.SMSW:
		// x/arch prints the unsuffixed Intel names, while Go's descriptor
		// grammar selects the destination width in the mnemonic. Memory
		// destinations are always the architectural 16-bit selector/status.
		bits := 0
		switch destination := inst.Args[0].(type) {
		case x86asm.Mem:
			bits = 16
		case x86asm.Reg:
			bits = decodedX86RegisterBits(destination)
		}
		width := map[int]string{16: "W", 32: "L", 64: "Q"}[bits]
		if width == "" {
			return "", fmt.Errorf("raw %s has unsupported destination width %d", inst.Op, bits)
		}
		replaceOp(inst.Op.String() + width)
	case x86asm.SHLD, x86asm.SHRD:
		// Go encodes double shifts with the three-operand SHL/SHR form,
		// whose immediate class is signed Yi8 (single shifts use Yu8).
		if count, ok := inst.Args[2].(x86asm.Imm); ok {
			firstSpace := strings.IndexByte(syntax, ' ')
			firstComma := strings.IndexByte(syntax, ',')
			if firstSpace < 0 || firstComma < firstSpace {
				return "", fmt.Errorf("raw %s has malformed double-shift operands", inst.Op)
			}
			syntax = syntax[:firstSpace+1] + fmt.Sprintf("$%d", int8(count)) + syntax[firstComma:]
		}
	case x86asm.CMPPD, x86asm.CMPPS, x86asm.CMPSD_XMM, x86asm.CMPSS:
		predicate, ok := inst.Args[2].(x86asm.Imm)
		if !ok || predicate < 0 || predicate > 255 || inst.Args[3] != nil {
			return "", fmt.Errorf("raw %s expected an unsigned 8-bit predicate", inst.Op)
		}
		// Go's legacy yxcmpi table places the signed predicate last, unlike
		// both Intel syntax and the vector VCMP family. Reorder typed args
		// before rendering, preserving register and segment/address details.
		inst.Args[0], inst.Args[1], inst.Args[2] = x86asm.Imm(int8(predicate)), inst.Args[0], inst.Args[1]
		syntax = x86asm.GoSyntax(inst, 0, nil)
		// The 32-bit printer masks negative immediates to uint32. The Go
		// encoder requires a signed byte, not that unsigned spelling.
		syntax = syntax[:strings.LastIndexByte(syntax, ',')+1] + fmt.Sprintf(" $%d", int8(predicate))
		if inst.Op == x86asm.CMPSD_XMM {
			replaceOp("CMPSD")
		}
		return syntax, nil
	case x86asm.NOP:
		// The decoder prints NOPL/NOPW according to the encoded data size.
		// The address operand of a multi-byte x86 NOP is not read, so the
		// semantic instruction is the operand-free Plan 9 NOP.
		return "NOP", nil
	case x86asm.MOVSXD:
		replaceOp("MOVLQSX")
	case x86asm.MOVD:
		// Intel MOVD transfers 32 bits. Go's MOVD spelling instead aliases
		// AMOVQ and transfers 64 bits for XMM/memory forms.
		replaceOp("MOVL")
	case x86asm.MOVDQA:
		replaceOp("MOVO")
	case x86asm.MOVDQU:
		replaceOp("MOVOU")
	case x86asm.MOVNTDQ:
		// Go's assembler calls the legacy 128-bit non-temporal store MOVNTO.
		// MOVNTDQ is reserved for the VEX/EVEX VMOVNTDQ spelling.
		replaceOp("MOVNTO")
	case x86asm.MOVSD_XMM:
		replaceOp("MOVSD")
	case x86asm.CVTDQ2PS, x86asm.CVTPI2PS:
		// Go's yxcvm2 table shares CVTPL2PS across SSE X and MMX M sources.
		replaceOp("CVTPL2PS")
	case x86asm.CVTPS2DQ, x86asm.CVTPS2PI:
		// Go's yxcvm1 table likewise names both destinations CVTPS2PL.
		replaceOp("CVTPS2PL")
	case x86asm.CVTTPS2DQ, x86asm.CVTTPS2PI:
		replaceOp("CVTTPS2PL")
	case x86asm.CVTDQ2PD, x86asm.CVTPI2PD:
		replaceOp("CVTPL2PD")
	case x86asm.CVTPD2DQ, x86asm.CVTPD2PI:
		replaceOp("CVTPD2PL")
	case x86asm.CVTTPD2DQ, x86asm.CVTTPD2PI:
		replaceOp("CVTTPD2PL")
	case x86asm.MUL, x86asm.IMUL, x86asm.DIV, x86asm.IDIV:
		argumentCount := 0
		for _, argument := range inst.Args {
			if argument != nil {
				argumentCount++
			}
		}
		if argumentCount == 1 {
			bits := inst.MemBytes * 8
			if source, ok := inst.Args[0].(x86asm.Reg); ok {
				bits = decodedX86RegisterBits(source)
			}
			width := map[int]string{8: "B", 16: "W", 32: "L", 64: "Q"}[bits]
			if width == "" {
				return "", fmt.Errorf("%s has unsupported source width %d", inst.Op, bits)
			}
			replaceOp(inst.Op.String() + width)
		} else if inst.Op == x86asm.IMUL && argumentCount == 3 {
			destination, ok := inst.Args[0].(x86asm.Reg)
			if !ok {
				return "", fmt.Errorf("three-operand IMUL destination is not a register")
			}
			width := map[int]string{16: "W", 32: "L", 64: "Q"}[decodedX86RegisterBits(destination)]
			if width == "" {
				return "", fmt.Errorf("three-operand IMUL has unsupported destination width %d", decodedX86RegisterBits(destination))
			}
			replaceOp("IMUL3" + width)
		}
	case x86asm.BSWAP:
		destination, ok := inst.Args[0].(x86asm.Reg)
		if !ok {
			return "", fmt.Errorf("BSWAP destination is not a register")
		}
		width := map[int]string{32: "L", 64: "Q"}[decodedX86RegisterBits(destination)]
		if width == "" {
			return "", fmt.Errorf("BSWAP has unsupported destination width %d", decodedX86RegisterBits(destination))
		}
		replaceOp("BSWAP" + width)
	case x86asm.MOVBE:
		bits := inst.MemBytes * 8
		for _, operand := range inst.Args {
			if register, ok := operand.(x86asm.Reg); ok {
				bits = decodedX86RegisterBits(register)
				break
			}
		}
		width := map[int]string{16: "W", 32: "L", 64: "Q"}[bits]
		if width == "" {
			return "", fmt.Errorf("MOVBE has unsupported operand width %d", bits)
		}
		replaceOp("MOVBE" + width)
	case x86asm.LZCNT, x86asm.TZCNT:
		// Go names each bit-count width explicitly. x/arch prints the
		// widthless Intel mnemonic, even for 16- and 64-bit encodings.
		destination, ok := inst.Args[0].(x86asm.Reg)
		if !ok {
			return "", fmt.Errorf("%s destination is not a register", inst.Op)
		}
		bits := decodedX86RegisterBits(destination)
		width := map[int]string{16: "W", 32: "L", 64: "Q"}[bits]
		if width == "" {
			return "", fmt.Errorf("%s has unsupported destination width %d", inst.Op, bits)
		}
		replaceOp(inst.Op.String() + width)
	case x86asm.CVTSI2SS, x86asm.CVTSI2SD:
		sourceBits := inst.MemBytes * 8
		if source, ok := inst.Args[1].(x86asm.Reg); ok {
			sourceBits = decodedX86RegisterBits(source)
		}
		sourceWidth := map[int]string{32: "L", 64: "Q"}[sourceBits]
		if sourceWidth == "" {
			return "", fmt.Errorf("%s has unsupported decoded source width %d", inst.Op, sourceBits)
		}
		resultWidth := "SS"
		if inst.Op == x86asm.CVTSI2SD {
			resultWidth = "SD"
		}
		replaceOp("CVTS" + sourceWidth + "2" + resultWidth)
	case x86asm.CVTSS2SI, x86asm.CVTSD2SI, x86asm.CVTTSS2SI, x86asm.CVTTSD2SI:
		// x/arch prints Intel's SI destination stem (and, in some memory
		// cases, derives the wrong Plan 9 width). Go's assembler names this
		// legacy family CVT{T}{SS,SD}2S{L,Q}. Recover the destination width
		// from REX.W, which is the architectural selector for all four ops.
		outputWidth := "L"
		if inst.Mode == 64 {
			for _, prefix := range inst.Prefix {
				if prefix.IsREX() && prefix&x86asm.PrefixREXW != 0 {
					outputWidth = "Q"
					break
				}
			}
		}
		name := map[x86asm.Op]string{
			x86asm.CVTSS2SI:  "CVTSS2S",
			x86asm.CVTSD2SI:  "CVTSD2S",
			x86asm.CVTTSS2SI: "CVTTSS2S",
			x86asm.CVTTSD2SI: "CVTTSD2S",
		}[inst.Op]
		replaceOp(name + outputWidth)
	case x86asm.PACKSSDW:
		replaceOp("PACKSSLW")
	case x86asm.PCMPEQD:
		replaceOp("PCMPEQL")
	case x86asm.PCMPGTD:
		replaceOp("PCMPGTL")
	case x86asm.PMADDWD:
		replaceOp("PMADDWL")
	case x86asm.PMULUDQ:
		replaceOp("PMULULQ")
	case x86asm.PSLLD:
		replaceOp("PSLLL")
	case x86asm.PSRAD:
		replaceOp("PSRAL")
	case x86asm.PSRLD:
		replaceOp("PSRLL")
	case x86asm.PSUBD:
		replaceOp("PSUBL")
	case x86asm.PUNPCKHDQ:
		replaceOp("PUNPCKHLQ")
	case x86asm.PUNPCKHWD:
		replaceOp("PUNPCKHWL")
	case x86asm.PUNPCKLDQ:
		replaceOp("PUNPCKLLQ")
	case x86asm.PUNPCKLWD:
		replaceOp("PUNPCKLWL")
	case x86asm.CRC32:
		bits := inst.MemBytes * 8
		if source, ok := inst.Args[1].(x86asm.Reg); ok {
			bits = decodedX86RegisterBits(source)
		}
		width := map[int]string{8: "B", 16: "W", 32: "L", 64: "Q"}[bits]
		if width == "" {
			return "", fmt.Errorf("CRC32 has unsupported decoded source width %d", bits)
		}
		replaceOp("CRC32" + width)
	case x86asm.MOVSX, x86asm.MOVZX:
		dst, ok := inst.Args[0].(x86asm.Reg)
		if !ok {
			return "", fmt.Errorf("%s destination is not a register", inst.Op)
		}
		destinationBits := decodedX86RegisterBits(dst)
		sourceBits := inst.MemBytes * 8
		if source, ok := inst.Args[1].(x86asm.Reg); ok {
			sourceBits = decodedX86RegisterBits(source)
		}
		widthLetter := func(bits int) string {
			switch bits {
			case 8:
				return "B"
			case 16:
				return "W"
			case 32:
				return "L"
			case 64:
				return "Q"
			default:
				return ""
			}
		}
		sourceLetter := widthLetter(sourceBits)
		destinationLetter := widthLetter(destinationBits)
		if sourceLetter == "" || destinationLetter == "" {
			return "", fmt.Errorf("%s has unsupported decoded widths %d -> %d", inst.Op, sourceBits, destinationBits)
		}
		extension := "SX"
		if inst.Op == x86asm.MOVZX {
			extension = "ZX"
		}
		replaceOp("MOV" + sourceLetter + destinationLetter + extension)
	}
	normalizeDecodedX86GoOpcode(inst, &syntax, replaceOp)
	syntax = normalizeDecodedX86SegmentMemorySyntax(syntax)
	return syntax, nil
}

// x/arch prints a raw segment override as GS:0x30 or GS:0x30(AX). The
// Plan 9 parser represents those same addresses as 48(GS) and 48(AX)(GS).
// Rewrite only FS/GS operands; other segment and RIP-relative forms retain
// their original spelling so unsupported address semantics fail closed.
func normalizeDecodedX86SegmentMemorySyntax(syntax string) string {
	space := strings.IndexByte(syntax, ' ')
	if space < 0 {
		return syntax
	}
	args := splitTopLevelCSV(syntax[space+1:])
	for i, arg := range args {
		arg = strings.TrimSpace(arg)
		segment := ""
		switch {
		case strings.HasPrefix(arg, "FS:"):
			segment = "FS"
		case strings.HasPrefix(arg, "GS:"):
			segment = "GS"
		default:
			continue
		}
		address := strings.TrimPrefix(arg, segment+":")
		open := strings.IndexByte(address, '(')
		offset := address
		base := ""
		if open >= 0 {
			offset = address[:open]
			base = address[open:]
		}
		if offset == "" {
			offset = "0"
		}
		value, err := strconv.ParseInt(offset, 0, 64)
		if err != nil || strings.Contains(base, "(IP)") || strings.Contains(base, "(RIP)") {
			continue
		}
		args[i] = fmt.Sprintf("%d%s(%s)", value, base, segment)
	}
	return syntax[:space+1] + strings.Join(args, ", ")
}

// normalizeDecodedX86GoOpcode bridges the architectural names emitted by
// x/arch's decoder and the semantic names/classes used by Go 1.27's
// cmd/internal/obj/x86 tables. Go's assembler intentionally uses aliases such
// as SETOS and CMOVQLE, while x/arch prints Intel names such as SETO and
// CMOVLE. x/arch also prints the byte-immediate ADD opcode as ADDL even when
// its destination is an 8-bit register; that spelling is rejected by Go's
// Yml/Ymb operand classes and must be corrected from the decoded operands.
func normalizeDecodedX86GoOpcode(inst x86asm.Inst, syntax *string, replaceOp func(string)) {
	op := strings.ToUpper(inst.Op.String())
	setAliases := map[string]string{
		"SETA": "SETHI", "SETAE": "SETCC", "SETB": "SETCS", "SETBE": "SETLS",
		"SETE": "SETEQ", "SETG": "SETGT", "SETGE": "SETGE", "SETL": "SETLT",
		"SETLE": "SETLE", "SETNE": "SETNE", "SETNO": "SETOC", "SETNP": "SETPC",
		"SETNS": "SETPL", "SETO": "SETOS", "SETP": "SETPS", "SETS": "SETMI",
	}
	if alias, ok := setAliases[op]; ok {
		replaceOp(alias)
		// GoSyntax deliberately omits the B suffix for extended byte registers
		// (for example it prints SETO R9). Reconstruct the decoded register's
		// actual byte spelling before reparsing the instruction.
		if len(inst.Args) > 0 {
			if reg, ok := inst.Args[0].(x86asm.Reg); ok {
				*syntax = alias + " " + reg.String()
			}
		}
		return
	}

	cmovConditions := map[string]string{
		"CMOVA": "HI", "CMOVAE": "CC", "CMOVB": "CS", "CMOVBE": "LS",
		"CMOVE": "EQ", "CMOVG": "GT", "CMOVGE": "GE", "CMOVL": "LT",
		"CMOVLE": "LE", "CMOVNE": "NE", "CMOVNO": "OC", "CMOVNP": "PC",
		"CMOVNS": "PL", "CMOVO": "OS", "CMOVP": "PS", "CMOVS": "MI",
	}
	if condition, ok := cmovConditions[op]; ok {
		bits := 0
		for i := 0; i < 2 && i < len(inst.Args); i++ {
			if reg, ok := inst.Args[i].(x86asm.Reg); ok {
				if n := decodedX86RegisterBits(reg); n > bits {
					bits = n
				}
			}
		}
		if bits == 0 {
			bits = inst.MemBytes * 8
		}
		width := map[int]string{16: "W", 32: "L", 64: "Q"}[bits]
		if width != "" {
			replaceOp("CMOV" + width + condition)
		}
		return
	}

	widthOpcode := decodedX86WidthOpcode(op)
	if widthOpcode == "" || len(inst.Args) == 0 {
		return
	}
	dstBits := 0
	if reg, ok := inst.Args[0].(x86asm.Reg); ok {
		dstBits = decodedX86RegisterBits(reg)
	} else if _, ok := inst.Args[0].(x86asm.Mem); ok {
		dstBits = inst.MemBytes * 8
	}
	width := map[int]string{8: "B", 16: "W", 32: "L", 64: "Q"}[dstBits]
	if width != "" {
		replaceOp(widthOpcode + width)
	}
}

func decodedX86WidthOpcode(op string) string {
	switch op {
	case "ADD", "ADC", "SBB", "SUB", "AND", "OR", "XOR", "CMP", "TEST":
		return op
	case "ROL", "ROR", "RCL", "RCR", "SHL", "SHR", "SAR":
		return op
	case "SHLD":
		return "SHL"
	case "SHRD":
		return "SHR"
	default:
		return ""
	}
}

// Go 1.27 names 0F 18 /0-/3 but not the newer /4, /6 and /7 cache
// hints. Decode their complete ModRM memory forms directly; /5 and register
// operands are not instructions. RIP-relative addresses remain rejected by
// decodedX86RMSource because their byte layout cannot be inferred here.
func decodedX86ExtendedPrefetchInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	rex := byte(0)
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			rex = 0
		case 0x65:
			segment = GS
			rex = 0
		case 0x66:
			rex = 0
		case 0x67:
			addressOverride = true
			rex = 0
		default:
			if mode == 64 && code[i] >= 0x40 && code[i] <= 0x4f {
				rex = code[i]
				i++
				continue
			}
			goto opcode
		}
		i++
	}

opcode:
	if len(code) < i+3 || code[i] != 0x0f || code[i+1] != 0x18 {
		return Instr{}, 0, false, nil
	}
	extension := code[i+2] >> 3 & 7
	op := Op("")
	switch extension {
	case 4:
		op = "PREFETCHRST2"
	case 6:
		op = "PREFETCHIT1"
	case 7:
		op = "PREFETCHIT0"
	default:
		return Instr{}, 0, false, nil
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if code[i+2]>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("%s requires a memory operand", op)
	}
	address, consumed, err := decodedX86RMSource(code[i+2:], mode, int(rex&1), int(rex>>1&1), segment, 1)
	if err != nil {
		return Instr{}, 0, true, err
	}
	return Instr{Op: op, Args: []Operand{address}, Raw: fmt.Sprintf("%s %s", op, address.String())}, i + 2 + consumed, true, nil
}

// decodedX86CacheLineWritebackInstruction recognizes the complete raw
// CLFLUSH/CLFLUSHOPT/CLWB memory family before x/arch's generic decoder. In
// particular, generated assembly in github.com/wencode/hack places a REX
// prefix before the mandatory 0x66 prefix, which x/arch v0.14 rejects even
// though x86 hardware accepts the prefix sequence.
func decodedX86CacheLineWritebackInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	hasDataSizePrefix := false
	addressOverride := false
	segment := Reg("")
	rex := byte(0)
	hasREX := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			// A legacy prefix after REX makes that REX byte ineffective. Only
			// the REX prefix immediately preceding the opcode escape applies.
			rex = 0
			hasREX = false
			segment = FS
			i++
		case 0x65:
			rex = 0
			hasREX = false
			segment = GS
			i++
		case 0x66:
			rex = 0
			hasREX = false
			hasDataSizePrefix = true
			i++
		case 0x67:
			rex = 0
			hasREX = false
			addressOverride = true
			i++
		default:
			if mode == 64 && code[i] >= 0x40 && code[i] <= 0x4f {
				rex = code[i]
				hasREX = true
				i++
				continue
			}
			goto opcode
		}
	}

opcode:
	if len(code) < i+3 || code[i] != 0x0f || code[i+1] != 0xae {
		return Instr{}, 0, false, nil
	}
	modRM := code[i+2]
	extension := modRM >> 3 & 7
	op := Op("")
	switch {
	case extension == 7 && !hasDataSizePrefix:
		op = "CLFLUSH"
	case extension == 7 && hasDataSizePrefix:
		op = "CLFLUSHOPT"
	case extension == 6 && hasDataSizePrefix:
		op = "CLWB"
	default:
		return Instr{}, 0, false, nil
	}
	ok = true
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	if hasREX && rex&0x0c != 0 {
		return Instr{}, 0, true, fmt.Errorf("REX.W and REX.R are absent from Go 1.27's %s encoding", op)
	}
	if modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("%s requires a memory operand", op)
	}
	bExt := int(rex & 1)
	xExt := int(rex>>1) & 1
	memory, consumed, decodeErr := decodedX86VEXRMSource(code[i+2:], mode, bExt, xExt, segment)
	if decodeErr != nil {
		return Instr{}, 0, true, decodeErr
	}
	instruction = Instr{
		Op:   op,
		Args: []Operand{memory},
		Raw:  fmt.Sprintf("%s %s", op, memory.String()),
	}
	return instruction, i + 2 + consumed, true, nil
}

// decodedX86CacheLineWriteback recovers instructions which x/arch v0.14
// cannot distinguish from their older 0F AE encodings. The explicit 0x66
// mandatory prefix plus the ModRM extension is the architectural distinction:
// /7 is CLFLUSHOPT and /6 is CLWB. Parse only the actual prefix/opcode region
// so an identical byte sequence inside a displacement cannot be mistaken for
// an opcode.
func decodedX86CacheLineWriteback(encoding []byte) (string, bool) {
	hasDataSizePrefix := false
	i := 0
	for i < len(encoding) {
		switch encoding[i] {
		case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x67, 0xf0, 0xf2, 0xf3:
			i++
		case 0x66:
			hasDataSizePrefix = true
			i++
		default:
			if encoding[i] >= 0x40 && encoding[i] <= 0x4f {
				i++
				continue
			}
			goto opcode
		}
	}

opcode:
	if !hasDataSizePrefix || i+2 >= len(encoding) || encoding[i] != 0x0f || encoding[i+1] != 0xae {
		return "", false
	}
	modRM := encoding[i+2]
	if modRM>>6 == 3 {
		return "", false
	}
	switch modRM >> 3 & 7 {
	case 7:
		return "CLFLUSHOPT", true
	case 6:
		return "CLWB", true
	default:
		return "", false
	}
}

func decodedX86RegisterBits(reg x86asm.Reg) int {
	switch {
	case x86asm.AL <= reg && reg <= x86asm.R15B:
		return 8
	case x86asm.AX <= reg && reg <= x86asm.R15W:
		return 16
	case x86asm.EAX <= reg && reg <= x86asm.R15L:
		return 32
	case x86asm.RAX <= reg && reg <= x86asm.R15:
		return 64
	default:
		return 0
	}
}

func isX86RawDirective(ins Instr) bool {
	switch Op(strings.ToUpper(string(ins.Op))) {
	case OpBYTE, OpWORD, "LONG", "QUAD":
		return true
	default:
		return false
	}
}

func x86RawDirectiveBytes(ins Instr) ([]byte, error) {
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return nil, fmt.Errorf("%s expects exactly one resolved integer constant: %q", ins.Op, ins.Raw)
	}
	value := uint64(ins.Args[0].Imm)
	switch Op(strings.ToUpper(string(ins.Op))) {
	case OpBYTE:
		return []byte{byte(value)}, nil
	case OpWORD:
		var buf [2]byte
		binary.LittleEndian.PutUint16(buf[:], uint16(value))
		return buf[:], nil
	case "LONG":
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], uint32(value))
		return buf[:], nil
	case "QUAD":
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], value)
		return buf[:], nil
	default:
		return nil, fmt.Errorf("not an x86 raw directive: %q", ins.Raw)
	}
}

func parseDecodedX86Instruction(syntax string) ([]Instr, error) {
	file, err := Parse(ArchAMD64, "TEXT decoded(SB), NOSPLIT, $0-0\n"+syntax+"\n")
	if err != nil {
		return nil, err
	}
	if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) < 2 {
		return nil, fmt.Errorf("decoder syntax produced no instruction")
	}
	return append([]Instr(nil), file.Funcs[0].Instrs[1:]...), nil
}
