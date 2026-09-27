package plan9asm

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"sort"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

type arm64RawLayoutPoint struct {
	segment int
	offset  int64
}

type arm64RawDataBlob struct {
	label   string
	bytes   []byte
	aliases map[string]int64
}

const arm64RawDataOp Op = "ARM64_RAW_DATA"

// normalizeARM64RawPCRelative replaces raw ARM64 PC-relative instructions
// with decoded instructions that name exact source labels. It deliberately
// models only source spans whose cmd/asm widths are known. An unknown-width
// pseudo instruction starts a new segment, so a raw displacement can never be
// guessed across it.
func normalizeARM64RawPCRelative(fn Func) (Func, error) {
	result, _, err := prepareARM64RawPCRelative(fn)
	return result, err
}

func prepareARM64RawPCRelative(fn Func) (Func, []arm64RawDataBlob, error) {
	return prepareARM64RawPCRelativeWithReturnClobbers(fn, 0)
}

func prepareARM64RawPCRelativeWithReturnClobbers(fn Func, returnClobbers uint32) (Func, []arm64RawDataBlob, error) {
	points := make([]arm64RawLayoutPoint, len(fn.Instrs))
	boundaries := make(map[arm64RawLayoutPoint]int)
	labels := make(map[arm64RawLayoutPoint]string)
	labelIndices := make(map[string]int)
	knownLabels := make(map[string]bool)

	segment := 0
	offset := int64(0)
	for i, ins := range fn.Instrs {
		point := arm64RawLayoutPoint{segment: segment, offset: offset}
		points[i] = point
		if ins.Op == OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == OpLabel {
			if _, exists := labels[point]; !exists {
				labels[point] = ins.Args[0].Sym
			}
			knownLabels[ins.Args[0].Sym] = true
			labelIndices[ins.Args[0].Sym] = i
			continue
		}

		width, known := arm64RawKnownSourceWidth(fn, ins)
		if !known {
			segment++
			offset = 0
			continue
		}
		if width != 0 {
			if _, exists := boundaries[point]; !exists {
				boundaries[point] = i
			}
			offset += width
		}
	}
	end := arm64RawLayoutPoint{segment: segment, offset: offset}
	if _, exists := boundaries[end]; !exists {
		boundaries[end] = len(fn.Instrs)
	}

	poolWords, poolBlobs, insertions := identifyARM64UnlabelledPool(fn, points, knownLabels, returnClobbers)
	inspection := fn
	if len(poolWords) != 0 {
		inspection.Instrs = append([]Instr(nil), fn.Instrs...)
		for at := range poolWords {
			inspection.Instrs[at].Op = arm64RawDataOp
		}
	}
	dataWords, dataBlobs, err := identifyARM64RawData(inspection, points, boundaries, labels, labelIndices)
	if err != nil {
		return Func{}, nil, err
	}
	for at := range poolWords {
		dataWords[at] = true
	}
	dataBlobs = append(dataBlobs, poolBlobs...)
	if anonymousData, err := identifyARM64AnonymousData(inspection, dataWords, labelIndices); err != nil {
		return Func{}, nil, err
	} else {
		dataBlobs = append(dataBlobs, anonymousData...)
	}

	replacements := make(map[int]Instr)
	if insertions == nil {
		insertions = make(map[int]string)
	}
	for i, ins := range fn.Instrs {
		if dataWords[i] {
			continue
		}
		displacement, op, pcRelative, err := arm64RawPCRelativeDisplacement(ins)
		if err != nil {
			return Func{}, nil, err
		}
		if !pcRelative {
			continue
		}
		switch op {
		case "ADR", "B", "BL", "CBZ", "CBNZ", "TBZ", "TBNZ":
			// These encodings define their displacement relative to the current
			// instruction address.
		case "ADRP":
			// A zero displacement always denotes the page containing this exact
			// instruction, independent of source layout and final link placement.
			// Insert a boundary label at the instruction and let the ordinary ADRP
			// lowerer page-align its blockaddress. Nonzero raw page deltas remain
			// unsafe because source layout cannot prove their link-time target page.
			if displacement != 0 {
				return Func{}, nil, fmt.Errorf("ARM64 WORD PC-relative ADRP page delta %+d is not source-layout safe: %q", displacement, ins.Raw)
			}
		default:
			return Func{}, nil, fmt.Errorf("ARM64 WORD PC-relative %s is not source-layout safe: %q", op, ins.Raw)
		}

		targetPoint := arm64RawLayoutPoint{
			segment: points[i].segment,
			offset:  points[i].offset + displacement,
		}
		target, ok := labels[targetPoint]
		if !ok {
			at, boundaryOK := boundaries[targetPoint]
			if !boundaryOK {
				return Func{}, nil, fmt.Errorf("ARM64 WORD PC-relative %s target %+d does not land on a proven instruction boundary: %q", op, displacement, ins.Raw)
			}
			if existing, exists := insertions[at]; exists {
				target = existing
			} else {
				target = arm64UniqueRawTargetLabel(knownLabels, targetPoint)
				knownLabels[target] = true
				insertions[at] = target
			}
		}
		decoded, err := decodeARM64RawWordInstructionTarget(ins, target)
		if err != nil {
			return Func{}, nil, err
		}
		replacements[i] = decoded
	}

	if len(replacements) == 0 && len(dataWords) == 0 {
		return fn, dataBlobs, nil
	}
	result := fn
	result.Instrs = make([]Instr, 0, len(fn.Instrs)+len(insertions))
	for i, ins := range fn.Instrs {
		if label, ok := insertions[i]; ok {
			result.Instrs = append(result.Instrs, Instr{
				Op:   OpLABEL,
				Args: []Operand{{Kind: OpLabel, Sym: label}},
				Raw:  label + ":",
			})
		}
		if dataWords[i] {
			ins.Op = arm64RawDataOp
		} else if replacement, ok := replacements[i]; ok {
			ins = replacement
		}
		result.Instrs = append(result.Instrs, ins)
	}
	if label, ok := insertions[len(fn.Instrs)]; ok {
		result.Instrs = append(result.Instrs, Instr{
			Op:   OpLABEL,
			Args: []Operand{{Kind: OpLabel, Sym: label}},
			Raw:  label + ":",
		})
	}
	return result, dataBlobs, nil
}

// identifyARM64AnonymousData retains literal WORD islands between a
// non-fallthrough branch and the next label (or function end). They have no
// source label, so only a PC-relative reference could make them reachable.
// Labeled regions are handled separately by identifyARM64RawData.
func identifyARM64AnonymousData(fn Func, dataWords map[int]bool, labels map[string]int) ([]arm64RawDataBlob, error) {
	for _, ins := range fn.Instrs {
		_, _, pcRelative, err := arm64RawPCRelativeDisplacement(ins)
		if err != nil {
			return nil, err
		}
		if pcRelative {
			return nil, nil
		}
		for _, arg := range ins.Args {
			if arg.Kind == OpMem && arg.Mem.Base == PC {
				return nil, nil
			}
			if arg.Kind == OpSym && strings.Contains(arg.Sym, fn.Sym+"+") {
				return nil, nil
			}
		}
	}

	var blobs []arm64RawDataBlob
	for i := 1; i < len(fn.Instrs); {
		if !arm64RawLiteralWord(fn.Instrs[i]) {
			i++
			continue
		}
		start := i
		for i < len(fn.Instrs) && arm64RawLiteralWord(fn.Instrs[i]) {
			i++
		}
		if !arm64RawAnonymousDataPredecessor(fn.Instrs[start-1]) ||
			(i < len(fn.Instrs) && fn.Instrs[i].Op != OpLABEL) || dataWords[start] {
			continue
		}

		name := fmt.Sprintf("__unreferenced_data_%d", start)
		for {
			if _, exists := labels[name]; !exists {
				break
			}
			name += "_"
		}
		bytes := make([]byte, 0, 4*(i-start))
		for j := start; j < i; j++ {
			word := uint32(fn.Instrs[j].Args[0].Imm)
			bytes = append(bytes, byte(word), byte(word>>8), byte(word>>16), byte(word>>24))
			dataWords[j] = true
		}
		blobs = append(blobs, arm64RawDataBlob{label: name, bytes: bytes})
	}
	return blobs, nil
}

func arm64RawLiteralWord(ins Instr) bool {
	return ins.Op == OpWORD && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == ""
}

func arm64RawAnonymousDataPredecessor(ins Instr) bool {
	if ins.Op == OpRET {
		return true
	}
	op := strings.ToUpper(string(ins.Op))
	if dot := strings.IndexByte(op, '.'); dot >= 0 {
		op = op[:dot]
	}
	return op == "B" || op == "JMP"
}

// identifyARM64RawData recognizes generator-emitted local constant pools. The
// characteristic form is ADR label followed later by a label and one or more
// WORD directives. The one ADR before the first source RET is excluded: that
// is the generated entry wrapper returning a pointer to the embedded code.
func identifyARM64RawData(fn Func, points []arm64RawLayoutPoint, boundaries map[arm64RawLayoutPoint]int, labels map[arm64RawLayoutPoint]string, labelIndices map[string]int) (map[int]bool, []arm64RawDataBlob, error) {
	firstReturn := len(fn.Instrs)
	for i, ins := range fn.Instrs {
		if ins.Op == OpRET {
			firstReturn = i
			break
		}
	}

	starts := make(map[int]string)
	codeLabels := make(map[string]bool)
	for i, ins := range fn.Instrs {
		displacement, op, pcRelative, err := arm64RawPCRelativeDisplacement(ins)
		if err != nil {
			return nil, nil, err
		}
		if !pcRelative {
			continue
		}
		targetPoint := arm64RawLayoutPoint{segment: points[i].segment, offset: points[i].offset + displacement}
		label, hasLabel := labels[targetPoint]
		targetIndex, hasBoundary := boundaries[targetPoint]
		if !hasLabel || !hasBoundary {
			continue
		}
		if op != "ADR" {
			codeLabels[label] = true
			continue
		}
		// ADR may name a continuation reached through an indirect branch,
		// not just an embedded literal pool. A label whose first instruction
		// is not WORD is code; leave mixed WORD/non-WORD pools on the strict
		// data path below so malformed tables cannot be silently reclassified.
		if targetIndex < len(fn.Instrs) && fn.Instrs[targetIndex].Op != OpWORD {
			codeLabels[label] = true
			continue
		}
		// Generated entry wrappers return a pointer to the embedded routine.
		// That ADR appears before the first source RET and points beyond it.
		if i < firstReturn && targetIndex > firstReturn {
			codeLabels[label] = true
			continue
		}
		starts[targetIndex] = label
	}
	// Preserve every explicitly referenced local label as code. Raw embedded
	// routines use PC-relative encodings handled above; source-level wrappers
	// may use ordinary Plan 9 branch operands.
	for _, ins := range fn.Instrs {
		if ins.Op == OpWORD || ins.Op == OpLABEL {
			continue
		}
		for _, operand := range ins.Args {
			var label string
			switch operand.Kind {
			case OpIdent:
				label = operand.Ident
			case OpSym:
				label = strings.TrimSuffix(strings.TrimSuffix(operand.Sym, "(SB)"), "<>")
			}
			if _, exists := labelIndices[label]; exists {
				codeLabels[label] = true
			}
		}
	}

	// Some generators append unreferenced metadata words (for example a mask
	// discriminator) immediately after an unconditional terminator and before
	// ADR-addressed tables. Classify only all-WORD label regions that cannot be
	// reached by control flow. Once such a region starts, adjacent all-WORD
	// labels remain data. Reachable invalid WORDs therefore still fail closed.
	type labelRegion struct {
		label       string
		labelIndex  int
		start, end  int
		allRawWords bool
	}
	regions := make([]labelRegion, 0, len(labelIndices))
	for label, labelIndex := range labelIndices {
		start := labelIndex + 1
		for start < len(fn.Instrs) && fn.Instrs[start].Op == OpLABEL {
			start++
		}
		end := len(fn.Instrs)
		for i := start; i < len(fn.Instrs); i++ {
			if fn.Instrs[i].Op == OpLABEL {
				end = i
				break
			}
		}
		allRawWords := start < end
		for i := start; i < end && allRawWords; i++ {
			ins := fn.Instrs[i]
			allRawWords = ins.Op == OpWORD && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == ""
		}
		regions = append(regions, labelRegion{label: label, labelIndex: labelIndex, start: start, end: end, allRawWords: allRawWords})
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].labelIndex < regions[j].labelIndex })
	previousDataEnd := -1
	for _, region := range regions {
		if !region.allRawWords || codeLabels[region.label] {
			previousDataEnd = -1
			continue
		}
		_, alreadyData := starts[region.start]
		followsData := previousDataEnd == region.labelIndex
		followsTerminator := false
		for i := region.labelIndex - 1; i >= 0; i-- {
			if fn.Instrs[i].Op == OpLABEL {
				continue
			}
			followsTerminator = arm64RawIsNonFallthroughTerminator(fn.Instrs[i])
			break
		}
		if !alreadyData && !followsData && !followsTerminator {
			previousDataEnd = -1
			continue
		}
		starts[region.start] = region.label
		previousDataEnd = region.end
	}

	dataWords := make(map[int]bool)
	blobs := make([]arm64RawDataBlob, 0, len(starts))
	startIndices := make([]int, 0, len(starts))
	for start := range starts {
		startIndices = append(startIndices, start)
	}
	sort.Ints(startIndices)
	for _, start := range startIndices {
		label := starts[start]
		labelIndex := labelIndices[label]
		end := len(fn.Instrs)
		for i := labelIndex + 1; i < len(fn.Instrs); i++ {
			if fn.Instrs[i].Op == OpLABEL {
				end = i
				break
			}
		}
		buf := make([]byte, 0, (end-start)*4)
		for i := start; i < end; i++ {
			ins := fn.Instrs[i]
			if ins.Op != OpWORD || len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
				return nil, nil, fmt.Errorf("ARM64 raw data label %q contains a non-WORD directive: %q", label, ins.Raw)
			}
			word := uint32(ins.Args[0].Imm)
			buf = append(buf, byte(word), byte(word>>8), byte(word>>16), byte(word>>24))
			dataWords[i] = true
		}
		if len(buf) != 0 {
			blobs = append(blobs, arm64RawDataBlob{label: label, bytes: buf})
		}
	}
	return dataWords, blobs, nil
}

func arm64RawIsNonFallthroughTerminator(ins Instr) bool {
	op := strings.ToUpper(string(ins.Op))
	if dot := strings.IndexByte(op, '.'); dot >= 0 {
		op = op[:dot]
	}
	if op == "RET" || op == "B" || op == "JMP" || op == "BR" {
		return true
	}
	if ins.Op != OpWORD || len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return false
	}
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], uint32(ins.Args[0].Imm))
	decoded, err := arm64asm.Decode(code[:])
	if err != nil {
		return false
	}
	switch decoded.Op.String() {
	case "B", "BR", "RET", "ERET", "DRPS":
		return true
	default:
		return false
	}
}

func arm64RawPCRelativeDisplacement(ins Instr) (displacement int64, op string, pcRelative bool, err error) {
	if ins.Op != OpWORD || len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return 0, "", false, nil
	}
	word := uint32(ins.Args[0].Imm)
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	decoded, decodeErr := arm64asm.Decode(code[:])
	if decodeErr != nil {
		return 0, "", false, nil
	}
	count := 0
	for _, arg := range decoded.Args {
		if arg == nil {
			break
		}
		if relative, ok := arg.(arm64asm.PCRel); ok {
			displacement = int64(relative)
			count++
		}
	}
	if count == 0 {
		return 0, decoded.Op.String(), false, nil
	}
	if count != 1 {
		return 0, decoded.Op.String(), true, fmt.Errorf("ARM64 WORD %#08x has %d PC-relative operands: %q", word, count, ins.Raw)
	}
	return displacement, decoded.Op.String(), true, nil
}

func arm64RawKnownSourceWidth(fn Func, ins Instr) (int64, bool) {
	if arm64RawFixedWidthLogical(ins) {
		return 4, true
	}
	switch ins.Op {
	case OpTEXT, OpLABEL, "NO_LOCAL_POINTERS", "PCDATA", "FUNCDATA":
		return 0, true
	case OpWORD:
		return 4, true
	case OpRET:
		if len(ins.Args) != 0 {
			return 0, false
		}
		if fn.FrameSize == 0 {
			return 4, true
		}
		// cmd/asm emits restore-FP, restore-SP, RET for ordinary framed
		// functions whose rounded frame fits ARM64's immediate ADD.
		if fn.FrameSize > 0 && fn.FrameSize <= 4080 {
			return 12, true
		}
		return 0, false
	case "B", OpJMP:
		if arm64RawFixedWidthJumpOperand(ins, false) {
			return 4, true
		}
		return 0, false
	case "BL", OpCALL:
		if arm64RawFixedWidthJumpOperand(ins, true) {
			return 4, true
		}
		return 0, false
	case "BCC", "BCS", "BEQ", "BGE", "BGT", "BHI", "BHS", "BLE",
		"BLO", "BLS", "BLT", "BMI", "BNE", "BPL", "BVC", "BVS":
		// Go 1.27's conditional-branch optab has a single C_SBRA form,
		// always four bytes. Do not infer a width for other operand forms.
		if len(ins.Args) == 1 {
			switch ins.Args[0].Kind {
			case OpIdent, OpSym:
				return 4, true
			case OpMem:
				if ins.Args[0].Mem.Base == PC && ins.Args[0].Mem.Index == "" {
					return 4, true
				}
			}
		}
		return 0, false
	case OpMOVD:
		if len(ins.Args) != 2 {
			return 0, false
		}
		for _, arg := range ins.Args {
			switch arg.Kind {
			case OpReg, OpFP, OpMem:
			default:
				return 0, false
			}
		}
		return 4, true
	default:
		return 0, false
	}
}

// Go's ARM64 logical-op optab has one-word register and bitmask-immediate
// forms, but also multiword constant-materialization forms. Only classify a
// source instruction as four bytes when its immediate is an AArch64 logical
// bitmask; guessing the width of the other forms would misplace raw ADR/branch
// targets. The same AND optab covers this complete alias family and W forms.
func arm64RawFixedWidthLogical(ins Instr) bool {
	op := strings.ToUpper(string(ins.Op))
	switch op {
	case "AND", "ORR", "EOR", "ANDS", "BIC", "ORN", "EON", "BICS", "TST",
		"ANDW", "ORRW", "EORW", "ANDSW", "BICW", "ORNW", "EONW", "BICSW", "TSTW":
	default:
		return false
	}
	w32 := strings.HasSuffix(op, "W")
	if op == "TST" || op == "TSTW" {
		if len(ins.Args) != 2 {
			return false
		}
	} else if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return false
	}
	source := ins.Args[0]
	for i, arg := range ins.Args[1:] {
		if arg.Kind != OpReg {
			return false
		}
		if isARM64GeneralOrZeroReg(arg.Reg) {
			continue
		}
		// The immediate optab also has a single-word C_RSP destination form.
		last := i == len(ins.Args)-2
		if source.Kind != OpImm || !last || (arg.Reg != SP && arg.Reg != "RSP") {
			return false
		}
	}
	switch source.Kind {
	case OpReg:
		return isARM64GeneralOrZeroReg(source.Reg)
	case OpRegShift:
		limit := int64(64)
		if w32 {
			limit = 32
		}
		return isARM64GeneralOrZeroReg(source.Reg) &&
			source.ShiftAmount >= 0 && source.ShiftAmount < limit
	case OpImm:
		if source.ImmRaw != "" || source.ImmIsFloat {
			return false
		}
		value := uint64(source.Imm)
		if w32 {
			value = uint64(uint32(value)) * 0x100000001
		}
		return arm64LogicalBitmaskImmediate(value)
	default:
		return false
	}
}

func arm64LogicalBitmaskImmediate(value uint64) bool {
	for width := uint(2); width <= 64; width *= 2 {
		mask := ^uint64(0)
		if width < 64 {
			mask = uint64(1)<<width - 1
		}
		unit := value & mask
		if unit == 0 || unit == mask {
			continue
		}
		repeated := unit
		for shift := width; shift < 64; shift *= 2 {
			repeated |= repeated << shift
		}
		if repeated != value {
			continue
		}
		prior := (unit<<1)&mask | unit>>(width-1)
		starts := unit &^ prior & mask
		if bits.OnesCount64(starts) == 1 {
			return true
		}
	}
	return false
}

// arm64RawFixedWidthJumpOperand mirrors Go 1.27's complete AB/ABL optab:
// C_SBRA and C_ZOREG for B/JMP, plus C_ZREG for BL/CALL. Every accepted form
// occupies one AArch64 instruction. Keeping this validation local prevents an
// invalid or expanding pseudo-op from being guessed as four bytes.
func arm64RawFixedWidthJumpOperand(ins Instr, link bool) bool {
	if len(ins.Args) != 1 {
		return false
	}
	operand := ins.Args[0]
	switch operand.Kind {
	case OpIdent, OpSym:
		return true // C_SBRA: local or relocated branch target.
	case OpReg:
		return link && isARM64GeneralOrZeroReg(operand.Reg) // C_ZREG.
	case OpMem:
		if operand.Mem.Base == PC {
			return operand.Mem.Index == "" // instruction-relative C_SBRA.
		}
		return operand.Mem.Off == 0 && operand.Mem.OffRaw == "" && operand.Mem.Index == "" &&
			isARM64GeneralOrZeroReg(operand.Mem.Base) // C_ZOREG.
	default:
		return false
	}
}

func arm64UniqueRawTargetLabel(known map[string]bool, point arm64RawLayoutPoint) string {
	base := fmt.Sprintf("raw_pc_%d_%x", point.segment, point.offset)
	base = strings.ReplaceAll(base, "-", "neg_")
	for suffix := 0; ; suffix++ {
		candidate := base
		if suffix != 0 {
			candidate = fmt.Sprintf("%s_%d", base, suffix)
		}
		if !known[candidate] {
			return candidate
		}
	}
}
