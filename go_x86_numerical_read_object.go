package plan9asm

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"golang.org/x/arch/x86/x86asm"
)

// These typed shapes observe scalar integer MOV/CMP source bytes only. They
// create no load, pointer, frame, caller or entry permission. Extensions share
// the established scalar grammar, including MOVSWW/MOVZWW and mode32 MOVLQZX.
type x86NumericalSBReadSpec struct {
	sourceBytes, gpBytes int64
	compare, extension   bool
	rejectedOn386        bool
	vector               x86NumericalSBVectorKind
}

type x86NumericalSBReadForm struct {
	spec             x86NumericalSBReadSpec
	operand, partner int
}

var x86NumericalSBReadSpecs = func() map[Op]x86NumericalSBReadSpec {
	result := map[Op]x86NumericalSBReadSpec{
		"MOVB": {sourceBytes: 1, gpBytes: 1},
		"MOVW": {sourceBytes: 2, gpBytes: 2},
		"MOVL": {sourceBytes: 4, gpBytes: 4},
		"MOVQ": {sourceBytes: 8, gpBytes: 8, rejectedOn386: true},
		"CMPB": {sourceBytes: 1, gpBytes: 1, compare: true},
		"CMPW": {sourceBytes: 2, gpBytes: 2, compare: true},
		"CMPL": {sourceBytes: 4, gpBytes: 4, compare: true},
		"CMPQ": {sourceBytes: 8, gpBytes: 8, compare: true, rejectedOn386: true},
	}
	for opcode, spec := range amd64ScalarExtensionMoveSpecs {
		result[opcode] = x86NumericalSBReadSpec{sourceBytes: int64(spec.sourceBits / 8), gpBytes: int64(spec.destinationBits / 8),
			extension: true, rejectedOn386: spec.rejectedOn386}
	}
	return result
}()

func x86NumericalSBReadProperties(ins Instr, arch string) (x86NumericalSBReadForm, bool) {
	if form, known := x86NumericalSBVectorReadProperties(ins, arch); known {
		return form, true
	}
	spec, known := x86NumericalSBReadSpecs[ins.Op]
	if !known || len(ins.Args) != 2 || arch != "amd64" && arch != "386" || arch == "386" && spec.rejectedOn386 {
		return x86NumericalSBReadForm{}, false
	}
	form := x86NumericalSBReadForm{spec: spec, partner: 1}
	if spec.extension {
		extension, recognized, err := x86ScalarExtensionProperties(ins.Op, ins, arch)
		if !recognized || err != nil {
			return x86NumericalSBReadForm{}, false
		}
		form.spec.sourceBytes = int64(extension.spec.sourceBits / 8)
		form.spec.gpBytes = int64(extension.spec.destinationBits / 8)
	} else if spec.compare {
		comparison, recognized, err := x86ScalarCompareProperties(ins.Op, ins, arch)
		if !recognized || err != nil || comparison.memory < 0 {
			return x86NumericalSBReadForm{}, false
		}
		form.operand, form.partner = comparison.memory, 1-comparison.memory
	} else {
		partner := ins.Args[form.partner]
		switch partner.Kind {
		case OpReg:
			valid := isX86YrlRegisterForArch(partner.Reg, arch)
			if spec.gpBytes == 1 {
				valid = isGoYmbRegisterForArch(partner.Reg, arch)
			}
			if !valid {
				return x86NumericalSBReadForm{}, false
			}
		default:
			return x86NumericalSBReadForm{}, false
		}
	}
	operand := ins.Args[form.operand]
	if operand.Kind != OpSym || strings.HasPrefix(strings.TrimSpace(operand.Sym), "$") {
		return x86NumericalSBReadForm{}, false
	}
	return form, true
}

func x86NumericalSBReadShape(ins Instr, arch string) (int, int64, bool) {
	form, valid := x86NumericalSBReadProperties(ins, arch)
	return form.operand, form.spec.sourceBytes, valid
}

type numericalSBRead struct {
	function          string
	instruction       int
	operand           int
	original          Instr
	pc, offset, width int64
	code              []byte
	relocation        gostaticstorage.TextRelocation
	variable          gostaticstorage.Variable
	owner             *GoNumericalStorageOwner
	ownerOrdinal      int
}

func numericalNativeName(name, pkg string) string {
	name = strings.ReplaceAll(strings.ReplaceAll(name, "∕", "/"), "·", ".")
	if strings.HasPrefix(name, ".") {
		name = pkg + name
	}
	return name
}

func numericalSameInstruction(a, b Instr, pkg, arch string) bool {
	if a.Op != b.Op || len(a.Args) != len(b.Args) {
		return false
	}
	form, valid := x86NumericalSBReadProperties(a, arch)
	otherForm, otherValid := x86NumericalSBReadProperties(b, arch)
	if !valid || !otherValid || form != otherForm {
		return false
	}
	for i, operand := range a.Args {
		other := b.Args[i]
		if operand.Kind == OpReg && other.Kind == OpReg && form.spec.vector == x86NumericalSBScalar {
			width := form.spec.gpBytes
			root, valid := amd64FullRegBase(operand.Reg)
			otherRoot, otherValid := amd64FullRegBase(other.Reg)
			if !valid || !otherValid || root != otherRoot || x86CallerByteMask(operand.Reg, width) != x86CallerByteMask(other.Reg, width) {
				return false
			}
			// Actual cmd/asm byte-register rewriting may print AL for source
			// AX. Compare the exact byte lane, never just the wider GP alias.
			operand.Reg, other.Reg = root, root
		}
		if operand.Kind == OpSym {
			base, offset, ok := parseSBRef(operand.Sym)
			otherBase, otherOffset, otherOK := parseSBRef(other.Sym)
			if !ok || !otherOK {
				return false
			}
			operand.Sym = fmt.Sprintf("%s%+d(SB)", numericalNativeName(base, pkg), offset)
			other.Sym = fmt.Sprintf("%s%+d(SB)", numericalNativeName(otherBase, pkg), otherOffset)
		}
		if !reflect.DeepEqual(operand, other) {
			return false
		}
	}
	return true
}

// Both listings are actual assembler output. The expanded listing's physical
// line associates a unique original expanded instruction with a native PC;
// original listing and binary PC tables retain its original CPP source role.
// No line-only mapping or relocation name can independently create a read.
type numericalListingRow struct {
	position string
	ins      Instr
}

// cmd/internal/obj's writer emits the same ordered flags and PC rows for both
// IsText kinds. Historical writers put align after the frame; current writers
// put it before. Neither this display nor ArgsSizeUnknown creates a Go entry:
// complete original/expanded/compiler objects still bind kind, ABI and bytes.
const numericalListingFlags = `(?: static)?(?: dupok)?(?: cfunc)?(?: nosplit)?(?: topframe)?(?: asm)?`
const numericalListingFrame = `args=0x[0-9a-f]+ locals=0x[0-9a-f]+(?: funcid=0x[0-9a-f]+)?`

var numericalListingHeader = regexp.MustCompile(`^(\S+) STEXT(?:FIPS)?` + numericalListingFlags +
	` size=[0-9]+ (?:align=0x[0-9a-f]+ ` + numericalListingFrame + `|` +
	numericalListingFrame + `(?: align=0x[0-9a-f]+)?)(?: leaf)?$`)

func numericalListingRows(raw []byte) (map[string]map[int64][]numericalListingRow, error) {
	rows := make(map[string]map[int64][]numericalListingRow)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(nil, 4<<20)
	name := ""
	for scanner.Scan() {
		line := scanner.Text()
		if header := numericalListingHeader.FindStringSubmatch(line); header != nil {
			name = header[1]
			if rows[name] != nil {
				return nil, numericalSBContext("duplicate listing TEXT")
			}
			rows[name] = make(map[int64][]numericalListingRow)
			continue
		}
		match := goAMD64FrameRow.FindStringSubmatch(line)
		if match == nil {
			fields := strings.Fields(line)
			for index, field := range fields {
				if index > 0 && strings.HasPrefix(field, "STEXT") ||
					strings.HasPrefix(field, "args=") || strings.HasPrefix(field, "locals=") {
					return nil, numericalSBContext("unknown complete native listing TEXT role")
				}
			}
			if len(fields) != 0 {
				// The writer emits Prog rows before byte/relocation displays.
				// No other display, including a truncated or unknown header,
				// can carry the previous TEXT's PC ownership forward.
				name = ""
			}
			continue // Complete binary records, not this display parser, validate objects.
		}
		pc, err := strconv.ParseInt(match[1], 16, 64)
		if err != nil || rows[name] == nil {
			return nil, numericalSBContext("unbound native listing PC")
		}
		parsed, err := Parse(ArchAMD64, "TEXT ·row(SB),4,$0\n"+match[3]+"\n")
		if err != nil || len(parsed.Funcs) != 1 || len(parsed.Funcs[0].Instrs) != 2 || parsed.Funcs[0].Instrs[1].Op == OpTEXT {
			continue // TEXT/FUNCDATA/PCDATA are not a machine read.
		}
		rows[name][pc] = append(rows[name][pc], numericalListingRow{match[2], parsed.Funcs[0].Instrs[1]})
	}
	return rows, scanner.Err()
}

func numericalRelocationEqual(a, b []gostaticstorage.TextRelocation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Offset != y.Offset || x.Size != y.Size || x.Type != y.Type || x.Add != y.Add ||
			x.Target.Name != y.Target.Name || x.Target.ABI != y.Target.ABI || x.Target.ABIKnown != y.Target.ABIKnown || x.Target.Package != y.Target.Package {
			return false
		}
	}
	return true
}

func numericalInstructionRelocation(text gostaticstorage.TextRecord, pc int64, native x86asm.Inst, arch string) (gostaticstorage.TextRelocation, int64, error) {
	var selected []gostaticstorage.TextRelocation
	for _, relocation := range text.Relocations {
		if relocation.Offset < pc+int64(native.Len) && relocation.Offset+relocation.Size > pc {
			selected = append(selected, relocation)
		}
	}
	if len(selected) != 1 || selected[0].Size != 4 || !selected[0].Target.ABIKnown || selected[0].Target.ABI != 0 {
		return gostaticstorage.TextRelocation{}, 0, numericalSBContext("read needs one exact numerical storage relocation/ABI")
	}
	r := selected[0]
	field := native.PCRelOff
	offset := r.Add
	if arch == "amd64" {
		if native.PCRel != 4 || r.Type != 14 || native.AddrSize != 64 {
			return r, 0, numericalSBContext("unknown AMD64 PC-relative read rule")
		}
		tail := int64(native.Len - native.PCRelOff - native.PCRel)
		if tail < 0 || offset > math.MaxInt64-tail {
			return r, 0, numericalSBContext("PC-relative read addend overflow")
		}
		offset += tail
	} else {
		if native.PCRel != 0 || r.Type != 1 || native.AddrSize != 32 {
			return r, 0, numericalSBContext("unknown 386 absolute read rule")
		}
		// These complete scalar forms use mod=00/rm=101's absolute disp32.
		// Locate that physical field from the opcode/ModRM, not from Add or
		// the listing. No SIB/index or address-size-prefix permission is given.
		code := text.Code[pc : pc+int64(native.Len)]
		prefix := 0
		for prefix < len(code) && code[prefix] == 0x66 {
			prefix++
		}
		if prefix >= len(code) {
			return r, 0, numericalSBContext("truncated absolute read opcode")
		}
		modrm := prefix + 1
		if code[prefix] == 0x0f {
			modrm++
			if prefix+1 < len(code) && (code[prefix+1] == 0x38 || code[prefix+1] == 0x3a) {
				modrm++
			}
		}
		if modrm >= len(code) || code[modrm]&0xc7 != 5 {
			return r, 0, numericalSBContext("unbound absolute scalar ModRM")
		}
		field = modrm + 1
	}
	if r.Offset != pc+int64(field) || field < 0 || field+4 > native.Len {
		return r, 0, numericalSBContext("relocation does not bind the decoded address field")
	}
	return r, offset, nil
}

func numericalOwnerContains(variable gostaticstorage.Variable, offset, width int64) bool {
	if offset < 0 || width <= 0 || offset > variable.Size || width > variable.Size-offset {
		return false
	}
	for byteOffset := offset; byteOffset < offset+width; byteOffset++ {
		found := false
		for _, span := range variable.Numerical {
			if span.Offset <= byteOffset && byteOffset-span.Offset < span.Length {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
