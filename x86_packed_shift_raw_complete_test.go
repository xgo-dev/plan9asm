package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
)

// An independent ISA directory, not an iteration over the implementation map.
// Go 1.27 _yvandnpd/_yvblendmpd bind the nine per-lane names. The uniform
// _yvpslld and byte _yvpslldq rows share the count/alias proof, not arithmetic.
// Intel SDM Vol. 2B PSLL/PSRL/PSRA and PSLLDQ/PSRLDQ additionally specify WIG:
// VEX uniform, EVEX word uniform, and both vector byte-shift generations.
// Per-lane W is fixed; an ignored W never authorizes another opcode family.
type x86PackedShiftRawMember struct {
	op        string
	bits      int
	opcode    byte
	immediate byte
	group     byte
	vex       bool
	mode      string
}

var x86PackedShiftRawMembers = []x86PackedShiftRawMember{
	{"VPSLLVW", 16, 0x12, 0, 0, false, "lane"},
	{"VPSLLVD", 32, 0x47, 0, 0, true, "lane"},
	{"VPSLLVQ", 64, 0x47, 0, 0, true, "lane"},
	{"VPSRLVW", 16, 0x10, 0, 0, false, "lane"},
	{"VPSRLVD", 32, 0x45, 0, 0, true, "lane"},
	{"VPSRLVQ", 64, 0x45, 0, 0, true, "lane"},
	{"VPSRAVW", 16, 0x11, 0, 0, false, "lane"},
	{"VPSRAVD", 32, 0x46, 0, 0, true, "lane"},
	{"VPSRAVQ", 64, 0x46, 0, 0, false, "lane"},
	{"VPSLLW", 16, 0xf1, 0x71, 6, true, "uniform"},
	{"VPSLLD", 32, 0xf2, 0x72, 6, true, "uniform"},
	{"VPSLLQ", 64, 0xf3, 0x73, 6, true, "uniform"},
	{"VPSRLW", 16, 0xd1, 0x71, 2, true, "uniform"},
	{"VPSRLD", 32, 0xd2, 0x72, 2, true, "uniform"},
	{"VPSRLQ", 64, 0xd3, 0x73, 2, true, "uniform"},
	{"VPSRAW", 16, 0xe1, 0x71, 4, true, "uniform"},
	{"VPSRAD", 32, 0xe2, 0x72, 4, true, "uniform"},
	{"VPSRAQ", 64, 0xe2, 0x72, 4, false, "uniform"},
	{"VPSLLDQ", 8, 0x73, 0x73, 7, true, "bytes"},
	{"VPSRLDQ", 8, 0x73, 0x73, 3, true, "bytes"},
}

type x86PackedShiftRawCase struct {
	member    x86PackedShiftRawMember
	width     int
	evex      bool
	immediate bool
	input     string // register, memory, or broadcast
	mask      int    // absent, merging K1, or zeroing K1
}

func x86PackedShiftRawCases() []x86PackedShiftRawCase {
	var rows []x86PackedShiftRawCase
	for _, member := range x86PackedShiftRawMembers {
		for _, evex := range []bool{false, true} {
			if !evex && !member.vex {
				continue
			}
			widths := []int{16, 32}
			if evex {
				widths = append(widths, 64)
			}
			for _, width := range widths {
				immediates := []bool{false}
				if member.mode == "uniform" {
					immediates = append(immediates, true)
				} else if member.mode == "bytes" {
					immediates = []bool{true}
				}
				for _, immediate := range immediates {
					inputs := []string{"register", "memory"}
					if !evex && immediate {
						inputs = []string{"register"} // Go's VEX immediate rows.
					}
					if evex && member.bits != 16 && member.mode != "bytes" &&
						(member.mode == "lane" || immediate) {
						inputs = append(inputs, "broadcast")
					}
					for _, input := range inputs {
						masks := []int{0}
						if evex && member.mode != "bytes" {
							masks = append(masks, 1, 2)
						}
						for _, mask := range masks {
							rows = append(rows, x86PackedShiftRawCase{member, width, evex, immediate, input, mask})
						}
					}
				}
			}
		}
	}
	return rows
}

func (row x86PackedShiftRawCase) name() string {
	return fmt.Sprintf("%s/%d/EVEX%t/immediate%t/%s/mask%d",
		row.member.op, row.width, row.evex, row.immediate, row.input, row.mask)
}

func (row x86PackedShiftRawCase) instruction() string {
	bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[row.width]
	count, data, suffix, mask := bank+"1", bank+"0", "", ""
	if row.member.mode == "uniform" {
		count = "X1"
	}
	if row.immediate {
		count = "$5"
		if row.input != "register" {
			data = "(BX)"
		}
	} else if row.input != "register" {
		count = "(BX)"
	}
	if row.input == "broadcast" {
		suffix = ".BCST"
	}
	if row.mask != 0 {
		mask = "K1,"
	}
	if row.mask == 2 {
		suffix += ".Z"
	}
	return fmt.Sprintf("%s%s %s,%s,%s%s2", row.member.op, suffix, count, data, mask, bank)
}

// Literal low-bank encodings are authored here from the instruction tables.
// ModRM.reg is destination2 for count forms, /group for immediate forms;
// vvvv is data0 or immediate destination2. BX is always an actual address.
func (row x86PackedShiftRawCase) code(wigOne bool) []byte {
	mapNumber, opcode, modrm, vvvv := byte(1), row.member.opcode, byte(0xd1), byte(0)
	if row.member.mode == "lane" {
		mapNumber = 2
	}
	if row.input != "register" {
		modrm = 0x13
	}
	if row.immediate {
		opcode, modrm, vvvv = row.member.immediate, 0xc0|row.member.group<<3, 2
		if row.input != "register" {
			modrm = row.member.group<<3 | 3
		}
	}
	w := row.member.mode == "lane" && row.member.bits != 32 ||
		row.evex && row.member.mode == "uniform" && row.member.bits == 64 || wigOne
	p1 := (^vvvv&15)<<3 | 1
	if w {
		p1 |= 0x80
	}
	length := map[int]byte{16: 0, 32: 1, 64: 2}[row.width]
	code := []byte{0xc4, 0xe0 | mapNumber, p1 | length<<2, opcode, modrm}
	if row.evex {
		p2 := byte(8) | length<<5
		if row.mask != 0 {
			p2 |= 1
		}
		if row.mask == 2 {
			p2 |= 0x80
		}
		if row.input == "broadcast" {
			p2 |= 0x10
		}
		code = []byte{0x62, 0xf0 | mapNumber, p1 | 4, p2, opcode, modrm}
	}
	if row.immediate {
		code = append(code, 5)
	}
	return code
}

func (row x86PackedShiftRawCase) wig() bool {
	return row.member.mode == "bytes" || row.member.mode == "uniform" && (!row.evex || row.member.bits == 16)
}

func (row x86PackedShiftRawCase) program(arch string, raw bool) (string, string, FuncSig) {
	word, move := int64(8), "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·Shift(SB),4,$0-%d\n%s data+0(FP),AX\n%s counts+%d(FP),BX\n%s out+%d(FP),DI\n",
		word*3+4, move, move, word, move, word*2)
	source.WriteString("VMOVUPS (AX),Z0\nVMOVUPS (AX),Z2\n")
	if !row.immediate && row.input == "register" {
		source.WriteString("VMOVUPS (BX),Z1\n")
	}
	if row.mask != 0 {
		fmt.Fprintf(&source, "KMOVD mask+%d(FP),K1\n", word*3)
	}
	if raw {
		source.WriteString(x86RawDisplacementDirectives(row.code(false)))
	} else {
		source.WriteString(row.instruction() + "\n")
	}
	source.WriteString("VMOVUPS Z2,(DI)\nVMOVUPS Y2,64(DI)\nVMOVUPS X2,96(DI)\nRET\n")
	sig := FuncSig{Name: "Shift", Args: []LLVMType{Ptr, Ptr, Ptr, I32}, Ret: Void}
	for index, typ := range sig.Args {
		sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(index) * word, Type: typ, Index: index, Field: -1})
	}
	return source.String(), "func Shift(data,counts,out *byte,mask uint32)", sig
}

func x86PackedShiftRawOriginalUnchanged(t *testing.T) {
	t.Helper()
	var originalMembers []string
	for _, member := range x86PackedShiftRawMembers {
		if member.mode == "lane" {
			originalMembers = append(originalMembers, member.op)
		}
	}
	if !reflect.DeepEqual(x86VariableShiftTestOps, originalMembers) ||
		fmt.Sprintf("%x", sha256.Sum256([]byte(x86TestGuardPagesC))) != "559a08f4f5e496e4321d167a9f2ef942db8761e035fe9b0fdf236632c4f1956e" {
		t.Fatal("original nine-member order or complete guard-page C changed")
	}
	const filename = "amd64_raw_variable_shift_test.go"
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, filename, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestX86VariableShiftMemoryAndViewsRuntime" {
			continue
		}
		start, end := set.Position(function.Pos()).Offset, set.Position(function.End()).Offset
		if fmt.Sprintf("%x", sha256.Sum256(data[start:end])) != "4b3e75cedc66221ce0e21d473f1263f7c910a9ca3afa767d828fcc47f67f3231" {
			t.Fatal("original 396 named/raw kernels, complete C, 96 value samples, aliases or guard-page observations changed")
		}
		return
	}
	t.Fatal("original complete variable-shift runtime disappeared")
}

func TestX86PackedShiftRawCompleteIndependentDirectory(t *testing.T) {
	x86PackedShiftRawOriginalUnchanged(t)
	counts := map[string]int{}
	for _, row := range x86PackedShiftRawCases() {
		counts[row.member.mode]++
		for _, arch := range []string{"386", "amd64"} {
			t.Run(arch+"/"+row.name(), func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, row.code(false))
				want := x86ScalarLaneInstruction(t, row.instruction())
				if ins.Op != want.Op || !reflect.DeepEqual(ins.Args, want.Args) || ins.x86SourceRaw == nil {
					t.Fatal("complete independent physical shift row lost opcode/operands/origin", ins.Raw, row.instruction())
				}
				form, known, err := x86PackedShiftProperties(ins.Op, ins, arch)
				if !known || err != nil || form.byteWidth != row.width || form.zeroing != (row.mask == 2) ||
					form.broadcast != (row.input == "broadcast") || (form.memory >= 0) != (row.input != "register") {
					t.Fatal("complete shared shift grammar lost a physical shape", known, err)
				}
			})
		}
	}
	if !reflect.DeepEqual(counts, map[string]int{"lane": 236, "uniform": 426, "bytes": 16}) {
		t.Fatal("complete physical row denominator changed", counts)
	}
}

func TestX86PackedShiftRawInitializedOriginalProducerClass(t *testing.T) {
	x86PackedShiftRawOriginalUnchanged(t)
	// One orthogonal public witness per member, width and source shape.
	// The full physical/mask matrix has its own source and object owners.
	for _, row := range x86PackedShiftRawCases() {
		if row.member.mode != "lane" || !row.evex || row.mask != 0 || row.input == "broadcast" {
			continue
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name()+"/"+api, func(t *testing.T) {
				for _, raw := range []bool{false, true} {
					source, declaration, _ := row.program("amd64", raw)
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("same initialized VMOVUPS producers lost the complete paired shift consumer", "raw", raw, err)
					}
				}
			})
		}
	}
}

func TestX86PackedShiftRawStandaloneCannotBorrowNamedAuthority(t *testing.T) {
	for _, row := range x86PackedShiftRawCases() {
		if row.input != "register" {
			continue
		}
		t.Run(row.name(), func(t *testing.T) {
			ins := x86RawMoveObservedInstruction(t, "amd64", row.code(false))
			state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
			for index := 0; index < 3; index++ {
				state.writeVector(index, 64, ^uint64(0), false)
			}
			state.masks[1] = true
			control := state.clone()
			named := x86ScalarLaneInstruction(t, row.instruction())
			if accepted, known := x86ResultPackedShiftStep(named, &control, nil, "amd64"); !known || !accepted {
				t.Fatal("independently initialized genuine named shift lost its existing NUM consumer")
			}
			for _, nativeRead := range []bool{false, true} {
				candidate := state.clone()
				accepted, known := x86ResultPackedShiftStepWithRead(ins, &candidate, nil, "amd64", nativeRead)
				if !known || accepted || !reflect.DeepEqual(candidate, state) {
					t.Fatal("standalone raw shift borrowed named or lowering-local source authority", nativeRead)
				}
			}
		})
	}
}

func TestX86PackedShiftRawWholeReplayAndMissingInputBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86PackedShiftRawCases() {
			t.Run(arch+"/"+row.name(), func(t *testing.T) {
				source, _, sig := row.program(arch, true)
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
				if err != nil {
					t.Fatal(err)
				}
				fn := file.Funcs[0]
				ordinal := len(fn.Instrs) - 5
				if fn.Instrs[ordinal].x86SourceRaw == nil {
					t.Fatal("exact raw shift disappeared from the complete source")
				}
				check := func(candidate Func) error {
					ctx := newX86Ctx(new(strings.Builder), candidate, sig, nil, nil, arch,
						map[string]string{"386": "i386-unknown-linux-gnu", "amd64": "x86_64-unknown-linux-gnu"}[arch], false)
					return ctx.checkLoweredScalarFPResultInitialization()
				}
				if err := check(fn); err != nil {
					t.Fatal("initialized complete raw shift lacks its paired whole-source owner", err)
				}
				controls := []struct {
					name string
					edit func(*Func)
				}{
					{"origin-only", func(fn *Func) { fn.Instrs[ordinal].x86SourceRaw = nil }},
					{"encoding-only", func(fn *Func) { fn.Instrs[ordinal].x86Encoded = !fn.Instrs[ordinal].x86Encoded }},
					{"missing-whole-replay", func(fn *Func) { fn.x86RawReplay = nil }},
					{"producer-source", func(fn *Func) { fn.Instrs[1].Raw += " " }},
					{"operand-after-decode", func(fn *Func) { fn.Instrs[ordinal].Args[len(fn.Instrs[ordinal].Args)-1].Reg = "Z3" }},
					{"missing-incoming-pointer", func(fn *Func) {
						fn.Instrs[1] = x86ScalarLaneInstruction(t, "MOVL $42,AX")
					}},
				}
				for _, control := range controls {
					changed := fn
					changed.Instrs = cloneX86ReplayInstrs(fn.Instrs)
					control.edit(&changed)
					if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("changed raw source bypassed the actual whole-function consumer", control.name, err)
					}
					if err := fn.x86RawReplay.validate(fn, arch); err != nil {
						t.Fatal("mutable replay clone damaged the immutable complete source", err)
					}
				}
			})
		}
	}
}

func TestX86PackedShiftRawPhysicalSnapshotRejectsAtomically(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86PackedShiftRawCases() {
			t.Run(arch+"/"+row.name(), func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, row.code(false))
				encoding := x86RawPackedShiftVEX
				if row.evex {
					encoding = x86RawPackedShiftEVEX
				}
				w := row.member.mode == "lane" && row.member.bits != 32 ||
					row.evex && row.member.mode == "uniform" && row.member.bits == 64
				if ins.x86PackedShiftEncoding != encoding || ins.x86PackedShiftW != w ||
					!ins.x86Encoded || !x86RawPackedShiftSource(ins, arch) {
					t.Fatal("actual generation, W and mode were not captured before source replay", ins.Raw)
				}
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				for index := 0; index < 3; index++ {
					state.writeVector(index, 64, ^uint64(0), false)
				}
				state.pointerGP[3], state.masks[1] = true, true
				before := state.clone()
				if accepted, known := x86LoweredRawPackedShiftStep(ins, &state, nil, arch); !known || !accepted ||
					!reflect.DeepEqual(state, before) {
					t.Fatal("complete original typed inputs lost the paired effect or unrelated state", accepted, known)
				}
				for _, control := range []struct {
					name string
					edit func(*Instr)
				}{
					{"missing-origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
					{"missing-snapshot", func(ins *Instr) { ins.x86SourceRaw.packedShift = x86RawPackedShiftIdentity{} }},
					{"snapshot-mode", func(ins *Instr) { ins.x86SourceRaw.packedShift.arch = "foreign" }},
					{"snapshot-W", func(ins *Instr) { ins.x86SourceRaw.packedShift.w = !ins.x86SourceRaw.packedShift.w }},
					{"snapshot-generation", func(ins *Instr) { ins.x86SourceRaw.packedShift.encoding = x86RawPackedShiftAbsent }},
					{"physical-W", func(ins *Instr) { ins.x86PackedShiftW = !ins.x86PackedShiftW }},
					{"physical-generation", func(ins *Instr) { ins.x86PackedShiftEncoding = x86RawPackedShiftAbsent }},
					{"physical-grammar", func(ins *Instr) { ins.x86Encoded = false }},
				} {
					changed := cloneX86ReplayInstrs([]Instr{ins})[0]
					control.edit(&changed)
					candidate := before.clone()
					if accepted, _ := x86LoweredRawPackedShiftStep(changed, &candidate, nil, arch); accepted ||
						x86RawPackedShiftSource(changed, arch) || !reflect.DeepEqual(candidate, before) {
						t.Fatal("edited physical snapshot borrowed or partially committed a paired effect", control.name)
					}
					if !x86RawPackedShiftSource(ins, arch) {
						t.Fatal("editing a replay clone mutated the original physical snapshot", control.name)
					}
				}
			})
		}
	}
}
