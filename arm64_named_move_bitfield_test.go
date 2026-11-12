package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type arm64NamedMoveBitfieldCase struct {
	op                       Op
	width, shift, immr, imms int
	source, destination      int
	form                     string
}

func arm64NamedMoveBitfieldCases() []arm64NamedMoveBitfieldCase {
	var cases []arm64NamedMoveBitfieldCase
	for _, width := range []int{32, 64} {
		suffix := ""
		if width == 32 {
			suffix = "W"
		}
		for _, op := range []Op{"MOVZ", "MOVN"} {
			for shift := 0; shift < width; shift += 16 {
				for _, destination := range []int{2, 31} {
					cases = append(cases, arm64NamedMoveBitfieldCase{
						op: op + Op(suffix), width: width, shift: shift, destination: destination,
					})
				}
			}
		}
		for _, op := range []Op{"BFM", "SBFM", "UBFM"} {
			for _, immediate := range [][2]int{{0, 0}, {0, width - 1}, {width - 1, 0},
				{width - 1, width - 1}, {3, 17}, {width - 3, 11}} {
				for _, form := range []string{"distinct", "alias", "zero-source", "discard"} {
					source, destination := 1, 2
					switch form {
					case "alias":
						destination = source
					case "zero-source":
						source = 31
					case "discard":
						destination = 31
					}
					cases = append(cases, arm64NamedMoveBitfieldCase{
						op: op + Op(suffix), width: width, immr: immediate[0], imms: immediate[1],
						source: source, destination: destination, form: form,
					})
				}
			}
		}
	}
	return cases
}

func (row arm64NamedMoveBitfieldCase) instruction() string {
	register := func(index int) string {
		if index == 31 {
			return "ZR"
		}
		return fmt.Sprintf("R%d", index)
	}
	if strings.HasPrefix(string(row.op), "MOV") {
		// Go spells the already shifted field, not an extra shift operand.
		return fmt.Sprintf("%s $%#x,%s", row.op, uint64(0xa55a)<<row.shift, register(row.destination))
	}
	// These are encoded immr/imms, not the aliases' lsb/width operands.
	return fmt.Sprintf("%s $%d,%s,$%d,%s", row.op, row.immr, register(row.source), row.imms, register(row.destination))
}

func (row arm64NamedMoveBitfieldCase) word() uint32 {
	if strings.HasPrefix(string(row.op), "MOV") {
		base := uint32(0x12800000)
		if strings.HasPrefix(string(row.op), "MOVZ") {
			base = 0x52800000
		}
		if row.width == 64 {
			base |= 1 << 31
		}
		return base | uint32(row.shift/16)<<21 | 0xa55a<<5 | uint32(row.destination)
	}
	base := uint32(0x13000000)
	if strings.HasPrefix(string(row.op), "BFM") {
		base = 0x33000000
	} else if strings.HasPrefix(string(row.op), "UBFM") {
		base = 0x53000000
	}
	if row.width == 64 {
		base |= 1<<31 | 1<<22
	}
	return base | uint32(row.immr)<<16 | uint32(row.imms)<<10 | uint32(row.source)<<5 | uint32(row.destination)
}

func (row arm64NamedMoveBitfieldCase) value(input, initial uint64) uint64 {
	if row.destination == 31 {
		return initial
	}
	if strings.HasPrefix(string(row.op), "MOV") {
		value := uint64(0xa55a) << row.shift
		if strings.HasPrefix(string(row.op), "MOVN") {
			value = ^value
		}
		if row.width == 32 {
			value &= 0xffffffff
		}
		return value
	}
	if row.source == 31 {
		input = 0
	}
	if row.destination == 1 {
		initial = input
	}
	// Select each architectural output bit independently. This does not repeat
	// the lowerer's BFI/BFXIL/SBFX aliases or its shift/mask implementation.
	var result uint64
	top := (row.imms - row.immr + row.width) % row.width
	for bit := 0; bit < row.width; bit++ {
		set := false
		if bit > top {
			switch {
			case strings.HasPrefix(string(row.op), "BFM"):
				set = initial>>bit&1 != 0
			case strings.HasPrefix(string(row.op), "SBFM"):
				set = input>>row.imms&1 != 0
			}
		} else {
			selected := (bit + row.immr) % row.width
			if selected <= row.imms {
				set = input>>selected&1 != 0
			} else if strings.HasPrefix(string(row.op), "BFM") {
				set = initial>>bit&1 != 0
			}
		}
		if set {
			result |= uint64(1) << bit
		}
	}
	return result
}

func TestARM64NamedMoveWideAndBitfieldGoEncoding(t *testing.T) {
	rows := arm64NamedMoveBitfieldCases()
	if len(rows) != 168 {
		t.Fatalf("complete named move/bitfield axes = %d, want 168", len(rows))
	}
	var source strings.Builder
	source.WriteString("TEXT namedencoding(SB),4,$0-0\n")
	for _, row := range rows {
		source.WriteString(row.instruction() + "\n")
	}
	source.WriteString("RET\n")
	actual := arm64ImmediateOriginalGoBytes(t, source.String(), "linux")
	if len(actual) < 4*(len(rows)+1) {
		t.Fatal("original Go named instruction bytes are incomplete")
	}
	for index, row := range rows {
		if got := binary.LittleEndian.Uint32(actual[4*index:]); got != row.word() {
			t.Fatalf("%s: original Go word = %08x, want %08x", row.instruction(), got, row.word())
		}
	}
}

func TestARM64NamedMoveWideAndBitfieldValuesThreeAPIs(t *testing.T) {
	const input, initial = uint64(0x89abcdef76543210), uint64(0xfedcba9876543210)
	var source, declarations strings.Builder
	declarations.WriteString("package namedinteger\n")
	signatures := map[string]FuncSig{}
	rows := arm64NamedMoveBitfieldCases()
	for index, row := range rows {
		name := fmt.Sprintf("Named%d", index)
		result := row.destination
		if result == 31 {
			result = 2 // ZR writes cannot change the full nonzero canary.
		}
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVD $%#x,R1\nMOVD $%#x,R2\n%s\nMOVD R%d,ret+0(FP)\nRET\n",
			name, input, initial, row.instruction(), result)
		fmt.Fprintf(&declarations, "func %s() uint64\n", name)
		signatures[name] = FuncSig{Name: name, Ret: I64, Frame: FrameLayout{
			Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
		}}
	}
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "test/namedinteger", declarations.String())
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	for _, api := range []string{"text", "module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			context := llvm.NewContext()
			defer context.Dispose()
			var module llvm.Module
			options := Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple, Sigs: signatures, ResolveSym: resolve}
			switch api {
			case "text":
				var ir string
				ir, err = Translate(file, options)
				if err == nil {
					module, err = parseIRModuleInContext(context, ir)
				}
			case "module":
				module, err = TranslateModuleInContext(context, file, options)
			case "GoModule":
				var translated *GoModuleTranslation
				translated, err = translateGoModuleInContext(context, pkg, []byte(source.String()), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: arm64LinuxGNUTriple, ResolveSym: resolve,
				})
				if translated != nil {
					module = translated.Module
				}
			}
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal("complete named family translation", err)
			}
			if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
				t.Fatal(err)
			}
			passes := llvm.NewPassBuilderOptions()
			defer passes.Dispose()
			passes.SetVerifyEach(true)
			if err := module.RunPasses("function(sroa,mem2reg,instcombine,simplifycfg)", llvm.TargetMachine{}, passes); err != nil {
				t.Fatal(err)
			}
			for index, row := range rows {
				fn := module.NamedFunction(fmt.Sprintf("Named%d", index))
				if fn.IsNil() {
					t.Fatal("missing named numerical fixture", index)
				}
				returns := 0
				for block := fn.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
					for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
						if instruction.InstructionOpcode() != llvm.Ret {
							continue
						}
						returns++
						if instruction.OperandsCount() != 1 || instruction.Operand(0).IsAConstantInt().IsNil() ||
							instruction.Operand(0).ZExtValue() != row.value(input, initial) {
							t.Errorf("%s/%s: %s, want %016x", row.instruction(), row.form, instruction.String(), row.value(input, initial))
						}
					}
				}
				if returns != 1 {
					t.Error("numerical fixture must have one return", index, returns)
				}
			}
		})
	}
}
