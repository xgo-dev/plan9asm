package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86UnalignedLoadCompleteOfficialRowsAndTypedEffects(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Join(strings.Fields(string(data)), "")
	for _, expected := range []string{
		"varylddqu=[]ytab{{Zm_r,1,argList{Ym,Yxr}},}",
		"{ALDDQU,ylddqu,Pf2,opBytes{0xf0}}",
	} {
		if !strings.Contains(legacy, expected) {
			t.Fatal("complete official legacy LDDQU grammar changed", expected)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var actual []goasmrules.X86AVXRule
	for _, rule := range rules {
		if rule.Opcode == "VLDDQU" {
			actual = append(actual, rule)
		}
	}
	opbytes := []string{"avxEscape | vex128 | vexF2 | vex0F | vexW0", "0xF0",
		"avxEscape | vex256 | vexF2 | vex0F | vexW0", "0xF0"}
	var expected []goasmrules.X86AVXRule
	for index, bank := range []string{"Yxr", "Yyr"} {
		expected = append(expected, goasmrules.X86AVXRule{
			Opcode: "VLDDQU", Ytab: "_yvlddqu", Prefix: "Pavx", Classes: []string{"Ym", bank},
			RowIndex: index, ZCase: "Zvex_rm_v_r", ZOffset: 2, EncodingOffset: index * 2, OpBytes: opbytes,
		})
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("complete original VEX LDDQU rows/attributes changed", actual)
	}
	for _, arch := range []string{"386", "amd64"} {
		var rows []string
		for _, shape := range []struct{ op, bank string }{{"LDDQU", "X"}, {"VLDDQU", "X"}, {"VLDDQU", "Y"}} {
			for _, memory := range []string{"1(AX)", "-16(BX)(CX*2)", "value+0(FP)", "table<>(SB)"} {
				rows = append(rows, shape.op+" "+memory+","+shape.bank+"1")
			}
		}
		requireX86GoAssemblerResult(t, arch, "TEXT forms(SB),4,$0-64\n"+strings.Join(rows, "\n")+"\nRET\n", true)
		for _, row := range rows {
			ins := x86ScalarLaneInstruction(t, row)
			effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
			if !known || err != nil || !effect.requiresResultProof || len(effect.operands) != 2 ||
				effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
				t.Fatal("complete LDDQU memory/byte effect is not registered", arch, row, known, err)
			}
		}
	}
}

func TestX86UnalignedLoadInitializedNativeInputsAndWholeUpperBytes(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete LDDQU objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		word, move := goWordSize(target.arch), "MOVQ"
		if word == 4 {
			move = "MOVL"
		}
		var source, declarations strings.Builder
		for index, row := range []string{"LDDQU 1(SI),X0", "VLDDQU 1(SI),X0", "VLDDQU 1(SI),Y0"} {
			name := fmt.Sprint("Unaligned", index)
			fmt.Fprintf(&declarations, "func %s(out *[72]byte,input *[128]byte,old *[64]byte)\n", name)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s input+%d(FP),SI\n"+
				"%s old+%d(FP),BX\nVMOVUPS (BX),Z0\nSTC\n%s\nVMOVUPS Z0,(DI)\nSETCS 64(DI)\nSTMXCSR 68(DI)\nRET\n",
				name, 3*word, move, move, word, move, 2*word, row)
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("initialized LDDQU source and observable upper bytes rejected", err)
				}
				if !strings.Contains(ir, "asm sideeffect \"lddqu ") ||
					strings.Count(ir, "asm sideeffect \"vlddqu ") != 2 || !strings.Contains(ir, "+sse3") {
					t.Fatal("LDDQU lost its original implementation-defined access or required ISA")
				}
				for _, pipeline := range []struct{ ir, level string }{
					{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
				} {
					x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.level)
				}
			})
		}
	}
}

func TestX86UnalignedLoadOriginalPhysicalWIGMemoryForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for word := 0; word < 2; word++ {
			for length, bank := range []string{"X", "Y"} {
				code := []byte{0xc4, 0xe1, byte(0x7b | word<<7 | length<<2), 0xf0, 0x40, 0x01}
				source := "TEXT Value(SB),4,$0-0\n" + x86RawDisplacementDirectives(code) + "RET\n"
				requireX86GoAssemblerResult(t, arch, source, true)
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
				if err != nil || len(file.Funcs[0].Instrs) != 3 {
					t.Fatal("complete physical VEX.WIG LDDQU was not decoded", arch, word, length, err)
				}
				ins := file.Funcs[0].Instrs[1]
				want := x86ScalarLaneInstruction(t, "VLDDQU 1(AX),"+bank+"0")
				if ins.Op != want.Op || !reflect.DeepEqual(ins.Args, want.Args) || ins.x86SourceRaw == nil {
					t.Fatal("physical WIG changed the complete memory or vector identity", ins.Raw)
				}
			}
		}
	}
}
