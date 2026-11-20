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

func x86COMIOracleNames() []string {
	return []string{"COMISS", "COMISD", "UCOMISS", "UCOMISD", "VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"}
}

func TestX86COMIIndependentCompleteEncoderRows(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), "var yxm = []ytab{\n\t{Zm_r_xm, 1, argList{Yxm, Yxr}},\n}") {
		t.Fatal("complete legacy yxm operand table changed")
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range x86COMIOracleNames() {
		double, vector := strings.HasSuffix(name, "D"), strings.HasPrefix(name, "V")
		opcode := "0x2F"
		if strings.Contains(name, "UCOMI") {
			opcode = "0x2E"
		}
		if !vector {
			prefix := "Pm"
			if double {
				prefix = "Pe"
			}
			entry := fmt.Sprintf("{A%s, yxm, %s, opBytes{%s}}", name, prefix, strings.ToLower(opcode))
			if !strings.Contains(string(legacy), entry) {
				t.Fatal("legacy scalar compare opcode attributes changed", entry)
			}
			count++
			continue
		}
		vex, evex, tuple := "avxEscape | vex128 | vex0F | vexW0", "avxEscape | evex128 | evex0F | evexW0", "evexN4 | evexSaeEnabled"
		if double {
			vex, evex, tuple = "avxEscape | vex128 | vex66 | vex0F | vexW0", "avxEscape | evex128 | evex66 | evex0F | evexW1", "evexN8 | evexSaeEnabled"
		}
		opbytes := []string{vex, opcode, evex, tuple, opcode}
		index := 0
		for _, row := range rules {
			if row.Opcode != name {
				continue
			}
			class, zcase, advance, offset := "Yxm", "Zvex_rm_v_r", 2, 0
			if index == 1 {
				class, zcase, advance, offset = "YxmEvex", "Zevex_rm_v_r", 3, 2
			}
			destination := "Yxr"
			if index == 1 {
				destination = "YxrEvex"
			}
			if row.Ytab != "_yvcomisd" || row.Prefix != "Pavx" || row.RowIndex != index || row.EncodingOffset != offset ||
				row.ZCase != zcase || row.ZOffset != advance || !reflect.DeepEqual(row.Classes, []string{class, destination}) || !reflect.DeepEqual(row.OpBytes, opbytes) {
				t.Fatalf("%s independent complete encoder row changed: %+v", name, row)
			}
			index++
			count++
		}
		if index != 2 {
			t.Fatal("missing scalar compare encoder rows", name, index)
		}
	}
	if count != 12 || len(x86COMISpecs) != 8 {
		t.Fatal("complete eight-name/twelve-row family changed", count, len(x86COMISpecs))
	}
}

func TestX86COMITypedEveryByteAndEffects(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86COMIOracleNames() {
			width := 4
			if strings.HasSuffix(name, "D") {
				width = 8
			}
			instruction := x86ScalarLaneInstruction(t, name+" X1,X2")
			effect, known, err := x86TypedInstructionByteEffect(instruction.Op, instruction, arch)
			want := x86TypedByteEffect{operands: []x86TypedByteOperand{
				{index: 0, operand: instruction.Args[0], width: int64(width), read: true},
				{index: 1, operand: instruction.Args[1], width: int64(width), read: true},
			}, flagsDefined: x86ByteFlagsAll, requiresResultProof: true}
			if !known || err != nil || !reflect.DeepEqual(effect, want) {
				t.Fatal("comparison gained a write or lost exact input bytes/FLAGS", arch, name, effect, err)
			}
			for _, input := range []int{1, 2} {
				for missing := -1; missing < 64; missing++ {
					state := &x86ResultState{}
					state.writeVector(1, 64, ^uint64(0), false)
					state.writeVector(2, 64, ^uint64(0), false)
					bytes := ^uint64(0)
					if missing >= 0 {
						bytes &^= 1 << uint(missing)
					}
					state.writeVector(input, 64, bytes, false)
					accepted := x86ResultTransfer(instruction, state, nil, 0, arch)
					want := missing < 0 || missing >= width
					if accepted != want || state.vectorBytes(input) != bytes || accepted && state.flags != x86ByteFlagsAll || !accepted && state.flags != 0 {
						t.Fatal("comparison consumed undefined bytes or changed inputs/FLAGS on failure", arch, name, input, missing)
					}
				}
			}
			for _, kind := range []string{"FP", "AUTO", "SB", "pointer"} {
				for missing := -1; missing < width; missing++ {
					owned := make([]bool, 16)
					state := &x86ResultState{fp: make([]bool, 16), auto: make([]bool, 16)}
					state.writeVector(2, 64, ^uint64(0), false)
					for i := range owned {
						owned[i], state.fp[i], state.auto[i] = i != missing, i != missing, i != missing
					}
					operand := "value+0(FP)"
					switch kind {
					case "AUTO":
						operand = "local-16(SP)"
					case "SB":
						operand = "external(SB)"
					case "pointer":
						operand = "(BX)"
						state.pointerGP[3] = true
					}
					accepted := x86ResultTransfer(x86ScalarLaneInstruction(t, name+" "+operand+",X2"), state, owned, 0, arch)
					want := (kind == "FP" || kind == "AUTO") && missing == -1
					if accepted != want {
						t.Fatal("comparison acquired unowned/undefined memory", arch, name, kind, missing)
					}
				}
			}
		}
	}
}

func TestX86COMIHelperCannotBorrowForeignDispatch(t *testing.T) {
	for _, operation := range []Op{"ADDQ", "MOVQ", "UNKNOWN.COMISS", "COMISS"} {
		var ir strings.Builder
		ctx := amd64Ctx{b: &ir, goarch: "amd64", targetTriple: "x86_64-unknown-linux-gnu"}
		instruction := x86ScalarLaneInstruction(t, "MOVQ AX,BX")
		known, terminated, err := ctx.lowerVectorScalarFlagCompare(operation, instruction)
		_, effectKnown, effectErr := x86TypedCOMIByteEffect(operation, instruction, "amd64")
		want := operation == "COMISS"
		if known != want || effectKnown != want || (err != nil) != want || (effectErr != nil) != want || terminated || ir.Len() != 0 {
			t.Fatal("COMI helper borrowed foreign source/dispatch identity", operation, known, effectKnown, err, effectErr)
		}
	}
}
