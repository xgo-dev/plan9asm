package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86VectorTestCompleteIndependentEncoderRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?s)var yxm_q4 = \[\]ytab\{\s*\{Zm_r, 1, argList\{Yxm, Yxr\}\},\s*\}`).Match(data) ||
		!strings.Contains(string(data), "{APTEST, yxm_q4, Pq4, opBytes{0x17}}") {
		t.Fatal("complete legacy PTEST row, prefix or opcode changed")
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	opcodes := map[string]string{"VPTEST": "0x17", "VTESTPD": "0x0F", "VTESTPS": "0x0E"}
	for _, rule := range rules {
		opcode, wanted := opcodes[rule.Opcode]
		if !wanted {
			continue
		}
		index := counts[rule.Opcode]
		counts[rule.Opcode]++
		classes := []string{"Yxm,Yxr", "Yym,Yyr"}
		bytes := []string{"avxEscape | vex128 | vex66 | vex0F38 | vexW0", opcode,
			"avxEscape | vex256 | vex66 | vex0F38 | vexW0", opcode}
		if index >= 2 || rule.RowIndex != index || rule.Ytab != "_yvptest" || rule.Prefix != "Pavx" ||
			rule.ZCase != "Zvex_rm_v_r" || rule.ZOffset != 2 || rule.EncodingOffset != 2*index ||
			strings.Join(rule.Classes, ",") != classes[index] || !reflect.DeepEqual(rule.OpBytes, bytes) {
			t.Fatal("complete vector-test encoder grammar or attributes changed", rule)
		}
	}
	for name := range opcodes {
		if counts[name] != 2 {
			t.Fatal("incomplete VEX vector-test inventory", counts)
		}
	}
	if len(amd64VectorTestSpecs) != 4 {
		t.Fatal("unaccounted vector-test family member")
	}
}

func TestX86VectorTestPairedBytesFlagsAndStandaloneBoundary(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86VectorTestInputRows() {
			ins := x86ScalarLaneInstruction(t, row)
			width := amd64VectorByteWidth(ins.Args[1].Reg)
			for missing := -1; missing < width; missing++ {
				state := x86ResultState{flags: x86ByteFlagAF, direction: x86ResultDirectionEither}
				state.pointerGP[6], state.gp[3] = true, 0x55
				state.xmm[1], state.vectorUpper[1], state.masks[2] = 0xffff, ^uint64(0)&^0xffff, true
				if missing >= 0 {
					state.writeVector(1, width, state.vectorBytes(1)&^(uint64(1)<<uint(missing)), true)
				}
				before := state.clone()
				if accepted, known := x86ResultVectorTestStep(ins, &state, nil, arch); !known || accepted ||
					!reflect.DeepEqual(state, before) {
					t.Fatal("standalone vector test acquired native backing or changed a failed state", arch, row)
				}
				accepted, known := x86LoweredVectorTestResultStep(ins, &state, nil, arch)
				want := before.clone()
				if missing < 0 {
					want.flags = x86ByteFlagsAll
				}
				if !known || accepted != (missing < 0) || !reflect.DeepEqual(state, want) {
					t.Fatal("vector-test bytes/FLAGS changed unrelated state or invented missing inputs", arch, row, missing)
				}
			}
		}
	}
}

func TestX86VectorTestRawIdentityRetainsSeparateControlEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86VectorTestInputRows() {
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+x86RawNumericalInstruction(t, arch, row)+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			file, err = normalizeX86RawFile(file, arch)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if !x86RawVectorTestSource(ins, arch) || !x86ResultPreservesPrivateStorage(ins, arch) ||
				x86PreservesNumericalSourceState(ins) ||
				x86ResultDirectionAfterSource(ins, x86ResultDirectionEither, arch) != x86ResultDirectionEither {
				t.Fatal("exact vector test confused arithmetic FLAGS, private controls and inert-source roles", row)
			}
			for _, change := range []func(*Instr){
				func(ins *Instr) { ins.Args[1].Reg = "X3" },
				func(ins *Instr) { ins.x86AddressBits = 16 },
				func(ins *Instr) { ins.x86UnboundAddressOverride = true },
				func(ins *Instr) { ins.x86SegmentPrefix = 0x64 },
				func(ins *Instr) { ins.x86RIPLiteral = true },
			} {
				changed := ins
				changed.Args = append([]Operand(nil), ins.Args...)
				change(&changed)
				if x86RawVectorTestSource(changed, arch) || x86ResultPreservesPrivateStorage(changed, arch) ||
					x86ResultDirectionAfterSource(changed, x86ResultDirectionEither, arch) != x86ResultDirectionUnknown {
					t.Fatal("changed original vector test borrowed private controls", arch, row)
				}
			}
		}
	}
}

func TestX86VectorTestLogicalFPBytesDoNotAcquireLegacyNativeStorage(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86VectorTestInputRows() {
			width := 16
			if strings.HasSuffix(row, "Y1") {
				width = 32
			}
			parameters := "a,b uint64"
			if width == 32 {
				parameters = "a,b,c,d uint64"
			}
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nVPXORD Y1,Y1,Y1\n%s\nRET\n",
				width, strings.Replace(row, "(SI)", "a+0(FP)", 1))
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value("+parameters+")", target.arch, target.triple, api)
				if strings.HasPrefix(row, "PTEST") {
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("logical FP values supplied legacy native storage", target, api)
					}
				} else if err != nil || ir == "" {
					t.Fatal("complete numerical FP span lost its virtual-value consumer", target, api, row, err)
				}
			}
		}
	}
}
