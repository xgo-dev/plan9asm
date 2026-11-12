package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestARM64ScalarMinMaxCompleteGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	rows := regexp.MustCompile(`\{AFADDS,\s*C_FREG,\s*C_(NONE|FREG),\s*C_NONE,\s*C_FREG,\s*(?:C_NONE,\s*)?54,\s*4,\s*0,\s*0,\s*0\}`).FindAllString(source, -1)
	allRows := regexp.MustCompile(`\{AFADDS,`).FindAllString(source, -1)
	if len(rows) != 2 || len(allRows) != 2 {
		t.Fatalf("Go's complete scalar binary optab changed: matching=%d complete=%d", len(rows), len(allRows))
	}
	for index, operation := range []string{"FMAX", "FMIN", "FMAXNM", "FMINNM"} {
		for width, suffix := range []string{"S", "D"} {
			name := operation + suffix
			encoding := fmt.Sprintf(`case A%s:\s*(?:op =|return) FPOP2S\(0, 0, %d, %d\)`, name, width, index+4)
			if !regexp.MustCompile(encoding).MatchString(source) || strings.Count(source, "oprangeset(A"+name+", t)") != 1 {
				t.Fatalf("Go %s no longer has the complete case-54 alias and exact encoding", name)
			}
		}
	}
}

func TestARM64ScalarMinMaxCompleteFormatsObjects(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT minmaxFormats(SB),4,$0-0\n")
	count := 0
	for _, row := range arm64MinMaxCases() {
		for bank := 0; bank < 32; bank++ {
			for _, destination := range []int{bank, (bank + 1) % 32, (bank + 2) % 32} {
				source.WriteString(row.instruction(bank, (bank+1)%32, destination, false) + "\n")
				count++
			}
			source.WriteString(row.instruction(bank, bank, bank, row.word == 0) + "\n")
			count++
		}
	}
	source.WriteString("RET\n")
	if count != 2560 {
		t.Fatal("changed independent format/width/register/alias denominator", count)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	signatures := map[string]FuncSig{"minmaxFormats": {Name: "minmaxFormats", Ret: Void}}
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "arm64-apple-darwin", "aarch64-pc-windows-msvc"} {
		for api, ir := range arm64MinMaxIRs(t, source.String(), triple, signatures) {
			t.Run(fmt.Sprintf("%s/API%d", triple, api), func(t *testing.T) {
				compileLLVMToObject(t, llc, triple, "minmax.ll", "minmax.o", ir)
			})
		}
		pkg := mustGoPackage(t, "example.com/minmax", "package minmax\nfunc minmaxFormats()\n")
		bound, err := TranslateGoModule(pkg, []byte(strings.ReplaceAll(source.String(), "TEXT minmaxFormats", "TEXT ·minmaxFormats")), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: triple,
		})
		if err != nil {
			t.Fatal(err)
		}
		ir := bound.Module.String()
		bound.Module.Dispose()
		if len(bound.Functions) != 1 || len(bound.Signatures) != 1 || strings.Count(ir, "asm sideeffect") != count {
			t.Fatal("typed Go consumer lost min/max format rows")
		}
		compileLLVMToObject(t, llc, triple, "minmax-go.ll", "minmax-go.o", ir)
	}
}

func TestARM64ScalarMinMaxNativeTargetAndMalformedPriority(t *testing.T) {
	for _, row := range arm64MinMaxCases() {
		for _, dead := range []bool{false, true} {
			prefix := ""
			if dead {
				prefix = "RET\n"
			}
			body := prefix + row.instruction(0, 1, 31, false) + "\nRET\n"
			for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "wasm32-unknown-unknown", "aarch64_be-unknown-linux-gnu"} {
				for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext", "TranslateGoModule"} {
					present, err := arm64MinMaxTargetAPI(t, api, "TEXT comparison(SB),4,$0-0\n"+body, triple)
					if present || !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s %s dead=%t missing native target %q: output=%t err=%v", row.name, api, dead, triple, present, err)
					}
				}
			}
		}
		if row.word != 0 {
			continue
		}
		for _, suffix := range []string{" F0", " F0,F1,F2,F3", " R0,F1", " F0,R1", " $0.0,F1", " (R0),F1", ".P F0,F1", " F32,F1", " F0,F-1", " V0.S4,V1.S4"} {
			invalid := row.name + suffix
			requireARM64GoAssemblerResult(t, "TEXT invalid(SB),4,$0-0\n"+invalid+"\nRET\n", false)
			for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
				for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext", "TranslateGoModule"} {
					source := "TEXT comparison(SB),4,$0-0\n" + row.instruction(0, 1, 2, false) + "\nRET\n" + invalid + "\nRET\n"
					present, err := arm64MinMaxTargetAPI(t, api, source, triple)
					if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s %q malformed source became context/output: %t %v", api, invalid, present, err)
					}
				}
			}
		}
	}
}

func TestARM64ScalarMinMaxSparseMergeEffect(t *testing.T) {
	// The NEP merge source is V[n], not old V[d]. Preserve sparse known bits,
	// never require the unobserved upper bits and never initialize them.
	for _, alias := range []bool{false, true} {
		destination := "V2"
		if alias {
			destination = "V0"
		}
		state := arm64MachineState{values: make(map[string]int)}
		input := arm64MachineVectorDefinition{low: 0xffffffff, high: 0x00ff00ff00ff00ff}
		state.setVectorDefinition("V0", input)
		if !alias {
			state.setVectorDefinition(destination, arm64MachineVectorDefinition{low: ^uint64(0), high: ^uint64(0)})
		}
		if err := state.applyVectorSpan(arm64MachineEffect{register: destination, copyFrom: "V0", width: 128, vectorSpan: true, write: true}); err != nil {
			t.Fatal(err)
		}
		if err := state.applyVectorSpan(arm64MachineEffect{register: destination, width: 32, vectorSpan: true, write: true}); err != nil {
			t.Fatal(err)
		}
		input.scalable = true // Architectural scalar write clears scalable high bits.
		if got := state.vectorDefinition(destination); got != input {
			t.Errorf("NEP first-source sparse merge alias=%t got %+v, want %+v", alias, got, input)
		}
	}
}

func TestARM64ScalarMinMaxDefinednessAndNativePairing(t *testing.T) {
	for _, row := range arm64MinMaxCases() {
		for _, firstKnown := range []int{0, row.bits, 128} {
			for _, readWidth := range []int{row.bits, 128} {
				ctx, flow := arm64FlagScratchBankFixture()
				ctx.targetTriple = "aarch64-unknown-linux-gnu"
				ctx.vRegSlot = map[int]string{0: "%first", 1: "%second", 2: "%destination"}
				flow.used, flow.entry = true, &ARM64GoRegisterABI{}
				if firstKnown != 0 {
					ctx.recordMachineRegister("F0", firstKnown, true)
				}
				ctx.recordMachineRegister("F1", row.bits, true)
				ctx.recordMachineRegister("F2", 128, true) // Must not survive a different-source merge.
				kind := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(row.name, "S"), "D"))
				form := arm64ScalarMinMaxForm{arm64ScalarMinMaxSpec{kind, row.bits}, "F0", "F1", "F2"}
				start := ctx.b.Len()
				if err := ctx.lowerARM64ScalarMinMax(form); err != nil {
					t.Fatal(err)
				}
				ctx.recordMachineOpaqueIR(start, Instr{})
				ctx.recordMachineRegister("F2", readWidth, false)
				err := flow.validate()
				want := firstKnown >= readWidth
				if want && err != nil || !want && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s/%d first=%d read=%d changed definedness: %v", row.name, row.bits, firstKnown, readWidth, err)
				}
				start = ctx.b.Len()
				fmt.Fprintln(ctx.b, `  call void asm sideeffect "nop", ""()`)
				ctx.recordMachineOpaqueIR(start, Instr{})
				if !flow.blocks[0].effects[len(flow.blocks[0].effects)-1].opaque {
					t.Fatal("min/max native-line proof leaked to an unrelated callout")
				}
			}
		}
	}
}

func TestARM64ScalarMinMaxSparseCopyBoundariesAndJoins(t *testing.T) {
	for _, effect := range []arm64MachineEffect{
		{register: "V0", copyFrom: "R0", width: 128, vectorSpan: true, write: true},
		{register: "R0", copyFrom: "V0", width: 128, vectorSpan: true, write: true},
		{register: "V0", copyFrom: "V1", width: 128, vectorSpan: true},
		{register: "V0", copyFrom: "V1", width: 64, vectorSpan: true, write: true},
		{register: "V0", copyFrom: "V1", width: 128, vectorOffset: 1, vectorSpan: true, write: true},
	} {
		state := arm64MachineState{values: make(map[string]int)}
		if err := state.applyVectorSpan(effect); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("invalid definedness copy accepted", effect, err)
		}
	}
	for _, readWidth := range []int{32, 128} {
		flow := &arm64MachineAvailability{used: true, entry: &ARM64GoRegisterABI{}, blocks: []arm64MachineBlock{
			{name: "entry", successors: []string{"left", "right"}},
			{name: "left", successors: []string{"join"}, effects: []arm64MachineEffect{{register: "V0", width: 128, write: true}}},
			{name: "right", successors: []string{"join"}, effects: []arm64MachineEffect{{register: "V0", width: 32, write: true}}},
			{name: "join", effects: []arm64MachineEffect{
				{register: "V2", copyFrom: "V0", width: 128, vectorSpan: true, write: true},
				{register: "V2", width: 32, vectorSpan: true, write: true},
				{register: "V2", width: readWidth},
			}},
		}}
		err := flow.validate()
		if readWidth == 32 && err != nil || readWidth == 128 && !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("merge restored bits unavailable on one predecessor, read=%d: %v", readWidth, err)
		}
	}
}

func TestARM64ScalarMinMaxWholeStateTranslation(t *testing.T) {
	for _, banks := range []bool{false, true} {
		cases := arm64MinMaxStateCases(banks)
		source, signatures := arm64MinMaxStateSource(cases[:4])
		for _, ir := range arm64MinMaxIRs(t, source, "aarch64-unknown-linux-gnu", signatures) {
			if strings.Count(ir, `asm sideeffect "fmax `) != 4 {
				t.Fatal("complete state consumer lost its min/max operations")
			}
		}
	}
}

func TestARM64ScalarMinMaxRawReservedAndUnrelatedWordBoundaries(t *testing.T) {
	for _, row := range arm64MinMaxCases() {
		if row.word == 0 {
			continue
		}
		reserved := row.word&^(3<<22) | 2<<22
		for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext", "TranslateGoModule"} {
			for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
				source := fmt.Sprintf("TEXT comparison(SB),4,$0-0\n%s\nRET\nWORD $%#08x\nRET\n", row.instruction(0, 1, 2, false), reserved)
				present, err := arm64MinMaxTargetAPI(t, api, source, triple)
				if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("reserved scalar min/max WORD became target context/output: %s/%s %t %v", api, triple, present, err)
				}
			}
		}
	}
	for _, operands := range [][]Operand{
		nil, {{Kind: OpImm, ImmRaw: "$(OTHER_OPCODE)"}},
		{{Kind: OpReg, Reg: "R0"}}, {{Kind: OpImm, ImmIsFloat: true}},
		{{Kind: OpImm, Imm: 0xd503201f}},
	} {
		file := &File{Arch: ArchARM64, Funcs: []Func{{Instrs: []Instr{{Op: OpWORD, Args: operands}}}}}
		if err := validateARM64ScalarMinMaxTarget(file, Options{}); err != nil {
			t.Fatalf("min/max claimed unrelated or unresolved WORD %+v: %v", operands, err)
		}
	}
}
