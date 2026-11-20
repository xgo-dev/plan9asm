package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

type x86NamedHalfRawCase struct {
	row  x86NamedHalfCase
	code []byte
}

// These four low-bank unmasked EVEX literals are independent physical
// witnesses, not bytes attributed to the overlapping Go named VEX encoder.
func x86NamedHalfLowEVEX() []x86NamedHalfRawCase {
	return []x86NamedHalfRawCase{
		{x86NamedHalfCase{width: 16}, []byte{0x62, 0xf2, 0x7d, 0x08, 0x13, 0xc1}},
		{x86NamedHalfCase{width: 32}, []byte{0x62, 0xf2, 0x7d, 0x28, 0x13, 0xc1}},
		{x86NamedHalfCase{narrow: true, width: 16}, []byte{0x62, 0xf3, 0x7d, 0x08, 0x1d, 0xc8, 0}},
		{x86NamedHalfCase{narrow: true, width: 32}, []byte{0x62, 0xf3, 0x7d, 0x28, 0x1d, 0xc8, 0}},
	}
}

func x86NamedHalfLowEVEXPrior(t *testing.T, arch string) {
	t.Helper()
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("low-bank physical half generation requires LLVM22 llvm-mc")
	}
	var source, input strings.Builder
	for _, row := range x86NamedHalfLowEVEX() {
		source.WriteString(x86RawDisplacementDirectives(row.code))
		for _, value := range row.code {
			fmt.Fprintf(&input, "0x%02x ", value)
		}
		input.WriteByte('\n')
	}
	x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], "TEXT LowEVEX(SB),4,$0-0\n"+source.String()+"RET\n")
	stage, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+x86AddressMemoryTargets(arch)[0],
		"--mattr=+f16c,+avx512f,+avx512vl")
	command.Stdin = strings.NewReader(input.String())
	output, err := runtimeOracleCombinedOutput(stage, command)
	cancel()
	if err != nil || strings.Contains(string(output), "invalid") || strings.Contains(string(output), "warning") ||
		strings.Count(string(output), "vcvtph2ps") != 2 || strings.Count(string(output), "vcvtps2ph") != 2 {
		t.Fatalf("independent low-bank EVEX half physical prior: %v\n%s", err, output)
	}
}

func x86NamedHalfRawCases(t *testing.T, arch string) []x86NamedHalfRawCase {
	t.Helper()
	var rows []x86NamedHalfCase
	var source strings.Builder
	for _, row := range x86NamedHalfCases("amd64") {
		if arch == "386" && row.high {
			continue
		}
		rows = append(rows, row)
		source.WriteString(row.instruction() + "\n")
	}
	// Capture in AMD64: genuine Go386 four-operand syntax rejection does not
	// invalidate its independently decoded low-bank physical EVEX counterpart.
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source.String()+"RET\n")
	if len(pcs) != len(rows)+1 {
		t.Fatal("incomplete independent ordinary half physical directory")
	}
	var result []x86NamedHalfRawCase
	for index, row := range rows {
		result = append(result, x86NamedHalfRawCase{row, append([]byte(nil), code[pcs[index]:pcs[index+1]]...)})
	}
	x86NamedHalfLowEVEXPrior(t, arch)
	return append(result, x86NamedHalfLowEVEX()...)
}

func x86NamedHalfRawInitialized(name, arch string, row x86NamedHalfRawCase) (string, string) {
	source, declaration := x86NamedHalfInitialized(name, arch, row.row, false)
	return strings.Replace(source, row.row.instruction()+"\n", x86RawDisplacementDirectives(row.code), 1), declaration
}

func TestX86NamedHalfRawLowBankPhysicalGenerationIsNotNamedInference(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		x86NamedHalfLowEVEXPrior(t, arch)
		for _, row := range x86NamedHalfLowEVEX() {
			code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", row.row.instruction()+"\nRET\n")
			for _, physical := range [][]byte{code[:pcs[1]], row.code} {
				t.Run(fmt.Sprintf("%s/%s/EVEX=%t", arch, row.row.instruction(), physical[0] == 0x62), func(t *testing.T) {
					ins := x86RawMoveObservedInstruction(t, arch, physical)
					profile := "," + inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}) + ","
					evex := physical[0] == 0x62
					if ins.x86SourceRaw == nil || strings.Contains(profile, ",+avx512f,") != evex ||
						strings.Contains(profile, ",+avx512vl,") != evex || !evex && !strings.Contains(profile, ",+f16c,") ||
						strings.Contains(profile, "+avx512fp16") {
						t.Fatal("ordinary half lost actual VEX/EVEX or borrowed raw-only FP16 generation", physical, profile)
					}
				})
			}
		}
	}
}

func TestX86NamedHalfRawInitializedFiveTargetNativeObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("ordinary raw half original-native objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86NamedHalfRawCases(t, target.arch)
			want := 59
			if target.arch == "386" {
				want = 51
			}
			if len(rows) != want {
				t.Fatal("incomplete ordinary raw source/control/generation directory", len(rows), want)
			}
			var source, declarations strings.Builder
			functions := make(map[string][]string)
			for index, row := range rows {
				name := fmt.Sprint("RawHalf", index)
				body, declaration := x86NamedHalfRawInitialized(name, target.arch, row)
				source.WriteString(body)
				declarations.WriteString(declaration)
				functions[name] = []string{row.row.operation()}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("initialized ordinary raw half source cannot compose with its actual producers", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86ScalarPrecisionRequireNativeEffects(t, body, functions)
						for index, row := range rows {
							name := fmt.Sprint("RawHalf", index)
							if row.row.narrow {
								x86NamedHalfRequireOriginalControl(t, body, name, row.row.immediate)
							}
							_, function, found := strings.Cut(body, "define void @"+name+"(")
							function, _, ended := strings.Cut(function, "\n}")
							if !found || !ended || strings.Contains(function, "{evex} "+strings.ToLower(row.row.operation())) != (row.code[0] == 0x62) {
								t.Fatal("raw half native opcode changed its actual physical generation", name, row.code)
							}
						}
						compileLLVMToObject(t, llc, target.triple, "raw-named-half.ll", "raw-named-half.o", body)
					}
				})
			}
		})
	}
}

func TestX86NamedHalfRawWholeProducerImmutableReplay(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86NamedHalfRawCases(t, arch)
		// Both ordinary members, physical generations and register/memory
		// roles. Full format/byte/mask axes already have the object matrix.
		for _, row := range rows {
			if row.row.high || row.row.sae || row.row.mask == 2 || row.row.width != 16 || row.row.immediate != 0 {
				continue
			}
			source, declaration := x86NamedHalfRawInitialized("Value", arch, row)
			x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], source)
			check := x86LegacyFloatReplayCheck(t, arch, source, declaration)
			mutations := []string{"valid", "origin", "replay", "mode", "encoded", "width", "operand",
				"producer", "spelling", "header", "bytes", "decoded-snapshot", "origin-operands"}
			var alternate Instr
			if !row.row.memory && row.row.mask == 0 {
				other := x86NamedHalfLowEVEX()[0].code
				if row.row.narrow {
					other = x86NamedHalfLowEVEX()[2].code
				}
				if row.code[0] == 0x62 {
					code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", row.row.instruction()+"\nRET\n")
					other = code[:pcs[1]]
				}
				alternate = x86RawMoveObservedInstruction(t, arch, other)
				mutations = append(mutations, "generation", "generation-snapshot")
			}
			for _, mutation := range mutations {
				t.Run(fmt.Sprintf("%s/%s/EVEX=%t/%s", arch, row.row.instruction(), row.code[0] == 0x62, mutation), func(t *testing.T) {
					file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
					if err != nil || file.Funcs[0].x86RawReplay == nil {
						t.Fatal("original ordinary raw half decode/replay prerequisite", err)
					}
					original, ordinal := file.Funcs[0], -1
					for at, ins := range original.Instrs {
						if ins.x86SourceRaw != nil && strings.Split(string(ins.Op), ".")[0] == row.row.operation() {
							ordinal = at
						}
					}
					if ordinal < 0 || original.x86RawReplay.validate(original, arch) != nil {
						t.Fatal("original half conversion lost its independently sealed source")
					}
					candidate := original
					candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
					ins := &candidate.Instrs[ordinal]
					switch mutation {
					case "origin":
						ins.x86SourceRaw = nil
					case "replay":
						candidate.x86RawReplay = nil
					case "encoded":
						ins.x86Encoded = !ins.x86Encoded
					case "width":
						ins.x86VectorBytes = 7
					case "operand":
						ins.Args[len(ins.Args)-1].Reg = "X7"
					case "producer":
						candidate.Instrs[1].Raw += " changed"
					case "spelling":
						ins.Raw += " changed"
					case "header":
						candidate.ArgSize++
					case "origin-operands":
						ins.x86SourceRaw.args[0].Reg = "X7"
					case "generation":
						replacement := cloneX86ReplayInstrs([]Instr{alternate})[0]
						replacement.x86SourceRaw = ins.x86SourceRaw
						*ins = replacement
					case "generation-snapshot":
						ins.x86SourceRaw = cloneX86ReplayInstrs([]Instr{alternate})[0].x86SourceRaw
					case "mode", "bytes", "decoded-snapshot":
						replay := *original.x86RawReplay
						if mutation == "mode" {
							replay.goarch = "arm64"
						}
						if mutation == "bytes" {
							replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
						}
						if mutation == "decoded-snapshot" {
							replay.decoded = cloneX86ReplayInstrs(replay.decoded)
							replay.decoded[ordinal].x86SourceRaw = nil
						}
						candidate.x86RawReplay = &replay
					}
					err = check(candidate)
					if mutation == "valid" {
						if err != nil {
							t.Fatal("initialized complete ordinary raw half producer must succeed", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("edited ordinary raw half/source acquired a paired native continuation", err)
					}
					if original.x86RawReplay.validate(original, arch) != nil {
						t.Fatal("mutation corrupted the original half replay")
					}
				})
			}
		}
	}
}
