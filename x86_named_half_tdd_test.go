package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Independent of the production FP16 maps. These are Go's two named F16C /
// AVX512F conversions, not the six raw-only AVX512-FP16 conversion members.
type x86NamedHalfCase struct {
	narrow, memory, high   bool
	width, mask, immediate int
	sae                    bool
}

func x86NamedHalfCases(arch string) []x86NamedHalfCase {
	var rows []x86NamedHalfCase
	for _, narrow := range []bool{false, true} {
		for _, width := range []int{16, 32, 64} {
			for _, memory := range []bool{false, true} {
				rows = append(rows, x86NamedHalfCase{narrow: narrow, width: width, memory: memory})
				if !narrow || arch == "amd64" {
					rows = append(rows, x86NamedHalfCase{narrow: narrow, width: width, memory: memory, mask: 1})
					if !narrow || !memory {
						rows = append(rows, x86NamedHalfCase{narrow: narrow, width: width, memory: memory, mask: 2})
					}
				}
				if width < 64 && arch == "amd64" {
					rows = append(rows, x86NamedHalfCase{narrow: narrow, width: width, memory: memory, high: true})
				}
				if width == 64 && !memory {
					rows = append(rows, x86NamedHalfCase{narrow: narrow, width: width, memory: memory, sae: true})
					if !narrow || arch == "amd64" {
						rows = append(rows, x86NamedHalfCase{narrow: narrow, width: width, memory: memory, sae: true, mask: 1})
						if !memory {
							rows = append(rows, x86NamedHalfCase{narrow: narrow, width: width, sae: true, mask: 2})
						}
					}
				}
				if narrow && width < 64 {
					rows = append(rows, x86NamedHalfCase{narrow: true, width: width, memory: memory, immediate: -1})
				}
			}
		}
	}
	// Bit 2 selects MXCSR.RC; bits 1:0 must not select fixed rounding then.
	for control := 4; control < 8; control++ {
		rows = append(rows, x86NamedHalfCase{narrow: true, width: 16, immediate: control})
	}
	return rows
}

func (row x86NamedHalfCase) registers() (source, destination int) {
	if row.high {
		return 16, 17
	}
	return 1, 0
}

func (row x86NamedHalfCase) operation() string {
	if row.narrow {
		return "VCVTPS2PH"
	}
	return "VCVTPH2PS"
}

func (row x86NamedHalfCase) instruction() string {
	source, destination := row.registers()
	wide, short := map[int]string{16: "X", 32: "Y", 64: "Z"}[row.width], "X"
	if row.width == 64 {
		short = "Y"
	}
	op := row.operation()
	if row.sae {
		op += ".SAE"
	}
	if row.mask == 2 {
		op += ".Z"
	}
	mask := ""
	if row.mask != 0 {
		mask = ",K1"
	}
	if row.narrow {
		out := fmt.Sprintf("%s%d", short, destination)
		if row.memory {
			out = "80(DI)"
		}
		return fmt.Sprintf("%s $%d,%s%d%s,%s", op, row.immediate, wide, source, mask, out)
	}
	in := fmt.Sprintf("%s%d", short, source)
	if row.memory {
		in = "(AX)"
	}
	return fmt.Sprintf("%s %s%s,%s%d", op, in, mask, wide, destination)
}

func x86NamedHalfGoPrior(t *testing.T, arch string, rows []x86NamedHalfCase) {
	t.Helper()
	var source strings.Builder
	for _, row := range rows {
		source.WriteString(row.instruction() + "\n")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, arch, source.String()+"RET\n")
	if len(pcs) != len(rows)+1 || len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("actual Go omitted a complete named half conversion boundary", arch, len(pcs), len(rows))
	}
	var input strings.Builder
	for index, row := range rows {
		instruction := code[pcs[index]:pcs[index+1]]
		evex := row.width == 64 || row.mask != 0 || row.high || row.sae
		if len(instruction) < 4 || (instruction[0] == 0x62) != evex {
			t.Fatal("independent Go generation differs from named shape", row.instruction(), instruction)
		}
		for _, value := range instruction {
			fmt.Fprintf(&input, "0x%02x ", value)
		}
		input.WriteByte('\n')
	}
	// LLVM's independent decoder observes the actual complete Go bytes, not
	// a copy of our decoder's generated opcode or vector-length metadata.
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("named half physical prior requires LLVM22 llvm-mc")
	}
	triple := "x86_64-unknown-linux-gnu"
	if arch == "386" {
		triple = "i386-unknown-linux-gnu"
	}
	stage, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+triple,
		"--mattr=+f16c,+avx512f,+avx512vl")
	command.Stdin = strings.NewReader(input.String())
	output, err := runtimeOracleCombinedOutput(stage, command)
	cancel()
	if err != nil || strings.Contains(string(output), "warning") || strings.Contains(string(output), "invalid") {
		t.Fatalf("independent named half physical prior: %v\n%s", err, output)
	}
	count := strings.Count(string(output), "vcvtph2ps") + strings.Count(string(output), "vcvtps2ph")
	if count != len(rows) {
		t.Fatal("LLVM did not independently decode every original Go conversion", arch, count, len(rows), string(output))
	}
}

func TestX86NamedHalfOriginalGoAndLLVMPhysicalPriors(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			rows, want := x86NamedHalfCases(arch), 55
			if arch == "386" {
				want = 36
			}
			if len(rows) != want {
				t.Fatal("independent named half control/source/generation inventory changed", arch, len(rows), want)
			}
			x86NamedHalfGoPrior(t, arch, rows)
		})
	}
}

func x86NamedHalfInitialized(name, arch string, row x86NamedHalfCase, dead bool) (string, string) {
	word, move, push, pop := goWordSize(arch), "MOVQ", "PUSHFQ", "POPQ"
	if arch == "386" {
		move, push, pop = "MOVL", "PUSHFL", "POPL"
	}
	source, destination := row.registers()
	header := fmt.Sprintf("TEXT %s(SB),4,$0-%d\n%s out+0(FP),DI\n%s input+%d(FP),AX\n"+
		"%s old+%d(FP),BX\n%s environment+%d(FP),SI\nMOVL mask+%d(FP),CX\nKMOVW CX,K1\n",
		name, 4*word+4, move, move, word, move, 2*word, move, 3*word, 4*word)
	if row.narrow || !row.memory {
		header += fmt.Sprintf("VMOVUPS (AX),Z%d\n", source)
	}
	header += fmt.Sprintf("VMOVUPS (BX),Z%d\nLDMXCSR (SI)\nMOVL $3,DX\nCMPL DX,$1\nSTD\n", destination)
	tail := ""
	if !dead {
		tail = fmt.Sprintf("VMOVUPS Z%d,(DI)\n", destination)
	}
	return header + row.instruction() + "\n" + tail + push + "\n" + pop + " DX\n" +
			"ANDL $0xcd5,DX\nMOVL DX,64(DI)\nSTMXCSR 68(DI)\nCLD\nRET\n",
		fmt.Sprintf("func %s(out *[128]byte,input,old *[64]byte,environment *uint32,mask uint32)\n", name)
}

func x86NamedHalfRequireOriginalControl(t *testing.T, ir, name string, control int) {
	t.Helper()
	_, body, found := strings.Cut(ir, "define void @"+name+"(")
	body, _, ended := strings.Cut(body, "\n}")
	if !found || !ended {
		t.Fatal("missing actual named half function", name)
	}
	count := 0
	for _, line := range strings.Split(body, "\n") {
		if !x86ScalarPrecisionNativeEffectLine(line, "VCVTPS2PH") {
			continue
		}
		match := regexp.MustCompile(`\bvcvtps2ph \$\$(-?[0-9]+),`).FindStringSubmatch(line)
		if match == nil {
			t.Fatal("actual native half call lost its original immediate", name, line)
		}
		immediate, err := strconv.ParseInt(match[1], 10, 16)
		if err != nil || immediate < -128 || immediate > 255 || byte(immediate) != byte(control) {
			t.Fatal("native half changed its immediate/MXCSR.RC selection", name, control, match[1], err)
		}
		count++
	}
	if count != 1 {
		t.Fatal("actual half function lost its sole original conversion", name, count)
	}
}

func TestX86NamedHalfCompleteInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete initialized named half objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86NamedHalfCases(target.arch)
			x86NamedHalfGoPrior(t, target.arch, rows)
			var source, declarations strings.Builder
			functions := make(map[string][]string)
			for index, row := range rows {
				name := fmt.Sprint("NamedHalf", index)
				body, declaration := x86NamedHalfInitialized(name, target.arch, row, false)
				source.WriteString(body)
				declarations.WriteString(declaration)
				functions[name] = []string{row.operation()}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete initialized original named half family remains unclosed", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86ScalarPrecisionRequireNativeEffects(t, body, functions)
						for index, row := range rows {
							if row.narrow {
								x86NamedHalfRequireOriginalControl(t, body, fmt.Sprint("NamedHalf", index), row.immediate)
							}
						}
						compileLLVMToObject(t, llc, target.triple, "named-half.ll", "named-half.o", body)
					}
				})
			}
		})
	}
}

func TestX86NamedHalfCompleteTypedInputsOutputsAndFlags(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86NamedHalfCases(arch)
		x86NamedHalfGoPrior(t, arch, rows)
		for _, row := range rows {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof ||
					effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
					t.Fatal("named half conversion lost its complete typed inputs, result or flag preservation", effect, known, err)
				}
				reads, writes := make(map[int]bool), make(map[int]bool)
				source, last := 0, len(ins.Args)-1
				if row.narrow {
					source = 1
				}
				for _, operand := range effect.operands {
					if operand.index < 0 || operand.index > last || !reflect.DeepEqual(operand.operand, ins.Args[operand.index]) {
						t.Fatal("named half effect borrowed an unrelated operand", operand, ins)
					}
					reads[operand.index] = reads[operand.index] || operand.read
					writes[operand.index] = writes[operand.index] || operand.write
				}
				for index := range ins.Args {
					wantRead := index == source || row.mask != 0 && index == last-1 ||
						row.mask == 1 && index == last && !row.narrow ||
						row.mask == 1 && index == last && row.narrow && !row.memory
					if reads[index] != wantRead || writes[index] != (index == last) {
						t.Fatal("named half effect lost source, K, actual merging register or write role", index, reads, writes)
					}
				}
			})
		}
	}
}

func TestX86NamedHalfMinimumISAIsNotSuppliedByUnrelatedProducers(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86NamedHalfCases(arch) {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				profile := "," + inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}) + ","
				evex := row.width == 64 || row.mask != 0 || row.high || row.sae
				required := []string{"+avx", "+f16c"}
				if evex {
					required = []string{"+avx512f"}
					if row.width < 64 {
						required = append(required, "+avx512vl")
					}
				}
				for _, feature := range required {
					if !strings.Contains(profile, ","+feature+",") {
						t.Fatal("isolated named half lost its actual generation/ISA carrier", row.instruction(), feature, profile)
					}
				}
				for _, feature := range []string{"+avx512fp16", "+avx512bw", "+avx512dq"} {
					if strings.Contains(profile, ","+feature+",") {
						t.Fatal("named half borrowed a different conversion family's ISA", feature, profile)
					}
				}
				if !evex && strings.Contains(profile, "+avx512") {
					t.Fatal("ordinary F16C input unnecessarily requires AVX512", profile)
				}
			})
		}
	}
}

func TestX86NamedHalfEveryActiveByteMergeMaskAndUpperAlias(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86NamedHalfCases(arch)
		x86NamedHalfGoPrior(t, arch, rows)
		for _, row := range rows {
			if row.memory {
				continue
			}
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				for _, alias := range []bool{false, true} {
					ins := x86ScalarLaneInstruction(t, row.instruction())
					source, destination := row.registers()
					input, output, carrier := row.width/2, row.width, row.width
					if row.narrow {
						input, output, carrier = row.width, row.width/2, 16
						if row.width == 64 {
							carrier = 32
						}
					}
					if alias {
						source = destination
						index := 0
						if row.narrow {
							index = 1
						}
						ins.Args[index].Reg = Reg(fmt.Sprint(string(ins.Args[index].Reg)[0:1], source))
					}
					for _, missingRegister := range []int{source, destination} {
						for missing := -1; missing < 64; missing++ {
							state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
								masks: [8]bool{1: true}}
							state.pointerGP[3], state.callerAddressGP[6] = true, true
							state.writeVector(source, 64, ^uint64(0), true)
							state.writeVector(destination, 64, ^uint64(0), true)
							if missing >= 0 {
								state.writeVector(missingRegister, 64, ^(uint64(1) << uint(missing)), true)
							}
							before, want := state.clone(), state.clone()
							valid := state.vectorBytes(source)&x86CallerVectorByteMask(int64(input)) == x86CallerVectorByteMask(int64(input)) &&
								(row.mask != 1 || state.vectorBytes(destination)&x86CallerVectorByteMask(int64(output)) == x86CallerVectorByteMask(int64(output)))
							if valid {
								want.writeVector(destination, carrier, ^uint64(0), false)
							}
							accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
							if accepted != valid || !reflect.DeepEqual(state, want) {
								t.Fatal("named half active input/merge bytes or physical upper-zeroing differ", alias, missingRegister, missing, accepted, valid, before, state, want)
							}
						}
					}
					if row.mask != 0 {
						state := x86ResultState{}
						state.writeVector(source, 64, ^uint64(0), true)
						state.writeVector(destination, 64, ^uint64(0), true)
						before := state.clone()
						if x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
							t.Fatal("named half invented an unknown K mask")
						}
					}
				}
			})
		}
	}
}

func TestX86NamedHalfMissingInputsRemainContextIncludingVoid(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86NamedHalfCases(arch)
		x86NamedHalfGoPrior(t, arch, rows)
		for _, row := range rows {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				source := "TEXT Value(SB),4,$0-0\n" + row.instruction() + "\nRET\n"
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()\n", arch, x86AddressMemoryTargets(arch)[0], api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("unknown named half data/address/merge/mask borrowed Void permission", api, err)
					}
				}
			})
		}
	}
}

func TestX86NamedHalfMode32NamedGrammarAndHighBankRemainIndependent(t *testing.T) {
	var high []x86NamedHalfCase
	for _, row := range x86NamedHalfCases("amd64") {
		if row.high {
			high = append(high, row)
		}
	}
	var original strings.Builder
	for _, row := range high {
		original.WriteString(row.instruction() + "\n")
	}
	// The Go frontend accepts these high named rows in 386 mode. That is
	// not a physical register binding and must not grant numerical facts.
	x86LEAActualTargetGoObject(t, "386", "i386-unknown-linux-gnu",
		"TEXT High(SB),4,$0-0\n"+original.String()+"RET\n")
	for index, row := range high {
		t.Run(row.instruction(), func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.instruction())
			if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("high Go386 frontend spelling acquired a physical typed form", known, err)
			}
			source, declaration := x86NamedHalfInitialized(fmt.Sprint("High", index), "386", row, false)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "386", "i386-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("named high-bank source borrowed mode32 physical inputs", api, err)
				}
			}
		})
	}
	for _, row := range x86NamedHalfCases("amd64") {
		if !row.narrow || row.mask == 0 {
			continue
		}
		t.Run("four-operands/"+row.instruction(), func(t *testing.T) {
			source := "TEXT Four(SB),4,$0-0\n" + row.instruction() + "\nRET\n"
			requireLEANativeGoObject(t, "amd64", source, true)
			requireLEANativeGoObject(t, "386", source, false)
			ins := x86ScalarLaneInstruction(t, row.instruction())
			if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "386"); !known || err == nil {
				t.Fatal("named Go386 four-operand grammar borrowed a physical masked row", known, err)
			}
		})
	}
}

func TestX86NamedHalfDynamicMXCSRAndDeadEffectsKeepActualOpcode(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("dynamic MXCSR half conversion objects require LLVM22")
	}
	for _, arch := range []string{"amd64", "386"} {
		triple := x86AddressMemoryTargets(arch)[0]
		var source, declarations strings.Builder
		functions := make(map[string][]string)
		controls := make(map[string]int)
		for _, width := range []int{16, 32, 64} {
			for control := 4; control < 8; control++ {
				for _, dead := range []bool{false, true} {
					name := fmt.Sprintf("Dynamic%d_%d_%t", width, control, dead)
					body, declaration := x86NamedHalfInitialized(name, arch,
						x86NamedHalfCase{narrow: true, width: width, immediate: control}, dead)
					source.WriteString(body)
					declarations.WriteString(declaration)
					functions[name] = []string{"VCVTPS2PH"}
					controls[name] = control
				}
			}
			for mask := 0; mask < 3; mask++ {
				name := fmt.Sprintf("DeadRead%d_%d", width, mask)
				body, declaration := x86NamedHalfInitialized(name, arch,
					x86NamedHalfCase{width: width, memory: true, mask: mask}, true)
				source.WriteString(body)
				declarations.WriteString(declaration)
				functions[name] = []string{"VCVTPH2PS"}
			}
		}
		x86LEAActualTargetGoObject(t, arch, triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
				if err != nil {
					t.Fatal("initialized dynamic MXCSR or dead conversion remains unclosed", err)
				}
				for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					x86ScalarPrecisionRequireNativeEffects(t, body, functions)
					for name, control := range controls {
						x86NamedHalfRequireOriginalControl(t, body, name, control)
					}
					if strings.Contains(body, "fptrunc ") {
						t.Fatal("MXCSR.RC controls 4-7 were replaced by fixed LLVM rounding")
					}
					compileLLVMToObject(t, llc, triple, "half-dynamic-mxcsr.ll", "half-dynamic-mxcsr.o", body)
				}
			})
		}
	}
}
