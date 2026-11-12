package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86SignExtendInitializedPrograms(arch string, batch int) (string, string, int) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations strings.Builder
	count := 0
	for _, ratio := range x86PackedSignExtendOracleRatios[batch*3 : (batch+1)*3] {
		for _, vector := range []bool{false, true} {
			for _, width := range []int{16, 32, 64} {
				if !vector && width != 16 {
					continue
				}
				bank, input := map[int]string{16: "X", 32: "Y", 64: "Z"}[width], "X"
				if width*ratio.input/ratio.output > 16 {
					input = "Y"
				}
				for _, memory := range []bool{false, true} {
					for _, mode := range []string{"plain", "merge", "zero"} {
						if !vector && mode != "plain" {
							continue
						}
						name, op := fmt.Sprint("Signed", count), "PMOVSX"+ratio.suffix
						if vector {
							op = "V" + op
						}
						first, mask := input+"0", ""
						if memory {
							first = "(BX)"
						}
						if mode != "plain" {
							mask = "K1,"
							if mode == "zero" {
								op += ".Z"
							}
						}
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s data+%d(FP),BX\n%s old+%d(FP),CX\nVMOVUPS (CX),Z1\n",
							name, 3*word, move, move, word, move, 2*word)
						if !memory {
							source.WriteString("VMOVUPS (BX),Z0\n")
						}
						// Both all-active and all-inactive constant masks still require
						// the typed mask/address contract, not zeroed implementation slots.
						value := -1
						if mode == "zero" {
							value = 0
						}
						fmt.Fprintf(&source, "MOVL $%d,DX\nKMOVD DX,K1\nMOVL $5,DX\nCMPL DX,$3\nSTD\n%s %s,%s%s1\nVMOVUPS Z1,(DI)\nSETCS 64(DI)\nSETOS 65(DI)\nCLD\nRET\n",
							value, op, first, mask, bank)
						fmt.Fprintf(&declarations, "func %s(out *[66]byte,data,old *[64]byte)\n", name)
						count++
					}
				}
			}
		}
	}
	return source.String(), declarations.String(), count
}

func TestX86PackedSignExtendInitializedFamilyFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for batch := 0; batch < 2; batch++ {
			t.Run(fmt.Sprintf("%s/batch%d", target.triple, batch), func(t *testing.T) {
				source, declarations, count := x86SignExtendInitializedPrograms(target.arch, batch)
				if count != 60 {
					t.Fatal("complete signed widening batch directory changed", count)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("complete initialized signed widening family rejected", err)
						}
						for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							x86PackedStringCompileObject(t, llc, target.triple, input, "-O0")
						}
					})
				}
			})
		}
	}
}

func TestX86PackedSignExtendMaskAndOwnedTupleBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, ratio := range x86PackedSignExtendOracleRatios {
			for _, width := range []int{16, 32, 64} {
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				for _, zero := range []bool{false, true} {
					op := "VPMOVSX" + ratio.suffix
					if zero {
						op += ".Z"
					}
					ins := x86ScalarLaneInstruction(t, op+" value+0(FP),K1,"+bank+"1")
					t.Run(arch+"/"+ins.Raw, func(t *testing.T) {
						for missing := -2; missing < 32; missing++ {
							state := x86FloatingHelperInitializedState()
							state.fp = make([]bool, 32)
							owned := make([]bool, 32)
							for at := range owned {
								owned[at], state.fp[at] = true, at != missing
							}
							if missing == -2 {
								state.masks[1] = false
							}
							before := state.clone()
							accepted := x86ScalarFPResultTransfer(ins, &state, owned, 32, arch)
							want := missing != -2 && (missing < 0 || missing >= width*ratio.input/ratio.output)
							if accepted != want || !accepted && !reflect.DeepEqual(state, before) ||
								accepted && state.vectorBytes(1) != ^uint64(0) {
								t.Fatal("a missing mask/actual tuple byte acquired a result or partly mutated state", missing, accepted, want)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86PackedSignExtendRawDoesNotBorrowZeroExtendOrErasedOrigin(t *testing.T) {
	var body strings.Builder
	var rows []string
	for _, ratio := range x86PackedSignExtendOracleRatios {
		for _, bank := range []string{"X", "Y", "Z"} {
			source := "X0"
			if bank == "Z" && ratio.output == 2*ratio.input {
				source = "Y0"
			}
			row := fmt.Sprintf("VPMOVSX%s %s,%s1", ratio.suffix, source, bank)
			rows = append(rows, row)
			fmt.Fprintln(&body, row)
		}
	}
	body.WriteString("RET")
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", body.String())
	if len(rows) != 18 || len(pcs) != 19 || pcs[18] != int64(len(code)-1) || code[len(code)-1] != 0xc3 {
		t.Fatal("complete independent original raw SX byte/PC directory changed", pcs)
	}
	for _, mode := range []int{32, 64} {
		x86NumericalNativeRequireMC(t, code[:pcs[18]], mode, 18, "+avx2,+avx512f,+avx512bw,+avx512vl")
	}
	for _, arch := range []string{"amd64", "386"} {
		var prior strings.Builder
		for index, row := range rows {
			prefix := "TEXT ·Value(SB),4,$0-4\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n"
			ending := "MOVL X1,ret+0(FP)\nRET\n"
			named := prefix + row + "\n" + ending
			raw := prefix + x86RawDisplacementDirectives(code[pcs[index]:pcs[index+1]]) + ending
			prior.WriteString(strings.Replace(named, "·Value", fmt.Sprint("·Named", index), 1))
			prior.WriteString(strings.Replace(raw, "·Value", fmt.Sprint("·Raw", index), 1))
		}
		x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], prior.String())
		for index, row := range rows {
			t.Run(arch+"/"+row, func(t *testing.T) {
				prefix := "TEXT ·Value(SB),4,$0-4\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n"
				ending := "MOVL X1,ret+0(FP)\nRET\n"
				named := prefix + row + "\n" + ending
				raw := prefix + x86RawDisplacementDirectives(code[pcs[index]:pcs[index+1]]) + ending
				check := x86LegacyFloatReplayCheck(t, arch, named, "func Value() uint32")
				if err := check(mustParseX86RawReturn(t, named).Funcs[0]); err != nil {
					t.Fatal("fully initialized genuine named SX control rejected", err)
				}
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, raw), arch)
				if err != nil || len(file.Funcs) != 1 {
					t.Fatal("independently accepted physical SX source failed to normalize", err)
				}
				original, ordinal := file.Funcs[0], -1
				for at, ins := range original.Instrs {
					if ins.x86SourceRaw != nil && strings.HasPrefix(string(ins.Op), "VPMOVSX") {
						ordinal = at
						if x86RawZeroExtendSource(ins, arch) {
							t.Fatal("raw SX silently acquired an existing ZX identity")
						}
					}
				}
				if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
					t.Fatal("original physical SX source lost its whole producer seal")
				}
				for _, erase := range []bool{false, true} {
					candidate := original
					candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
					if erase {
						candidate.Instrs[ordinal].x86SourceRaw = nil
					}
					if err := check(candidate); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("raw SX or an erased origin borrowed ordinary named/ZX numerical permission", erase, err)
					}
				}
			})
		}
	}
}
