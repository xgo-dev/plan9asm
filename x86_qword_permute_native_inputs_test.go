package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestX86QwordPermuteOriginalConformanceThreeAPIObjects(t *testing.T) {
	data, err := os.ReadFile("testdata/conformance/amd64/conformance_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []struct{ name, declaration string }{
		{"qwordPermuteSemantics", "func qwordPermuteSemantics(out *[8]uint64,data *[4]uint64)"},
		{"qwordVariablePermuteSemantics", "func qwordVariablePermuteSemantics(out *[8]uint64,data,control *[4]uint64)"},
	} {
		t.Run(member.name, func(t *testing.T) {
			start := strings.Index(string(data), "TEXT ·"+member.name+"(SB),")
			if start < 0 {
				t.Fatal("complete original qword-permute function missing")
			}
			end := strings.Index(string(data[start:]), "\n\tRET\n")
			if end < 0 {
				t.Fatal("complete original qword-permute return missing")
			}
			source := "#include \"textflag.h\"\n" + string(data[start:start+end+len("\n\tRET\n")])
			x86PackedFaultProgramObjects(t, source, member.declaration)
		})
	}
}

func (row x86QwordPermuteOracleRow) program(arch, name string, dead bool) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s data+%d(FP),BX\n",
		name, 2*word, move, move, word)
	for index := 0; index < 3; index++ {
		fmt.Fprintf(&source, "VPXORD Z%d,Z%d,Z%d\n", index, index, index)
	}
	if row.mode != "plain" {
		mask := -1
		if row.mode == "zero" {
			mask = 0
		}
		fmt.Fprintf(&source, "MOVL $%d,AX\nKMOVD AX,K1\n", mask)
	}
	source.WriteString("MOVL $5,DX\nCMPL DX,$3\n")
	source.WriteString(row.instruction() + "\n")
	if !dead {
		// All 64 bytes observe Y upper-zeroing as well as the actual output.
		source.WriteString("VMOVUPS Z2,(DI)\nSETCS 64(DI)\nSETOS 65(DI)\n")
	}
	source.WriteString("RET\n")
	return source.String(), fmt.Sprintf("func %s(out *[66]byte,data *[64]byte)\n", name)
}

func x86QwordPermuteRequireRead(t *testing.T, body string, bytes int) {
	t.Helper()
	pattern := fmt.Sprintf(`(?m)^\s+%%[^\n]+ = load volatile <%d x i8>, [^\n]*, align 1$`, bytes)
	if len(regexp.MustCompile(pattern).FindAllString(body, -1)) != 1 || strings.Count(body, "load volatile ") != 1 ||
		strings.Contains(body, "@llvm.masked.load") || strings.Contains(body, "br i1") {
		t.Fatal("E4NF native tuple was removable, narrowed or mask-dependent", bytes, body)
	}
}

// The complete 72/24 form witnesses are objects once per API/target, not the
// Cartesian product of selectors, missing bytes and backend objects.
func TestX86QwordPermuteInitializedFiveTargetObjectsAndExactReads(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86QwordPermuteOracleRows(target.arch)
			var source, declarations strings.Builder
			var names []string
			for index, row := range rows {
				name := fmt.Sprint("Permute", index)
				names = append(names, name)
				body, declaration := row.program(target.arch, name, false)
				source.WriteString(body)
				declarations.WriteString(declaration)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized qword-permute family rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					optimized := x86DwordProductIROptimize(t, ir)
					for index, row := range rows {
						if row.input == "register" {
							continue
						}
						bytes := row.width()
						if row.input == "broadcast" {
							bytes = 8
						}
						for _, input := range []string{ir, optimized} {
							x86QwordPermuteRequireRead(t, x86StringMemoryFunction(t, input, names[index]), bytes)
						}
					}
					for _, pipeline := range []struct{ ir, level string }{{ir, "-O0"}, {ir, "-O2"}, {optimized, "-O2"}} {
						x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.level)
					}
				})
			}
		})
	}
}

func TestX86QwordPermuteVoidDeadAndZeroMaskNeedActualInputs(t *testing.T) {
	for _, row := range x86QwordPermuteOracleRows("amd64") {
		if row.input == "register" || row.mode == "merge" {
			continue
		}
		for _, missing := range []string{"none", "pointer", "numeric-address", "index", "control", "mask"} {
			if missing == "control" && row.immediate || missing == "mask" && row.mode == "plain" {
				continue
			}
			source, declaration := row.program("amd64", "Value", true)
			switch missing {
			case "pointer":
				source = strings.Replace(source, "MOVQ data+8(FP),BX\n", "", 1)
			case "numeric-address":
				source = strings.Replace(source, "MOVQ data+8(FP),BX", "MOVQ $42,BX", 1)
			case "index":
				source = strings.Replace(source, "(BX)", "(BX)(SI*2)", 1)
			case "control":
				source = strings.Replace(source, "VPXORD Z1,Z1,Z1\n", "", 1)
			case "mask":
				source = strings.Replace(source, "KMOVD AX,K1\n", "", 1)
			}
			t.Run(row.instruction()+"/"+missing, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if missing == "none" {
						if err != nil || ir == "" {
							t.Fatal("dead initialized native read lacks its paired source", api, err)
						}
						bytes := row.width()
						if row.input == "broadcast" {
							bytes = 8
						}
						x86QwordPermuteRequireRead(t, x86StringMemoryFunction(t, ir, "Value"), bytes)
					} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("Void/zero mask invented a missing actual native address/control/mask", api, missing, err)
					}
				}
			})
		}
	}
}

func TestX86QwordPermuteRawOriginReplayAndMode32GrammarStaySeparate(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"VPERMQ", "VPERMPD"} {
			for _, bank := range []string{"Y", "Z"} {
				for _, immediate := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/immediate%t", arch, op, bank, immediate), func(t *testing.T) {
						row := x86QwordPermuteOracleRow{op, bank, "plain", "register", immediate}
						code, pcs := x86NumericalBoundaryGoBytes(t, arch, row.instruction()+"\nRET")
						if len(pcs) != 2 || pcs[1] != int64(len(code)-1) || code[len(code)-1] != 0xc3 {
							t.Fatal("actual original physical instruction/RET prior changed", code, pcs)
						}
						prefix := "TEXT ·Value(SB),4,$0-4\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"
						suffix := "MOVL X2,ret+0(FP)\nRET\n"
						namedSource := prefix + row.instruction() + "\n" + suffix
						strict, lowered := x86RegisterReplayConsumers(t, arch, namedSource)
						named := mustParseX86RawReturn(t, namedSource).Funcs[0]
						if strict(named) != nil || lowered(named) != nil || named.x86RawReplay != nil {
							t.Fatal("actual fully initialized named register source lost its existing numerical role")
						}
						file, err := normalizeX86RawFile(mustParseX86RawReturn(t, prefix+x86RawDisplacementDirectives(code[:pcs[1]])+suffix), arch)
						if err != nil {
							t.Fatal("complete actual raw source normalization failed", err)
						}
						original, ordinal := file.Funcs[0], -1
						for index, ins := range original.Instrs {
							if ins.Op == Op(op) && ins.x86SourceRaw != nil {
								ordinal = index
							}
						}
						if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil ||
							!errors.Is(lowered(original), ErrProbeNeedsContext) {
							t.Fatal("raw identity supplied an unowned initialized numerical entry")
						}
						changed := original
						changed.Instrs = cloneX86ReplayInstrs(original.Instrs)
						changed.Instrs[ordinal].x86SourceRaw = nil
						if strict(changed) != nil || !errors.Is(lowered(changed), ErrProbeNeedsContext) || original.x86RawReplay.validate(original, arch) != nil {
							t.Fatal("erasing an origin bypassed the immutable complete producer or altered its original")
						}
					})
				}
			}
		}
	}
	for _, op := range []string{"VPERMQ", "VPERMPD"} {
		for _, operands := range []string{"$216,Y0,K1,Y2", "Y0,Y1,K1,Y2", "$216,Z0,K1,Z2", "Z0,Z1,K1,Z2"} {
			source := "TEXT physical(SB),4,$0-0\n" + op + ".Z " + operands + "\nRET\n"
			code := assembleX87ControlBytes(t, "amd64", source)
			decoded, length, recognized, err := decodedX86RawQwordPermuteInstruction(code, 32)
			if !recognized || err != nil || length != len(code)-1 || string(decoded.Op) != op+".Z" || len(decoded.Args) != 4 {
				t.Fatal("low-bank mode32 physical EVEX masked prior was lost", op, operands, code, decoded, err)
			}
			requireX86GoAssemblerResult(t, "386", source, false)
		}
	}
}

func TestX86QwordPermuteInvalidNamedFormsMatchActualGo(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"VPERMQ", "VPERMPD"} {
			for _, operands := range []string{
				"$-129,Y0,Y2", "$256,Y0,Y2", "$1.5,Y0,Y2", "$-1,Z0,Z2",
				"$0,X0,X2", "X0,X1,X2", "$0,Y0,Z2", "Y0,Z1,Z2", "Y0,(AX),Y2",
				"Y0,Y1,(AX)", "$0,Y0,K0,Y2", "Y0,Y1,K0,Y2",
			} {
				instruction := op + " " + operands
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					source := "TEXT ·Value(SB),4,$0-0\n" + instruction + "\nRET\n"
					requireX86GoAssemblerResult(t, arch, source, false)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", arch, x86AddressMemoryTargets(arch)[0], api)
						if err == nil || ir != "" {
							t.Fatal("Go-rejected named operand form acquired a public body", api, err)
						}
					}
				})
			}
			for _, instruction := range []string{
				op + ".Z $0,Y0,Y2", op + ".Z Y0,Y1,Y2", op + ".BCST $0,Y0,Y2",
				op + ".BCST Y0,Y1,Y2", op + ".SAE $0,Y0,Y2", op + ".RN_SAE Y0,Y1,Y2",
			} {
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					source := "TEXT ·Value(SB),4,$0-0\n" + instruction + "\nRET\n"
					requireX86GoAssemblerResult(t, arch, source, false)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", arch, x86AddressMemoryTargets(arch)[0], api)
						if err == nil || ir != "" {
							t.Fatal("reserved suffix acquired native or numerical permission", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86QwordPermuteUnboundFormatsRetainContextAndPhysicalObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT ·Format(SB),4,$0-0\n")
			for _, row := range x86QwordPermuteOracleRows(target.arch) {
				fmt.Fprintln(&source, row.instruction())
			}
			source.WriteString("RET\n")
			file, signatures := x86UnboundVoidFormatSources(t, source.String(), target.arch, target.triple)
			ir := x86InstructionFormatObjectUnit(t, file, signatures, target.arch, target.triple, 0,
				func(c *amd64Ctx, ins Instr) (bool, bool, error) {
					return c.lowerQwordPermute(ins.Op, ins)
				})
			x86PackedStringCompileObject(t, llc, target.triple, ir, "-O0")
		})
	}
}
