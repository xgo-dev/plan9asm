package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86PackedConversionIndependentEveryByteEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, spec := range x86PackedConversionOracleSpecs() {
			for _, shape := range spec.shapes() {
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}
				for _, masking := range []string{"", "merge", "zero"} {
					if spec.legacy && masking != "" {
						continue
					}
					op, mask := spec.name, ""
					if masking != "" {
						mask = "K1,"
					}
					if masking == "zero" {
						op += ".Z"
					}
					ins := x86ScalarLaneInstruction(t, op+" "+bank[shape.source]+"0,"+mask+bank[shape.destination]+"1")
					f, known, err := x86PackedConversionProperties(ins, arch)
					if err != nil || !known || f.inputBytes != shape.lanes*spec.input/8 || f.shape.destinationBytes != shape.destination {
						t.Fatal(ins.Raw, f, err)
					}
					for missing := -1; missing < 64; missing++ {
						for _, missingDestination := range []bool{false, true} {
							state := x86ResultState{flags: x86ByteFlagsAll}
							state.masks[1] = true
							state.writeVector(0, 64, ^uint64(0), false)
							state.writeVector(1, 64, ^uint64(0), false)
							index := 0
							if missingDestination {
								index = 1
							}
							if missing >= 0 {
								state.writeVector(index, 64, ^(uint64(1) << uint(missing)), false)
							}
							want := missing < 0 || !missingDestination && missing >= shape.lanes*spec.input/8 ||
								missingDestination && (masking != "merge" || missing >= shape.lanes*spec.output/8)
							accepted, recognized := x86ResultPackedConversionStep(ins, &state, nil, arch)
							if !recognized || accepted != want {
								t.Fatal("required byte mismatch", ins.Raw, arch, missing, missingDestination, accepted, want)
							}
							if accepted {
								expected := ^uint64(0)
								if spec.legacy && missingDestination && missing >= 16 {
									expected &^= uint64(1) << uint(missing)
								}
								if state.vectorBytes(1) != expected || state.flags != x86ByteFlagsAll {
									t.Fatal("upper alias or integer FLAGS changed", ins.Raw, state.vectorBytes(1), expected)
								}
							}
						}
					}
					effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
					if err != nil || !known || effect.flagsRead != 0 || effect.flagsKilled != 0 || effect.flagsDefined != 0 {
						t.Fatal("typed family effect/FLAGS disagreement", ins.Raw, effect, err)
					}
					state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0)}, masks: map[Reg]bool{"K1": true}}
					if !x86CallerPackedConversionStep(&ins, f, &state, nil) {
						t.Fatal("initialized register grammar missing caller effect", ins.Raw)
					}
				}
			}
		}
	}
}

func TestX86PackedConversionResultAndStorageBoundaries(t *testing.T) {
	for _, spec := range x86PackedConversionOracleSpecs() {
		shape := spec.shapes()[0]
		bank := map[int]string{16: "X", 32: "Y", 64: "Z"}
		for _, initialized := range []bool{false, true} {
			setup := ""
			if initialized {
				setup = "XORPS X0,X0\n"
				if !spec.legacy {
					setup = "VPXORD Z0,Z0,Z0\n"
				}
			}
			assembly := fmt.Sprintf("TEXT ·f(SB),4,$0-4\n%s%s %s0,%s1\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n", setup, spec.name, bank[shape.source], bank[shape.destination])
			for _, api := range []string{"text", "module", "Go"} {
				_, err := x86ScalarFPBitViewAPI(t, assembly, "func f() uint32", "amd64", "x86_64-unknown-linux-gnu", api)
				if initialized && err != nil || !initialized && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("uninitialized conversion result boundary", spec.name, initialized, api, err)
				}
			}
		}
		for _, operand := range []string{"data+0(FP)", "local-16(SP)", "(SP)", "(BP)"} {
			assembly := "TEXT ·f(SB),4,$64-64\n" + spec.name + " " + operand + "," + bank[shape.destination] + "1\nRET\n"
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"f": {
				Name: "f", Ret: Void, Args: []LLVMType{I64, I64, I64, I64, I64, I64, I64, I64},
			}}})
			if err == nil {
				t.Fatal("logical slots acquired packed native backing", spec.name, operand)
			}
		}
	}
}

func TestX86PackedConversionPhysicalBroadcastTuple(t *testing.T) {
	for _, spec := range x86PackedConversionOracleSpecs() {
		if spec.legacy {
			continue
		}
		for _, shape := range spec.shapes() {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[shape.destination]
			row := spec.name + ".BCST (AX)," + bank + "1"
			x86UnboundVoidScalarFormatObject(t, "TEXT ·f(SB),4,$0-0\n"+row+"\nRET\n", "f", "amd64", "x86_64-unknown-linux-gnu")
			initialized := "TEXT ·f(SB),4,$0-8\nMOVQ p+0(FP),AX\n" + row + "\nRET\n"
			ir, err := x86ScalarFPBitViewAPI(t, initialized, "func f(p *byte)", "amd64", "x86_64-unknown-linux-gnu", "text")
			if err != nil {
				t.Fatal(row, err)
			}
			if !strings.Contains(ir, fmt.Sprintf("{1to%d}", shape.lanes)) || !strings.Contains(ir, fmt.Sprintf("elementtype([%d x i8])", spec.input/8)) {
				t.Fatal("physical broadcast confused carrier with active lanes", row, ir)
			}
		}
	}
}

func TestX86PackedConversionMalformedTypedGrammar(t *testing.T) {
	for _, spec := range x86PackedConversionOracleSpecs() {
		shape := spec.shapes()[0]
		bank := map[int]string{16: "X", 32: "Y", 64: "Z"}
		source, destination := bank[shape.source]+"0", bank[shape.destination]+"1"
		invalid := []string{
			spec.name + " " + source,
			spec.name + " $1," + destination,
			spec.name + " " + source + ",(AX)",
			spec.name + " " + source + ",K0," + destination,
			spec.name + " " + source + ",K8," + destination,
			spec.name + ".Z " + source + "," + destination,
			spec.name + ".BCST " + source + "," + destination,
			spec.name + ".RN_SAE (AX)," + destination,
			spec.name + ".SAE (AX)," + destination,
			spec.name + ".RN_SAE.SAE " + source + "," + destination,
			spec.name + " " + source + ",Y32",
		}
		if spec.legacy {
			invalid = append(invalid, spec.name+".BCST (AX),"+destination,
				spec.name+" "+source+",K1,"+destination)
		}
		for _, row := range invalid {
			ins := x86ScalarLaneInstruction(t, row)
			if _, known, err := x86PackedConversionProperties(ins, "amd64"); !known || err == nil {
				t.Fatal("malformed complete-family form accepted", row, err)
			}
		}
		for _, position := range []int{0, 1} {
			ins := x86ScalarLaneInstruction(t, spec.name+" "+source+","+destination)
			ins.Args[position].Reg = Reg(bank[amd64VectorByteWidth(ins.Args[position].Reg)] + "8")
			if _, known, err := x86PackedConversionProperties(ins, "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("mode32 invented physical vector register", ins, err)
			}
		}
	}
	context := &amd64Ctx{goarch: "amd64"}
	if known, _, err := context.lowerPackedNumericConversion("UNKNOWN", Instr{Op: "OTHER"}); known || err != nil {
		t.Fatal("conversion lowerer claimed another instruction family", known, err)
	}
	valid := x86ScalarLaneInstruction(t, "CVTPS2PL X0,X1")
	if known, _, err := context.lowerPackedNumericConversion("OTHER", valid); known || err != nil {
		t.Fatal("unknown dispatch claimed a packed source spelling", known, err)
	}
	if known, _, err := context.lowerPackedNumericConversion("CVTPS2PL", Instr{Op: "OTHER"}); !known || err == nil {
		t.Fatal("known dispatch lost its mismatched source identity", known, err)
	}
}

func TestX86PackedConversionCompleteCallerConsumer(t *testing.T) {
	var originals strings.Builder
	count := 0
	for _, spec := range x86PackedConversionOracleSpecs() {
		for _, shape := range spec.shapes() {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}
			row := spec.name + " " + bank[shape.source] + "0," + bank[shape.destination] + "1"
			body := "VMOVUPS (DI),Z0\n" + row + "\nVMOVSS X1,(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			originals.WriteString(strings.Replace(assembly, "TEXT ·kernel", fmt.Sprintf("TEXT ·kernel%d", count), 1))
			count++
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal("complete initialized conversion caller", row, err)
			}
			for _, operand := range []string{"(BX)", "(DX)", "(SP)", "(BP)", "a+0(FP)"} {
				body := spec.name + " " + operand + "," + bank[shape.destination] + "1\nVMOVSS X1,(DX)"
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
				pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
				if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("conversion acquired unproved address/envelope/backing", row, operand, err)
				}
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", originals.String(), "", true)
	t.Logf("%d complete caller shapes, five independent address/backing negatives each", count)
}

func TestX86PackedConversionWholeFileSyntaxBeforeContext(t *testing.T) {
	for _, context := range []struct{ name, arch, triple, instruction string }{
		{"target", "amd64", "", "CVTPS2PL X0,X1"},
		{"foreign target", "amd64", "aarch64-unknown-linux-gnu", "CVTPS2PL X0,X1"},
		{"physical MMX", "amd64", "x86_64-unknown-linux-gnu", "CVTPS2PL X0,M0"},
		{"physical mode32", "386", "i386-unknown-linux-gnu", "VCVTPS2DQ X8,X0"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			source := "TEXT ·f(SB),4,$0-0\n" + context.instruction + "\nRET\n"
			_, err := x86ScalarFPBitViewAPI(t, source, "func f()", context.arch, context.triple, api)
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("original physical/target boundary lost", context.name, api, err)
			}
			for _, malformed := range []string{"VCVTPS2DQ.Z X0,X1", "CVTPS2PL X0,(AX)"} {
				for _, suffix := range []struct{ assembly, declaration string }{
					{malformed + "\n", "func f()"},
					{"TEXT ·g(SB),4,$0-0\nRET\n" + malformed + "\n", "func f();func g()"},
				} {
					_, err := x86ScalarFPBitViewAPI(t, source+suffix.assembly, suffix.declaration, context.arch, context.triple, api)
					if err == nil || errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "packed numeric conversion grammar") {
						t.Fatal("earlier Context hid dead malformed source", context.name, api, malformed, err)
					}
				}
			}
		}
	}
}
