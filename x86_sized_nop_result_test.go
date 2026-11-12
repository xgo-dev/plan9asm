package plan9asm

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86SizedNOPCompleteGoRowsAndInertState(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(string(data)), "")
	for _, row := range []string{
		"varydivl=[]ytab{{Zm_o,2,argList{Yml}},}",
		"{ANOPW,ydivl,Pe,opBytes{0x0f,0x1f,00}},",
		"{ANOPL,ydivl,Px,opBytes{0x0f,0x1f,00}},",
	} {
		if !strings.Contains(compact, row) {
			t.Fatal("complete sized-NOP Go row or opcode attributes changed", row)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"NOPW", "NOPL"} {
			code := assembleX87ControlBytes(t, arch, "TEXT f(SB),4,$0-0\n"+op+" AX\nRET\n")
			want := []byte{0x0f, 0x1f, 0xc0, 0xc3}
			if op == "NOPW" {
				want = append([]byte{0x66}, want...)
			}
			if !bytes.Equal(code, want) {
				t.Fatalf("original %s/%s bytes %x, want %x", arch, op, code, want)
			}
			operands := strings.Fields("AX CX DX BX SP BP SI DI")
			if arch == "amd64" {
				operands = append(operands, strings.Fields("R8 R9 R10 R11 R12 R13 R14 R15 g")...)
				operands = append(operands, "(g)", "(AX)(g*2)")
			}
			operands = append(operands, "(AX)", "4096(BP)", "(AX)(DX*8)", "external(SB)", "value+0(FP)")
			var original strings.Builder
			original.WriteString("TEXT f(SB),4,$0-0\n")
			for _, operand := range operands {
				original.WriteString(op + " " + operand + "\n")
			}
			original.WriteString("RET\n")
			goAssemblerOracleOutput(t, arch, original.String(), "", true)
			for _, operand := range operands {
				t.Run(arch+"/"+op+"/"+operand, func(t *testing.T) {
					instruction := x86ScalarLaneInstruction(t, op+" "+operand)
					effect, known, err := x86TypedGPByteEffect(instruction.Op, instruction, arch)
					if !known || err != nil || len(effect.operands) != 0 || effect.flagsRead != 0 ||
						effect.flagsDefined != 0 || effect.flagsKilled != 0 || effect.dynamicMemory || effect.requiresResultProof {
						t.Fatal("sized NOP lacks its complete no-read/no-write effect", known, effect, err)
					}
					if _, _, memory := x86InstructionMemoryShape(instruction, 0, arch); memory {
						t.Fatal("ignored ModRM operand invented a memory access")
					}
					predicate := x86ResultPredicate{kind: x86ResultComparisonBytes, register: 1, width: 16}
					if after := x86ResultPredicateAfter(instruction, predicate, arch); after != predicate {
						t.Fatal("inert instruction lost an unchanged source predicate")
					}
					for _, consumer := range x86ResultGPSIMDConsumers {
						for _, initialized := range []bool{false, true} {
							state := x86ResultState{fp: []bool{false, true}, direction: x86ResultDirectionBackward}
							if initialized {
								state.gp[0], state.xmm[0], state.vectorUpper[0] = 0x53, 0x5511, 0xaabbccdd00000000
								state.pointerGP[3], state.masks[1], state.flags = true, true, x86ByteFlagsAll
							}
							before := state.clone()
							if !consumer.step(instruction, &state, []bool{false, false}, 0, arch) || !reflect.DeepEqual(state, before) {
								t.Fatal("inert instruction consumed or manufactured state", consumer.name, initialized)
							}
						}
					}
				})
			}
		}
	}
}

func TestX86SizedNOPOriginalProgramPortableAndObjects(t *testing.T) {
	const owner = "TestAMD64SizedNOPRuntimePreservesState"
	source := x86X87FunctionLiteral(t, "amd64_lower_nop_width_test.go", owner, "source")
	driver := x86X87FunctionLiteral(t, "amd64_lower_nop_width_test.go", owner, "mainC")
	execution := x86ScalarCountHostExecution(t)
	const declaration = "func sizednopsemantics(out *byte)"
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-macosx", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
				if err != nil {
					t.Fatal("unchanged complete original sized-NOP source", api, err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, execution.llc, triple, text, level)
					}
				}
			}
		})
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("portable/"+api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					execution.compileAndRunLLVM(t, "original-sized-nop", text, driver, level)
				}
			}
		})
	}
	t.Log("unchanged original literals: Go/LLVM objects and actual-host portable state; not native x86 execution")
}
