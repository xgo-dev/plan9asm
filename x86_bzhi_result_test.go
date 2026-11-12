package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86BZHICompleteGoRowsAndPhysicalInputs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(string(data)), "")
	for _, row := range []string{
		"var_ybextrl=[]ytab{{zcase:Zvex_v_rm_r,zoffset:2,args:argList{Yrl,Yml,Yrl}},}",
		"{as:ABZHIL,ytab:_ybextrl,prefix:Pavx,op:opBytes{avxEscape|vex128|vex0F38|vexW0,0xF5,}},",
		"{as:ABZHIQ,ytab:_ybextrl,prefix:Pavx,op:opBytes{avxEscape|vex128|vex0F38|vexW1,0xF5,}},",
	} {
		if !strings.Contains(compact, row) {
			t.Fatal("complete original BZHI row or opcode attributes changed", row)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"BZHIL", "BZHIQ"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				code := assembleX87ControlBytes(t, arch, "TEXT f(SB),4,$0-0\n"+op+" AX,BX,CX\nRET\n")
				want := []byte{0xc4, 0xe2, 0x78, 0xf5, 0xcb, 0xc3}
				if op == "BZHIQ" {
					want[2] = 0xf8
				}
				if !bytes.Equal(code, want) {
					t.Fatalf("original %s/%s bytes %x, want %x", arch, op, code, want)
				}
				ins := x86ScalarLaneInstruction(t, op+" AX,(BX),CX")
				width := int64(4)
				if arch == "amd64" && op == "BZHIQ" {
					width = 8
				}
				effect, known, err := x86TypedGPByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 3 {
					t.Fatal("complete BZHI family has no typed input/result contract", known, err)
				}
				for index, operand := range effect.operands {
					bytes := width
					if index == 0 {
						bytes = 1 // The ISA consumes only the index's low byte.
					}
					if operand.index != index || !reflect.DeepEqual(operand.operand, ins.Args[index]) ||
						operand.width != bytes || operand.read != (index < 2) || operand.write != (index == 2) {
						t.Fatal("BZHI physical source/control/write dependency changed", operand)
					}
					got, write, valid := x86InstructionMemoryShape(ins, index, arch)
					if valid != (index == 1) || valid && (got != width || write) {
						t.Fatal("BZHI source tuple disagrees with physical operand size", index, got, write, valid)
					}
				}
				if effect.flagsRead != 0 || effect.flagsDefined != x86ByteFlagCF|x86ByteFlagOF|x86ByteFlagZF|x86ByteFlagSF ||
					effect.flagsKilled != x86ByteFlagsAll || effect.dynamicMemory || !effect.requiresResultProof {
					t.Fatal("BZHI invented defined/preserved status or waived source inputs", effect)
				}
			})
		}
	}
}

func TestX86BZHICompleteInitializedSourceObjects(t *testing.T) {
	x86BitFieldInitializedSourceObjects(t, []string{"BZHIL", "BZHIQ"}, "byte", "MOVB")
}

func TestX86BZHIVoidAndUnusedBoolCannotInventInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"BZHIL", "BZHIQ"} {
			for _, unused := range []bool{false, true} {
				declaration, extent := "func Value()", 0
				if unused {
					declaration, extent = "func Value(unused bool)", 1
				}
				prefixes := map[string]string{
					"initialized": "MOVB $4,AL\nMOVL $7,BX\n",
					"no-index":    "MOVL $7,BX\n",
					"high-only":   "MOVB $4,AH\nMOVL $7,BX\n",
					"no-source":   "MOVB $4,AL\n",
				}
				for name, prefix := range prefixes {
					t.Run(fmt.Sprintf("%s/%s/bool%t/%s", target.triple, op, unused, name), func(t *testing.T) {
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s%s AX,BX,CX\nRET\n", extent, prefix, op)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if name == "initialized" {
								if err != nil || ir == "" {
									t.Error("initialized low-byte BZHI control rejected", api, err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Error("Void or unused bool manufactured BZHI inputs", api, err)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86BZHIOriginalProgramPortableAndObjects(t *testing.T) {
	const owner = "TestAMD64BZHIRuntimeSemanticsAndFlags"
	source := x86X87FunctionLiteral(t, "amd64_lower_bzhi_test.go", owner, "source")
	driver := x86X87FunctionLiteral(t, "amd64_lower_bzhi_test.go", owner, "mainC")
	execution := x86ScalarCountHostExecution(t)
	const declaration = "func bzhisemantics(out *byte)"
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-macosx", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
				if err != nil {
					t.Fatal("unchanged complete original BZHI source", api, err)
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
					execution.compileAndRunLLVM(t, "original-bzhi", text, driver, level)
				}
			}
		})
	}
	t.Log("unchanged original literals: Go and three-target LLVM objects plus actual-host portable values/FLAGS; not native x86 execution")
}
