package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86MandatoryDescriptorObligationIndependentOfResultLayout(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := []string{
			"BEXTRL BX,AX,CX", "BZHIL BX,AX,CX", "BLSIL BX,AX",
			"LAHF", "SAHF", "RDTSC", "RDTSCP", "CMPL AX,AX",
			"VPCOMPRESSB X0,X1", "VPEXPANDQ X0,X1",
		}
		for _, op := range []string{"CRC32B", "CRC32W", "CRC32L", "MULB", "MULW", "MULL", "IMULB", "IMULW", "IMULL"} {
			operand := "BX"
			if strings.HasPrefix(op, "CRC32") {
				operand += ",AX"
			}
			rows = append(rows, op+" "+operand)
		}
		if arch == "amd64" {
			rows = append(rows, "CRC32Q BX,AX", "MULQ BX", "IMULQ BX")
			for _, op := range x86ImmediateCompareResultMembers {
				rows = append(rows, op+" $0,Z0,Z1,K2")
			}
		}
		for _, row := range rows {
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof {
					t.Fatal("independent mandatory descriptor witness changed", known, err)
				}
				fn := Func{Sym: "Value", Instrs: []Instr{ins}}
				for _, result := range []LLVMType{Void, I32} {
					if !x86TypedFPResultNeedsProof(fn, FuncSig{Name: "Value", Ret: result}, arch) {
						t.Fatal("mandatory descriptor bypassed by Void or missing result layout", result)
					}
				}
			})
		}
	}
}

func TestX86MandatoryRawDescriptorCannotBypassResultLayout(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		// These decoded forms retain actual registered mandatory descriptors.
		// Raw CRC/MUL have distinct unregistered physical roles; their named
		// descriptors cannot serve as a witness for this metadata contract.
		for _, row := range []string{"LAHF", "SAHF", "CMOVLLE BX,AX"} {
			t.Run(arch+"/"+row, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+x86RawNumericalInstruction(t, arch, row)+"RET\n")
				if err != nil {
					t.Fatal(err)
				}
				file, err = normalizeX86RawFile(file, arch)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof || x86ResultNamedPredicateInstruction(ins) {
					t.Fatal("raw mandatory descriptor witness changed", known, err)
				}
				for _, result := range []LLVMType{Void, I32} {
					if !x86TypedFPResultNeedsProof(file.Funcs[0], FuncSig{Name: "Value", Ret: result}, arch) {
						t.Fatal("raw syntax bypassed a mandatory descriptor", result)
					}
				}
			})
		}
	}
}

func TestX86MandatoryCRCAndImplicitMultiplyVoidThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		var rows []string
		for _, suffix := range []string{"B", "W", "L", "Q"} {
			if target.arch == "386" && suffix == "Q" {
				continue // These three Q spellings have no Go mode32 row.
			}
			rows = append(rows, "CRC32"+suffix+" BX,AX", "MUL"+suffix+" BX", "IMUL"+suffix+" BX")
		}
		var original strings.Builder
		for index, row := range rows {
			for _, initialized := range []bool{false, true} {
				body := row + "\nRET\n"
				if initialized {
					body = "MOVL $3,AX\nMOVL $7,BX\n" + body
				}
				source := "TEXT Value(SB),4,$0-0\n" + body
				name := fmt.Sprintf("Value%d_%t", index, initialized)
				original.WriteString(strings.Replace(source, "Value(SB)", name+"(SB)", 1))
				t.Run(fmt.Sprintf("%s/%s/initialized-%t", target.triple, row, initialized), func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", target.arch, target.triple, api)
						if initialized {
							if err != nil || ir == "" {
								t.Fatal("initialized mandatory inputs rejected", api, err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("dead numerical output hid missing inputs", api, err)
						}
					}
				})
			}
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, original.String())
	}
}
