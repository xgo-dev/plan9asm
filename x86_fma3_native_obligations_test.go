package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// This tests emission obligations separately from numerical initialization.
// Direct lowerer fragments are not public source, LLVM object, or native CPU
// execution certificates. Pure llvm.fma cannot preserve MXCSR, a dead native
// exception, an original masked access, or the exact source instruction.
func TestX86FMA3OriginalNativeFloatingObligations(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86FMA3NamedFormats(arch)
		for _, opcode := range append(go127FMA3PackedOps(), go127FMA3ScalarOps()...) {
			t.Run(arch+"/"+opcode, func(t *testing.T) {
				for _, row := range rows {
					if strings.Split(strings.Fields(row)[0], ".")[0] != opcode {
						continue
					}
					ins := x86ScalarLaneInstruction(t, row)
					original := ins
					var output strings.Builder
					ctx := newX86Ctx(&output, Func{}, FuncSig{Name: "FMA", Ret: Void}, nil, nil,
						arch, x86AddressMemoryTargets(arch)[0], false)
					if err := ctx.emitEntryAllocas(); err != nil {
						t.Fatal(err)
					}
					before := output.Len()
					recognized, terminated, err := ctx.lowerFMA3(ins.Op, ins)
					if !recognized || terminated || err != nil || !reflect.DeepEqual(ins, original) {
						t.Fatal("complete named FMA3 emitter changed source or rejected original format", row, err)
					}
					fragment := output.String()[before:]
					var native string
					for _, line := range strings.Split(fragment, "\n") {
						if strings.Contains(line, "asm sideeffect") && strings.Contains(line, strings.ToLower(opcode)+" ") {
							if native != "" {
								t.Fatal("FMA3 duplicated an original floating instruction", row)
							}
							native = line
						}
					}
					if native == "" || !strings.Contains(native, "~{fpsr}") || !strings.Contains(native, "~{memory}") ||
						strings.Contains(native, "~{flags}") || !strings.Contains(native, ",0,") {
						t.Fatalf("%s lost original opcode, tied old destination, MXCSR/access effects or preserved FLAGS: native=%q pure-fma=%t ignore-exceptions=%t",
							row, native, strings.Contains(fragment, "@llvm.fma."), strings.Contains(fragment, "fpexcept.ignore"))
					}
					if strings.Contains(fragment, "@llvm.fma.") || strings.Contains(fragment, "fpexcept.ignore") {
						t.Fatal("native FMA3 was replaced by pure or exception-ignoring numerical arithmetic", row)
					}
					width := map[byte]int{'X': 16, 'Y': 32, 'Z': 64}[ins.Args[len(ins.Args)-1].Reg[0]]
					scalar := strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD")
					bits := 32
					if strings.HasSuffix(opcode, "SD") || strings.HasSuffix(opcode, "PD") {
						bits = 64
					}
					if strings.Contains(row, "(AX)") {
						memory := width
						if scalar || strings.Contains(row, ".BCST") {
							memory = bits / 8
						}
						if !strings.Contains(native, fmt.Sprintf("elementtype([%d x i8])", memory)) ||
							!strings.Contains(native, ",*m") {
							t.Fatal("FMA3 lost its original native memory tuple", row, native)
						}
					}
					for _, control := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
						if strings.Contains(row, "."+control) &&
							!strings.Contains(native, "{"+strings.ToLower(strings.TrimSuffix(control, "_SAE"))+"-sae}") {
							t.Fatal("FMA3 dropped explicit original rounding/SAE control", row, native)
						}
					}
					if strings.Contains(row, ".Z ") && !strings.Contains(native, "{z}") ||
						strings.Contains(row, ".BCST") && !strings.Contains(native, fmt.Sprintf("{1to%d}", width*8/bits)) {
						t.Fatal("FMA3 dropped original masking or broadcast control", row, native)
					}
					features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}})
					evex := width == 64 || len(ins.Args) == 4 || strings.Contains(row, ".BCST") || strings.Contains(row, "_SAE")
					if evex {
						if !strings.Contains(features, "+avx512f") || !scalar && width < 64 && !strings.Contains(features, "+avx512vl") {
							t.Fatal("isolated original EVEX FMA3 borrowed another function's ISA", row, features)
						}
					} else if !strings.Contains(features, "+avx") || !strings.Contains(features, "+fma") {
						t.Fatal("isolated original VEX FMA3 lost AVX/FMA ISA", row, features)
					}
				}
			})
		}
	}
}
