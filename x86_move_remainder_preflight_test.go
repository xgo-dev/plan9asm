package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// One initialized source per member is a producer/API preflight, not the101
// source-row ownership proof. It deliberately leaves selection, late EVEX,
// masks, store directions and386 high-bank/context classification to the
// complete original-row owner after the existing-helper baseline is observed.
func TestX86MoveRemainderExistingProducersThreeAPIsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			cases := []struct{ instruction, observation string }{
				{"VLDDQU (AX),X1", "VMOVD X1,CX"},
				{"VMASKMOVPD (AX),X0,X1", "VMOVD X1,CX"},
				{"VMASKMOVPS (AX),X0,X1", "VMOVD X1,CX"},
				{"VMOVD X1,BX", "MOVL BX,CX"},
				{"VMOVHLPS X0,X1,X2", "PEXTRD $0,X2,CX"},
				{"VMOVHPD (AX),X1,X2", "PEXTRD $2,X2,CX"},
				{"VMOVHPS (AX),X1,X2", "PEXTRD $2,X2,CX"},
				{"VMOVLHPS X0,X1,X2", "PEXTRD $2,X2,CX"},
				{"VMOVLPD (AX),X1,X2", "PEXTRD $0,X2,CX"},
				{"VMOVLPS (AX),X1,X2", "PEXTRD $0,X2,CX"},
				{"VMOVMSKPD X1,BX", "MOVL BX,CX"},
				{"VMOVMSKPS X1,BX", "MOVL BX,CX"},
				{"VMOVNTDQ X1,(AX)", "VMOVD X1,CX"},
				{"VMOVNTDQA (AX),X1", "VMOVD X1,CX"},
				{"VMOVNTPD X1,(AX)", "VMOVD X1,CX"},
				{"VMOVNTPS X1,(AX)", "VMOVD X1,CX"},
				{"VMOVQ X1,BX", "MOVL BX,CX"},
				{"VMOVSD X0,X1,X2", "PEXTRD $2,X2,CX"},
				{"VMOVSS X0,X1,X2", "PEXTRD $1,X2,CX"},
				{"VPMASKMOVD (AX),X0,X1", "VMOVD X1,CX"},
				{"VPMASKMOVQ (AX),X0,X1", "VMOVD X1,CX"},
				{"VPMOVMSKB X1,BX", "MOVL BX,CX"},
			}
			var programs []struct{ opcode, name, source, declaration string }
			members := map[string]bool{}
			for index, row := range cases {
				opcode := strings.Fields(row.instruction)[0]
				if members[opcode] {
					t.Fatal("duplicated preflight member", opcode)
				}
				members[opcode] = true
				name := fmt.Sprint("MovePreflight", index)
				// Existing initialized native/vector producer. Initialized full
				// aliases include every scalar upper/old-low and half base input.
				initialization := "VMOVUPS (AX),Z0\nVMOVUPS (AX),Z1\nVMOVUPS (AX),Z2\n"
				body, declaration := x86PackedMoveInitializedInstruction(name, arch, initialization, row.instruction, row.observation)
				programs = append(programs, struct{ opcode, name, source, declaration string }{opcode, name, body, declaration})
			}
			// Reuse the existing implicit-DI producer rather than treating an
			// absent explicit destination as FLAGS or inventing a memory tuple.
			name := "MovePreflightImplicit"
			body, declaration := x86ImplicitMaskMoveOracleProgram(arch, "VMASKMOVDQU", name)
			programs = append(programs, struct{ opcode, name, source, declaration string }{"VMASKMOVDQU", name, body, declaration})
			members["VMASKMOVDQU"] = true
			if len(members) != 23 || len(programs) != 23 {
				t.Fatal("incomplete producer/member directory", len(members), len(programs))
			}
			for _, program := range programs {
				t.Run(program.opcode, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, arch, triple, program.source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, program.source, program.declaration, arch, triple, api)
							if err != nil || ir == "" {
								t.Fatal("initialized original member source rejected", err)
							}
							x86CompactExpandRequireAllDefinitions(t, ir, []string{program.name})
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, triple, ir, level)
							}
						})
					}
				})
			}
		})
	}
	t.Log("member preflight only: original Go source+threeAPI backend O0/O2; no101-row selection, minimum-ISA, new raw, numeric or native-runtime claim")
}
