package plan9asm

import (
	"strings"
	"testing"
)

func TestARM64SharedVectorHelperCaseIdentity(t *testing.T) {
	for _, line := range []string{"VMOV ZR,V0.B16", "VDUP ZR,V0.B16", "VSHL $1,V0.S4,V0.S4", "VSSHR $1,V0.S4,V0.S4"} {
		file, err := Parse(ArchARM64, "TEXT identity(SB),$0-0\n"+line+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		instruction := file.Funcs[0].Instrs[1]
		for _, identity := range []string{strings.ToLower(string(instruction.Op)), "", "VEOR"} {
			t.Run(line+"/"+identity, func(t *testing.T) {
				context, output := newARM64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Name: "identity", Ret: Void}, nil)
				changed := instruction
				changed.Op = Op(identity)
				before := output.Len()
				handled, _, err := context.lowerVec(instruction.Op, false, changed)
				if identity == strings.ToLower(string(instruction.Op)) {
					if !handled || err != nil {
						t.Fatalf("historical case-insensitive helper dispatch rejected: handled=%t err=%v", handled, err)
					}
				} else if !handled || err == nil || output.Len() != before {
					t.Fatalf("empty/contradictory identity emitted before rejection: handled=%t err=%v bytes=%d", handled, err, output.Len()-before)
				}
			})
		}
	}
}
