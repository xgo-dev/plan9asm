package exclusive

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func TestReservationControlFlow(t *testing.T) {
	for _, tc := range []struct {
		name, body   string
		wide, reject bool
	}{
		{"legacyGoarm", "LDREX (R1),R0\nCMP R0,R2\nBNE fail\nMOVB runtime·goarm(SB),R8\nCMP $7,R8\nBLT 2(PC)\nDMB MB_ISHST\nSTREX R3,(R1),R0\nfail:", false, false},
		{"straight", "LDREX (R1),R2\nSTREX R3,(R1),R0", false, false},
		{"releaseThenAtomic", "LDAXR (R1),R2\nSTLR R2,(R4)\nSTLXR R3,(R1),R0", true, false},
		{"conditionalStore", "LDREX (R1),R2\nSTREX.NE R3,(R1),R0", false, true},
		{"indirectBR", "LDAXR (R1),R2\nBR R6\nCLREX\nSTLXR R3,(R1),R0", true, true},
		{"indirectBX", "LDREX (R1),R2\nBX R6\nRET\nSTREX R3,(R1),R0", false, true},
		{"sameStoreSources", "LDXP (R0),(R1,R2)\nSTXP (R1,R1),(R0),R3", true, false},
		{"sameLoadDestinations", "LDXP (R0),(R1,R1)\nSTXP (R1,R2),(R0),R3", true, true},
		{"jumpAcrossReturn", "LDREX (R1),R2\nB elsewhere\nRET\nelsewhere:\nSTREX R3,(R1),R0", false, true},
		{"jumpPastClear", "LDAXR (R1),R2\nCBZ R2,attempt\nSTLR R2,(R4)\nattempt:\nSTLXR R3,(R1),R0", true, true},
		{"missedReload", "LDREX (R1),R2\nBNE attempt\nLDREX (R5),R2\nattempt:\nSTREX R3,(R1),R0", false, true},
		{"jumpIntoPair", "B 2(PC)\nLDREX (R1),R2\nSTREX R3,(R1),R0", false, true},
		{"wrongISA64", "LDREX (R1),R2\nSTREX R3,(R1),R0", true, true},
		{"wrongISA32", "LDAXR (R1),R2\nSTLXR R3,(R1),R0", false, true},
	} {
		arch := asm.ArchARM
		if tc.wide {
			arch = asm.ArchARM64
		}
		f, err := asm.Parse(arch, "TEXT f(SB),NOSPLIT,$0-0\n"+tc.body+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = Rewrite(f.Funcs[0], tc.wide, false)
		if tc.reject != (err != nil) {
			t.Errorf("%s: error = %v", tc.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "exclusive") {
			t.Fatal(err)
		}
	}
}
