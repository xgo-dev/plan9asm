package plan9asm

import "testing"

func TestARM64StackMemoryScalableExtent(t *testing.T) {
	for _, test := range []struct {
		op, source string
		low, high  int64
	}{
		{"PLDR", "-VL*256", -65536, 0},
		{"ZLDR", "VL*255", 0, 65280},
		{"ZST4D", "-VL*2", -512, 0},
		{"PPRFB", "VL*1", 0, 256},
	} {
		low, high, width, err := arm64StackMemoryExtent(Instr{Op: Op(test.op)}, MemRef{Base: SP, OffRaw: test.source})
		if err != nil || low != test.low || high != test.high || width != 1024 {
			t.Fatalf("%s %s: got [%d,%d]+%d, %v", test.op, test.source, low, high, width, err)
		}
	}
	for _, source := range []string{"unknown_offset", "VL*8192", "-VL*8192"} {
		if _, _, _, err := arm64StackMemoryExtent(Instr{Op: "ZLDR"}, MemRef{Base: "RSP", OffRaw: source}); err == nil {
			t.Fatalf("accepted unresolved or excessive displacement %s", source)
		}
	}
}

func TestARM64StackWritebackZeroRegisterProof(t *testing.T) {
	for _, test := range []struct {
		name, prefix string
		failure      bool
	}{
		{"zero-entry", "", false},
		{"written-index", "MOVD $16,R7\n", true},
		{"call-clobber", "BL callee(SB)\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, "TEXT zero_writeback(SB),$0-0\n"+test.prefix+"VST1.P [V0.B16],(RSP)(R7)\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ctx := &arm64Ctx{blocks: arm64SplitBlocks(file.Funcs[0])}
			_, _, err = ctx.stackMovementRange()
			if (err != nil) != test.failure {
				t.Fatalf("error=%v; want failure=%v", err, test.failure)
			}
		})
	}
}
