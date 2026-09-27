package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateAMD64SegmentMemory(t *testing.T) {
	src := `
TEXT loadGS(SB),NOSPLIT,$0-0
	MOVQ 0x30(GS), DI
	MOVQ DI, 0(CX)(GS)
	MOVQ -8(FS), AX
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "x86_64-pc-windows-msvc",
		Sigs: map[string]FuncSig{
			"loadGS": {Name: "loadGS", Ret: Void},
		},
		Goarch: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"load i64, ptr addrspace(256)",
		"store i64",
		"ptr addrspace(256)",
		"load i64, ptr addrspace(257)",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("segment-relative output missing %q:\n%s", want, ir)
		}
	}
	if strings.Contains(ir, "0x30(GS)") {
		t.Fatalf("segment-relative memory was emitted as a symbol:\n%s", ir)
	}
}

func TestAMD64SegmentMemoryRejectsInvalidUses(t *testing.T) {
	c, _ := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "segmentErrors", Ret: Void}, nil)
	if _, err := c.addrFromMem(MemRef{Segment: GS}); err == nil {
		t.Fatal("addrFromMem accepted a segment-relative address")
	}
	if _, _, err := c.ptrFromMem(MemRef{Segment: Reg("CS")}); err == nil {
		t.Fatal("ptrFromMem accepted an unsupported segment")
	}
	if ok, _, err := c.lowerMov(OpMOVQ, Instr{Args: []Operand{
		{Kind: OpMem, Mem: MemRef{Segment: Reg("CS")}},
		{Kind: OpReg, Reg: AX},
	}}); !ok || err == nil {
		t.Fatalf("lowerMov(invalid segment) = (%v, %v), want handled error", ok, err)
	}
}
