package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestTranslateAMD64SegmentMemory(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	src := `
TEXT ·loadGS(SB),4,$0-0
	MOVQ 0x30(GS), DI
	MOVQ DI, 0(CX)(GS)
	MOVQ -8(FS), AX
	RET
`
	triple := "x86_64-pc-windows-msvc"
	x86LEAActualTargetGoObject(t, "amd64", triple, src)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, src, "func loadGS()", "amd64", triple, api)
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" ||
				!strings.Contains(err.Error(), "unclosed source effect at instruction 1: MOVQ DI, 0(CX)(GS)") {
				t.Fatal("complete original source lost its unbound native-store boundary", err)
			}
		})
	}
	// This independent read-only counterpart removes exactly the unbound
	// store. The complete original above remains a Go-format-positive,
	// translation-Context control, not a successful native-write fixture.
	store := "\tMOVQ DI, 0(CX)(GS)\n"
	if strings.Count(src, store) != 1 {
		t.Fatal("original full segment fixture changed its single native store")
	}
	readOnly := strings.Replace(src, store, "", 1)
	if strings.Count(readOnly, "MOVQ") != 2 || strings.Count(readOnly, "TEXT ") != 1 {
		t.Fatal("read-only counterpart lost an original segment read or TEXT")
	}
	x86LEAActualTargetGoObject(t, "amd64", triple, readOnly)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("read-only/"+api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, readOnly, "func loadGS()", "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("independent read-only segment counterpart was rejected", err)
			}
			for _, irLevel := range []string{"0", "2"} {
				output := ir
				if irLevel == "2" {
					output = x86DwordProductIROptimize(t, ir)
				}
				for _, want := range []string{
					"load volatile i64, ptr addrspace(256)",
					"load volatile i64, ptr addrspace(257)",
				} {
					if strings.Count(output, want) != 1 {
						t.Fatalf("segment-relative output missing %q:\n%s", want, output)
					}
				}
				if strings.Count(output, "load volatile ") != 2 {
					t.Fatal("dead-result segment reads were duplicated or eliminated", output)
				}
				for _, line := range strings.Split(output, "\n") {
					if strings.Contains(line, "store ") && strings.Contains(line, "ptr addrspace(") {
						t.Fatal("read-only counterpart acquired a native segment store", line)
					}
				}
				if strings.Contains(output, "0x30(GS)") {
					t.Fatalf("segment-relative memory was emitted as a symbol:\n%s", output)
				}
				for _, backendLevel := range []string{"0", "2"} {
					t.Run("IR"+irLevel+"/backend"+backendLevel, func(t *testing.T) {
						x86PackedStringCompileObject(t, llc, triple, output, "-O"+backendLevel)
					})
				}
			}
		})
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
