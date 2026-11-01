package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86ScalarCompareNames(arch string) []string {
	var names []string
	for _, stem := range []string{"CMP", "TEST"} {
		for _, suffix := range []string{"B", "W", "L", "Q"} {
			if arch != "386" || suffix != "Q" {
				names = append(names, stem+suffix)
			}
		}
	}
	return names
}

func x86ScalarCompareInstruction(op, memory, other string) string {
	if strings.HasPrefix(op, "TEST") {
		return op + " " + other + "," + memory
	}
	return op + " " + memory + "," + other
}

func x86ScalarCompareResultSource(name, body string) string {
	// PEXTRD, unlike the older MOVL X0,AX compatibility path, actually invokes
	// the private scalar-result observer. Both branches initialize every byte.
	return fmt.Sprintf("TEXT ·%s(SB),4,$0-4\n%s\nJE equal\nMOVL $7,AX\nMOVL AX,X0\nJMP done\nequal:\nPXOR X0,X0\ndone:\nPEXTRD $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n", name, body)
}

func TestX86ScalarCompareSourceDataResultFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			source.WriteString("GLOBL external(SB),8,$16\n")
			for index, op := range x86ScalarCompareNames(target.arch) {
				name := fmt.Sprintf("compare%d", index)
				source.WriteString(x86ScalarCompareResultSource(name, x86ScalarCompareInstruction(op, "external+3(SB)", "$1")))
				fmt.Fprintf(&declarations, "func %s() uint32\n", name)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "compare.ll", "compare.o", ir)
				})
			}
		})
	}
}

func TestX86ScalarCompareUnboundExternalResultStaysContext(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range x86ScalarCompareNames(target.arch) {
			for _, offset := range []int{-7, 0, 3} {
				source := x86ScalarCompareResultSource("view", x86ScalarCompareInstruction(op, fmt.Sprintf("external%+d(SB)", offset), "$1"))
				for _, api := range []string{"text", "module", "Go"} {
					_, err := x86ScalarFPBitViewAPI(t, source, "var external [32]byte\nfunc view() uint32", target.arch, target.triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("external source-layout guard bypassed: %s/%s/%s/%d: %v", target.triple, api, op, offset, err)
					}
				}
			}
		}
	}
}

func x86ScalarComparePointerSource(arch, name, setup, compare, tail string) string {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	source := x86ScalarCompareResultSource(name, move+" p+0(FP),DX\n"+setup+compare+"\n"+tail)
	source = strings.Replace(source, "$0-4", fmt.Sprintf("$0-%d", word+4), 1)
	return strings.ReplaceAll(source, "ret+0(FP)", fmt.Sprintf("ret+%d(FP)", word))
}

func TestX86ScalarCompareIncomingPointerResultFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, op := range x86ScalarCompareNames(target.arch) {
				name := fmt.Sprintf("view%d", index)
				compare := x86ScalarCompareInstruction(op, "-7(DX)(CX*2)", "$1")
				source.WriteString(x86ScalarComparePointerSource(target.arch, name, "MOVL $4,CX\n", compare, ""))
				fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "compare-pointer.ll", "compare-pointer.o", ir)
				})
			}
		})
	}
}

func TestX86ScalarCompareIncomingPointerDoesNotGrantOtherEffects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move := "MOVQ"
		if target.arch == "386" {
			move = "MOVL"
		}
		for _, op := range x86ScalarCompareNames(target.arch) {
			for _, row := range []struct{ name, setup, address, partner, tail string }{
				{"unknown-index", "", "(DX)(CX*2)", "$1", ""},
				{"opaque-index", move + " p+0(FP),CX\n", "(DX)(CX*2)", "$1", ""},
				{"numeric-not-pointer", move + " $1234,DX\n", "(DX)", "$1", ""},
				{"unknown-numerical-input", "", "(DX)", "AX", ""},
				{"opaque-numerical-input", move + " p+0(FP),AX\n", "(DX)", "AX", ""},
				{"no-reusable-backing-credit", "", "(DX)", "$1", "MOVL (DX),DX\nMOVL (DX),AX\n"},
				{"no-write-data-credit", "", "(DX)", "$1", "MOVL BX,(DX)\n"},
				{"no-segment-credit", "", "(FS)", "$1", ""},
				{"unknown-segment-offset", "", "8(CX)(FS*2)", "$1", ""},
				{"opaque-segment-offset", move + " p+0(FP),CX\n", "8(CX)(FS*2)", "$1", ""},
			} {
				source := x86ScalarComparePointerSource(target.arch, "view", row.setup,
					x86ScalarCompareInstruction(op, row.address, row.partner), row.tail)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *byte) uint32", target.arch, target.triple, api)
					if row.name == "no-segment-credit" {
						// Keep the original tuple. Its absolute hardware base
						// needs no incoming GP numerical or pointer authority.
						if err != nil || !strings.Contains(ir, "ptr addrspace(257)") || !strings.Contains(ir, "load volatile") {
							t.Fatalf("original hardware-segment read was lost %s/%s/%s: %v", target.triple, op, api, err)
						}
						continue
					}
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("conditional read expanded authority %s/%s/%s/%s: %v", target.triple, op, row.name, api, err)
					}
				}
			}
			if strings.HasPrefix(op, "TEST") {
				source := x86ScalarComparePointerSource(target.arch, "view", "",
					x86ScalarCompareInstruction(op, "(DX)", "$1"), "LAHF\n")
				if _, err := x86ScalarFPBitViewAPI(t, source, "func view(p *byte) uint32", target.arch, target.triple, "text"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("TEST undefined AF became observable: %s/%s: %v", target.triple, op, err)
				}
			}
		}
	}
}

// The compare's continuation grants no credit to another read. Ordinary MOVL
// now has its own paired volatile load and numerical effect; both operations
// must survive even though the MOVL result is dead. Overwriting DX above still
// revokes the pointer before a later access.
func TestX86ScalarCompareAndMoveRetainIndependentNativeReads(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			names := x86ScalarCompareNames(target.arch)
			for index, op := range names {
				name := fmt.Sprintf("CompareMove%d", index)
				compare := x86ScalarCompareInstruction(op, "(DX)", "$1")
				source.WriteString(x86ScalarComparePointerSource(target.arch, name, "", compare, "MOVL (DX),AX\n"))
				fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("separately paired native reads rejected", api, err)
				}
				for level, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					if got := strings.Count(text, "load volatile"); got < 2*len(names) {
						t.Fatal("a native read borrowed earlier backing or was discarded", api, level, got)
					}
					x86ResultInitializationObject(t, llc, target.triple, text, fmt.Sprintf("compare-move-%s-O%d", api, level*2))
				}
			}
		})
	}
}
