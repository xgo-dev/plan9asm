package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarFPBitViewsNewParameterReadsRequireWholeSourceFacts(t *testing.T) {
	for _, fixture := range []x86ScalarFPBitFixture{
		{name: "integer-low", declaration: "func view(x uint64) float32\n", body: "MOVSS x+0(FP),X1\nVMOVSS X1,X1,K1,X0\nMOVSS X0,ret+8(FP)"},
		{name: "integer-suboffset", declaration: "func view(x uint64) float32\n", body: "MOVSS x+2(FP),X1\nVMOVSS X1,X1,K1,X0\nMOVSS X0,ret+8(FP)"},
		{name: "cross-fields", declaration: "func view(a,b uint32) float64\n", body: "MOVSD a+0(FP),X1\nVMOVSD X1,X1,K1,X0\nMOVSD X0,ret+8(FP)"},
		{name: "mixed-fields", declaration: "func view(a float32,b uint32) float64\n", body: "MOVSD a+0(FP),X1\nVMOVSD X1,X1,K1,X0\nMOVSD X0,ret+8(FP)"},
		{name: "unknown-low", declaration: "func view(x uint64) float64\n", body: "MOVSS x+0(FP),X1\nVMOVSD X7,X1,X0\nMOVSD X0,ret+8(FP)"},
		{name: "branch-only-low", declaration: "func view(x uint64) float32\n", body: "MOVSS x+0(FP),X1\nMOVL $1,AX\nCMPL AX,$0\nJE joined\nMOVSS X1,X7\njoined:\nVMOVSS X7,X1,X0\nMOVSS X0,ret+8(FP)"},
	} {
		// Go's four-operand masked register rows are AMD64-only. Keep
		// their original mode32 rejection separate from numerical Context.
		reject386 := fixture.name != "unknown-low" && fixture.name != "branch-only-low"
		x86ScalarFPViewContextFixture(t, fixture, reject386)
	}
}

func TestX86ScalarFPBitViewsActualHighBankNumericalFacts(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, bits := range []int{32, 64} {
		move := "MOVSS"
		if bits == 64 {
			move = "MOVSD"
		}
		for index := 16; index < 32; index++ {
			fixture := x86ScalarFPBitFixture{
				name:        fmt.Sprintf("%d/X%d", bits, index),
				declaration: fmt.Sprintf("func view(x uint64) uint%d\n", bits),
				body:        fmt.Sprintf("MOVL $1,AX\nKMOVD AX,K1\nV%s.Z x+0(FP),K1,X%d\nV%s X%d,ret+8(FP)", move, index, move, index),
			}
			for _, target := range x86RawReturnTargets {
				t.Run(fixture.name+"/"+target.triple, func(t *testing.T) {
					source := x86ScalarFPBitAssembly(t, fixture, target.arch)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, fixture.declaration, target.arch, target.triple, api)
						if target.arch == "386" {
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Errorf("%s mode32 high spelling acquired a physical bank: %v\n%s", api, err, ir)
							}
							continue
						}
						if err != nil {
							t.Errorf("%s actual AMD64 EVEX bank lacks numerical facts: %v", api, err)
							continue
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, level)
						}
					}
				})
			}
		}
	}
}

func TestX86ScalarFPBitViewsHighBankFactsIntersectAllPaths(t *testing.T) {
	for _, fixture := range []x86ScalarFPBitFixture{
		{name: "unknown-high-mask", declaration: "func view(x uint64) uint64\n", body: "VMOVSD.Z x+0(FP),K1,X31\nVMOVSD X31,ret+8(FP)"},
		{name: "unknown-high-merge", declaration: "func view(x uint64) uint64\n", body: "MOVL $0,AX\nKMOVD AX,K1\nVMOVSD x+0(FP),K1,X31\nVMOVSD X31,ret+8(FP)"},
		{name: "partial-high", declaration: "func view(x uint64) uint64\n", body: "MOVSS x+0(FP),X1\nVMOVSS X1,X31,X31\nVMOVSD X31,ret+8(FP)"},
		{name: "branch-only-high", declaration: "func view(x uint64) uint64\n", body: "MOVL $1,AX\nKMOVD AX,K1\nCMPL AX,$0\nJE joined\nVMOVSD.Z x+0(FP),K1,X31\njoined:\nVMOVSD X31,ret+8(FP)"},
		{name: "unknown-upper-fullX", declaration: "func view(x uint64) uint32\n", body: "MOVSS x+0(FP),X1\nVMOVSS X1,X31,X31\nVADDPS X31,X31,X31\nVMOVSS X31,ret+8(FP)"},
	} {
		x86ScalarFPInitializationContextFixture(t, fixture)
	}
	left, right := x86ResultState{}, x86ResultState{}
	for index := range left.xmm {
		left.xmm[index], right.xmm[index] = 0xffff, 0xffff
	}
	for missing := 0; missing < 16; missing++ {
		right.xmm[31] = 0xffff &^ (uint16(1) << uint(missing))
		merged := left.intersect(right)
		if merged.xmm[31] != right.xmm[31] || left.xmm[31] != 0xffff {
			t.Fatalf("high-bank byte %d did not intersect independently", missing)
		}
		merged.xmm[31] = 0
		if right.xmm[31] == 0 || left.xmm[31] != 0xffff {
			t.Fatal("mutating merged state changed a predecessor")
		}
	}
}

func TestX86ScalarFPBitViewsNewReadHelperRequiresSourceBeforeIR(t *testing.T) {
	var output strings.Builder
	ctx := newAMD64Ctx(&output, Func{}, FuncSig{
		Args: []LLVMType{I64}, Ret: LLVMType("float"),
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: LLVMType("float"), Index: 0, Field: -1}},
		},
	}, nil, nil, false)
	if _, err := ctx.loadScalarFPBits(0, 32); !errors.Is(err, ErrProbeNeedsContext) || output.Len() != 0 {
		t.Fatalf("new parameter byte view manufactured source evidence: %v\n%s", err, output.String())
	}
}

func TestX86ScalarFPBitViewsTypedFloatingEffectsNeedAllInputs(t *testing.T) {
	for _, operation := range []string{"ADD", "SUB", "MUL", "DIV"} {
		for _, bits := range []int{32, 64} {
			move, suffix, packed := "MOVSS", "SS", "PS"
			if bits == 64 {
				move, suffix, packed = "MOVSD", "SD", "PD"
			}
			prefix := fmt.Sprintf("%s x+0(FP),X0\n", move)
			for name, body := range map[string]string{
				"undefined-low":   prefix + operation + suffix + " X7,X0",
				"undefined-fullX": prefix + "V" + operation + packed + " X7,X0,X0",
				"unknown-mask":    prefix + "V" + operation + suffix + " X0,X0,K1,X0",
				"branch-only":     prefix + "MOVL $1,AX\nCMPL AX,$0\nJE joined\n" + move + " x+0(FP),X7\njoined:\n" + operation + suffix + " X7,X0",
			} {
				fixture := x86ScalarFPBitFixture{
					name:        fmt.Sprintf("%s%d/%s", operation, bits, name),
					declaration: fmt.Sprintf("func view(x uint64) uint%d\n", bits),
					body:        body + fmt.Sprintf("\n%s X0,ret+8(FP)", move),
				}
				x86ScalarFPViewContextFixture(t, fixture, name == "unknown-mask")
			}
			// The new numeric view supplies no missing byte, even to a zero
			// mask or a scalar broadcast. This independent declaration leaves
			// a real alignment hole before the uint64 field.
			fixture := x86ScalarFPBitFixture{
				name:        fmt.Sprintf("%s%d/memory-hole", operation, bits),
				declaration: fmt.Sprintf("func view(a byte,x uint64) uint%d\n", bits),
				body:        fmt.Sprintf("%s x+8(FP),X0\nV%s%s.BCST a+0(FP),X0,X0\n%s X0,ret+16(FP)", move, operation, packed, move),
			}
			x86ScalarFPInitializationContextFixture(t, fixture)
		}
	}
}

func x86ScalarFPViewContextFixture(t *testing.T, fixture x86ScalarFPBitFixture, actualGoRejectsMode32 bool) {
	t.Helper()
	for _, target := range x86RawReturnTargets {
		t.Run(fixture.name+"/"+target.triple, func(t *testing.T) {
			source := x86ScalarFPBitAssembly(t, fixture, target.arch)
			if actualGoRejectsMode32 && target.arch == "386" {
				goAssemblerOracleOutput(t, target.arch, source, "", false)
			} else {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, fixture.declaration, target.arch, target.triple, api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Errorf("%s source lacks whole numerical facts: %v\n%s", api, err, ir)
				}
			}
		})
	}
}

func TestX86ScalarFPBitViewsTypedFloatingControlsKeepPublicQueryClosed(t *testing.T) {
	for _, fixture := range x86FloatBinaryFPFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, fixture.assembly)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkX86ScalarFPResultInitialization(file.Funcs[0], fixture.sig, "amd64"); err != nil {
				t.Errorf("existing complete numeric byte-field consumer: %v", err)
			}
			if err := checkX86ABI0ResultInitialization(file.Funcs[0], fixture.sig, "amd64", x86ResultTransfer, false); !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("private numerical facts widened public asmdecl query: %v", err)
			}
		})
	}
	// Y/Z effects are not represented by this X-byte proof. Do not truncate
	// their required source width into a known low-X witness.
	for _, bank := range []string{"Y", "Z"} {
		fixture := x86ScalarFPBitFixture{
			name:        bank + "-unmodeled-wide",
			declaration: "func view(x uint64) uint32\n",
			body:        "MOVSS x+0(FP),X0\nVADDPS " + bank + "0," + bank + "0," + bank + "0\nMOVSS X0,ret+8(FP)",
		}
		x86ScalarFPInitializationContextFixture(t, fixture)
	}
}
