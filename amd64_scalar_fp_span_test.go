package plan9asm

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestX86ScalarFPBitViewsEveryLogicalByteAndBoundary(t *testing.T) {
	for _, bits := range []int{32, 64} {
		for missing := -1; missing < bits/8; missing++ {
			var slots []FrameSlot
			for offset := 0; offset < bits/8; offset++ {
				if offset != missing {
					slots = append(slots, FrameSlot{Offset: int64(offset), Type: I8, Index: offset, Field: -1})
				}
			}
			for _, masked := range []bool{false, true} {
				for _, write := range []bool{false, true} {
					t.Run(fmt.Sprintf("%d/missing%d/mask%t/write%t", bits, missing, masked, write), func(t *testing.T) {
						var ir strings.Builder
						ctx := newAMD64Ctx(&ir, Func{}, FuncSig{Frame: FrameLayout{Params: slots}}, nil, nil, false)
						if _, err := ctx.scalarFPSpan(0, bits); (err == nil) != (missing == -1) {
							t.Fatalf("byte span result: %v", err)
						}
						if missing == -1 {
							return // Positive actual loads/stores are covered by objects and runtime.
						}
						var err error
						operand := Operand{Kind: OpFP}
						if write {
							mask := ""
							if masked {
								mask = "0"
							}
							err = ctx.storeVectorScalarMemory(operand, bits, "1", mask)
						} else if masked {
							_, err = ctx.loadX86ScalarMemoryIf(operand, bits, "false")
						} else {
							_, err = ctx.loadScalarFPBits(0, bits)
						}
						if !errors.Is(err, ErrProbeNeedsContext) || ir.Len() != 0 {
							t.Fatalf("missing byte granted scalar access/IR: %v\n%s", err, ir.String())
						}
					})
				}
			}
		}
	}
	for name, slots := range map[string][]FrameSlot{
		"pointer":  {{Type: Ptr, Field: -1}},
		"bool":     {{Type: I1, Field: -1}, {Offset: 1, Type: I32, Index: 1, Field: -1}},
		"overlap":  {{Type: I64, Field: -1}, {Offset: 2, Type: I32, Index: 1, Field: -1}},
		"overflow": {{Offset: math.MaxInt64 - 1, Type: I64, Field: -1}},
		"negative": {{Offset: -1, Type: I64, Field: -1}},
	} {
		t.Run(name, func(t *testing.T) {
			var ir strings.Builder
			ctx := newAMD64Ctx(&ir, Func{}, FuncSig{Frame: FrameLayout{Params: slots}}, nil, nil, false)
			if _, err := ctx.loadScalarFPBits(0, 32); !errors.Is(err, ErrProbeNeedsContext) || ir.Len() != 0 {
				t.Fatalf("unbound layout accepted: %v\n%s", err, ir.String())
			}
		})
	}
}

func TestX86ScalarFPBitViewsResultReadsNeedAllPathInitialization(t *testing.T) {
	for name, body := range map[string]string{
		"entry read":        "MOVSS ret+8(FP),X0\nMOVSS X0,ret+8(FP)",
		"partial source":    "MOVB $1,AX\nMOVL AX,ret+8(FP)\nMOVSS ret+8(FP),X0\nMOVSS X0,ret+8(FP)",
		"partial result":    "MOVW $1,ret+8(FP)\nMOVSS ret+8(FP),X0\nMOVSS X0,ret+8(FP)",
		"missing branch":    "MOVL $1,AX\nCMPL AX,$0\nJE joined\nMOVL $1,ret+8(FP)\njoined:\nMOVSS ret+8(FP),X0\nMOVSS X0,ret+8(FP)",
		"unknown call":      "MOVL $1,ret+8(FP)\nCALL ·other(SB)\nMOVSS ret+8(FP),X0\nMOVSS X0,ret+8(FP)",
		"loop entry read":   "MOVL $1,AX\nloop:\nMOVSS ret+8(FP),X0\nMOVSS X0,ret+8(FP)\nSUBL $1,AX\nJNE loop",
		"undefined mask":    "MOVL $1,ret+8(FP)\nVMOVSS ret+8(FP),K1,X0\nMOVSS X0,ret+8(FP)",
		"masked only write": "MOVL $0,AX\nKMOVD AX,K1\nMOVSS x+0(FP),X0\nVMOVSS X0,K1,ret+8(FP)",
	} {
		for _, target := range x86RawReturnTargets {
			t.Run(name+"/"+target.triple, func(t *testing.T) {
				source := "TEXT ·view(SB),4,$0-12\n" + body + "\nRET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(x uint64) uint32", target.arch, target.triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("%s undefined result became numeric: %v\n%s", api, err, ir)
					}
				}
			})
		}
	}
}

func TestX86ScalarFPBitViewsReadonlyCallerBoundariesRemainContext(t *testing.T) {
	for _, body := range []string{
		"MOVSS (DI),X0\nMOVSS X0,(DI)",
		"VMOVSD (SI),X0\nVMOVSD X0,(SI)",
		"MOVL $0,AX\nKMOVD AX,K1\nVMOVSS.Z (BX),K1,X0\nVMOVSS X0,(DX)",
		"MOVSS (SP),X0\nMOVSS X0,(DX)",
	} {
		t.Run(body, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", assembly)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("readonly/unknown backing acquired permission: %v", err)
			}
		})
	}
}

func TestX86ScalarFPBitViewsPrivateInitializationDoesNotExpandAsmDecl(t *testing.T) {
	fixture := x86ScalarFPBitFixture{
		name: "private-mask", declaration: "func view(x,y uint64) uint64\n",
		body: "MOVSD x+0(FP),X0\nMOVSD X0,ret+16(FP)\nMOVSS y+8(FP),X1\n" +
			"MOVL $1,AX\nKMOVD AX,K1\nVMOVSS X1,K1,ret+18(FP)", args: 24,
	}
	source := x86ScalarFPBitAssembly(t, fixture, "amd64")
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "bitview", "package bitview\n"+fixture.declaration)
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	signatures, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	function := file.Funcs[0]
	sig := signatures[resolve(function.Sym)]
	if err := checkX86ScalarFPResultInitialization(function, sig, "amd64"); err != nil {
		t.Fatalf("private numerical-byte query: %v", err)
	}
	if err := CheckX86ABI0ResultInitialization(function, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("private mask transfer expanded public asmdecl authority: %v", err)
	}
}
