package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86IntegerFPByteRoleCase struct {
	name, declaration, body string
	args                    int
}

func x86IntegerFPByteRoleCases(word int) []x86IntegerFPByteRoleCase {
	return []x86IntegerFPByteRoleCase{
		{"undefined-wide-source", "func Value() (uint8,uint8)", "MOVW AX,ret+0(FP)\nRET", 2},
		{"undefined-neighbor-read", "func Value() (uint8,uint8,uint16)", "MOVB $1,ret+0(FP)\nMOVW ret+0(FP),AX\nMOVW AX,ret+2(FP)\nRET", 4},
		{"result-padding", "func Value() (uint8,uint32)", "MOVL $1,AX\nMOVL AX,ret+0(FP)\nMOVL AX,ret+4(FP)\nRET", 8},
		{"noncanonical-bool", "func Value() (bool,uint8)", "MOVW $0x0202,AX\nMOVW AX,ret+0(FP)\nRET", 2},
		{"parameter-write", "func Value(x uint16) uint16", fmt.Sprintf("MOVB $1,x+1(FP)\nMOVW $1,ret+%d(FP)\nRET", word), word + 2},
		{"partial-pointer-read", "func Value(p *uint64) uint16", fmt.Sprintf("MOVW p+1(FP),AX\nMOVW AX,ret+%d(FP)\nRET", word), word + 2},
		{"partial-pointer-write", "func Value() *uint64", "MOVW $1,ret+0(FP)\nRET", word},
		{"unknown-interior-read", "func Value() (uint32,uint32)", "MOVL $1,ret+0(FP)\nMOVL ret+6(FP),AX\nMOVL AX,ret+4(FP)\nRET", 8},
		{"unknown-cfg-source", "func Value(x uint32) (uint8,uint8)", fmt.Sprintf("MOVL x+0(FP),AX\nCMPL AX,$0\nJE bad\nMOVW $0x0201,BX\nJMP join\nbad:\nNOP\njoin:\nMOVW BX,ret+%d(FP)\nRET", word), word + 2},
	}
}

const x86IntegerFPByteStatusSource = "TEXT ·Value(SB),4,$0-5\nCLD\nMOVL $0,AX\nCMPL AX,$0\nMOVL $0x04030201,BX\nMOVL BX,ret+0(FP)\nMOVW ret+1(FP),CX\nSETEQ DX\nMOVB DX,ret+4(FP)\nRET\n"

func TestX86IntegerFPByteViewsKeepIndependentRoles(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range x86IntegerFPByteRoleCases(word) {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\n", row.args, row.body)
					ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, target.arch, target.triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("new byte view borrowed an independent role: output=%t, error=%v", ir != "", err)
					}
				})
			}
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/natural-pointer/"+api, func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\n%s AX,ret+%d(FP)\nRET\n", 2*word, move, move, word)
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *uint64) *uint64", target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatalf("exact natural pointer transfer changed: %v", err)
				}
			})
		}
	}
}

func TestX86IntegerFPByteViewsMode32QwordKeepsVectorConsumer(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue
		}
		for _, alias := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
			for _, api := range []string{"text", "module", "Go"} {
				for _, gp := range []struct{ role, source string }{{"store", "MOVL $1,AX\n" + alias + " AX,ret+0(FP)"}, {"load", alias + " ret+0(FP),AX\nMOVL AX,ret+0(FP)\nMOVL AX,ret+4(FP)"}} {
					t.Run(target.triple+"/"+alias+"/GP/"+api+"/"+gp.role, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·Value(SB),4,$0-8\n"+gp.source+"\nRET\n", "func Value() uint64", target.arch, target.triple, api)
						if err == nil || ir != "" {
							t.Fatalf("mode32 GP qword borrowed X/m64: output=%t, error=%v", ir != "", err)
						}
					})
				}
				t.Run(target.triple+"/"+alias+"/X/"+api, func(t *testing.T) {
					source := "TEXT ·Value(SB),4,$0-8\nPXOR X0,X0\n" + alias + " X0,ret+0(FP)\n" + alias + " ret+0(FP),X1\n" + alias + " X1,ret+0(FP)\nRET\n"
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint64", target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatalf("legal mode32 X/m64 route changed: %v", err)
					}
				})
			}
		}
	}
	ctx := newX86Ctx(&strings.Builder{}, Func{}, FuncSig{}, nil, nil, "386", "", false)
	ctx.fpResults = []FrameSlot{{Offset: 0, Type: I64}}
	for _, write := range []bool{false, true} {
		if handled, err := ctx.integerFPByteView(0, 8, write); !handled || !errors.Is(err, ErrProbeNeedsContext) || ctx.fpScalarChecked {
			t.Fatalf("descriptor admitted mode32 GP qword: handled=%t, error=%v", handled, err)
		}
	}
}

func TestX86IntegerFPByteViewsPreserveStatusAndDirection(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, x86IntegerFPByteStatusSource, "func Value() (uint8,uint8,uint8,uint8,bool)", target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal(err)
				}
				x86ScalarFPTupleSpanConstantResult(t, ir, []uint64{1, 2, 3, 4, 1})
			})
		}
	}
}

func TestX86IntegerFPByteViewsDescriptorCannotCreateStorage(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			name string
			off  int64
			slot FrameSlot
		}{
			{"pointer", 0, FrameSlot{Offset: 0, Type: Ptr}},
			{"padding", 2, FrameSlot{Offset: 0, Type: I8}},
			{"unsupported-type", 0, FrameSlot{Offset: 0, Type: "{ i8, i8 }"}},
			{"negative-offset", -1, FrameSlot{Offset: 0, Type: I32}},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				ctx := newX86Ctx(&strings.Builder{}, Func{}, FuncSig{}, nil, nil, arch, "", false)
				ctx.fpResults = []FrameSlot{row.slot}
				handled, err := ctx.integerFPByteView(row.off, 2, false)
				if !handled || !errors.Is(err, ErrProbeNeedsContext) || ctx.fpScalarChecked {
					t.Fatalf("layout created a source/storage proof: handled=%t, checked=%t, error=%v", handled, ctx.fpScalarChecked, err)
				}
			})
		}
		t.Run(arch+"/physical-bool-needs-role", func(t *testing.T) {
			ctx := newX86Ctx(&strings.Builder{}, Func{}, FuncSig{}, nil, nil, arch, "", false)
			ctx.fpResults = []FrameSlot{{Offset: 0, Type: I1}}
			ctx.classicFrame = "%unbound_frame"
			if err := ctx.storeFPVectorBytesMode(0, 1, "zeroinitializer", "", true); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("byte engine acquired physical bool storage without canonical proof: %v", err)
			}
		})
	}
}
