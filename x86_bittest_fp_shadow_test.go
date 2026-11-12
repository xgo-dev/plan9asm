package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

// These literal names and widths are independent of the production descriptor.
// Go's two complete ybtl rows are Yi8/Yml and Yrl/Yml; only the former has a
// fixed logical FP envelope. A register-indexed native bit string is separate.
type x86BitTestFPShadowCase struct {
	name  string
	width int
}

func x86BitTestFPShadowNames(arch string) []x86BitTestFPShadowCase {
	rows := []x86BitTestFPShadowCase{
		{"BTW", 2}, {"BTL", 4}, {"BTCW", 2}, {"BTCL", 4},
		{"BTRW", 2}, {"BTRL", 4}, {"BTSW", 2}, {"BTSL", 4},
	}
	if arch == "amd64" {
		rows = append(rows, x86BitTestFPShadowCase{"BTQ", 8}, x86BitTestFPShadowCase{"BTCQ", 8},
			x86BitTestFPShadowCase{"BTRQ", 8}, x86BitTestFPShadowCase{"BTSQ", 8})
	}
	return rows
}

func x86BitTestFPShadowReturn(arch string) string {
	if arch == "386" {
		return "MOVL x+0(FP),AX\nMOVL AX,ret+8(FP)\nMOVL x+4(FP),DX\nMOVL DX,ret+12(FP)\nRET\n"
	}
	return "MOVQ x+0(FP),AX\nMOVQ AX,ret+8(FP)\nRET\n"
}

func TestX86BitTestLogicalFPParameterShadowThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		count := 0
		for _, row := range x86BitTestFPShadowNames(target.arch) {
			for offset := 0; offset+row.width <= 8; offset++ {
				count++
				source := fmt.Sprintf("TEXT ·value(SB),4,$0-16\n%s $-1,x+%d(FP)\n%s", row.name, offset, x86BitTestFPShadowReturn(target.arch))
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/offset%d/%s", target.triple, row.name, offset, api), func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func value(x uint64) uint64", target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("existing exact BIT logical parameter shadow cannot return its complete value", err)
						}
					})
				}
			}
		}
		want := 52
		if target.arch == "386" {
			want = 48
		}
		if count != want {
			t.Fatalf("complete independent bit-test/offset denominator changed: %d want %d", count, want)
		}
	}
}

func TestX86BitTestLogicalFPShadowDoesNotGrantOtherStores(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct{ name, declaration, body string }{
			{"ordinary-partial-MOV", "func value(x uint64) uint64", "MOVB $17,x+0(FP)"},
			{"pointer", "func value(x *uint64) uint64", "BTCW $0,x+0(FP)"},
			{"bool", "func value(x bool,y byte) uint64", "BTCW $0,x+0(FP)"},
			{"padding", "func value(x byte,y uint64) uint64", "BTCW $0,x+0(FP)"},
			{"register-index", "func value(x uint64) uint64", "MOVL $0,CX\nBTCW CX,x+0(FP)"},
			{"uninitialized-result", "func value(x uint64) uint64", "BTCW $0,ret+8(FP)"},
			{"unknown-native", "func value(x uint64) uint64", "BTCW $0,(AX)"},
			{"SP-native", "func value(x uint64) uint64", "BTCW $0,(SP)"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					pkg := mustGoPackage(t, "bitshadow", "package bitshadow\n"+row.declaration+"\n")
					sig, err := DeriveGoFuncABI0Signature("value", pkg.Types.Scope().Lookup("value").(*types.Func), arch, types.SizesFor("gc", arch))
					if err != nil {
						t.Fatal(err)
					}
					result := sig.Frame.Results[0].Offset
					stores := fmt.Sprintf("MOVL $1,ret+%d(FP)\nMOVL $0,ret+%d(FP)\n", result, result+4)
					source := fmt.Sprintf("TEXT ·value(SB),4,$0-%d\n%s\n%sRET\n", result+8, row.body, stores)
					ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, arch, testTargetTriple("linux", arch), api)
					if err == nil || ir != "" {
						t.Fatalf("BIT shadow supplied unrelated input/native permission: %v, IR bytes=%d", err, len(ir))
					}
				})
			}
		}
		// A public declaration query has no paired logical-field write consumer.
		pkg := mustGoPackage(t, "bitdecl", "package bitdecl\nfunc value(x uint64) uint64\n")
		sig, err := DeriveGoFuncABI0Signature("value", pkg.Types.Scope().Lookup("value").(*types.Func), arch, types.SizesFor("gc", arch))
		if err != nil {
			t.Fatal(err)
		}
		file, err := Parse(ArchAMD64, "TEXT value(SB),4,$0-16\nBTCW $-1,x+0(FP)\n"+x86BitTestFPShadowReturn(arch))
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("public declaration query borrowed the paired shadow writer", err)
		}
	}
}

func TestX86BitTestFPShadowOriginalCompleteGoObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			count := 0
			for _, row := range x86BitTestFPShadowNames(target.arch) {
				for offset := 0; offset+row.width <= 8; offset++ {
					fmt.Fprintf(&source, "TEXT ·bit%d(SB),4,$0-16\n%s $-1,x+%d(FP)\n%s", count, row.name, offset, x86BitTestFPShadowReturn(target.arch))
					count++
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			t.Logf("actual original Go object retains %d complete returning BIT-shadow TEXTs; not native execution", count)
		})
	}
}

func TestX86BitTestLogicalFPShadowExactByteEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		pkg := mustGoPackage(t, "bitbytes", "package bitbytes\nfunc value(x uint64) uint64\n")
		sig, err := DeriveGoFuncABI0Signature("value", pkg.Types.Scope().Lookup("value").(*types.Func), arch, types.SizesFor("gc", arch))
		if err != nil {
			t.Fatal(err)
		}
		context := amd64Ctx{sig: sig, fpResults: sig.Frame.Results, goarch: arch}
		for _, row := range x86BitTestFPShadowNames(arch) {
			for offset := 0; offset+row.width <= 8; offset++ {
				t.Run(fmt.Sprintf("%s/%s/%d", arch, row.name, offset), func(t *testing.T) {
					ins := x86PureGPUnknownInstruction(t, fmt.Sprintf("%s $-1,x+%d(FP)", row.name, offset))
					owned := make([]bool, 16)
					state := x86ResultState{fp: make([]bool, 16), flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
					for index := range owned {
						owned[index] = true
						state.fp[index] = index < 8
					}
					state.gp[0], state.pointerGP[1], state.callerAddressGP[1] = 0x35, true, true
					want := state.clone()
					want.flags = x86ByteFlagZF | x86ByteFlagCF
					if accepted, known := context.scalarBitTestFPShadowTransfer(ins, &state, owned, arch); !known || !accepted || !reflect.DeepEqual(state, want) {
						t.Fatal("BIT shadow changed unrelated bytes/FLAGS/DF or opaque identities", accepted, known)
					}
					for missing := offset; missing < offset+row.width; missing++ {
						bad := state.clone()
						bad.fp[missing] = false
						before := bad.clone()
						if accepted, known := context.scalarBitTestFPShadowTransfer(ins, &bad, owned, arch); !known || accepted || !reflect.DeepEqual(bad, before) {
							t.Fatal("BIT shadow manufactured an unread input byte or changed state on rejection", missing)
						}
					}
				})
			}
		}
	}
}
