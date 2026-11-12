package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86PointerBitTransportOriginalSDKStorepNoWB(t *testing.T) {
	directory := filepath.Join(runtime.GOROOT(), "src/internal/runtime/atomic")
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		directory = filepath.Join(runtime.GOROOT(), "src/runtime/internal/atomic")
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "atomic_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := os.ReadFile(filepath.Join(directory, "atomic_amd64.go"))
	if err != nil {
		t.Fatal(err)
	}
	declaration := regexp.MustCompile(`(?m)^func StorepNoWB\([^\n]+`).FindString(string(declarations))
	start := strings.Index(string(assembly), "TEXT ·StorepNoWB(SB)")
	if start < 0 || declaration == "" {
		t.Fatal("actual SDK lost its complete StorepNoWB declaration/source")
	}
	source := string(assembly[start:])
	if end := strings.Index(source, "\nTEXT "); end >= 0 {
		source = source[:end] + "\n"
	}
	pkg := importedGlobalPackage(t, "atomic", "amd64",
		[]string{"package atomic\nimport \"unsafe\"\n" + declaration + "\n"}, map[string]*types.Package{"unsafe": types.Unsafe})
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, "#include \"textflag.h\"\n"+source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, target.arch, target.triple, api)
				if err != nil {
					t.Error("unchanged SDK pointer bit transport rejected", api, err)
					continue
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, ir, level)
				}
			}
		})
	}
}

func TestX86PointerBitTransportExchangeDoesNotInventResultFacts(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, suffix := int64(8), "Q"
		if arch == "386" {
			word, suffix = 4, "L"
		}
		for _, operand := range []string{"AX,0(BX)", "0(BX),AX", "BX,0(BX)"} {
			t.Run(arch+"/"+operand, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, "XCHG"+suffix+" "+operand)
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				for _, register := range []Reg{AX, BX} {
					root, _, _ := x86ResultGP(register, word, arch)
					state.pointerGP[root], state.callerAddressGP[root], state.callerAddressOrigin[root] = true, true, 7
					state.canonicalGP[root] = 0x55
					state.resultAddressGP[root] = x86ResultSlotAddress{start: 0, end: word, valid: true}
				}
				form, err := parseAMD64ExchangeForm(arch, ins.Op, amd64ExchangeSpecs[ins.Op], ins)
				if err != nil {
					t.Fatal(err)
				}
				root, mask, _ := x86ResultGP(form.register.Reg, word, arch)
				before := state.clone()
				if accepted, known := x86LoweredExchangeResultStep(ins, &state, nil, arch); accepted || !known || !reflect.DeepEqual(state, before) {
					t.Fatal("unscoped query acquired actual caller pointer-data bits")
				}
				want := state.clone()
				want.gp[root] &^= mask
				want.canonicalGP[root] &^= mask
				if word == 4 {
					want.gp[root] |= 0xf0
				}
				want.pointerGP[root], want.callerAddressGP[root], want.callerAddressOrigin[root] = false, false, 0
				want.resultAddressGP[root] = x86ResultSlotAddress{}
				if accepted, known := x86LoweredExchangeResultStepWithAddressBits(ins, &state, nil, arch, true); !accepted || !known || !reflect.DeepEqual(state, want) {
					t.Fatal("unknown old native memory became NUM/pointer or changed unrelated FLAGS/DF/address roles")
				}
			})
		}
	}
}

func TestX86PointerBitTransportFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move, suffix := 8, "MOVQ", "Q"
			if target.arch == "386" {
				word, move, suffix = 4, "MOVL", "L"
			}
			var source, declarations strings.Builder
			for ordinal, body := range []string{move + " AX,0(BX)", "XCHG" + suffix + " AX,0(BX)",
				"XCHG" + suffix + " 0(BX),AX", move + " AX,DX\nXCHG" + suffix + " DX,0(BX)",
				"XCHG" + suffix + " BX,0(BX)", "LOCK\nCMPXCHG" + suffix + " CX,0(BX)"} {
				name := fmt.Sprintf("Transport%d", ordinal)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s ptr+0(FP),BX\n%s val+%d(FP),AX\n%s desired+%d(FP),CX\n%s\nRET\n",
					name, 3*word, move, move, word, move, 2*word, body)
				fmt.Fprintf(&declarations, "func %s(ptr **byte, val, desired *byte)\n", name)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("complete native pointer-data object batch", api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, ir, level)
				}
			}
		})
	}
}

func TestX86PointerBitTransportCompleteInputRoles(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move, suffix := 8, "MOVQ", "Q"
		if target.arch == "386" {
			word, move, suffix = 4, "MOVL", "L"
		}
		for _, row := range []struct {
			name, body, omit string
			accept           bool
		}{
			{"move", move + " AX,0(BX)", "", true},
			{"exchange", "XCHG" + suffix + " AX,0(BX)", "", true},
			{"reverse-exchange", "XCHG" + suffix + " 0(BX),AX", "", true},
			{"copied-exchange", move + " AX,DX\nXCHG" + suffix + " DX,0(BX)", "", true},
			{"address-value-alias", "XCHG" + suffix + " BX,0(BX)", "", true},
			{"equal-CAS", "LOCK\nCMPXCHG" + suffix + " CX,0(BX)", "", true},
			{"missing-value", "XCHG" + suffix + " AX,0(BX)", "value", false},
			{"missing-address", "XCHG" + suffix + " AX,0(BX)", "address", false},
			{"partial-value", "MOVB $1,AX\nXCHG" + suffix + " AX,0(BX)", "value", false},
			{"pointer-is-not-addend", "XADD" + suffix + " AX,0(BX)", "", false},
			{"pointer-is-not-byte", "XCHGB AX,0(BX)", "", false},
			{"pointer-is-not-word", "XCHGW AX,0(BX)", "", false},
			{"dword-data-role", "XCHGL AX,0(BX)", "", target.arch == "386"},
			{"old-value-not-NUM", "XCHG" + suffix + " AX,0(BX)\n" + move + " AX,0(BX)", "", false},
			{"old-value-not-pointer", "XCHG" + suffix + " AX,0(BX)\n" + move + " 0(AX),DX", "", false},
		} {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				prefix := fmt.Sprintf("%s ptr+0(FP),BX\n%s val+%d(FP),AX\n%s desired+%d(FP),CX\n", move, move, word, move, 2*word)
				if row.omit == "value" {
					prefix = strings.Replace(prefix, fmt.Sprintf("%s val+%d(FP),AX\n", move, word), "", 1)
				}
				if row.omit == "address" {
					prefix = strings.Replace(prefix, move+" ptr+0(FP),BX\n", "", 1)
				}
				source := fmt.Sprintf("TEXT ·transport(SB),4,$0-%d\n%s%s\nRET\n", 3*word, prefix, row.body)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func transport(ptr **byte, val, desired *byte)", target.arch, target.triple, api)
					if row.accept {
						if err != nil || ir == "" {
							t.Error("actual complete pointer data role rejected", api, err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Error("pointer bit transport expanded NUM or native-address authority", api, err)
					}
				}
			})
		}
	}
}
