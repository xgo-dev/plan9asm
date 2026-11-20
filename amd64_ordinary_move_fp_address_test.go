package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86OrdinaryMoveFPAddressFixture(arch, width, address string) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if word == 4 {
		move = "MOVL"
	}
	return fmt.Sprintf("TEXT ·FPAddress(SB),4,$0-%d\n%s input+0(FP),AX\nMOV%s %s,BX\n"+
			"%s $0,BX\n%s AX,ret+%d(FP)\nRET\n", 2*word, move, width, address, move, move, word),
		"func FPAddress(input uintptr) uintptr\n"
}

func TestX86OrdinaryMoveNamedFPAddressObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	observations := 0
	for _, target := range x86RawReturnTargets {
		for _, width := range []string{"W", "L", "Q"} {
			if target.arch == "386" && width == "Q" {
				continue // Independently rejected by the grammar owner below.
			}
			t.Run(target.triple+"/"+width, func(t *testing.T) {
				source, declaration := x86OrdinaryMoveFPAddressFixture(target.arch, width, "$input+0(FP)")
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("dead address of an independently typed scalar field rejected", api, err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				}
			})
			observations++
		}
	}
	if observations != 13 {
		t.Fatal("complete mode/target FP-address object partition changed", observations)
	}
}

func TestX86OrdinaryMoveNamedFPAddressSourceBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, width := range []string{"W", "L", "Q"} {
			for _, control := range []string{"numeric-FP", "punctuated-FP", "register-FP", "outside-field", "changed-Raw", "changed-operand", "changed-name", "physical-origin", "address-as-number"} {
				t.Run(arch+"/"+width+"/"+control, func(t *testing.T) {
					address := "$input+0(FP)"
					if control == "numeric-FP" {
						address = "$0(FP)"
					} else if control == "punctuated-FP" {
						address = "$pkg.值+0(FP)"
					} else if control == "register-FP" {
						address = "$AX+0(FP)"
					} else if control == "outside-field" {
						address = "$input+32(FP)"
					}
					source, declaration := x86OrdinaryMoveFPAddressFixture(arch, width, address)
					if control == "address-as-number" {
						move, word := "MOVQ", goWordSize(arch)
						if word == 4 {
							move = "MOVL"
						}
						source = strings.Replace(source, "MOV"+width+" ", move+" $0,BX\nMOV"+width+" ", 1)
						source = strings.Replace(source, "\n"+move+" $0,BX\n"+move+" AX,ret+", "\n"+move+" BX,ret+", 1)
					}
					invalidName := control == "numeric-FP" || control == "punctuated-FP" || control == "register-FP"
					accepted := !invalidName && !(arch == "386" && width == "Q")
					observed := source
					if arch == "386" && width == "Q" {
						// The existing frame-diagnostic observer deliberately models
						// one focused instruction and stack steps. Keep this exact
						// original MOV in that closed context; Go reports its LEAQ
						// rewrite with PARAM bias +4, rather than the source opcode.
						observed = "TEXT ·FPAddress(SB),4,$0-8\nMOVQ " + address + ",BX\nRET\n"
					}
					goAssemblerOracleOutput(t, arch, observed, "", accepted)
					ins := x86ScalarLaneInstruction(t, "MOV"+width+" "+address+",BX")
					original := fmt.Sprintf("%#v", ins)
					switch control {
					case "changed-Raw":
						ins.Raw = "MOV" + width + " $input+8(FP),BX"
					case "changed-operand":
						ins.Args[0].FPOffset = 8
					case "changed-name":
						ins.Args[0].FPName = "other"
					case "physical-origin":
						ins.x86Encoded = true
					}
					view, known, err := x86NamedFrameMoveAddressInstruction(ins, arch)
					if control != "outside-field" && control != "address-as-number" && known && err == nil {
						t.Error("invalid/changed FP spelling or physical role became a named address", view)
					}
					if invalidName || control == "outside-field" || control == "address-as-number" || arch == "386" && width == "Q" {
						for _, api := range []string{"text", "module", "Go"} {
							if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, x86AddressMemoryTargets(arch)[0], api); err == nil || ir != "" {
								t.Error("invalid/unmapped/mode32-Q FP address produced public IR", api, len(ir), err)
							}
						}
					}
					if control == "outside-field" && original != fmt.Sprintf("%#v", ins) {
						t.Fatal("source-only address projection mutated original instruction")
					}
				})
			}
		}
	}
}

func TestX86FixedLocalAddressOnlyBareNamesBatch(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var source, declarations strings.Builder
	count := 0
	for _, op := range []string{"LEAW", "LEAL", "LEAQ", "MOVW", "MOVL", "MOVQ"} {
		for _, name := range []string{"slot", "δοκιμή", "槽"} {
			symbol := fmt.Sprintf("BareAddress%d", count)
			address := name + "(SP)"
			if strings.HasPrefix(op, "MOV") {
				address = "$" + address
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$16-16\nMOVQ input+0(FP),AX\nMOVQ AX,0(SP)\n"+
				"%s %s,BX\nMOVQ $0,BX\nMOVQ 0(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n", symbol, op, address)
			fmt.Fprintf(&declarations, "func %s(input uint64) uint64\n", symbol)
			count++
		}
	}
	if count != 18 {
		t.Fatal("complete address-family/width/name inventory changed", count)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	triple := "x86_64-unknown-linux-gnu"
	pkg, request, _, options := x86CMOVFixedLocalFixture(t, source.String(), declarations.String(), "linux/amd64", triple)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
		if err != nil || ir == "" {
			t.Fatal("original bounded bare AUTO addresses were rejected", err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			x86PackedStringCompileObject(t, llc, triple, ir, level)
		}
	})
}

func TestX86OrdinaryMoveFrameAddressUnicodeNames(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range []string{"参数", "δοκιμή", "pkg·值"} {
			t.Run(arch+"/FP/"+name, func(t *testing.T) {
				source, declaration := x86OrdinaryMoveFPAddressFixture(arch, "W", "$"+name+"+0(FP)")
				goAssemblerOracleOutput(t, arch, source, "", true)
				ins := x86ScalarLaneInstruction(t, "MOVW $"+name+"+0(FP),BX")
				original := fmt.Sprintf("%#v", ins)
				view, known, err := x86NamedFrameMoveAddressInstruction(ins, arch)
				if !known || err != nil || view.Args[0].FPName != name || original != fmt.Sprintf("%#v", ins) {
					t.Error("legitimate Go FP symbol or original identity was lost", known, err, view)
				}
				triple := x86AddressMemoryTargets(arch)[0]
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("legitimate Unicode FP address rejected", api, err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, ir, level)
					}
				}
			})
		}
	}
	for _, name := range []string{"槽-16", "δοκιμή"} {
		t.Run("amd64/AUTO/"+name, func(t *testing.T) {
			source := "TEXT ·UnicodeAuto(SB),4,$16-16\nMOVQ input+0(FP),AX\nMOVQ AX,0(SP)\n" +
				"MOVW $" + name + "(SP),BX\nMOVQ $0,BX\nMOVQ 0(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n"
			declaration := "func UnicodeAuto(input uint64) uint64\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			triple := "x86_64-unknown-linux-gnu"
			pkg, request, _, options := x86CMOVFixedLocalFixture(t, source, declaration, "linux/amd64", triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
				if err != nil || ir == "" {
					t.Fatal("legitimate Unicode AUTO address rejected", err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			})
		})
	}
}
