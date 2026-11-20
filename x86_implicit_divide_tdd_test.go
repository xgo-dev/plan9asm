package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// This directory is independent of the lowerer's multiply/divide switch.
// The byte dividend is AX16, not AL; the remaining dividends are DX:AX.
var x86ImplicitDivideOracle = []struct {
	name, suffix string
	bits         int
	signed       bool
}{
	{"DIVB", "B", 8, false}, {"DIVW", "W", 16, false},
	{"DIVL", "L", 32, false}, {"DIVQ", "Q", 64, false},
	{"IDIVB", "B", 8, true}, {"IDIVW", "W", 16, true},
	{"IDIVL", "L", 32, true}, {"IDIVQ", "Q", 64, true},
}

func TestX86ImplicitDivideCompleteIndependentGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for table, expected := range map[string]string{
		"ydivb": "{Zm_o,2,argList{Ymb}},", "ydivl": "{Zm_o,2,argList{Yml}},",
	} {
		match := regexp.MustCompile(`(?s)var ` + table + ` = \[\]ytab\{(.*?)\n\}`).FindSubmatch(data)
		if len(match) != 2 || strings.Join(strings.Fields(string(match[1])), "") != expected {
			t.Fatal("complete Go implicit division operand class, zcase or offset changed", table)
		}
	}
	actual := regexp.MustCompile(`\{A(?:I?DIV)[BWLQ], [^\n]+`).FindAllString(string(data), -1)
	want := []string{
		`{ADIVB, ydivb, Pb, opBytes{0xf6, 06}},`,
		`{ADIVL, ydivl, Px, opBytes{0xf7, 06}},`,
		`{ADIVQ, ydivl, Pw, opBytes{0xf7, 06}},`,
		`{ADIVW, ydivl, Pe, opBytes{0xf7, 06}},`,
		`{AIDIVB, ydivb, Pb, opBytes{0xf6, 07}},`,
		`{AIDIVL, ydivl, Px, opBytes{0xf7, 07}},`,
		`{AIDIVQ, ydivl, Pw, opBytes{0xf7, 07}},`,
		`{AIDIVW, ydivl, Pe, opBytes{0xf7, 07}},`,
	}
	if !reflect.DeepEqual(actual, want) || len(x86ImplicitDivideOracle) != len(want) {
		t.Fatal("complete Go division family/prefix/extension directory changed", actual)
	}
}

func x86ImplicitDivideInitializedBody(name, suffix string, bits int, source string) string {
	move := "MOV" + suffix
	body := move + " $7,AX\n"
	if bits == 8 {
		body = "MOVW $7,AX\n" // Both AL and AH are mandatory dividend bytes.
	} else {
		body += move + " $0,DX\n"
	}
	if source == "CX" {
		body += move + " $3,CX\n"
	}
	return body + name + " " + source + "\n"
}

func TestX86ImplicitDivideInitializedFamilyFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := goWordSize(target.arch), "MOVQ"
			if target.arch == "386" {
				move = "MOVL"
			}
			var assembly, declarations strings.Builder
			count := 0
			for _, row := range x86ImplicitDivideOracle {
				if target.arch == "386" && row.bits == 64 {
					continue // Stock Go rejects Q in mode32; no supported target is skipped.
				}
				for _, source := range []string{"CX", "1(SI)"} {
					name := fmt.Sprint("Divide", count)
					fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
					fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),SI\nMOVL $0,AX\n%sMOVL AX,ret+%d(FP)\nRET\n",
						name, word+4, move, x86ImplicitDivideInitializedBody(row.name, row.suffix, row.bits, source), word)
					count++
				}
			}
			want := 16
			if target.arch == "386" {
				want = 12
			}
			if count != want {
				t.Fatal("complete division direction/width/source matrix changed", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original division family lost its native continuation", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if regexp.MustCompile(`\b(?:sdiv|udiv|srem|urem)\b`).MatchString(text) || strings.Count(text, "asm sideeffect") != count {
							t.Fatal("division native #DE/access effects became LLVM poison or optional arithmetic")
						}
						compileLLVMToObject(t, llc, target.triple, "implicit-divide.ll", "implicit-divide.o", text)
					}
				})
			}
		})
	}
}

func TestX86ImplicitDivideDeadVoidRequiresEveryImplicitInput(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range x86ImplicitDivideOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			for _, unused := range []bool{false, true} {
				declaration, extent := "func Value()", 0
				if unused {
					declaration, extent = "func Value(unused bool)", 1
				}
				body := x86ImplicitDivideInitializedBody(row.name, row.suffix, row.bits, "CX")
				controls := []string{"accumulator", "divisor"}
				if row.bits != 8 {
					controls = append(controls, "high-half")
				} else {
					controls = append(controls, "AH")
				}
				for _, missing := range controls {
					t.Run(fmt.Sprintf("%s/%s/unused=%t/%s", arch, row.name, unused, missing), func(t *testing.T) {
						changed := body
						switch missing {
						case "accumulator":
							changed = strings.Replace(changed, "MOV"+row.suffix+" $7,AX\n", "", 1)
							if row.bits == 8 {
								changed = strings.Replace(changed, "MOVW $7,AX\n", "", 1)
							}
						case "divisor":
							changed = strings.Replace(changed, "MOV"+row.suffix+" $3,CX\n", "", 1)
						case "high-half":
							changed = strings.Replace(changed, "MOV"+row.suffix+" $0,DX\n", "", 1)
						case "AH":
							changed = strings.Replace(changed, "MOVW $7,AX\n", "MOVB $7,AL\n", 1)
						}
						if changed == body {
							t.Fatal("missing-input mutation did not change source")
						}
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sRET\n", extent, changed)
						x86LEAActualTargetGoObject(t, arch, triple, source)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("dead division invented implicit source bytes", api, err)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86ImplicitDivideZeroOverflowAndWideMinCannotDisappear(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		t.Run(arch, func(t *testing.T) {
			var assembly strings.Builder
			signatures := make(map[string]FuncSig)
			count := 0
			for _, row := range x86ImplicitDivideOracle {
				if arch == "386" && row.bits == 64 {
					continue
				}
				cases := []string{"zero", "quotient-overflow"}
				if row.signed {
					cases = append(cases, "wide-min/-1", "narrow-min/-1")
				}
				for _, fault := range cases {
					name, low, high, divisor := fmt.Sprint("Fault", count), uint64(7), uint64(0), int64(0)
					if fault != "zero" {
						divisor = 1
						if row.signed {
							low = uint64(1) << uint(row.bits-1)
						} else {
							low, high = 0, 1
						}
					}
					if fault == "wide-min/-1" {
						low, high, divisor = 0, uint64(1)<<uint(row.bits-1), -1
					} else if fault == "narrow-min/-1" {
						high, divisor = ^uint64(0), -1
					}
					move := "MOV" + row.suffix
					body := fmt.Sprintf("%s $%#x,AX\n%s $%#x,DX\n", move, low, move, high)
					if row.bits == 8 {
						body = fmt.Sprintf("MOVW $%#x,AX\n", (low&255)|(high&255)<<8)
					}
					fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-0\n%s%s $%d,CX\n%s CX\nRET\n", name, body, move, divisor, row.name)
					signatures[name] = FuncSig{Name: name, Ret: Void}
					count++
				}
			}
			requireX86GoAssemblerResult(t, arch, assembly.String(), true)
			file, err := Parse(ArchAMD64, assembly.String())
			if err != nil {
				t.Fatal(err)
			}
			ir := x86ScalarFormatObjectUnit(t, file, signatures, arch, triple, 0)
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				if strings.Count(text, "asm sideeffect") != count || regexp.MustCompile(`\b(?:sdiv|udiv|srem|urem)\b`).MatchString(text) {
					t.Fatal("zero/overflow #DE or wide-min/-1 became eliminated LLVM poison", arch, count)
				}
			}
		})
	}
}
