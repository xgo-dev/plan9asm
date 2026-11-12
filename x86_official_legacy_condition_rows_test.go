package plan9asm

// These initialized source and original-byte owners keep object coverage
// distinct from execution. No instruction grants its own numerical inputs,
// destination backing, FLAGS or physical-stack permission.
import (
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialConditionalInitializedProducerObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "Q", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "L", "i386-unknown-linux-gnu"
		}
		var source, declarations strings.Builder
		count, branches, sets := 0, 0, 0
		flush := func() {
			if source.Len() == 0 {
				return
			}
			x86LEAActualTargetGoObject(t, arch, triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
				if err != nil || ir == "" {
					t.Fatal("initialized real data/FLAGS/closed-CFG producer", arch, api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			}
			source.Reset()
			declarations.Reset()
		}
		for _, entry := range catalog.Optab {
			if entry.Ytab == "yjcond" {
				if entry.Prefix != "Px" || len(entry.Rows) != 3 {
					t.Fatal("complete Jcc source schema changed", entry)
				}
				for _, row := range entry.Rows {
					classes := strings.Join(row.Classes, ",")
					hint := ""
					switch classes {
					case "Ybr":
					case "Yi0,Ybr":
						hint = "$0,"
					case "Yi1,Ybr":
						hint = "$1,"
					default:
						t.Fatal("unknown Jcc hint class", row)
					}
					name := fmt.Sprintf("Condition%d", count)
					fmt.Fprintf(&declarations, "func %s(a,b,no,yes uintptr) uintptr\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s a+0(FP),AX\nMOV%s b+%d(FP),BX\nMOV%s no+%d(FP),DX\nMOV%s yes+%d(FP),CX\nCMP%s AX,BX\n%s %staken\nMOV%s DX,CX\ntaken:\nMOV%s CX,ret+%d(FP)\nRET\n",
						name, word*5, move, move, word, move, word*2, move, word*3, move, entry.Opcode, hint, move, move, word*4)
					count++
					branches++
					if count%32 == 0 {
						flush()
					}
				}
			} else if entry.Ytab == "yscond" && strings.HasPrefix(entry.Opcode, "SET") {
				if entry.Prefix != "Pb" || len(entry.Rows) != 1 {
					t.Fatal("complete SETcc source schema changed", entry)
				}
				// Full physical old word is real input. SET itself needs no
				// old byte; the complete returned word observes preservation.
				for _, destination := range []string{"AX", "AH", "0(SI)"} {
					name := fmt.Sprintf("Condition%d", count)
					if destination == "0(SI)" {
						fmt.Fprintf(&declarations, "func %s(out *[1]byte,a,b uintptr)\n", name)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),SI\nMOV%s a+%d(FP),BX\nMOV%s b+%d(FP),CX\nCMP%s BX,CX\n%s 0(SI)\nRET\n",
							name, word*3, move, move, word, move, word*2, move, entry.Opcode)
					} else {
						fmt.Fprintf(&declarations, "func %s(a,b,old uintptr) uintptr\n", name)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s old+%d(FP),AX\nMOV%s a+0(FP),BX\nMOV%s b+%d(FP),CX\nCMP%s BX,CX\n%s %s\nMOV%s AX,ret+%d(FP)\nRET\n",
							name, word*4, move, word*2, move, move, word, move, entry.Opcode, destination, move, word*3)
					}
					count++
					sets++
					if count%32 == 0 {
						flush()
					}
				}
			}
		}
		flush()
		if branches != 48 || sets != 48 || count != 96 {
			t.Fatal("complete source/producer projection changed", arch, branches, sets, count)
		}
	}
}

func TestX86OfficialConditionalBranchRelaxationBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, registerBytes, storeBytes := 8, "Q", 3, 5
		if arch == "386" {
			word, move, registerBytes, storeBytes = 4, "L", 2, 4
		}
		var source strings.Builder
		var cases []x86OfficialPackedCase
		for _, backward := range []bool{false, true} {
			for _, outside := range []bool{false, true} {
				name := fmt.Sprintf("Boundary%d", len(cases))
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s a+0(FP),AX\nMOV%s b+%d(FP),BX\nMOV%s no+%d(FP),DX\nMOV%s yes+%d(FP),CX\n", name, word*5, move, move, word, move, word*2, move, word*3)
				padding := 127 - registerBytes
				displacement := 127
				if backward {
					// The taken block returns directly: no intervening JMP can
					// itself relax and change this independent boundary anchor.
					padding = 128 - (storeBytes + 1 + registerBytes + 2)
					fmt.Fprintf(&source, "JMP check\ntaken:\nMOV%s CX,ret+%d(FP)\nRET\n", move, word*4)
					displacement = -128
				}
				if outside {
					padding++
					displacement++
					if backward {
						displacement = -133
					}
				}
				if backward {
					source.WriteString(strings.Repeat("XCHGL AX,AX\n", padding) + "check:\n")
				}
				fmt.Fprintf(&source, "CMP%s AX,BX\n", move)
				line := strings.Count(source.String(), "\n") + 1
				source.WriteString("JNE taken\n")
				if backward {
					fmt.Fprintf(&source, "MOV%s DX,ret+%d(FP)\nRET\n", move, word*4)
				} else {
					fmt.Fprintf(&source, "%sMOV%s DX,CX\ntaken:\nMOV%s CX,ret+%d(FP)\nRET\n", strings.Repeat("XCHGL AX,AX\n", padding), move, move, word*4)
				}
				code := []byte{0x75, byte(displacement)}
				if outside {
					code = []byte{0x0f, 0x85}
					for b := 0; b < 4; b++ {
						code = append(code, byte(uint32(displacement)>>uint(b*8)))
					}
				}
				cases = append(cases, x86OfficialPackedCase{row: fmt.Sprintf("independent/relax/back=%t/outside=%t", backward, outside), symbol: name, line: line,
					witness: goasmrules.X86PackedBinaryWitness{Instruction: "JNE taken", Encoding: code}})
			}
		}
		listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
		if err != nil {
			t.Fatal(err)
		}
		if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
			t.Fatal("original rel8 endpoint/rel32 relaxation", arch, err)
		}
	}
}

type x86OfficialConditionCase struct {
	row, opcode string
	branch      bool
	witness     goasmrules.X86ConditionWitness
}

func x86OfficialConditionCases(catalog goasmrules.X86LegacyCatalog, arch string) ([]x86OfficialConditionCase, error) {
	rows, err := goasmrules.X86ConditionalRows(catalog, arch)
	if err != nil {
		return nil, err
	}
	var cases []x86OfficialConditionCase
	for _, row := range rows {
		for _, w := range row.Witnesses {
			cases = append(cases, x86OfficialConditionCase{row.ID, row.Opcode, row.Branch, w})
		}
	}
	aliases := x86ConditionalBranchAliasOracle()
	names := make([]string, 0, len(aliases))
	for alias, canonical := range aliases {
		if alias != canonical {
			names = append(names, alias)
		}
	}
	sort.Strings(names)
	for _, alias := range names {
		for _, row := range rows {
			if row.Opcode != aliases[alias] {
				continue
			}
			for _, w := range row.Witnesses {
				if w.Layout != "short-forward" {
					continue
				}
				w.Instruction = alias + strings.TrimPrefix(w.Instruction, row.Opcode)
				cases = append(cases, x86OfficialConditionCase{"alias/" + alias + "/" + row.ID, row.Opcode, true, w})
			}
		}
	}
	for _, row := range rows {
		if row.Branch {
			continue
		}
		w := row.Witnesses[0]
		w.Instruction, w.Layout = row.Opcode+" AL", "AL"
		cases = append(cases, x86OfficialConditionCase{"alias/AL/" + row.ID, row.Opcode, false, w})
	}
	if len(rows) != 64 || len(cases) != 343 || len(names) != 29 {
		return nil, fmt.Errorf("condition source/canonical/alias closure changed: %d/%d/%d", len(rows), len(cases), len(names))
	}
	return cases, nil
}

func TestX86OfficialConditionalSetOriginalGoByteAliasPaths(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86ConditionalRows(catalog, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		var cases []x86OfficialPackedCase
		for _, row := range rows {
			if row.Branch {
				continue
			}
			for index, alias := range []string{"BP", "SI", "DI"} {
				code := append([]byte(nil), row.Witnesses[0].Encoding...)
				if arch == "amd64" {
					code[2] = 0xc5 + byte(index)
					code = append([]byte{0x40}, code...)
				} else {
					// Go's Pb fallback picks BX for the empty SET source:
					// exchange, reissue the exact byte SET, exchange back.
					code[2] = 0xc3
					exchange := []byte{0x87, 0xdd + byte(index)}
					code = append(append(append([]byte(nil), exchange...), code...), exchange...)
				}
				name := fmt.Sprintf("SetAlias%d", len(cases))
				instruction := row.Opcode + " " + alias
				line := strings.Count(source.String(), "\n") + 2
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, instruction)
				cases = append(cases, x86OfficialPackedCase{row: row.ID + "/" + alias, symbol: name, line: line,
					witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction, Encoding: code}})
			}
		}
		if len(cases) != 48 {
			t.Fatal("complete SETcc byte-alias source paths changed", len(cases))
		}
		listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
		if err != nil {
			t.Fatal(err)
		}
		if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
			t.Fatal("Go byte alias/synthesized sequence identity", arch, err)
		}
		t.Logf("%s:48 original SETcc alias statements; byte/sequence observation only, no NUM/FLAGS/frame/native continuation grant", arch)
	}
}

func TestX86OfficialConditionalObservableInputBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, word, triple := "Q", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, word, triple = "L", 4, "i386-unknown-linux-gnu"
		}
		for _, opcode := range []string{"JEQ", "SETNE"} {
			fixture := x86OfficialConditionCase{row: "independent/input-boundary", opcode: opcode, branch: opcode == "JEQ",
				witness: goasmrules.X86ConditionWitness{Instruction: opcode + " AH", Layout: "AH"}}
			if fixture.branch {
				fixture.witness.Instruction, fixture.witness.Layout = "JEQ taken", "short-forward"
			}
			base, decl, _ := x86OfficialConditionAssembly([]x86OfficialConditionCase{fixture}, arch)
			controls := []struct{ name, remove string }{{"complete", ""}}
			if fixture.branch {
				controls = append(controls, struct{ name, remove string }{"unknown-flags", "CMP" + move + " AX,BX\n"},
					struct{ name, remove string }{"unknown-compare", fmt.Sprintf("MOV%s b+%d(FP),BX\n", move, word)},
					struct{ name, remove string }{"unknown-yes", fmt.Sprintf("MOV%s yes+%d(FP),CX\n", move, word*3)},
					struct{ name, remove string }{"unknown-no", fmt.Sprintf("MOV%s no+%d(FP),DX\n", move, word*2)})
			} else {
				controls = append(controls, struct{ name, remove string }{"unknown-flags", "CMP" + move + " BX,CX\n"},
					struct{ name, remove string }{"unknown-compare", fmt.Sprintf("MOV%s b+%d(FP),CX\n", move, word)},
					struct{ name, remove string }{"unknown-old-upper", fmt.Sprintf("MOV%s old+%d(FP),AX\n", move, word*2)})
			}
			for _, control := range controls {
				t.Run(arch+"/"+opcode+"/"+control.name, func(t *testing.T) {
					source := base
					if control.remove != "" {
						if strings.Count(source, control.remove) != 1 {
							t.Fatal("mutation is not uniquely bound")
						}
						source = strings.Replace(source, control.remove, "", 1)
					}
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, decl, arch, triple, api)
						if control.remove == "" && (err != nil || ir == "") || control.remove != "" && (ir != "" || !errors.Is(err, ErrProbeNeedsContext)) {
							t.Fatal("real input/FLAGS/preserved-byte obligation changed", api, err)
						}
					}
				})
			}
		}
	}
}

func x86OfficialConditionAssembly(cases []x86OfficialConditionCase, arch string) (string, string, []x86OfficialPackedCase) {
	word, move := 8, "Q"
	if arch == "386" {
		word, move = 4, "L"
	}
	var source, declarations strings.Builder
	var observed []x86OfficialPackedCase
	for index, fixture := range cases {
		w := fixture.witness
		name := fmt.Sprintf("ConditionRow%d", index)
		line := 0
		if fixture.branch {
			fmt.Fprintf(&declarations, "func %s(a,b,no,yes uintptr) uintptr\n", name)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s a+0(FP),AX\nMOV%s b+%d(FP),BX\nMOV%s no+%d(FP),DX\nMOV%s yes+%d(FP),CX\n", name, word*5, move, move, word, move, word*2, move, word*3)
			backward := strings.HasSuffix(w.Layout, "backward")
			padding := ""
			if strings.HasPrefix(w.Layout, "near") {
				padding = strings.Repeat("XCHGL AX,AX\n", 128)
			}
			result := "CX"
			if backward {
				fmt.Fprintf(&source, "JMP check\ntaken:\nMOV%s CX,DX\nJMP done\n%scheck:\n", move, padding)
				result = "DX"
			}
			fmt.Fprintf(&source, "CMP%s AX,BX\n", move)
			line = strings.Count(source.String(), "\n") + 1
			fmt.Fprintln(&source, w.Instruction)
			if !backward {
				fmt.Fprintf(&source, "%sMOV%s DX,CX\ntaken:\n", padding, move)
			} else {
				source.WriteString("done:\n")
			}
			fmt.Fprintf(&source, "MOV%s %s,ret+%d(FP)\nRET\n", move, result, word*4)
		} else {
			memory := w.Layout == "0(SI)"
			if memory {
				fmt.Fprintf(&declarations, "func %s(out *[1]byte,a,b uintptr)\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),SI\nMOV%s a+%d(FP),BX\nMOV%s b+%d(FP),CX\nCMP%s BX,CX\n", name, word*3, move, move, word, move, word*2, move)
			} else {
				fmt.Fprintf(&declarations, "func %s(a,b,old uintptr) uintptr\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s old+%d(FP),AX\nMOV%s a+0(FP),BX\nMOV%s b+%d(FP),CX\nCMP%s BX,CX\n", name, word*4, move, word*2, move, move, word, move)
			}
			line = strings.Count(source.String(), "\n") + 1
			fmt.Fprintln(&source, w.Instruction)
			if !memory {
				fmt.Fprintf(&source, "MOV%s AX,ret+%d(FP)\n", move, word*3)
			}
			source.WriteString("RET\n")
		}
		// Go's listing prints the canonical opcode for a frontend alias. The
		// original spelling stays in witness/source; only the byte observer's
		// opcode comparison receives the independently bound canonical name.
		canonical := fixture.opcode + strings.TrimPrefix(w.Instruction, strings.Fields(w.Instruction)[0])
		observed = append(observed, x86OfficialPackedCase{row: fixture.row + "/" + w.Layout, symbol: name, line: line,
			witness: goasmrules.X86PackedBinaryWitness{Instruction: canonical, Encoding: w.Encoding}})
	}
	return source.String(), declarations.String(), observed
}

func TestX86OfficialConditionalRowsOriginalBytesAndObservableObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			cases, err := x86OfficialConditionCases(catalog, arch)
			if err != nil {
				t.Fatal(err)
			}
			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			for start := 0; start < len(cases); start += 32 {
				end := start + 32
				if end > len(cases) {
					end = len(cases)
				}
				t.Run(fmt.Sprintf("batch%02d", start/32), func(t *testing.T) {
					source, declarations, observed := x86OfficialConditionAssembly(cases[start:end], arch)
					listing, err := x86ScalarLiteralGoListing(t, arch, source)
					if err != nil {
						t.Fatal(err)
					}
					if err := x86OfficialPackedVerifyListing(listing, observed); err != nil {
						t.Fatal("independent source-row/layout/Go-byte identity", err)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
							if err != nil || ir == "" {
								t.Fatal("real conditional data/byte output continuation", api, err)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, triple, ir, level)
							}
						})
					}
				})
			}
		})
	}
}
