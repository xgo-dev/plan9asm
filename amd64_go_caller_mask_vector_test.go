package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// The denominator comes from every original Go encoder row, not the caller
// registry or the library which first exposed its missing effect registration.
func x86OfficialMaskVectorRows(t *testing.T) []string {
	t.Helper()
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	family := map[string]bool{
		"VPMOVM2B": true, "VPMOVM2W": true, "VPMOVM2D": true, "VPMOVM2Q": true,
		"VPMOVB2M": true, "VPMOVW2M": true, "VPMOVD2M": true, "VPMOVQ2M": true,
	}
	var rows []string
	counts := map[string]int{}
	for _, rule := range rules {
		if !family[rule.Opcode] {
			continue
		}
		toVector := strings.HasPrefix(rule.Opcode, "VPMOVM2")
		vectorIndex, maskIndex := 0, 1
		if toVector {
			vectorIndex, maskIndex = 1, 0
		}
		if len(rule.Classes) != 2 || rule.Classes[maskIndex] != "Yk" ||
			rule.Prefix != "Pavx" || rule.ZCase != "Zevex_rm_v_r" ||
			rule.ZOffset != 3 || rule.EncodingOffset != rule.RowIndex*3 || len(rule.OpBytes) != 9 {
			t.Fatalf("unmodeled official mask/vector row: %+v", rule)
		}
		bank := map[string]string{"YxrEvex": "X", "YyrEvex": "Y", "Yzr": "Z"}[rule.Classes[vectorIndex]]
		bits := map[string]string{"X": "128", "Y": "256", "Z": "512"}[bank]
		w := "evexW0"
		if strings.HasSuffix(rule.Opcode, "W") || strings.HasSuffix(rule.Opcode, "Q") ||
			strings.Contains(rule.Opcode, "W2M") || strings.Contains(rule.Opcode, "Q2M") {
			w = "evexW1"
		}
		terms := strings.Split(rule.OpBytes[rule.EncodingOffset], " | ")
		opcode := "0x28"
		if strings.Contains(rule.Opcode, "D") || strings.Contains(rule.Opcode, "Q") {
			opcode = "0x38"
		}
		if !toVector {
			opcode = map[string]string{"0x28": "0x29", "0x38": "0x39"}[opcode]
		}
		if bank == "" || !reflect.DeepEqual(terms, []string{"avxEscape", "evex" + bits, "evexF3", "evex0F38", w}) ||
			rule.OpBytes[rule.EncodingOffset+1] != "0" || !strings.EqualFold(rule.OpBytes[rule.EncodingOffset+2], opcode) {
			t.Fatalf("unmodeled encoding generation/attributes: %+v", rule)
		}
		operands := bank + "1,K1"
		if toVector {
			operands = "K1," + bank + "1"
		}
		rows = append(rows, rule.Opcode+" "+operands)
		counts[rule.Opcode]++
	}
	for opcode := range family {
		if counts[opcode] != 3 {
			t.Fatalf("%s complete X/Y/Z denominator changed: %d", opcode, counts[opcode])
		}
	}
	if len(rows) != 24 {
		t.Fatalf("complete mask/vector Go-row denominator changed: %d", len(rows))
	}
	return rows
}

func TestX86GoCallerMaskVectorCompleteOfficialEffectRegistration(t *testing.T) {
	for _, row := range x86OfficialMaskVectorRows(t) {
		t.Run(row, func(t *testing.T) {
			source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if !x86CallerVectorMoveKnown(file.Funcs[0].Instrs[1]) {
				t.Fatal("Go-accepted complete mask/vector row lacks its caller effect")
			}
		})
	}
}

func TestX86GoCallerMaskVectorActualTypedSourceAndObjects(t *testing.T) {
	for index, row := range x86OfficialMaskVectorRows(t) {
		t.Run(fmt.Sprintf("%02d/%s", index, row), func(t *testing.T) {
			body := "KMOVQ AX,K1\nVMOVUPS (DI),Z1\n" + row + "\n"
			if strings.HasPrefix(row, "VPMOVM2") {
				body += "VMOVSS X1,(DX)"
			} else {
				body += "KMOVQ K1,AX\nMOVL AX,(DX)"
			}
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM22 llc required")
			}
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
				options := Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
				ir, err := Translate(file, options)
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "mask-vector-text.ll", "mask-vector-text.o", ir)
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "mask-vector-module.ll", "mask-vector-module.o", module.String())
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatal("actual selected typed caller/LLVM object failed", err)
				}
			}
		})
	}
}

func TestX86MaskVectorGrammarKeepsModeAndDispatchBoundaries(t *testing.T) {
	for _, row := range x86OfficialMaskVectorRows(t) {
		for _, bank := range []string{"X", "Y", "Z"} {
			if !strings.Contains(row, bank+"1") {
				continue
			}
			for _, index := range []int{0, 7, 8, 31} {
				spelling := strings.Replace(row, bank+"1", fmt.Sprint(bank, index), 1)
				t.Run(spelling, func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+spelling+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					for _, arch := range []string{"amd64", "386"} {
						_, known, err := x86MaskVectorProperties(ins, arch)
						if !known {
							t.Fatal("recognized family fell through")
						}
						if arch == "386" && index >= 8 {
							if bank == "Z" {
								goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+spelling+"\nRET\n", "", false)
								if err == nil || errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("Go-invalid mode32 Z bank became a physical binding")
								}
							} else {
								goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+spelling+"\nRET\n", "", true)
								if !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("unproved physical mode32 X/Y binding was accepted", err)
								}
							}
						} else if err != nil {
							t.Fatal("valid physical bank rejected", err)
						}
					}
				})
			}
		}
	}
	file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\nVPMOVM2B K1,X1\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ins := file.Funcs[0].Instrs[1]
	ins.Op = "vpmovm2b"
	var output strings.Builder
	ctx := amd64Ctx{b: &output, goarch: "amd64"}
	if known, _, err := ctx.lowerMaskVectorMove("VPMOVM2B", ins); !known || err != nil {
		t.Fatal("equivalent case-normalized opcode lost its existing dispatch", err)
	}
	output.Reset()
	if known, _, err := ctx.lowerMaskVectorMove("VPMOVM2W", ins); !known || err == nil || output.Len() != 0 {
		t.Fatal("contradictory dispatch emitted a different opcode", err)
	}
}

func TestX86GoCallerMaskVectorInitializationAndUnaffectedState(t *testing.T) {
	for _, row := range x86OfficialMaskVectorRows(t) {
		t.Run(row, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			form, recognized, err := x86MaskVectorProperties(ins, "amd64")
			if !recognized || err != nil {
				t.Fatal("shared grammar lost official row", err)
			}
			initial := x86SourceStackState{
				bp: x86SourceStackAddress{original: true}, gOriginal: true, numericFlags: true,
				callers: map[Reg]x86CallerPointerValue{DI: {argument: 0}}, known: map[Reg]uint8{AX: 0xff},
				vectors: map[Reg]uint64{"Z1": ^uint64(0), "Z31": 0x55},
				masks:   map[Reg]bool{"K1": true, "K0": false, "K7": true},
			}
			state, want := x86CloneCallerState(initial), x86CloneCallerState(initial)
			if form.spec.maskToVector {
				want.vectors["Z1"] = ^uint64(0)
			} else {
				want.masks["K1"] = true
			}
			if !x86CallerVectorMoveStep(&ins, &state, nil) || !reflect.DeepEqual(state, want) {
				t.Fatalf("mask/vector effect changed unrelated state: got=%+v want=%+v", state, want)
			}
			for missing := 0; missing < form.byteWidth; missing++ {
				state = x86CloneCallerState(initial)
				if form.spec.maskToVector {
					state.masks["K1"] = false
				} else {
					state.vectors["Z1"] &^= uint64(1) << uint(missing)
				}
				before := x86CloneCallerState(state)
				required := form.spec.maskToVector || x86MaskVectorSignBytes(row, form.byteWidth)&(uint64(1)<<uint(missing)) != 0
				if !required {
					before.masks["K1"] = true
				}
				if x86CallerVectorMoveStep(&ins, &state, nil) == required || !reflect.DeepEqual(before, state) {
					t.Fatalf("missing input %d acquired effect or mutated state", missing)
				}
			}
			if form.spec.maskToVector {
				state = x86CloneCallerState(initial)
				state.vectors["Z1"] = 0
				if !x86CallerVectorMoveStep(&ins, &state, nil) || state.vectors["Z1"] != ^uint64(0) {
					t.Fatal("EVEX overwrite did not define low data and clear wider aliases")
				}
			} else {
				state = x86CloneCallerState(initial)
				state.vectors["Z1"] = x86CallerVectorByteMask(int64(form.byteWidth))
				state.masks["K1"] = false
				if !x86CallerVectorMoveStep(&ins, &state, nil) || !state.masks["K1"] {
					t.Fatal("complete selected vector requires no unrelated upper aliases or old destination mask")
				}
			}
		})
	}
}

func TestX86GoCallerMaskVectorRejectsUninitializedActualSources(t *testing.T) {
	for _, row := range x86OfficialMaskVectorRows(t) {
		t.Run(row, func(t *testing.T) {
			var body string
			if strings.HasPrefix(row, "VPMOVM2") {
				body = row + "\nVMOVSS X1,(DX)"
			} else {
				body = row + "\nKMOVQ K1,AX\nMOVL AX,(DX)"
			}
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown entry mask/vector acquired raw-return permission: %v", err)
			}
		})
	}
}

func TestX86GoCallerMaskVectorK0IsInitializedDataNotWritemasking(t *testing.T) {
	for _, row := range x86OfficialMaskVectorRows(t) {
		if !strings.HasPrefix(row, "VPMOVM2") {
			continue
		}
		row = strings.ReplaceAll(row, "K1", "K0")
		for _, initialized := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/initialized=%t", row, initialized), func(t *testing.T) {
				body := row + "\nVMOVSS X1,(DX)"
				if initialized {
					body = "KMOVQ AX,K0\n" + body
				}
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
				goAssemblerOracleOutput(t, "amd64", assembly, "", true)
				pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
				err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
				if initialized && err != nil || !initialized && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("K0 acquired implicit all-one/zero value or lost defined data: %v", err)
				}
			})
		}
	}
}

func TestX86MaskVectorGrammarRejectsEverySiblingInvalidForm(t *testing.T) {
	for _, opcode := range []string{
		"VPMOVM2B", "VPMOVM2W", "VPMOVM2D", "VPMOVM2Q",
		"VPMOVB2M", "VPMOVW2M", "VPMOVD2M", "VPMOVQ2M",
	} {
		toVector := strings.HasPrefix(opcode, "VPMOVM2")
		args := []string{"K1,Z1", "K1,K2", "K1,0(AX)", "X1,Z1", "K8,Z1", "K1,Z32", "K1,K2,Z1", "K1"}
		if !toVector {
			args = []string{"Z1,K1", "K1,K2", "0(AX),K1", "Z1,X1", "Z1,K8", "Z32,K1", "Z1,K2,K1", "Z1"}
		}
		for index, operands := range args {
			spelling := opcode + " " + operands
			if index == 0 {
				spelling = opcode + ".Z " + operands
			}
			t.Run(spelling, func(t *testing.T) {
				for _, arch := range []string{"amd64", "386"} {
					source := "TEXT f(SB),4,$0-0\n" + spelling + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", false)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						continue // Source parser rejection grants no supported form.
					}
					ins := file.Funcs[0].Instrs[1]
					if _, known, err := x86MaskVectorProperties(ins, arch); !known || err == nil {
						t.Fatal("invalid sibling form escaped the shared grammar", err)
					}
					if x86CallerVectorMoveKnown(ins) {
						t.Fatal("Go-rejected sibling acquired a caller effect")
					}
				}
			})
		}
	}
}

func TestX86MaskVectorOfficialRowsThreeAPIsFiveTargets(t *testing.T) {
	rows := x86OfficialMaskVectorRows(t)
	var assembly strings.Builder
	for index, row := range rows {
		fmt.Fprintf(&assembly, "TEXT ·F%d(SB),4,$0-0\n%s\nRET\n", index, row)
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			file, sigs := x86UnboundVoidFormatSources(t, assembly.String(), target.arch, target.triple)
			x86ScalarFormatObjectUnit(t, file, sigs, target.arch, target.triple, 0)
			t.Log("24 unchanged unbound Go rows; three public Context controls and emitter-only objects; initialized programs have a separate owner")
		})
	}
}
