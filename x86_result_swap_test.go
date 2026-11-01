package plan9asm

import (
	"bytes"
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

func TestX86ResultSwapCompleteOriginalEncoderDirectory(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"{AXCHGB, yml_mb, Pb, opBytes{0x86, 0x86}}",
		"{AXCHGW, yxchg, Pe, opBytes{0x90, 0x90, 0x87, 0x87}}",
		"{AXCHGL, yxchg, Px, opBytes{0x90, 0x90, 0x87, 0x87}}",
		"{AXCHGQ, yxchg, Pw, opBytes{0x90, 0x90, 0x87, 0x87}}",
	} {
		if !bytes.Contains(data, []byte(row)) {
			t.Fatal("independent complete opcode registration changed", row)
		}
	}
	for name, rows := range map[string]string{
		"yml_mb": `{Zr_m,1,argList{Yrb,Ymb}},{Zm_r,1,argList{Ymb,Yrb}},`,
		"yxchg":  `{Z_rp,1,argList{Yax,Yrl}},{Zrp_,1,argList{Yrl,Yax}},{Zr_m,1,argList{Yrl,Yml}},{Zm_r,1,argList{Yml,Yrl}},`,
	} {
		body := regexp.MustCompile(`(?s)var ` + name + ` = \[\]ytab\{(.*?)\n\}`).FindSubmatch(data)
		if len(body) != 2 || regexp.MustCompile(`\s+`).ReplaceAllString(string(body[1]), "") != rows {
			t.Fatal("independent ordered encoder classes/offset advances changed", name)
		}
	}
	if len(regexp.MustCompile(`\{AXCHG[BWLQ],`).FindAll(data, -1)) != 4 {
		t.Fatal("original family acquired an unenumerated opcode")
	}
}

func TestX86ResultSwapOriginalPhysicalByteWitnesses(t *testing.T) {
	for _, row := range []struct {
		arch, body string
		code       []byte
	}{
		{"amd64", "XCHGB AH,AL", []byte{0x86, 0xe0}},
		{"amd64", "XCHGB AL,AH", []byte{0x86, 0xc4}},
		{"amd64", "XCHGB AH,R11", []byte{0x41, 0x86, 0xe3}},
		{"amd64", "XCHGB R11,AH", []byte{0x44, 0x86, 0xdc}},
		{"amd64", "XCHGB DH,R11", []byte{0x41, 0x86, 0xf3}},
		{"amd64", "XCHGB CH,SI", []byte{0x40, 0x86, 0xee}},
		{"amd64", "XCHGW AX,AX", []byte{0x66, 0x90}},
		{"amd64", "XCHGL AX,AX", []byte{0x90}},
		{"amd64", "XCHGQ AX,AX", []byte{0x48, 0x90}},
		{"amd64", "XCHGL BX,BX", []byte{0x87, 0xdb}},
		{"amd64", "XCHGL AX,BX", []byte{0x93}},
		{"amd64", "XCHGL BX,AX", []byte{0x93}},
		{"amd64", "XCHGQ AX,R11", []byte{0x49, 0x93}},
		{"386", "XCHGB AH,AL", []byte{0x86, 0xe0}},
		{"386", "XCHGB SI,DI", []byte{0x96, 0x87, 0xdf, 0x86, 0xc3, 0x87, 0xdf, 0x96}},
		{"386", "XCHGL AX,AX", []byte{0x90}},
	} {
		t.Run(row.arch+"/"+row.body, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$0-0\n" + row.body + "\nRET\n"
			actual := x86OrderingHintGoBytes(t, row.arch, source)
			want := append(append([]byte(nil), row.code...), 0xc3)
			if !bytes.Equal(actual, want) {
				t.Fatalf("actual whole Go instruction sequence=%x, want=%x", actual, want)
			}
			t.Logf("original Go complete bytes=%x (encoding, not a runtime or permission certificate)", actual)
		})
	}
}

func x86ResultSwapRegisterAxes(arch string) []string {
	gp := []string{"AX", "CX", "DX", "BX", "SI", "DI"}
	byteRegs := append(append([]string(nil), gp...), "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH")
	widths := "BWL"
	if arch == "amd64" {
		widths += "Q"
		byteRegs = append(byteRegs, "SIB", "DIB")
		for index := 8; index < 16; index++ {
			reg := fmt.Sprint("R", index)
			gp = append(gp, reg)
			byteRegs = append(byteRegs, reg, reg+"B")
		}
	}
	var rows []string
	for _, width := range widths {
		registers := gp
		if width == 'B' {
			registers = byteRegs
		}
		for _, first := range registers {
			for _, second := range registers {
				rows = append(rows, fmt.Sprintf("XCHG%c %s,%s", width, first, second))
			}
		}
	}
	return rows
}

// This independent source-name classifier is used only to assert rejection of
// Go-accepted REX reinterpretations. It is not the production grammar.
func x86ResultSwapHighByteREX(row string) bool {
	fields := strings.FieldsFunc(row, func(r rune) bool { return r == ' ' || r == ',' })
	if fields[0] != "XCHGB" {
		return false
	}
	high, rex := false, false
	for _, reg := range fields[1:] {
		high = high || reg == "AH" || reg == "CH" || reg == "DH" || reg == "BH"
		rex = rex || reg == "SP" || reg == "BP" || reg == "SI" || reg == "DI" || reg == "BPB" || reg == "SIB" || reg == "DIB" || strings.HasPrefix(reg, "R")
	}
	return high && rex
}

func TestX86ResultSwapCompleteRegisterAxes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86ResultSwapRegisterAxes(arch)
		goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+strings.Join(rows, "\n")+"\nRET\n", "", true)
		for _, row := range rows {
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86YMMReadSource(t, row)
				before := fmt.Sprintf("%#v", ins)
				for _, consumer := range x86ResultGPSIMDConsumers {
					state := x86ResultState{flags: x86ByteFlagCF | x86ByteFlagAF | x86ByteFlagOF}
					for index := range state.gp {
						state.gp[index] = 0xff
					}
					state.xmm[0], state.masks[0] = 0x55aa, true
					want := state.clone()
					accepted := arch != "amd64" || !x86ResultSwapHighByteREX(row)
					if got := consumer.step(ins, &state, nil, 0, arch); got != accepted || !reflect.DeepEqual(state, want) {
						t.Errorf("%s initialized register swap: accepted=%t want=%t, state=%#v want=%#v", consumer.name, got, accepted, state, want)
					}
				}
				if before != fmt.Sprintf("%#v", ins) {
					t.Fatal("observer changed original source metadata")
				}
			})
		}
	}
}

func TestX86ResultSwapEveryInputByteAndAliasPreservation(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, test := range []struct {
			row             string
			first, second   int
			firstMask, last uint8
			width           int
		}{
			{"XCHGB AH,AL", 0, 0, 2, 1, 1},
			{"XCHGB AL,AH", 0, 0, 1, 2, 1},
			{"XCHGB AX,AL", 0, 0, 1, 1, 1},
			{"XCHGB AL,BL", 0, 3, 1, 1, 1},
			{"XCHGW AX,BX", 0, 3, 3, 3, 2},
			{"XCHGL AX,BX", 0, 3, 15, 15, 4},
			{"XCHGL BX,BX", 3, 3, 15, 15, 4},
			{"XCHGQ AX,BX", 0, 3, 255, 255, 8},
		} {
			if arch == "386" && test.width == 8 {
				continue // Go rejects this Q row; rejection is exercised below.
			}
			t.Run(arch+"/"+test.row, func(t *testing.T) {
				ins := x86YMMReadSource(t, test.row)
				for operand := 0; operand < 2; operand++ {
					for missing := -1; missing < 8; missing++ {
						initial := x86ResultState{flags: x86ByteFlagPF | x86ByteFlagSF}
						initial.gp[test.first] = test.firstMask | 0x80
						initial.gp[test.second] |= test.last | 0x80
						index, mask := test.first, test.firstMask
						if operand == 1 {
							index, mask = test.second, test.last
						}
						if missing >= 0 {
							initial.gp[index] &^= uint8(1) << uint(missing)
						}
						need := mask
						if test.first == test.second {
							need = test.firstMask | test.last
						}
						accepted := missing < 0 || need&(uint8(1)<<uint(missing)) == 0
						want := initial.clone()
						if accepted && test.width >= 4 {
							want.gp[test.first], want.gp[test.second] = 0xff, 0xff
						}
						for _, consumer := range x86ResultGPSIMDConsumers {
							state := initial.clone()
							if got := consumer.step(ins, &state, nil, 0, arch); got != accepted || !reflect.DeepEqual(state, want) {
								t.Fatalf("%s operand=%d missing=%d: accepted=%t want=%t, state=%#v want=%#v", consumer.name, operand, missing, got, accepted, state, want)
							}
						}
					}
				}
			})
		}
	}
}

func TestX86ResultSwapOpaqueIdentityIsNotNumeric(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, width := range []string{"B", "W", "L", "Q"} {
			if arch == "386" && width == "Q" {
				continue
			}
			for _, second := range []string{"numeric", "opaque", "unknown", "self"} {
				t.Run(arch+"/"+width+"/"+second, func(t *testing.T) {
					row := "XCHG" + width + " AX,BX"
					initial := x86ResultState{flags: x86ByteFlagsAll}
					initial.pointerGP[0] = true
					if second == "numeric" {
						initial.gp[3] = 0xff
					} else if second == "opaque" {
						initial.pointerGP[3] = true
					} else if second == "self" {
						row = "XCHG" + width + " AX,AX"
					}
					word := width == "Q" && arch == "amd64" || width == "L" && arch == "386"
					accepted := second == "self" && width != "B" || word && second != "unknown"
					want := initial.clone()
					if accepted && second != "self" {
						want.gp[0], want.gp[3] = initial.gp[3], initial.gp[0]
						want.pointerGP[0], want.pointerGP[3] = initial.pointerGP[3], initial.pointerGP[0]
					}
					ins := x86YMMReadSource(t, row)
					for _, consumer := range x86ResultGPSIMDConsumers {
						state := initial.clone()
						if got := consumer.step(ins, &state, nil, 0, arch); got != accepted || !reflect.DeepEqual(state, want) {
							t.Fatalf("%s opaque domain: accepted=%t want=%t, state=%#v want=%#v", consumer.name, got, accepted, state, want)
						}
					}
				})
			}
		}
	}
}

func TestX86ResultSwapAccumulatorNOPDoesNotDefineBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, width := range []string{"W", "L", "Q"} {
			if arch == "386" && width == "Q" {
				continue
			}
			for mask := 0; mask < 256; mask++ {
				ins := x86YMMReadSource(t, "XCHG"+width+" AX,AX")
				initial := x86ResultState{flags: uint8(mask) & x86ByteFlagsAll}
				initial.gp[0] = uint8(mask)
				for _, consumer := range x86ResultGPSIMDConsumers {
					state := initial.clone()
					if !consumer.step(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, initial) {
						t.Fatalf("%s/%s/%s opcode90 manufactured defined bytes or changed flags at mask=%02x", arch, width, consumer.name, mask)
					}
				}
			}
		}
	}
}

func TestX86ResultSwapOriginalScalarLaneWitnessAndAllPaths(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, resultMove, typ := 8, "MOVQ", "uint64"
		if arch == "386" {
			word, resultMove, typ = 4, "MOVL", "uint32"
		}
		finish := fmt.Sprintf("MOVL $0,BX\nMOVL BX,X0\nPINSRW $0,AX,X0\nVPEXTRQ $0,X0,BX\n%s BX,ret0+%d(FP)\nRET", resultMove, word)
		for name, test := range map[string]struct {
			body string
			pass bool
		}{
			"original AH AL":              {"MOVW x+0(FP),AX\nXCHGB AH,AL\n" + finish, true},
			"simultaneous AL AH":          {"MOVW x+0(FP),AX\nXCHGB AL,AH\n" + finish, true},
			"partial unknown AH":          {"MOVB x+0(FP),AL\nXCHGB AH,AL\n" + finish, false},
			"unknown AL":                  {"MOVB $7,AH\nXCHGB AH,AL\n" + finish, false},
			"NOP is not L zero extension": {"MOVW x+0(FP),AX\nXCHGL AX,AX\nMOVL AX,X0\n" + fmt.Sprintf("PEXTRD $0,X0,BX\n%s BX,ret0+%d(FP)\nRET", resultMove, word), false},
			"flags survive every swap":    {"MOVW x+0(FP),AX\nCMPW AX,$0\nXCHGB AH,AL\nJE other\nXCHGW AX,AX\nJMP done\nother:\nXCHGB AH,AL\ndone:\n" + finish, true},
			"one path unknown byte":       {"MOVB x+0(FP),AL\nCMPB AL,$0\nJE done\nMOVB $7,AH\ndone:\nXCHGB AH,AL\n" + finish, false},
			"native memory not granted":   {"MOVW x+0(FP),AX\nXCHGW AX,(SI)\n" + finish, false},
			"result RMW not granted":      {fmt.Sprintf("MOVW x+0(FP),AX\nXCHGW AX,ret0+%d(FP)\n", word) + finish, false},
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x uint16) "+typ, test.body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					err := check(file.Funcs[0], sig, arch)
					if test.pass && err != nil || !test.pass && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("all-path scalar input/result obligation pass=%t error=%v", test.pass, err)
					}
				}
			})
		}
	}
}

func TestX86ResultSwapREXAliasesKeepContext(t *testing.T) {
	for _, high := range []string{"AH", "CH", "DH", "BH"} {
		for _, rex := range []string{"SI", "DIB", "R11", "R11B"} {
			for _, reverse := range []bool{false, true} {
				row := "XCHGB " + high + "," + rex
				if reverse {
					row = "XCHGB " + rex + "," + high
				}
				t.Run(row, func(t *testing.T) {
					source := "TEXT ·Value(SB),4,$0-4\nMOVL $7,AX\nMOVL $9,BX\nMOVL $11,CX\nMOVL $13,DX\nMOVL $17,SI\nMOVL $19,DI\nMOVL $23,R11\n" + row + "\nMOVL AX,ret0+0(FP)\nRET\n"
					goAssemblerOracleOutput(t, "amd64", source, "", true)
					pkg := mustGoPackage(t, "example.invalid/resultinit", "package resultinit\nfunc Value() uint32\n")
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ResultSwapTranslateAPI(t, api, source, pkg, "amd64", "x86_64-unknown-linux-gnu")
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("%s gave a high-byte spelling a different physical REX view: %v", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86ResultSwapOpaqueOriginalSourceAndResultBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, swap, typ, word := "MOVQ", "XCHGQ", "uint64", 8
		if arch == "386" {
			move, swap, typ, word = "MOVL", "XCHGL", "uint32", 4
		}
		prefix := fmt.Sprintf("%s p+0(FP),AX\n%s x+%d(FP),BX\n%s AX,BX\n", move, move, word, swap)
		for name, test := range map[string]struct {
			body string
			pass bool
		}{
			"numeric snapshot reaches result": {prefix + fmt.Sprintf("%s AX,ret0+%d(FP)\nRET", move, 2*word), true},
			"opaque snapshot is not numeric":  {prefix + fmt.Sprintf("%s BX,ret0+%d(FP)\nRET", move, 2*word), false},
			"opaque snapshot has no pointee":  {prefix + fmt.Sprintf("MOVL (BX),AX\n%s AX,ret0+%d(FP)\nRET", move, 2*word), false},
			"unknown second required read":    {fmt.Sprintf("%s p+0(FP),AX\nMOVW $7,BX\n%s AX,BX\n%s $42,ret0+%d(FP)\nRET", move, swap, move, 2*word), false},
			"opaque survives encoded NOP":     {fmt.Sprintf("%s p+0(FP),AX\nXCHGL AX,AX\n%s $42,ret0+%d(FP)\nRET", move, move, 2*word), true},
			"opaque NOP defines no numbers":   {fmt.Sprintf("%s p+0(FP),AX\nXCHGL AX,AX\n%s AX,ret0+%d(FP)\nRET", move, move, 2*word), false},
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(p *[8]uint32,x "+typ+") "+typ, test.body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					err := check(file.Funcs[0], sig, arch)
					if test.pass && err != nil || !test.pass && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("opaque identity/result separation pass=%t error=%v", test.pass, err)
					}
				}
			})
		}
	}
}

func TestX86ResultSwapRejectsNonRegisterAuthorityAndMalformedGrammar(t *testing.T) {
	for _, test := range []struct {
		arch, row string
	}{
		{"amd64", "XCHGB SP,AX"}, {"amd64", "XCHGB BPB,AL"},
		{"386", "XCHGB BP,DI"}, {"amd64", "XCHGQ SP,AX"},
		{"amd64", "XCHGQ BP,AX"}, {"386", "XCHGQ AX,BX"},
		{"386", "XCHGL R8,AX"}, {"386", "XCHGB R8B,AL"},
		{"amd64", "XCHGW $1,AX"}, {"amd64", "XCHGL AX,X0"},
		{"amd64", "XCHGL.Z AX,BX"}, {"arm64", "XCHGL AX,BX"},
		{"amd64", "XCHGW AX"}, {"amd64", "XCHGL AX,BX,CX"},
		{"amd64", "XCHGB AH,(R11)"}, {"amd64", "XCHGB (R11),AH"},
		{"amd64", "XCHGQ AX,(BX)"}, {"amd64", "XCHGQ (BX),AX"},
		{"amd64", "XCHGW AX,value+0(FP)"}, {"amd64", "XCHGW AX,tmp+0(SP)"},
		{"amd64", "XCHGW AX,value(SB)"}, {"amd64", "XCHGW AX,$value(SB)"},
	} {
		t.Run(test.arch+"/"+test.row, func(t *testing.T) {
			ins := x86YMMReadSource(t, test.row)
			initial := x86ResultState{flags: x86ByteFlagsAll, fp: []bool{true, true}, auto: []bool{true, true}}
			for index := range initial.gp {
				initial.gp[index], initial.pointerGP[index] = 0xff, true
			}
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := initial.clone()
				accepted := consumer.step(ins, &state, []bool{true, true}, 0, test.arch)
				if test.arch == "386" && test.row == "XCHGB BP,DI" {
					want := initial.clone()
					want.pointerGP[5], want.pointerGP[7] = false, false
					if !accepted || !reflect.DeepEqual(state, want) {
						t.Fatal("ordinary mode32 byte exchange changed unrelated state", consumer.name, state)
					}
					continue
				}
				if accepted || !reflect.DeepEqual(state, initial) {
					t.Fatalf("%s widened register or memory authority: %#v", consumer.name, state)
				}
			}
		})
	}
	ins := x86YMMReadSource(t, "XCHGL AX,BX")
	if _, err := parseAMD64ExchangeForm("amd64", "XCHGL", amd64ExchangeSpec{amd64ExchangeSwap, 16}, ins); err == nil {
		t.Fatal("typed exchange accepted a contradictory width")
	}
	if _, err := parseAMD64ExchangeForm("amd64", "XCHGW", amd64ExchangeSpecs["XCHGW"], ins); err == nil {
		t.Fatal("typed exchange accepted a contradictory source opcode")
	}
}
