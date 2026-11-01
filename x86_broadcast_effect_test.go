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
	"sort"
	"strings"
	"testing"
)

// This directory is independent of the production broadcast grammar.
var x86BroadcastTestDirectory = []struct {
	name, table  string
	bytes, lane  int
	destinations string
	source       string
}{
	{"VPBROADCASTB", "_yvpbroadcastb", 1, 1, "XYZ", "XG"},
	{"VPBROADCASTW", "_yvpbroadcastb", 2, 2, "XYZ", "XG"},
	{"VPBROADCASTD", "_yvpbroadcastb", 4, 4, "XYZ", "XG"},
	{"VPBROADCASTQ", "_yvpbroadcastb", 8, 8, "XYZ", "XG"},
	{"VBROADCASTSS", "_yvbroadcastss", 4, 4, "XYZ", "X"},
	{"VBROADCASTSD", "_yvbroadcastsd", 8, 8, "YZ", "X"},
	{"VBROADCASTF128", "_yvbroadcastf128", 16, 8, "Y", ""},
	{"VBROADCASTI128", "_yvbroadcastf128", 16, 8, "Y", ""},
	{"VBROADCASTF32X2", "_yvbroadcastf32x2", 8, 4, "YZ", "X"},
	{"VBROADCASTI32X2", "_yvbroadcasti32x2", 8, 4, "XYZ", "X"},
	{"VBROADCASTF32X4", "_yvbroadcastf32x4", 16, 4, "YZ", ""},
	{"VBROADCASTF64X2", "_yvbroadcastf32x4", 16, 8, "YZ", ""},
	{"VBROADCASTI32X4", "_yvbroadcastf32x4", 16, 4, "YZ", ""},
	{"VBROADCASTI64X2", "_yvbroadcastf32x4", 16, 8, "YZ", ""},
	{"VBROADCASTF32X8", "_yvbroadcastf32x8", 32, 4, "Z", ""},
	{"VBROADCASTF64X4", "_yvbroadcastf32x8", 32, 8, "Z", ""},
	{"VBROADCASTI32X8", "_yvbroadcastf32x8", 32, 4, "Z", ""},
	{"VBROADCASTI64X4", "_yvbroadcastf32x8", 32, 8, "Z", ""},
	{"VPBROADCASTMB2Q", "_yvpbroadcastmb2q", 1, 8, "XYZ", "K"},
	{"VPBROADCASTMW2D", "_yvpbroadcastmb2q", 2, 4, "XYZ", "K"},
}

func TestX86BroadcastCompleteIndependentGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	compact := func(s string) string { return strings.Join(strings.Fields(s), "") }
	text := compact(string(data))
	var actualNames, expectedNames []string
	for _, match := range regexp.MustCompile("as: A(VP?BROADCAST[A-Z0-9]+)").FindAllStringSubmatch(string(data), -1) {
		actualNames = append(actualNames, match[1])
	}
	for _, spec := range x86BroadcastTestDirectory {
		expectedNames = append(expectedNames, spec.name)
	}
	sort.Strings(actualNames)
	sort.Strings(expectedNames)
	if !reflect.DeepEqual(actualNames, expectedNames) {
		t.Fatalf("whole Go broadcast directory changed: %v", actualNames)
	}
	rows := func(z, classes string, advance int) string {
		return fmt.Sprintf("{zcase:%s,zoffset:%d,args:argList{%s}},", z, advance, classes)
	}
	want := map[string]string{}
	want["_yvbroadcastf128"] = rows("Zvex_rm_v_r", "Ym,Yyr", 2)
	for _, table := range []string{"_yvbroadcastf32x2", "_yvbroadcastf32x4", "_yvbroadcastf32x8", "_yvbroadcasti32x2", "_yvbroadcastsd", "_yvbroadcastss", "_yvpbroadcastb", "_yvpbroadcastmb2q"} {
		widths, source := []string{"YyrEvex", "Yzr"}, "Ym"
		switch table {
		case "_yvbroadcastf32x2", "_yvbroadcastsd":
			source = "YxmEvex"
		case "_yvbroadcasti32x2", "_yvbroadcastss":
			widths, source = []string{"YxrEvex", "YyrEvex", "Yzr"}, "YxmEvex"
		case "_yvbroadcastf32x8":
			widths = []string{"Yzr"}
		case "_yvpbroadcastb":
			widths, source = []string{"YxrEvex", "YyrEvex", "Yzr"}, "Yrl"
		case "_yvpbroadcastmb2q":
			widths, source = []string{"YxrEvex", "YyrEvex", "Yzr"}, "Yk"
		}
		if table == "_yvbroadcastsd" {
			want[table] += rows("Zvex_rm_v_r", "Yxm,Yyr", 2)
		}
		if table == "_yvbroadcastss" || table == "_yvpbroadcastb" {
			for _, dst := range []string{"Yxr", "Yyr"} {
				want[table] += rows("Zvex_rm_v_r", "Yxm,"+dst, 2)
			}
		}
		for pass := 0; pass < 2; pass++ {
			for _, dst := range widths {
				if table == "_yvpbroadcastmb2q" {
					want[table] += rows("Zevex_rm_v_r", source+","+dst, 3)
				} else {
					want[table] += rows("Zevex_rm_v_r", source+","+dst, 0)
					want[table] += rows("Zevex_rm_k_r", source+",Yknot0,"+dst, 3)
				}
			}
			if table != "_yvpbroadcastb" {
				break
			}
			source = "YxmEvex"
		}
	}
	for table, expected := range want {
		found := regexp.MustCompile("(?s)var " + table + " = \\[\\]ytab\\{(.*?)\\n\\}").FindStringSubmatch(string(data))
		if len(found) != 2 || compact(found[1]) != expected {
			t.Fatalf("complete %s zcase/offset/classes changed", table)
		}
	}
	vex := func(width int, opcode string) string {
		return fmt.Sprintf("avxEscape|vex%d|vex66|vex0F38|vexW0,%s,", width, opcode)
	}
	evex := func(width int, w, tuple, prefix, opcode string) string {
		return fmt.Sprintf("avxEscape|evex%d|%s|evex0F38|evex%s,%s,%s,", width, prefix, w, tuple, opcode)
	}
	total := 0
	for _, spec := range x86BroadcastTestDirectory {
		var code strings.Builder
		name := spec.name
		switch {
		case strings.HasPrefix(name, "VPBROADCAST") && spec.source == "XG":
			opcode := map[string]string{"VPBROADCASTB": "0x78", "VPBROADCASTW": "0x79", "VPBROADCASTD": "0x58", "VPBROADCASTQ": "0x59"}[name]
			gp := map[string]string{"VPBROADCASTB": "0x7A", "VPBROADCASTW": "0x7B", "VPBROADCASTD": "0x7C", "VPBROADCASTQ": "0x7C"}[name]
			w := "W0"
			if spec.bytes == 8 {
				w = "W1"
			}
			code.WriteString(vex(128, opcode) + vex(256, opcode))
			for _, width := range []int{128, 256, 512} {
				code.WriteString(evex(width, w, "evexZeroingEnabled", "evex66", gp))
			}
			for _, width := range []int{128, 256, 512} {
				code.WriteString(evex(width, w, fmt.Sprintf("evexN%d|evexZeroingEnabled", spec.bytes), "evex66", opcode))
			}
		case name == "VBROADCASTSS" || name == "VBROADCASTSD":
			opcode, w := "0x18", "W0"
			if name == "VBROADCASTSD" {
				opcode, w = "0x19", "W1"
			} else {
				code.WriteString(vex(128, opcode))
			}
			code.WriteString(vex(256, opcode))
			for _, bank := range spec.destinations {
				code.WriteString(evex(map[rune]int{'X': 128, 'Y': 256, 'Z': 512}[bank], w, fmt.Sprintf("evexN%d|evexZeroingEnabled", spec.bytes), "evex66", opcode))
			}
		case spec.source == "K":
			w, opcode := "W0", "0x3A"
			if spec.bytes == 1 {
				w, opcode = "W1", "0x2A"
			}
			for _, width := range []int{128, 256, 512} {
				code.WriteString(evex(width, w, "0", "evexF3", opcode))
			}
		case strings.HasSuffix(name, "128"):
			opcode := "0x1A"
			if strings.Contains(name, "I") {
				opcode = "0x5A"
			}
			code.WriteString(vex(256, opcode))
		default:
			w, opcode := "W0", "0x1A"
			if strings.Contains(name, "64") {
				w = "W1"
			}
			if strings.HasSuffix(name, "X2") && strings.Contains(name, "32") {
				opcode = "0x19"
			}
			if spec.bytes == 32 {
				opcode = "0x1B"
			}
			if strings.Contains(name, "I") {
				opcode = map[string]string{"0x19": "0x59", "0x1A": "0x5A", "0x1B": "0x5B"}[opcode]
			}
			for _, bank := range spec.destinations {
				code.WriteString(evex(map[rune]int{'X': 128, 'Y': 256, 'Z': 512}[bank], w, fmt.Sprintf("evexN%d|evexZeroingEnabled", spec.bytes), "evex66", opcode))
			}
		}
		expected := "{as:A" + name + ",ytab:" + spec.table + ",prefix:Pavx,op:opBytes{" + code.String() + "}}"
		if !strings.Contains(text, expected) {
			t.Fatalf("complete attributes/opcode row changed: %s", expected)
		}
		total += strings.Count(want[spec.table], "{zcase:")
	}
	if total != 111 {
		t.Fatalf("independent row directory: %d", total)
	}
}

func TestX86BroadcastBothResultObservers(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, spec := range x86BroadcastTestDirectory {
			if spec.source != "X" && spec.source != "XG" {
				continue
			}
			for _, bank := range spec.destinations {
				for _, input := range spec.source {
					for _, alias := range []bool{false, true} {
						src, dst, sourceIndex := "X1", fmt.Sprintf("%c2", bank), 1
						if alias {
							src, sourceIndex = "X2", 2
						}
						if input == 'G' {
							src, sourceIndex = "AX", 0
						}
						for _, masked := range []string{"", "K3,", "Z"} {
							op, mask := spec.name, masked
							if masked == "Z" {
								op, mask = op+".Z", "K3,"
							}
							row := op + " " + src + "," + mask + dst
							t.Run(arch+"/"+row+fmt.Sprint(alias), func(t *testing.T) {
								ins := x86YMMReadSource(t, row)
								width := spec.bytes
								if arch == "386" && spec.name == "VPBROADCASTQ" && input == 'G' {
									width = 4
								}
								for _, consumer := range x86ResultGPSIMDConsumers {
									state := x86ResultState{flags: x86ByteFlagsAll}
									state.gp[sourceIndex] = uint8((1 << uint(width)) - 1)
									state.xmm[sourceIndex] = uint16((1 << uint(width)) - 1)
									state.xmm[2] |= 0xffff
									state.masks[3] = true
									if !consumer.step(ins, &state, nil, 0, arch) || state.xmm[2] != 0xffff || state.flags != x86ByteFlagsAll {
										t.Fatalf("%s did not close initialized register broadcast %+v", consumer.name, state)
									}
									for missing := 0; missing < width; missing++ {
										state := x86ResultState{flags: x86ByteFlagsAll}
										state.gp[sourceIndex] = uint8((1 << uint(width)) - 1)
										state.xmm[sourceIndex] = uint16((1 << uint(width)) - 1)
										state.masks[3] = true
										if masked == "K3," {
											state.xmm[2] |= 0xffff
										}
										if input == 'G' {
											state.gp[sourceIndex] &^= 1 << uint(missing)
										} else {
											state.xmm[sourceIndex] &^= 1 << uint(missing)
										}
										before := state.clone()
										if consumer.step(ins, &state, nil, 0, arch) || !reflect.DeepEqual(before, state) {
											t.Fatalf("%s manufactured missing source byte%d", consumer.name, missing)
										}
									}
								}
							})
						}
					}
				}
			}
		}
	}
}

func TestX86BroadcastDeadResultsRetainCompleteFamilyObligation(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, spec := range x86BroadcastTestDirectory {
			source := "(AX)"
			if spec.source == "K" {
				source = "K0"
			} else if strings.Contains(spec.source, "X") {
				source = "X1"
			}
			row := fmt.Sprintf("%s %s,%c2", spec.name, source, spec.destinations[0])
			for _, declaration := range []string{"func Value()", "func Value(unused bool)"} {
				t.Run(arch+"/"+spec.name+"/"+declaration, func(t *testing.T) {
					_, file, signature, source := x86ResultInitializationFixture(t, arch, declaration, row+"\nRET\n")
					goAssemblerOracleOutput(t, arch, source, "", true)
					if !x86TypedFPResultNeedsProof(file.Funcs[0], signature, arch) {
						t.Fatal("dead broadcast bypassed its whole-source input obligation", row)
					}
				})
			}
		}
	}
}

func TestX86BroadcastOriginalFunctionResultClosure(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, typ, index := 8, "MOVQ", "uint64", 11
		if arch == "386" {
			word, move, typ, index = 4, "MOVL", "uint32", 3
		}
		for _, bad := range []bool{false, true} {
			body := fmt.Sprintf("%s x+0(FP),AX\nPINSRD $0,AX,X%d\n", move, index)
			if bad {
				body = "NOP\n"
			}
			body += fmt.Sprintf("VPBROADCASTW X%d,X%d\nVPEXTRQ $0,X%d,BX\n%s BX,ret0+%d(FP)\nRET", index, index, index, move, word)
			_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x "+typ+") "+typ, body)
			goAssemblerOracleOutput(t, arch, source, "", true)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				err := check(file.Funcs[0], sig, arch)
				if bad && !errors.Is(err, ErrProbeNeedsContext) || !bad && err != nil {
					t.Fatalf("%s bad%t: %v", arch, bad, err)
				}
			}
		}
	}
}

func TestX86BroadcastOriginalPhysicalWIGWitness(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		code := assembleX87ControlBytes(t, arch, "TEXT f(SB),4,$0-0\nVPBROADCASTQ AX,X2\nRET\n")
		want := []byte{0x62, 0xf2, 0xfd, 0x08, 0x7c, 0xd0, 0xc3}
		if !bytes.Equal(code, want) {
			t.Fatalf("%s actual bytes%x want%x", arch, code, want)
		}
		state := x86ResultState{gp: [16]uint8{15}}
		ins := x86YMMReadSource(t, "VPBROADCASTQ AX,X2")
		for _, consumer := range x86ResultGPSIMDConsumers {
			copy := state.clone()
			valid := arch == "386"
			if got := consumer.step(ins, &copy, nil, 0, arch); got != valid {
				t.Fatalf("%s %s WIG accepted%t want%t", arch, consumer.name, got, valid)
			}
		}
	}
}

func TestX86BroadcastMode32GPQPhysicalLaneWidth(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\nMOVL $1,AX\nVPBROADCASTQ AX,X2\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", Sigs: map[string]FuncSig{
		"f": {Name: "f", Ret: Void},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "insertelement <4 x i32>") || strings.Contains(ir, "insertelement <2 x i64>") {
		t.Fatal("mode32 original W1 GP broadcast did not use physical WIG dword lanes")
	}
}

func TestX86BroadcastRawOriginalMode32GPQWIG(t *testing.T) {
	code := assembleX87ControlBytes(t, "386", "TEXT f(SB),4,$0-0\nVPBROADCASTQ AX,X2\nRET\n")
	want := []byte{0x62, 0xf2, 0xfd, 0x08, 0x7c, 0xd0, 0xc3}
	if !bytes.Equal(code, want) {
		t.Fatalf("actual Go W1 bytes%x", code)
	}
	ins, length, known, err := decodedX86VEXPackedBroadcastInstruction(code[:6], 32)
	if err != nil || !known || length != 6 {
		t.Fatalf("actual Go mode32 WIG decoder: known%t length%d err%v", known, length, err)
	}
	form, known, err := x86BroadcastProperties(ins.Op, ins, "386")
	if err != nil || !known || form.sourceBytes != 4 || form.laneBits != 32 {
		t.Fatalf("physical mode32 GP-Q effect %+v known%t err%v", form, known, err)
	}
}

func TestX86BroadcastTypedGrammarCompleteGoWitnesses(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		source.WriteString("TEXT f(SB),4,$0-0\n")
		for _, spec := range x86BroadcastTestDirectory {
			inputs := []string{"32(AX)"}
			for _, kind := range spec.source {
				inputs = append(inputs, map[rune]string{'X': "X3", 'G': "AX", 'K': "K0"}[kind])
			}
			if spec.source == "K" {
				inputs = inputs[1:]
			}
			for _, bank := range spec.destinations {
				for _, input := range inputs {
					for _, masking := range []int{0, 1, 2} {
						if masking != 0 && (spec.source == "K" || strings.HasSuffix(spec.name, "128")) {
							continue
						}
						op, mask := spec.name, ""
						if masking != 0 {
							mask = "K7,"
						}
						if masking == 2 {
							op += ".Z"
						}
						row := fmt.Sprintf("%s %s,%s%c7", op, input, mask, bank)
						source.WriteString(row + "\n")
						t.Run(arch+"/"+row, func(t *testing.T) {
							ins := x86YMMReadSource(t, row)
							f, known, err := x86BroadcastProperties(ins.Op, ins, arch)
							width, lane := spec.bytes, spec.lane*8
							if arch == "386" && spec.name == "VPBROADCASTQ" && input == "AX" {
								width, lane = 4, 32
							}
							if err != nil || !known || f.sourceBytes != width || f.laneBits != lane ||
								f.byteWidth != map[rune]int{'X': 16, 'Y': 32, 'Z': 64}[bank] || (f.mask >= 0) != (masking != 0) || f.zeroing != (masking == 2) {
								t.Fatalf("typed row %+v known%t err%v", f, known, err)
							}
						})
					}
				}
			}
		}
		source.WriteString("RET\n")
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
	}
}

func TestX86BroadcastAuthorityAndGrammarControls(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []string{
			"VPBROADCASTW $1,X0", "VPBROADCASTW Y0,X0", "VPBROADCASTW AL,X0",
			"VBROADCASTSD AX,Y0", "VBROADCASTSD X0,X0", "VBROADCASTSS.BCST X0,Y0",
			"VBROADCASTF128 X0,Y0", "VBROADCASTF32X4 X0,Y0", "VBROADCASTF32X2 X0,X0",
			"VPBROADCASTMB2Q X0,X1", "VPBROADCASTMW2D.Z K1,X1",
			"VPBROADCASTW.Z X0,X1", "VPBROADCASTW X0,K0,X1",
		} {
			t.Run(arch+"/"+row, func(t *testing.T) {
				source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
				if row == "VPBROADCASTW.Z X0,X1" {
					// Go 1.20 emits reserved EVEX.z=1/aaa=0. Observe the
					// complete original bytes and require raw rejection too;
					// this is never a supported form or an executable test.
					x86BroadcastReservedZeroMaskGoObservation(t, arch, source,
						[]byte{0x62, 0xf2, 0x7d, 0x88, 0x79, 0xc8, 0xc3}, true)
				} else {
					goAssemblerOracleOutput(t, arch, source, "", false)
				}
				ins := x86YMMReadSource(t, row)
				if _, known, err := x86BroadcastProperties(ins.Op, ins, arch); !known || err == nil {
					t.Fatal("Go-rejected form acquired typed effect")
				}
			})
		}
		for _, row := range []string{"VPBROADCASTW (AX),X2", "VPBROADCASTW x+0(FP),X2", "VBROADCASTF32X4 (AX),Y2", "VPBROADCASTMB2Q K0,X2", "VPBROADCASTW SP,X2", "VPBROADCASTQ BP,X2"} {
			ins := x86YMMReadSource(t, row)
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := x86ResultState{}
				for index := range state.gp {
					state.gp[index] = 0xff
				}
				for index := range state.xmm {
					state.xmm[index] = 0xffff
				}
				for index := range state.masks {
					state.masks[index] = true
				}
				// K0 is an ordinary initialized data source here, not a
				// writemask or a grant of native memory permission.
				ordinary := arch == "386" && row == "VPBROADCASTQ BP,X2" || row == "VPBROADCASTMB2Q K0,X2"
				if consumer.step(ins, &state, nil, 0, arch) != ordinary {
					t.Fatalf("%s borrowed native/mask/SP/BP permission: %s", consumer.name, row)
				}
			}
		}
		for _, row := range []string{"VPBROADCASTW AX,X2", "VPBROADCASTQ AX,Z2"} {
			ins := x86YMMReadSource(t, row)
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := x86ResultState{gp: [16]uint8{255}, pointerGP: [16]bool{true}}
				before := state.clone()
				if consumer.step(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
					t.Fatal("opaque identity washed into numerical broadcast")
				}
			}
		}
		for _, row := range []string{"VPBROADCASTW X1,K3,X2", "VPBROADCASTW.Z X1,K3,X2"} {
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := x86ResultState{xmm: [32]uint16{1: 65535, 2: 65535}}
				if consumer.step(x86YMMReadSource(t, row), &state, nil, 0, arch) {
					t.Fatal("undefined K mask accepted")
				}
			}
		}
		for missing := 0; missing < 16; missing++ {
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := x86ResultState{xmm: [32]uint16{1: 65535, 2: 65535 &^ (1 << uint(missing))}, masks: [8]bool{3: true}}
				if consumer.step(x86YMMReadSource(t, "VPBROADCASTW X1,K3,X2"), &state, nil, 0, arch) {
					t.Fatal("unknown inactive merge destination byte accepted")
				}
			}
		}
	}
	for _, row := range []string{"VPBROADCASTW X8,X0", "VPBROADCASTQ AX,Y15", "VBROADCASTF128 (AX),Y15", "VBROADCASTF32X2 X20,Y21"} {
		ins := x86YMMReadSource(t, row)
		goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
		if _, known, err := x86BroadcastProperties(ins.Op, ins, "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("Go object mistaken for physical high-bank binding")
		}
	}
}

func TestX86BroadcastCompleteRegisterBanks(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		limit := 32
		gps := []Reg{AX, CX, DX, BX, SP, BP, SI, DI, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
		if arch == "386" {
			limit, gps = 8, gps[:8]
		}
		for _, spec := range x86BroadcastTestDirectory {
			if spec.source != "X" && spec.source != "XG" {
				continue
			}
			var sources []Reg
			for i := 0; i < limit; i++ {
				sources = append(sources, Reg(fmt.Sprint("X", i)))
			}
			if spec.source == "XG" {
				sources = append(sources, gps...)
			}
			for _, src := range sources {
				for _, bank := range spec.destinations {
					for dst := 0; dst < limit; dst++ {
						for masking := 0; masking < 3; masking++ {
							op, mask := spec.name, ""
							if masking != 0 {
								mask = "K7,"
							}
							if masking == 2 {
								op += ".Z"
							}
							ins := x86YMMReadSource(t, fmt.Sprintf("%s %s,%s%c%d", op, src, mask, bank, dst))
							for _, consumer := range x86ResultGPSIMDConsumers {
								state := x86ResultState{flags: x86ByteFlagsAll, masks: [8]bool{7: true}}
								for i := range state.gp {
									state.gp[i] = 255
								}
								for i := range state.xmm {
									state.xmm[i] = 65535
								}
								valid := src != SP && (src != BP || arch == "386")
								if got := consumer.step(ins, &state, nil, 0, arch); got != valid || state.flags != x86ByteFlagsAll {
									t.Fatalf("%s %s row%s accepted%t want%t", arch, consumer.name, ins.Raw, got, valid)
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestX86BroadcastOriginalAllPathAndOpaqueControls(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, typ, index := 8, "MOVQ", "uint64", 11
		if arch == "386" {
			word, move, typ, index = 4, "MOVL", "uint32", 3
		}
		initialize := fmt.Sprintf("PINSRD $0,AX,X%d\n", index)
		for _, test := range []struct {
			name, body, decl string
			valid            bool
		}{
			{"both_paths", fmt.Sprintf("CMP%s AX,AX\nJE good\n%sJMP joined\ngood:\n%sjoined:\n", map[string]string{"amd64": "Q", "386": "L"}[arch], initialize, initialize), "", true},
			{"one_unknown_path", fmt.Sprintf("CMP%s AX,AX\nJE good\nJMP joined\ngood:\n%sjoined:\n", map[string]string{"amd64": "Q", "386": "L"}[arch], initialize), "", false},
			{"partial_word", fmt.Sprintf("PINSRB $0,AX,X%d\n", index), "", false},
			{"opaque_pointer", fmt.Sprintf("VPBROADCASTW AX,X%d\n", index), "func Value(x *uint64) " + typ, false},
		} {
			t.Run(arch+"/"+test.name, func(t *testing.T) {
				decl := test.decl
				if decl == "" {
					decl = "func Value(x " + typ + ") " + typ
				}
				body := fmt.Sprintf("%s x+0(FP),AX\n", move) + test.body
				body += fmt.Sprintf("VPBROADCASTW X%d,X%d\nVPEXTRQ $0,X%d,BX\n%s BX,ret0+%d(FP)\nRET", index, index, index, move, word)
				_, file, sig, source := x86ResultInitializationFixture(t, arch, decl, body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					err := check(file.Funcs[0], sig, arch)
					if test.valid && err != nil || !test.valid && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("valid%t err%v", test.valid, err)
					}
				}
			})
		}
	}
}
