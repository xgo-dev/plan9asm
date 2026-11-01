package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86AESFamilyNamedAndRawThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, target := range x86RawReturnTargets {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", target.triple, raw), func(t *testing.T) {
				var source, declarations strings.Builder
				declarations.WriteString("package aesobjects\n")
				count := 0
				for _, name := range x86AESOracleNames {
					widths := []int{16}
					if strings.HasPrefix(name, "V") && !strings.Contains(name, "IMC") && !strings.Contains(name, "KEYGEN") {
						widths = append(widths, 32, 64)
					}
					for _, width := range widths {
						bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
						for _, operand := range []string{bank + "0", fmt.Sprintf("%d(AX)(CX*2)", width)} {
							row, _ := x86AESOracleRow(name, operand, bank)
							code := x86OrderingHintGoBytes(t, target.arch, "TEXT actual(SB),4,$0-0\n"+row+"\nRET\n")
							if raw {
								row = x86DwordProductDirectives(code[:len(code)-1])
							}
							fmt.Fprintf(&source, "TEXT ·F%d(SB),4,$0-0\n%s\nRET\n", count, row)
							fmt.Fprintf(&declarations, "func F%d()\n", count)
							count++
						}
					}
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source.String(), declarations.String(), target.arch, target.triple)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("original AES formats invented native addresses or vector inputs", api, err)
						}
					})
				}
				file, err := Parse(ArchAMD64, source.String())
				if err != nil {
					t.Fatal(err)
				}
				file, err = normalizeX86RawFile(file, target.arch)
				if err != nil {
					t.Fatal(err)
				}
				signatures := make(map[string]FuncSig)
				for _, fn := range file.Funcs {
					name := strings.TrimPrefix(fn.Sym, "·")
					signatures[name] = FuncSig{Name: name, Ret: Void}
				}
				ir := x86InstructionFormatObjectUnit(t, file, signatures, target.arch, target.triple, 0,
					func(c *amd64Ctx, ins Instr) (bool, bool, error) { return c.lowerAES(ins.Op, ins) })
				for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, input, level)
					}
				}
			})
		}
	}
}

func TestX86AESFamilyCompressedDisp8EntireTupleAxes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86AESOracleNames[6:10] {
			for _, width := range []int{16, 32, 64} {
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				for _, disp := range []int{-128, -1, 1, 127} {
					for _, address := range []string{fmt.Sprintf("%d(AX)", disp*width), fmt.Sprintf("%d(AX)(CX*2)", disp*width), fmt.Sprintf("%d(BP)", disp*width)} {
						// X16 forces Go's EVEX X/Y rows. Their original bytes are
						// never patched into a different register contract. Go accepts
						// that spelling in mode32, but physical high banks remain Context.
						row := name + " " + address + "," + bank + "1," + bank + "16"
						if width == 64 {
							row = name + " " + address + ",Z1,Z2"
						}
						t.Run(arch+"/"+row, func(t *testing.T) {
							code := x86OrderingHintGoBytes(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
							mode := 64
							if arch == "386" {
								if width != 64 {
									if _, _, known, err := decodedX86AESInstruction(code, 32); !known || !errors.Is(err, ErrProbeNeedsContext) {
										t.Fatal("actual mode32 high destination acquired a low-bank identity", row, fmt.Sprintf("%x", code), err)
									}
									// Inspect exactly the same original bytes in physical
									// mode64 for their tuple address, not mode32 permission.
								} else {
									mode = 32
								}
							}
							ins, length, known, err := decodedX86AESInstruction(code, mode)
							if !known || err != nil || length != len(code)-1 || ins.Args[0].Mem.Off != int64(disp*width) {
								t.Fatal("actual Go compressed full tuple did not retain exact native address", row, fmt.Sprintf("%x", code), ins, err)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86AESFamilyOriginalGoPhysicalRegisterExtensionAxes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86AESOracleNames[6:10] {
			for _, width := range []int{16, 32, 64} {
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				for role := 0; role < 3; role++ {
					for _, index := range []int{0, 7, 8, 15, 16, 31} {
						args := []string{bank + "0", bank + "1", bank + "2"}
						args[role] = fmt.Sprintf("%s%d", bank, index)
						row := name + " " + strings.Join(args, ",")
						t.Run(arch+"/"+row, func(t *testing.T) {
							if arch == "386" && width == 64 && index >= 8 {
								goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
								if _, known, err := x86AESProperties(Op(name), x86YMMReadSource(t, row), arch); !known || err == nil {
									t.Fatal("actual Go rejected mode32 Z bank acquired a valid grammar row", row, err)
								}
								return
							}
							code := x86OrderingHintGoBytes(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
							mode := 64
							if arch == "386" {
								mode = 32
								if index >= 8 {
									if _, _, known, err := decodedX86AESInstruction(code, mode); !known || !errors.Is(err, ErrProbeNeedsContext) {
										t.Fatal("actual Go high spelling acquired a different physical mode32 register", row, fmt.Sprintf("%x", code), err)
									}
									return
								}
							}
							ins, length, known, err := decodedX86AESInstruction(code, mode)
							if !known || err != nil || length != len(code)-1 || ins.Args[role].Reg != Reg(args[role]) {
								t.Fatal("all original VEX/EVEX source/state/destination extension bits", row, fmt.Sprintf("%x", code), ins, err)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86AESFamilyMode32NamedHighAndRawReservedBoundaries(t *testing.T) {
	for _, name := range x86AESOracleNames[6:10] {
		for _, bank := range []string{"X", "Y"} {
			row := name + " " + bank + "16," + bank + "1," + bank + "2"
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
			if _, known, err := x86AESProperties(Op(name), x86YMMReadSource(t, row), "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("Go named high mode32 vector borrowed physical identity", row, err)
			}
		}
	}
	valid := x86OrderingHintGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\nVAESENC 64(AX),Z1,Z2\nRET\n")
	for _, mutation := range []func([]byte){func(b []byte) { b[2] &^= 4 }, func(b []byte) { b[3] |= 1 }, func(b []byte) { b[3] |= 0x80 }, func(b []byte) { b[3] |= 0x10 }, func(b []byte) { b[3] |= 0x60 }} {
		changed := append([]byte(nil), valid...)
		mutation(changed)
		if _, _, known, err := decodedX86AESInstruction(changed, 64); !known || err == nil {
			t.Fatal("reserved AES bytes acquired an unrelated raw effect", fmt.Sprintf("%x", changed), err)
		}
	}
}

func TestX86AESFamilyPhysicalWIGIndependentLLVMDecoder(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, name := range x86AESOracleNames[6:] {
		forms := []struct {
			width       int
			destination int
		}{{16, 2}}
		if !strings.Contains(name, "IMC") && !strings.Contains(name, "KEYGEN") {
			forms = append(forms, struct {
				width       int
				destination int
			}{32, 2}, struct {
				width       int
				destination int
			}{16, 16}, struct {
				width       int
				destination int
			}{32, 16}, struct {
				width       int
				destination int
			}{64, 2})
		}
		for _, form := range forms {
			width := form.width
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			row, _ := x86AESOracleRow(name, fmt.Sprintf("%d(AX)", width), bank)
			row = strings.TrimSuffix(row, bank+"2") + fmt.Sprintf("%s%d", bank, form.destination)
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			// Intel's VEX and EVEX AES attributes are WIG. This is an
			// explicit physical-attribute fixture, not a claimed Go named row.
			for _, wide := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/W=%t", row, wide), func(t *testing.T) {
					physical := append([]byte(nil), code[:len(code)-1]...)
					if wide {
						physical[2] |= 0x80
					}
					var input strings.Builder
					for _, b := range physical {
						fmt.Fprintf(&input, "0x%02x ", b)
					}
					ctx, cancel := runtimeOracleStageContext(t)
					defer cancel()
					command := exec.CommandContext(ctx, mc, "--disassemble", "--triple=x86_64-unknown-linux-gnu")
					command.Stdin = strings.NewReader(input.String() + "\n")
					output, err := runtimeOracleCombinedOutput(ctx, command)
					if err != nil || !strings.Contains(strings.ToLower(string(output)), strings.ToLower(name)) || strings.Contains(string(output), "warning:") {
						t.Fatal("independent LLVM22 physical WIG decoder", err, string(output))
					}
					ins, length, known, err := decodedX86AESInstruction(physical, 64)
					if !known || err != nil || length != len(physical) || ins.Op != Op(name) {
						t.Fatal("complete physical AES WIG attribute lost", fmt.Sprintf("%x", physical), ins, err)
					}
				})
			}
		}
	}
}

func TestX86AESFamilyLogicalFPNumericalSpanContracts(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, name := range x86AESOracleNames {
			row, _ := x86AESOracleRow(name, "a+0(FP)", "X")
			for _, contract := range []struct {
				parameters string
				accepted   bool
			}{{"a,b uint64", true}, {"a,b,c,d float32", true}, {"a,b float64", true},
				{"a uint8,b uint64", false}, {"a uint8,b uint64,c uint32", false}, {"a,b *byte", false}, {"a,b,c,d *byte", false}} {
				t.Run(target.triple+"/"+name+"/"+contract.parameters, func(t *testing.T) {
					size := 16
					switch contract.parameters {
					case "a uint8,b uint64":
						if target.arch == "386" {
							size = 12
						}
					case "a uint8,b uint64,c uint32":
						if target.arch == "amd64" {
							size = 20
						}
					case "a,b *byte":
						size = int(goWordSize(target.arch)) * 2
					case "a,b,c,d *byte":
						size = int(goWordSize(target.arch)) * 4
					}
					source := fmt.Sprintf("TEXT ·F(SB),4,$0-%d\n%s\nRET\n", size, row)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					initialized := strings.Replace(source, fmt.Sprintf("$0-%d\n", size),
						fmt.Sprintf("$0-%d\nMOVL $1,AX\nMOVL AX,X1\n", size), 1)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							declaration := "func F(" + contract.parameters + ")\n"
							if contract.accepted && strings.HasPrefix(name, "V") && !strings.Contains(name, "IMC") && !strings.Contains(name, "KEYGEN") {
								ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
								if ir == "" || err != nil {
									t.Fatal("unused original FP round result cannot change an unrelated source contract", api, err)
								}
							}
							ir, err := x86ScalarFPBitViewAPI(t, initialized, declaration, target.arch, target.triple, api)
							accepted := contract.accepted && strings.HasPrefix(name, "V")
							if (err == nil) != accepted || !accepted && ir != "" {
								t.Fatal("numeric FP bytes cannot supply native legacy AES alignment, holes or pointer backing", accepted, err)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86AESFamilyAbsoluteDisp32AndImmediateClasses(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86AESOracleNames {
			for _, address := range []int64{-2147483649, -2147483648, 2147483647, 4294967295, 4294967296} {
				accepted := address == int64(int32(address)) || arch == "386" && address == int64(uint32(address))
				row, _ := x86AESOracleRow(name, fmt.Sprint(address), "X")
				t.Run(arch+"/"+row, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", accepted)
					_, known, err := x86AESProperties(Op(name), x86YMMReadSource(t, row), arch)
					if !known || (err == nil) != accepted {
						t.Fatal("physical Go disp32 extent differs from shared AES grammar", accepted, err)
					}
				})
			}
		}
		for _, name := range []string{"AESKEYGENASSIST", "VAESKEYGENASSIST"} {
			var all strings.Builder
			for immediate := -129; immediate <= 256; immediate++ {
				accepted := immediate >= 0 && immediate <= 255 || name == "VAESKEYGENASSIST" && immediate >= -128 && immediate < 0
				row := fmt.Sprintf("%s $%d,X0,X2", name, immediate)
				if accepted {
					all.WriteString(row + "\n")
				} else {
					goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
				}
				if _, known, err := x86AESProperties(Op(name), x86YMMReadSource(t, row), arch); !known || (err == nil) != accepted {
					t.Fatal("complete Yu8/Yi8 immediate classes", arch, row, accepted, err)
				}
			}
			goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+all.String()+"RET\n", "", true)
		}
	}
}

func TestX86AESFamilyCompleteIndependentEncoderRows(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	data, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []struct{ name, body string }{{"yaes", "{Zlitm_r, 2, argList{Yxm, Yxr}},"}, {"yxshuf", "{Zibm_r, 2, argList{Yu8, Yxm, Yxr}},"}} {
		start := strings.Index(string(data), "var "+table.name+" = []ytab{")
		if start < 0 {
			t.Fatal(table.name)
		}
		actual := strings.SplitN(strings.SplitN(string(data)[start:], "\n}", 2)[0], "[]ytab{", 2)[1]
		a, err := x86SignedPackedFloatGoOpcodeTokens(actual)
		if err != nil {
			t.Fatal(err)
		}
		w, err := x86SignedPackedFloatGoOpcodeTokens(table.body)
		if err != nil || !reflect.DeepEqual(a, w) {
			t.Fatal("complete legacy zcase/zoffset/classes changed", table.name, actual)
		}
	}
	legacyRows := regexp.MustCompile(`\{A(AES[A-Z]+), ([^,]+), ([^,]+), opBytes\{([^}]+)\}\}`).FindAllStringSubmatch(string(data), -1)
	if len(legacyRows) != 6 || len(x86AESSpecs) != 12 {
		t.Fatal("whole family inventory changed", len(legacyRows), len(x86AESSpecs))
	}
	for i, name := range x86AESOracleNames[:6] {
		table, escape, opcode := "yaes", "0x38", []string{"0xdc", "0xdd", "0xde", "0xdf", "0xdb", "0xdf"}[i]
		if i == 5 {
			table, escape = "yxshuf", "0x3a"
		}
		want := fmt.Sprintf("{A%s, %s, Pq, opBytes{%s, %s, 0}}", name, table, escape, opcode)
		if !strings.Contains(string(data), want) {
			t.Fatal("legacy complete prefix/opcode attributes changed", want)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rule := range rules {
		if !strings.HasPrefix(rule.Opcode, "VAES") {
			continue
		}
		index := counts[rule.Opcode]
		counts[rule.Opcode]++
		isIMC, isKey := rule.Opcode == "VAESIMC", rule.Opcode == "VAESKEYGENASSIST"
		opcode := map[string]string{"VAESENC": "0xDC", "VAESENCLAST": "0xDD", "VAESDEC": "0xDE", "VAESDECLAST": "0xDF", "VAESIMC": "0xDB", "VAESKEYGENASSIST": "0xDF"}[rule.Opcode]
		if opcode == "" {
			t.Fatal("unaccounted actual Go AES member", rule.Opcode)
		}
		table, classes, zcase := "_yvaesdec", []string{"Yxm,Yxr,Yxr", "Yym,Yyr,Yyr", "YxmEvex,YxrEvex,YxrEvex", "YymEvex,YyrEvex,YyrEvex", "Yzm,Yzr,Yzr"}, "Zvex_rm_v_r"
		zoffset, offset := []int{2, 2, 3, 3, 3}, []int{0, 2, 4, 7, 10}
		var opbytes []string
		if isKey {
			table, classes, zcase = "_yvaeskeygenassist", []string{"Yu8,Yxm,Yxr", "Yi8,Yxm,Yxr"}, "Zvex_i_rm_r"
			zoffset, offset = []int{0, 2}, []int{0, 0}
			opbytes = []string{"avxEscape | vex128 | vex66 | vex0F3A | vexW0", opcode}
		} else if isIMC {
			table, classes = "_yvaesimc", []string{"Yxm,Yxr"}
			zoffset, offset = []int{2}, []int{0}
			opbytes = []string{"avxEscape | vex128 | vex66 | vex0F38 | vexW0", opcode}
		} else {
			for _, width := range []int{128, 256} {
				opbytes = append(opbytes, fmt.Sprintf("avxEscape | vex%d | vex66 | vex0F38 | vexW0", width), opcode)
			}
			for _, width := range []int{128, 256, 512} {
				opbytes = append(opbytes, fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F38 | evexW0", width), fmt.Sprintf("evexN%d", width/8), opcode)
			}
			if index >= 2 {
				zcase = "Zevex_rm_v_r"
			}
		}
		if index >= len(classes) || rule.RowIndex != index || rule.Ytab != table || rule.Prefix != "Pavx" || rule.ZCase != zcase || rule.ZOffset != zoffset[index] || rule.EncodingOffset != offset[index] || strings.Join(rule.Classes, ",") != classes[index] || !reflect.DeepEqual(rule.OpBytes, opbytes) {
			t.Fatal("independent entire encoder row/attributes changed", rule)
		}
	}
	for i, name := range x86AESOracleNames[6:] {
		want := 5
		if i == 4 {
			want = 1
		}
		if i == 5 {
			want = 2
		}
		if counts[name] != want {
			t.Fatal(name, counts, want)
		}
	}
	aliases, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil || regexp.MustCompile(`instructions\["V?AES`).Match(aliases) {
		t.Fatal("actual Go AES alias inventory changed", err)
	}
}

func TestX86AESFamilyActualGoRawEncoderForms(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86AESOracleNames {
			widths := []int{16}
			if strings.HasPrefix(name, "V") && !strings.Contains(name, "IMC") && !strings.Contains(name, "KEYGEN") {
				widths = append(widths, 32, 64)
			}
			for _, width := range widths {
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				for _, source := range []string{bank + "0", fmt.Sprintf("%d(AX)", width), fmt.Sprintf("-%d(AX)(CX*2)", width), "(FS)", "(GS)"} {
					row, _ := x86AESOracleRow(name, source, bank)
					t.Run(arch+"/"+row, func(t *testing.T) {
						code := x86OrderingHintGoBytes(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
						file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+x86DwordProductDirectives(code[:len(code)-1])+"\nRET\n")
						if err != nil {
							t.Fatal(err)
						}
						decoded, err := decodeX86RawDirectives(file.Funcs[0], arch)
						if err != nil {
							t.Fatal("actual Go AES physical row missing", row, fmt.Sprintf("%x", code), err)
						}
						ins := decoded.Instrs[1]
						form, known, err := x86AESProperties(ins.Op, ins, arch)
						if !known || err != nil || form.byteWidth != width {
							t.Fatal("actual Go raw AES identity", ins, err)
						}
						named := x86YMMReadSource(t, row)
						for i := range named.Args {
							if named.Args[i].Kind == OpMem && (named.Args[i].Mem.Base == FS || named.Args[i].Mem.Base == GS) {
								named.Args[i].Mem.Segment, named.Args[i].Mem.Base = named.Args[i].Mem.Base, ""
							}
							if named.Args[i].Kind == OpMem && named.Args[i].Mem.Index == "" {
								named.Args[i].Mem.Scale = ins.Args[i].Mem.Scale // no-index scale is not an encoded input
							}
							if named.Args[i].Kind == OpMem && strings.Contains(name, "KEYGEN") {
								named.Args[i].Mem.Segment = "" // actual From3 prefix omission, independently bound above
							}
						}
						if ins.Op != named.Op || !reflect.DeepEqual(ins.Args, named.Args) {
							t.Fatalf("physical original operand/tuple width changed %s code=%x actual=%#v named=%#v", row, code, ins.Args, named.Args)
						}
					})
				}
			}
		}
	}
	// Independent fixed byte witness: prefix, map, opcode and immediate. The
	// source encoder is checked independently of our decoder/typed grammar.
	for name, want := range map[string][]byte{"AESENC X0,X1": {0x66, 0x0f, 0x38, 0xdc, 0xc8, 0xc3}, "AESKEYGENASSIST $27,X0,X2": {0x66, 0x0f, 0x3a, 0xdf, 0xd0, 27, 0xc3}, "VAESENC X0,X1,X2": {0xc4, 0xe2, 0x71, 0xdc, 0xd0, 0xc3}, "VAESKEYGENASSIST $-128,X0,X2": {0xc4, 0xe3, 0x79, 0xdf, 0xd0, 128, 0xc3}} {
		got := x86OrderingHintGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+name+"\nRET\n")
		if !bytes.Equal(got, want) {
			t.Fatal("independent fixed AES prefix/opcode bytes", name, got, want)
		}
	}
}

func TestX86AESFamilyThreeAPIsFiveTargetNumericResults(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, name := range x86AESOracleNames {
				for _, memory := range []bool{false, true} {
					first, params, offset := "X0", "", 0
					if memory {
						first, params, offset = "a+0(FP)", "a,b uint64", 16
					}
					row, destination := x86AESOracleRow(name, first, "X")
					if memory && !strings.HasPrefix(name, "V") {
						row, destination = x86AESOracleRow(name, "X3", "X")
						row = "MOVOU a+0(FP),X3\n" + row
					}
					fmt.Fprintf(&source, "TEXT ·F%d(SB),4,$0-%d\nMOVL $1,AX\nMOVL AX,X0\nMOVL AX,X1\n%s\nMOVQ X%d,ret+%d(FP)\nRET\n", count, offset+8, row, destination, offset)
					fmt.Fprintf(&declarations, "func F%d(%s) uint64\n", count, params)
					count++
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "aes-results-"+api+".ll", "aes-results-"+api+".o", ir)
				})
			}
		})
	}
}

func TestX86AESFamilyPermissionAndEncodingBoundaries(t *testing.T) {
	for _, name := range x86AESOracleNames {
		for _, source := range []string{"(SP)", "(BP)", "tmp(SP)"} {
			row, _ := x86AESOracleRow(name, source, "X")
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-16\n"+row+"\nRET\n", "", true)
			ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·F(SB),4,$0-16\n"+row+"\nRET\n", "func F(a,b uint64)\n", "amd64", "x86_64-unknown-linux-gnu", "text")
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatal("AES grammar granted unbound native stack storage", row, err)
			}
		}
	}
}
