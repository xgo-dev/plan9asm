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

// Independent Intel condition/opcode/flag inventory, not the production map.
var x86CMOVOracleConditions = []struct {
	name   string
	opcode byte
	flags  uint8
}{
	{"CC", 0x43, x86ByteFlagCF}, {"CS", 0x42, x86ByteFlagCF},
	{"EQ", 0x44, x86ByteFlagZF}, {"GE", 0x4d, x86ByteFlagSF | x86ByteFlagOF},
	{"GT", 0x4f, x86ByteFlagZF | x86ByteFlagSF | x86ByteFlagOF}, {"HI", 0x47, x86ByteFlagCF | x86ByteFlagZF},
	{"LE", 0x4e, x86ByteFlagZF | x86ByteFlagSF | x86ByteFlagOF}, {"LS", 0x46, x86ByteFlagCF | x86ByteFlagZF},
	{"LT", 0x4c, x86ByteFlagSF | x86ByteFlagOF}, {"MI", 0x48, x86ByteFlagSF},
	{"NE", 0x45, x86ByteFlagZF}, {"OC", 0x41, x86ByteFlagOF},
	{"OS", 0x40, x86ByteFlagOF}, {"PC", 0x4b, x86ByteFlagPF},
	{"PL", 0x49, x86ByteFlagSF}, {"PS", 0x4a, x86ByteFlagPF},
}

func TestX86CMOVFamilyActualGoCompletePhysicalBytesAndCaller(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, width := range []string{"W", "L", "Q"} {
			if arch == "386" && width == "Q" {
				continue
			}
			for _, condition := range x86CMOVOracleConditions {
				name := "CMOV" + width + condition.name
				for _, row := range []struct {
					source, destination string
					modrm, rex          byte
				}{
					{"BX", "AX", 0xc3, 0}, {"AX", "AX", 0xc0, 0}, {"(DI)", "AX", 0x07, 0}, {"R8", "R9", 0xc8, 0x45},
				} {
					if arch == "386" && row.rex != 0 {
						continue
					}
					t.Run(arch+"/"+name+"/"+row.source, func(t *testing.T) {
						instruction := name + " " + row.source + "," + row.destination
						actual := x86OrderingHintGoBytes(t, arch, "TEXT original(SB),4,$0-0\n"+instruction+"\nRET\n")
						var want []byte
						if width == "W" {
							want = append(want, 0x66)
						}
						rex := row.rex
						if width == "Q" {
							if rex == 0 {
								rex = 0x48
							} else {
								rex |= 8
							}
						}
						if rex != 0 {
							want = append(want, rex)
						}
						want = append(want, 0x0f, condition.opcode, row.modrm, 0xc3)
						if !bytes.Equal(actual, want) {
							t.Fatalf("independent exact Go prefix/opcode/ModRM bytes %s got %x want %x", instruction, actual, want)
						}
						file, err := Parse(ArchAMD64, "TEXT original(SB),4,$0-0\n"+x86DwordProductDirectives(actual[:len(actual)-1])+"\nRET\n")
						if err != nil {
							t.Fatal(err)
						}
						decoded, err := decodeX86RawDirectives(file.Funcs[0], arch)
						if err != nil {
							t.Fatal(err)
						}
						if decoded.Instrs[1].Op != Op(name) {
							t.Fatal("physical condition alias/width normalization", decoded.Instrs[1].Op, name)
						}
						if arch != "amd64" || row.rex != 0 {
							return
						}
						prefix := "MOVQ $9,BX\nCMPQ AX,BX\n"
						body := x86DwordProductDirectives(actual[:len(actual)-1])
						assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", prefix+body+"\nMOVL AX,(DX)", 1)
						pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
						if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
							t.Fatal("actual Go physical source/caller effect", err)
						}
					})
				}
			}
		}
	}
}

func x86CMOVOracleNames(arch string) []string {
	var names []string
	for _, width := range []string{"W", "L", "Q"} {
		if arch == "386" && width == "Q" {
			continue
		}
		for _, condition := range x86CMOVOracleConditions {
			names = append(names, "CMOV"+width+condition.name)
		}
	}
	return names
}

func TestX86CMOVFamilyCompleteIndependentEncoderRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	table := string(data)
	if !regexp.MustCompile(`(?s)var yml_rl = \[\]ytab\{\s*\{Zm_r, 1, argList\{Yml, Yrl\}\},\s*\}`).MatchString(table) {
		t.Fatal("complete Go conditional-move zcase/zoffset/classes changed")
	}
	rows := regexp.MustCompile(`\{A(CMOV[A-Z]+), ([^,]+), ([^,]+), opBytes\{([^}]+)\}\}`).FindAllStringSubmatch(table, -1)
	if len(rows) != 48 || len(x86ConditionalMoveSpecs) != 48 {
		t.Fatal("complete family inventory changed", len(rows), len(x86ConditionalMoveSpecs))
	}
	seen := map[string]bool{}
	for _, width := range []string{"W", "L", "Q"} {
		for _, condition := range x86CMOVOracleConditions {
			name, prefix := "CMOV"+width+condition.name, map[string]string{"W": "Pq", "L": "Pm", "Q": "Pw"}[width]
			bytes := fmt.Sprintf("0x%02x", condition.opcode)
			if width == "Q" {
				bytes = "0x0f, " + bytes
			}
			want := fmt.Sprintf("{A%s, yml_rl, %s, opBytes{%s}}", name, prefix, bytes)
			if !strings.Contains(table, want) {
				t.Fatal("independent complete encoder attributes changed", want)
			}
			if _, found := x86ConditionalMoveSpecs[Op(name)]; !found {
				t.Fatal("missing actual Go member", name)
			}
			seen[name] = true
		}
	}
	for _, row := range rows {
		if !seen[row[1]] {
			t.Fatal("unaccounted actual Go family row", row)
		}
	}
	aliases, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(aliases), `instructions["CMOV`) {
		t.Fatal("actual Go source alias inventory changed")
	}
}

func TestX86CMOVFamilyIndependentAbsoluteAddressExtent(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86CMOVOracleNames(arch) {
			for _, test := range []struct {
				address string
				valid   bool
			}{
				{"0", true}, {"-1", true}, {"2147483647", true}, {"-2147483648", true},
				{"2147483648", arch == "386"}, {"4294967295", arch == "386"}, {"4294967296", false}, {"-2147483649", false},
			} {
				file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+name+" "+test.address+",AX\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				_, known, err := x86ConditionalMoveProperties(ins.Op, ins, arch)
				if !known || (err == nil) != test.valid {
					t.Errorf("%s %s absolute address %s valid=%t err=%v", arch, name, test.address, test.valid, err)
				}
			}
		}
		for _, address := range []string{"0", "-1", "2147483647", "-2147483648", "2147483648", "4294967295", "4294967296", "-2147483649"} {
			valid := address != "4294967296" && address != "-2147483649" && (arch == "386" || address != "2147483648" && address != "4294967295")
			goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\nCMOVLLE "+address+",AX\nRET\n", "", valid)
		}
	}
}

func TestX86CMOVFamilyWholeFormatsEffectsAndShapes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		registers := strings.Fields("AX BX CX DX SP BP SI DI")
		if arch == "amd64" {
			registers = append(registers, strings.Fields("R8 R9 R10 R11 R12 R13 R14 R15")...)
		}
		sources := append(append([]string(nil), registers...), "(AX)", "-1(AX)(CX*2)", "127(AX)(DX*8)", "value+0(FP)", "local-8(SP)", "·data(SB)", "(FS)", "(GS)")
		var assembly strings.Builder
		count := 0
		for _, name := range x86CMOVOracleNames(arch) {
			for _, source := range sources {
				row := name + " " + source + ",AX"
				fmt.Fprintf(&assembly, "TEXT f%d(SB),4,$16-8\n%s\nRET\n", count, row)
				count++
				file, err := Parse(ArchAMD64, "TEXT f(SB),4,$16-8\n"+row+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				before := fmt.Sprintf("%#v", ins)
				form, known, err := x86ConditionalMoveProperties(ins.Op, ins, arch)
				if !known || err != nil {
					t.Fatal(arch, row, err)
				}
				width := int64(form.bits / 8)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				flags := uint8(0)
				for _, condition := range x86CMOVOracleConditions {
					if strings.HasSuffix(name, condition.name) {
						flags = condition.flags
					}
				}
				if !known || err != nil || effect.flagsRead != flags || effect.flagsDefined != 0 || effect.flagsKilled != 0 || effect.dynamicMemory ||
					len(effect.operands) != 2 || effect.operands[0].index != 0 || effect.operands[1].index != 1 ||
					!effect.operands[0].read || effect.operands[0].write || !effect.operands[1].read || !effect.operands[1].write ||
					effect.operands[0].width != width || effect.operands[1].width != width {
					t.Fatal(row, effect, err)
				}
				if !x86SourceStackInstructionKnown(ins, "MOVQ", "Q", arch) {
					t.Fatal("source-stack omitted typed member", row)
				}
				for index, arg := range ins.Args {
					bytes, write, valid := x86InstructionMemoryShape(ins, index, arch)
					memory := index == 0 && isAMD64MemoryOperand(arg)
					if valid != memory || valid && (bytes != width || write || x86ScalarMoveMemoryBytes(ins, index, arch) != width) {
						t.Fatal("source extent/direction", row, bytes, write, valid)
					}
					if arg.Kind == OpFP {
						if bytes, write, valid := X86FPAccessBytes(ins, index, arch); !valid || write || bytes != width {
							t.Fatal("FP extent disagreement", row)
						}
					}
				}
				if before != fmt.Sprintf("%#v", ins) {
					t.Fatal("source identity mutated", row)
				}
			}
			// Destination Yrl is independent of the source class, including self aliases.
			for _, destination := range registers {
				fmt.Fprintf(&assembly, "TEXT f%d(SB),4,$0-0\n%s %s,%s\nRET\n", count, name, destination, destination)
				count++
			}
		}
		goAssemblerOracleOutput(t, arch, assembly.String(), "", true)
		t.Logf("%s independent actual-Go forms %d", arch, count)
	}
}

func TestX86CMOVFamilyDispatchAndGoRejectedForms(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86CMOVOracleNames("amd64") {
			if arch == "386" && name[4] == 'Q' {
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+name+" AX,BX\nRET\n", "", false)
				continue
			}
			operands := []string{"$1,AX", "AX,(BX)", "AL,AX", "AH,AX", "AX,AL", "X1,AX", "K1,AX", "M0,AX", "(AX)(SP*2),BX"}
			if arch == "386" {
				operands = append(operands, "R8,AX", "AX,R8")
			}
			for _, operands := range operands {
				source := "TEXT f(SB),4,$0-0\n" + name + " " + operands + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					continue
				}
				if _, known, err := x86ConditionalMoveProperties(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1], arch); !known || err == nil {
					t.Fatal("Go rejection obtained an effect", arch, source, err)
				}
			}
		}
	}
	for _, identity := range []Op{"", "CMOVLLE", "cmovlle", "CMOVLGE", "CMOVLLE.Z"} {
		ins := Instr{Op: identity, Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}}
		before := append([]Operand(nil), ins.Args...)
		_, known, err := x86ConditionalMoveProperties("CMOVLLE", ins, "amd64")
		valid := identity == "" || strings.EqualFold(string(identity), "CMOVLLE")
		if !known || (err == nil) != valid || !reflect.DeepEqual(ins.Args, before) {
			t.Fatal("dispatch identity", identity, err)
		}
		if !valid {
			var out strings.Builder
			ctx := amd64Ctx{b: &out, goarch: "amd64"}
			if _, _, err := ctx.lowerConditionalMove("CMOVLLE", ins); err == nil || out.Len() != 0 {
				t.Fatal("contradictory identity emitted IR")
			}
		}
	}
}

func TestX86CMOVFamilyThreeAPIsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, target := range x86OrderingHintTargets {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", target.triple, raw), func(t *testing.T) {
				var body strings.Builder
				for _, name := range x86CMOVOracleNames(target.arch) {
					for _, source := range []string{"AX", "BX", "(DI)", "-1(DI)(SI*2)"} {
						fmt.Fprintf(&body, "%s %s,BX\n", name, source)
					}
				}
				if raw {
					bytes := x86OrderingHintGoBytes(t, target.arch, "TEXT original(SB),4,$0-0\n"+body.String()+"RET\n")
					body.Reset()
					if bytes[len(bytes)-1] != 0xc3 {
						t.Fatal("actual Go body lacks its exact trailing RET")
					}
					for _, value := range bytes[:len(bytes)-1] {
						fmt.Fprintf(&body, "BYTE $%d\n", value)
					}
				} else {
					for _, name := range x86CMOVOracleNames(target.arch) {
						fmt.Fprintf(&body, "%s value+0(FP),BX\n%s ·data(SB),BX\n%s (FS),BX\n%s (GS),BX\n", name, name, name, name)
					}
				}
				source := "TEXT ·Forms(SB),4,$0-8\n" + body.String() + "RET\nGLOBL ·data(SB),8,$8\nDATA ·data+0(SB)/8,$0x1020304050607080\n"
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc Forms(value uint64)\n", target.arch, target.triple)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("original formats invented predicate, data or native input bytes", api, err)
					}
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				file, err = normalizeX86RawFile(file, target.arch)
				if err != nil {
					t.Fatal(err)
				}
				signatures := map[string]FuncSig{"Forms": {Name: "Forms", Args: []LLVMType{I64}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}}}
				ir := x86InstructionFormatObjectUnit(t, file, signatures, target.arch, target.triple, 0,
					func(c *amd64Ctx, ins Instr) (bool, bool, error) { return c.lowerConditionalMove(ins.Op, ins) })
				for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, input, level)
					}
				}
			})
		}
	}
}

func TestX86CMOVFamilyBoundFrameNumericalExtent(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for _, width := range []string{"W", "L", "Q"} {
			if target.arch == "386" && width == "Q" {
				continue
			}
			for _, test := range []struct {
				declaration, field string
				valid              bool
			}{
				{"func Value(x uint64)", "x+0(FP)", true},
				{"func Value(x uint64)", "x+1(FP)", width != "Q"},
				{"func Value(x uint8,y uint8)", "x+0(FP)", width == "W"},
				{"func Value(x uint8,y uint32)", "x+0(FP)", false},
				{"func Value(x float64)", "x+0(FP)", true},
				{"func Value(x *uint64)", "x+0(FP)", false},
				{"func Value()", "ret+0(FP)", false},
			} {
				for _, api := range []string{"text", "module", "Go"} {
					size := 8
					if test.declaration == "func Value(x uint8,y uint8)" {
						size = 2
					}
					if test.declaration == "func Value(x *uint64)" && target.arch == "386" {
						size = 4
					}
					if test.declaration == "func Value()" {
						size = 0
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nCMOV%sLE %s,AX\nRET\n", size, width, test.field)
					if test.valid {
						ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\n"+test.declaration+"\n", target.arch, target.triple)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("original FP format invented old destination or predicate bytes", api, err)
						}
					}
					// Only the source storage varies: give every row independent
					// old-destination data and FLAGS before testing its exact span.
					source = strings.Replace(source, fmt.Sprintf("$0-%d\n", size),
						fmt.Sprintf("$0-%d\nMOVL $7,AX\nCMPL AX,$0\n", size), 1)
					_, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\n"+test.declaration+"\n", target.arch, target.triple)
					if test.valid && err != nil || !test.valid && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("numerical FP bit extent/hole/type permission", target.triple, width, test.declaration, api, err)
					}
				}
			}
		}
	}
}

func TestX86CMOVFamilyNativeStackAndFPAuthorityUnchanged(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for _, operand := range []string{"(SP)", "(BP)", "(SI)(BP*1)", "value+7(FP)", "missing+8(FP)", "p+0(FP)"} {
			t.Run(target.triple+"/"+operand, func(t *testing.T) {
				declaration := "package ordering\nfunc Value(value uint64)\n"
				size, width, setup := 8, "Q", ""
				if target.arch == "386" {
					width = "L"
				}
				if operand == "p+0(FP)" {
					declaration = "package ordering\nfunc Value(p *uint64)\n"
					if target.arch == "386" {
						size = 4
					}
				}
				ordinary := target.arch == "386" && strings.Contains(operand, "BP")
				if ordinary {
					size, declaration = 4, "package ordering\nfunc Value(p *byte)\n"
					setup = "MOVL p+0(FP),BP\n"
					if strings.Contains(operand, "BP*") {
						setup = "MOVL p+0(FP),SI\nMOVL $0,BP\n"
					}
				}
				// Every row has an independent defined numerical old destination
				// and FLAGS, so a Context result must still be about source storage.
				setup += fmt.Sprintf("MOV%s $7,AX\nCMP%s AX,$0\n", width, width)
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sCMOV%sLE %s,AX\nRET\n", size, setup, width, operand)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86OrderingHintTranslateAPI(t, api, source, declaration, target.arch, target.triple)
					if ordinary {
						if err != nil {
							t.Fatal("ordinary386 BP native CMOV", api, err)
						}
						for _, input := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
							x86RequireCMOVVolatileWidth(t, input, 4, 1)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("new native-stack, pointer or missing-FP input authority", api, err)
					}
				}
			})
		}
	}
}
