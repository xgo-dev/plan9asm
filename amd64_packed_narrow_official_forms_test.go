package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// Select the semantic family by name, but derive its entire vector syntax
// denominator from Go's independent encoder reader, never the lowerer spec.
func x86OfficialPackedNarrowRows(t *testing.T, arch string) []string {
	t.Helper()
	byOpcode := x86OfficialPackedBinaryWitnesses(t)
	var rows []string
	for _, opcode := range []string{"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB"} {
		witnesses := byOpcode[opcode]
		if len(witnesses) == 0 {
			t.Fatal("missing independent official pack family", opcode)
		}
		for _, witness := range witnesses {
			if arch == "386" && strings.Count(witness, ",") == 3 {
				continue // Actual mode32 frontend refusals are a separate gate.
			}
			rows = append(rows, witness)
		}
	}
	return rows
}

func TestX86PackedNarrowOfficialRowsThreeAPIsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, raw := range []bool{false, true} {
		var rawRows []string
		if raw {
			rawRows = x86OfficialPackedNarrowRawRows(t)
		}
		for _, target := range []struct{ arch, triple string }{
			{"amd64", "x86_64-apple-darwin"},
			{"amd64", "x86_64-unknown-linux-gnu"},
			{"amd64", "x86_64-pc-windows-msvc"},
			{"386", "i386-unknown-linux-gnu"},
			{"386", "i686-pc-windows-msvc"},
		} {
			t.Run(fmt.Sprintf("raw=%t/%s", raw, target.triple), func(t *testing.T) {
				var source, declarations strings.Builder
				declarations.WriteString("package narrow\n")
				rows := x86OfficialPackedNarrowRows(t, target.arch)
				if raw {
					// Physical mode32 masks are legal even though its named Go
					// frontend rejects them; bytes come from the actual amd64 Go
					// encoder with low physical register/address banks throughout.
					rows = rawRows
				}
				for index, row := range rows {
					fmt.Fprintf(&source, "TEXT ·F%d(SB),4,$0-0\n%s\nRET\n", index, row)
					fmt.Fprintf(&declarations, "func F%d()\n", index)
				}
				goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
				pkg := mustGoPackage(t, "example.invalid/narrow", declarations.String())
				file, err := Parse(ArchAMD64, source.String())
				if err != nil {
					t.Fatal(err)
				}
				sigs := map[string]FuncSig{}
				for index := range rows {
					name := fmt.Sprintf("F%d", index)
					sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func),
						target.arch, types.SizesFor("gc", target.arch))
					if err != nil {
						t.Fatal(err)
					}
					sigs[name] = sig
				}
				before := fmt.Sprintf("%#v %#v", file, sigs)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewPackageAPI(t, source.String(), pkg, target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("original named/raw format batch invented native entry inputs", api, err)
					}
				}
				units := *file
				units.Funcs = append([]Func(nil), file.Funcs...)
				if raw {
					for index, fn := range units.Funcs {
						decoded, err := decodeX86RawDirectives(fn, target.arch)
						if err != nil {
							t.Fatal("actual physical format unit could not be decoded", err)
						}
						units.Funcs[index] = decoded
					}
				}
				// Keep every original form, but release each bounded object
				// before the next batch. Units are not initialized entries.
				for start := 0; start < len(units.Funcs); start += 64 {
					end := start + 64
					if end > len(units.Funcs) {
						end = len(units.Funcs)
					}
					batch := units
					batch.Funcs = units.Funcs[start:end]
					ir := x86InstructionFormatObjectUnit(t, &batch, sigs, target.arch, target.triple, 0,
						func(c *amd64Ctx, ins Instr) (bool, bool, error) {
							return c.lowerPackedSaturatingNarrow(ins.Op, ins)
						})
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				}
				if before != fmt.Sprintf("%#v %#v", file, sigs) {
					t.Fatal("object coverage changed original source/signatures")
				}
				t.Logf("all %d original named/physical Go forms retain emitter-only LLVM objects and three-API Context; independent initialized sources own public/runtime coverage", len(rows))
			})
		}
	}
}

func x86OfficialPackedNarrowRawRows(t *testing.T) []string {
	t.Helper()
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM 22 llvm-mc required")
	}
	var rows []string
	var disassembly strings.Builder
	var equivalentPairs [][2]int
	for _, row := range x86OfficialPackedNarrowRows(t, "amd64") {
		code := assembleX87ControlBytes(t, "amd64", "TEXT rawpack(SB),4,$0-0\n"+row+"\nRET\n")
		code = code[:len(code)-1]
		appendBytes := func(bytes []byte) {
			var source strings.Builder
			for _, value := range bytes {
				fmt.Fprintf(&source, "BYTE $%d\n", value)
				fmt.Fprintf(&disassembly, "0x%02x ", value)
			}
			disassembly.WriteByte('\n')
			rows = append(rows, source.String())
		}
		original := len(rows)
		appendBytes(code)
		opcode, _, _ := strings.Cut(strings.Fields(row)[0], ".")
		// WIG is physical grammar beyond Go's chosen W0 encoding. EVEX
		// dword-to-word is W0-only; every VEX and EVEX word-to-byte row
		// must have an independently disassembled equivalent W1 object.
		if code[0] == 0x62 && opcode != "VPACKSSWB" && opcode != "VPACKUSWB" {
			continue
		}
		wig := append([]byte(nil), code...)
		if wig[0] == 0xc5 {
			wig = append([]byte{0xc4, wig[1]&0x80 | 0x61, wig[1] & 0x7f}, wig[2:]...)
		}
		if (wig[0] != 0xc4 && wig[0] != 0x62) || wig[2]&0x80 != 0 {
			t.Fatalf("unexpected original Go pack prefix: %s %x", row, code)
		}
		wig[2] |= 0x80
		equivalentPairs = append(equivalentPairs, [2]int{original, len(rows)})
		appendBytes(wig)
	}
	for _, triple := range []string{"x86_64", "i386"} {
		ctx, cancel := runtimeOracleStageContext(t)
		command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+triple,
			"--mattr=+avx2,+avx512bw,+avx512vl")
		command.Stdin = strings.NewReader(disassembly.String())
		output, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil || strings.Contains(string(output), "warning:") {
			t.Fatalf("independent pack physical grammar: %s %v\n%s", triple, err, output)
		}
		var instructions []string
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "vpack") {
				instructions = append(instructions, line)
			}
		}
		if len(instructions) != len(rows) {
			t.Fatalf("physical pack disassembly lost forms: %s got %d, want %d", triple, len(instructions), len(rows))
		}
		for _, pair := range equivalentPairs {
			if instructions[pair[0]] != instructions[pair[1]] {
				t.Fatalf("WIG changed physical instruction: %s %q != %q", triple, instructions[pair[0]], instructions[pair[1]])
			}
		}
	}
	t.Logf("%d actual Go W0 rows plus %d independently equivalent W1 rows", len(rows)-len(equivalentPairs), len(equivalentPairs))
	return rows
}

func TestX86PackedNarrowMode32ActualGoRawForms(t *testing.T) {
	rows := x86OfficialPackedNarrowRows(t, "386")
	source := "TEXT rawpack(SB),4,$0-0\n" + strings.Join(rows, "\n") + "\nRET\n"
	goAssemblerOracleOutput(t, "386", source, "", true)
	code := assembleX87ControlBytes(t, "386", source)
	decoded, err := decodeX86RawDirectives(rawX86Function(code), "386")
	if err != nil {
		t.Fatal("actual Go mode32 pack bytes lost physical decoding", err)
	}
	named, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	want := named.Funcs[0].Instrs[1:]
	if len(decoded.Instrs) != len(want) {
		t.Fatal("actual byte decoder lost instructions", len(decoded.Instrs), len(want))
	}
	for index, instruction := range decoded.Instrs {
		if instruction.Op != want[index].Op || !reflect.DeepEqual(instruction.Args, want[index].Args) {
			t.Fatalf("mode32 instruction %d: %+v != %+v", index, instruction, want[index])
		}
	}
}

func TestX86PackedNarrowE4NFMemoryRemainsObservable(t *testing.T) {
	for _, opcode := range []string{"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			rows := []string{opcode + ".Z (AX)," + bank + "0,K1," + bank + "1"}
			if opcode == "VPACKSSDW" || opcode == "VPACKUSDW" {
				rows = append(rows, opcode+".BCST.Z (AX),"+bank+"0,K1,"+bank+"1")
			}
			for _, row := range rows {
				t.Run(row, func(t *testing.T) {
					source := "TEXT pack(SB),4,$0-0\nMOVL $0,CX\nKMOVQ CX,K1\n" + row + "\nRET\n"
					goAssemblerOracleOutput(t, "amd64", source, "", true)
					initialized := strings.Replace(source, "$0-0\n", "$0-8\nMOVQ p+0(FP),AX\nVPXORD Z0,Z0,Z0\n", 1)
					goAssemblerOracleOutput(t, "amd64", initialized, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						if ir, err := x86ScalarFPBitViewAPI(t, source, "func pack()", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("original missing-address source invented native input", api, err)
						}
						ir, err := x86ScalarFPBitViewAPI(t, initialized, "func pack(p *[64]byte)", "amd64", "x86_64-unknown-linux-gnu", api)
						if err != nil {
							t.Fatal(err)
						}
						if !strings.Contains(ir, "load volatile") ||
							!strings.Contains(x86MulDivRoundOptimize(t, ir), "load volatile") {
							t.Fatal("E4NF memory read disappeared for a zero mask/dead output")
						}
					}
				})
			}
		}
	}
}

func TestX86PackedNarrowLegacyGoModeAndNativeStorageBoundaries(t *testing.T) {
	for _, opcode := range []string{"PACKSSLW", "PACKSSWB", "PACKUSWB"} {
		for _, source := range []string{"M0", "(AX)"} {
			t.Run("386/"+opcode+"/"+source, func(t *testing.T) {
				assembly := "TEXT pack(SB),4,$0-0\n" + opcode + " " + source + ",M1\nRET\n"
				goAssemblerOracleOutput(t, "386", assembly, "", false)
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Translate(file, Options{Goarch: "386",
					Sigs: map[string]FuncSig{"pack": {Name: "pack", Ret: Void}}}); err == nil {
					t.Fatal("Go-rejected mode32 MMX row acquired successful lowering")
				}
			})
		}
	}
	for _, opcode := range []string{"PACKSSLW", "PACKSSWB", "PACKUSDW", "PACKUSWB"} {
		t.Run("virtual-memory/"+opcode, func(t *testing.T) {
			assembly := "TEXT pack(SB),4,$64-64\n" + opcode + " value+0(FP),X0\nRET\n"
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			sig := x86WordMaddFPType(t)
			sig.Name = "pack"
			if _, err := Translate(file, Options{Goarch: "amd64",
				Sigs: map[string]FuncSig{"pack": sig}}); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("virtual independent FP slots invented native legacy alignment", err)
			}
		})
	}
}
