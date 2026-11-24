package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func x86ADJSPCarrySource(name string, amount int) string {
	const form = "TEXT ·%s(SB),516,$0-4\nCLC\nADJSP $%d\nSETCS AL\n" +
		"ADJSP $-%d,SP\nSETCS CL\nMOVBLZX AL,AX\nMOVBLZX CL,CX\n" +
		"SHLL $1,CX\nORL CX,AX\nMOVL AX,ret+0(FP)\nRET\n"
	return fmt.Sprintf(form, name, amount, amount)
}

func TestX86ADJSPOrdinaryCarry(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range []struct{ arch, triple, width string }{
		{"amd64", "x86_64-unknown-linux-gnu", "Q"},
		{"386", "i386-unknown-linux-gnu", "L"},
	} {
		for _, row := range []struct {
			amount, want int
			first, last  string
		}{
			{127, 0, "SUB", "ADD"},
			{128, 3, "ADD", "SUB"},
			{129, 0, "SUB", "ADD"},
		} {
			t.Run(fmt.Sprintf("%s/%d", target.arch, row.amount), func(t *testing.T) {
				source := x86ADJSPCarrySource("Value", row.amount)
				listing := x86InsertExtractGoListing(t, target.arch, source)
				imm := row.amount
				if imm == 128 {
					imm = -imm
				}
				for _, mnemonic := range []string{row.first, row.last} {
					want := fmt.Sprintf("%s%s\t$%d, SP", mnemonic, target.width, imm)
					if !strings.Contains(string(listing), want) {
						t.Fatalf("Go listing lacks %q:\n%s", want, listing)
					}
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, api)
					if err != nil {
						t.Fatalf("%s: %v", api, err)
					}
					optimized := x86MulDivRoundOptimize(t, ir)
					if !strings.Contains(optimized, fmt.Sprintf("ret i32 %d", row.want)) {
						t.Fatalf("%s changed the carry result:\n%s", api, optimized)
					}
					x86ResultInitializationObject(t, llc, target.triple, ir, api)
				}
			})
		}

		for _, row := range []struct{ name, body, want string }{
			{"address-dependent-flags", "ADJSP $128\nSETOS AL\nADJSP $-128\nMOVBLZX AL,AX\n", "undefined input"},
			{"physical-stack-read", "ADJSP $128\nMOVL (SP),AX\nADJSP $-128\n", ""},
			{"branch-skips-release", "ADJSP $128\nMOVL $8,AX\nJMP done\nADJSP $-128\ndone:\n", "control edge"},
		} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				source := "TEXT ·Value(SB),516,$0-4\n" + row.body + "MOVL AX,ret+0(FP)\nRET\n"
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				_, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, "Go")
				if !errors.Is(err, ErrProbeNeedsContext) || row.want != "" && !strings.Contains(err.Error(), row.want) {
					t.Fatalf("GOARCH=%s should require the original SP: %v", target.arch, err)
				}
			})
		}
	}
}

func TestX86ADJSPRewrittenDestinations(t *testing.T) {
	for _, target := range []struct{ arch, triple string }{
		{"386", "i386-unknown-linux-gnu"}, {"amd64", "x86_64-unknown-linux-gnu"},
	} {
		source := x86ADJSPCarrySource("Value", 128)
		baseline := assembleX87ControlBytes(t, target.arch, source)
		fsPrefix := x86SymbolIndexedActualSegmentPrefixes(t, target.arch)["FS"]
		for _, row := range []struct {
			destination string
			prefix      bool
		}{
			{"AX", false}, {"Z31", false}, {"CR15", false}, {"0", false},
			{"(SP)", false}, {"(FS)", false}, {"0(AX)(CX*1)", false}, {"0(AX)(SP*1)", false},
			{"absent(SB)", false}, {"absent<>(SB)", false}, {"absent(SB)(AX)", false},
			{"0(AX)(FS*1)", true},
		} {
			t.Run(target.arch+"/"+row.destination, func(t *testing.T) {
				program := strings.Replace(source, "ADJSP $128", "ADJSP $128,"+row.destination, 1)
				want := baseline
				if row.prefix && fsPrefix != 0 {
					// CLC precedes the rewritten ADD and its producer's index prefix.
					want = append([]byte{baseline[0], fsPrefix}, baseline[1:]...)
				}
				original := assembleX87ControlBytes(t, target.arch, program)
				if !bytes.Equal(original, want) {
					t.Fatalf("Go destination rewrite follows different bytes: %x, want %x", original, want)
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, program, "func Value() uint32", target.arch, target.triple, api)
					if err != nil || !strings.Contains(x86MulDivRoundOptimize(t, ir), "ret i32 3") {
						t.Fatalf("%s must only observe the rewritten SP and flags: %v", api, err)
					}
				}
			})
		}
		for _, row := range []struct{ destination, displacement string }{
			{"8(SP)", "8"}, {"absent+8(SB)", "8"}, {"$7", "7"},
		} {
			t.Run(target.arch+"/invalid-"+row.destination, func(t *testing.T) {
				program := strings.Replace(source, "ADJSP $128", "ADJSP $128,"+row.destination, 1)
				x86ADJSPRequireGoDisplacementFailure(t, target.arch, program, row.displacement)
				_, err := x86ScalarFPBitViewAPI(t, program, "func Value() uint32", target.arch, target.triple, "Go")
				if err == nil || !strings.Contains(err.Error(), "ADJSP destination") {
					t.Fatalf("Go-invalid destination acquired a rewritten SP: %v", err)
				}
			})
		}
	}
}

func x86ADJSPRequireGoDisplacementFailure(t *testing.T, arch, source, displacement string) {
	t.Helper()
	dir := t.TempDir()
	input, object := filepath.Join(dir, "original.s"), filepath.Join(dir, "original.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-o", object, input)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	exit, exited := err.(*exec.ExitError)
	expected := "asm: asmand: bad address $" + displacement + ",SP\nasm: assembly failed\n"
	if ctx.Err() != nil || !exited || exit.ExitCode() != 1 || string(output) != expected {
		t.Fatalf("original Go did not reject the rewritten displacement: %v\n%s", err, output)
	}
}

func x86ADJSPLogicalFrameSource(name, arch string) string {
	result := x86ResultPointerWord(arch)
	return fmt.Sprintf(`TEXT ·%s(SB),4,$32-%d
MOVL value+0(FP),AX
MOVL AX,spill-16(SP)
ADJSP $128,SP
MOVL spill-16(SP),AX
ADCL $0,AX
MOVL AX,ret+%d(FP)
ADJSP $-128,SP
RET
`, name, result+4, result)
}

func TestX86ADJSPKeepsLogicalFrameCells(t *testing.T) {
	const declaration = "func Value(value uint32) uint32"
	for _, target := range []struct{ arch, triple string }{
		{"386", "i386-unknown-linux-gnu"}, {"amd64", "x86_64-unknown-linux-gnu"},
	} {
		t.Run(target.arch, func(t *testing.T) {
			source := x86ADJSPLogicalFrameSource("Value", target.arch)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
				if err != nil {
					t.Fatalf("%s lost the rebased AUTO/FP cells: %v", api, err)
				}
				x86ScalarFPNamedConstantResult(t, ir+"define i32 @Probe() { %r = call i32 @Value(i32 41)\n ret i32 %r }\n", "Probe", []uint64{42})
			}
			for _, invalid := range []string{
				strings.Replace(source, "MOVL AX,spill-16(SP)", "NOP", 1),
				strings.ReplaceAll(source, "spill-16(SP)", "16(SP)"),
			} {
				goAssemblerOracleOutput(t, target.arch, invalid, "", true)
				_, err := x86ScalarFPBitViewAPI(t, invalid, declaration, target.arch, target.triple, "Go")
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("undefined or physical SP storage acquired logical AUTO bytes: %v", err)
				}
			}
		})
	}
}

func x86ADJSPPhysicalScratchSource(name string) string {
	return fmt.Sprintf(`TEXT ·%s(SB),516,$0-4
ADJSP $128
NOP SP
MOVL $6,124(SP)
ADDL $1,124(SP)
ADJSP $32
CMPL 156(SP),$7
JNE bad
MOVL 156(SP),AX
JMP done
bad:
MOVL $15,AX
done:
ADJSP $-160
MOVL AX,ret+0(FP)
RET
`, name)
}

func TestX86ADJSPPhysicalScratch(t *testing.T) {
	for _, target := range []struct{ arch, triple string }{
		{"386", "i386-unknown-linux-gnu"}, {"amd64", "x86_64-unknown-linux-gnu"},
	} {
		source := x86ADJSPPhysicalScratchSource("Value")
		alias := `TEXT ·Value(SB),4,$32-4
MOVL $6,spill-16(SP)
ADJSP $128
ADDL $1,144(SP)
ADJSP $-128
MOVL spill-16(SP),AX
MOVL AX,ret+0(FP)
RET
`
		for _, row := range []struct{ name, source string }{{"nested", source}, {"named-alias", alias}} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				goAssemblerOracleOutput(t, target.arch, row.source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, row.source, "func Value() uint32", target.arch, target.triple, api)
					if err != nil {
						t.Fatalf("%s lost the initialized stack cell: %v", api, err)
					}
					x86ScalarFPNamedConstantResult(t, ir, "Value", []uint64{7})
				}
			})
		}
		for _, row := range []struct{ name, source string }{
			{"crosses-owned-end", strings.Replace(source, "124(SP)", "125(SP)", 1)},
			{"uninitialized", strings.Replace(source, "MOVL $6,124(SP)", "NOP", 1)},
			{"released", strings.Replace(source, "ADJSP $32", "ADJSP $-128\nADJSP $160", 1)},
			{"escaped", strings.Replace(source, "MOVL 156(SP),AX", "LEAL 156(SP),AX", 1)},
			{"physical-sp-value", strings.Replace(source, "NOP SP", "MOVL SP,AX", 1)},
		} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				goAssemblerOracleOutput(t, target.arch, row.source, "", true)
				_, err := x86ScalarFPBitViewAPI(t, row.source, "func Value() uint32", target.arch, target.triple, "Go")
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unproved physical stack access was accepted: %v", err)
				}
			})
		}
	}
}

func x86ADJSPMixedStackSources(arch string) (flags, value, memory, named string) {
	suffix, width := "L", 4
	if arch == "amd64" {
		suffix, width = "Q", 8
	}
	flags = fmt.Sprintf(`TEXT ·Value(SB),516,$0-4
CLC
PUSHF%[1]s
ADJSP $128
SETCS AL
MOVB $1,128(SP)
ADJSP $-128
CLC
POPF%[1]s
SETCS BL
MOVBLZX AL,AX
MOVBLZX BL,BX
ADDL BX,AX
MOVL AX,ret+0(FP)
RET
`, suffix)
	value = fmt.Sprintf(`TEXT ·Value(SB),516,$0-4
PUSH%[1]s $6
ADJSP $129
ADDL $1,129(SP)
PUSHW $0
POPW CX
ADJSP $-129
POP%[1]s AX
MOVL AX,ret+0(FP)
RET
`, suffix)
	memory = fmt.Sprintf(`TEXT ·Value(SB),516,$0-4
ADJSP $%[2]d
MOV%[1]s $7,0(SP)
PUSH%[1]s 0(SP)
MOV%[1]s $0,%[2]d(SP)
POP%[1]s 0(SP)
MOVL 0(SP),AX
ADJSP $-%[2]d
MOVL AX,ret+0(FP)
RET
`, suffix, width)
	named = fmt.Sprintf(`TEXT ·Value(SB),4,$32-4
MOVL $0,spill-16(SP)
ADJSP $128
PUSH%[1]s $7
POP%[1]s spill-%[2]d(SP)
MOVL spill-16(SP),AX
ADJSP $-128
MOVL AX,ret+0(FP)
RET
`, suffix, 16+width)
	return
}

func TestX86ADJSPMixedStack(t *testing.T) {
	for _, target := range []struct{ arch, triple string }{
		{"386", "i386-unknown-linux-gnu"}, {"amd64", "x86_64-unknown-linux-gnu"},
	} {
		flags, value, memory, named := x86ADJSPMixedStackSources(target.arch)
		for _, row := range []struct {
			name, source string
			want         uint64
		}{{"flags", flags, 2}, {"value", value, 7}, {"memory", memory, 7}, {"named-pop", named, 7}} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				goAssemblerOracleOutput(t, target.arch, row.source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, row.source, "func Value() uint32", target.arch, target.triple, api)
					if err != nil {
						t.Fatalf("%s lost initialized private stack storage: %v", api, err)
					}
					x86ScalarFPNamedConstantResult(t, ir, "Value", []uint64{row.want})
				}
			})
		}
		fullArithmeticFlags := strings.Replace(flags, "CLC\nPUSHF", "MOVL $1,CX\nADDL $0,CX\nCLD\nPUSHF", 1)
		for _, row := range []struct{ name, source string }{
			{"partly-defined-flags", strings.Replace(flags, "MOVB $1,128(SP)", "MOVL 128(SP),CX", 1)},
			{"ambient-flags", strings.Replace(fullArithmeticFlags, "MOVB $1,128(SP)", "MOVB 129(SP),CL", 1)},
			{"released-value", strings.Replace(value, "ADDL $1,129(SP)", "ADJSP $-133\nADJSP $133\nADDL $1,129(SP)", 1)},
			{"pop-beyond-live-storage", strings.Replace(memory, " 0(SP)\nMOVL 0(SP),AX", " 8(SP)\nMOVL 0(SP),AX", 1)},
		} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				goAssemblerOracleOutput(t, target.arch, row.source, "", true)
				_, err := x86ScalarFPBitViewAPI(t, row.source, "func Value() uint32", target.arch, target.triple, "Go")
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unproved private stack effect was accepted: %v", err)
				}
			})
		}
	}
}

type x86ADJSPVectorCopyCase struct {
	opcode, register, mode string
	width, lane            int
}

func x86ADJSPVectorCopyCases() []x86ADJSPVectorCopyCase {
	var cases []x86ADJSPVectorCopyCase
	for _, row := range []struct {
		opcode string
		widths int
		lane   int // Zero for forms without a writemask.
	}{
		{"MOVUPS", 16, 0}, {"MOVUPD", 16, 0}, {"MOVOU", 16, 0},
		{"VMOVDQU", 32, 0}, {"VMOVUPS", 64, 4}, {"VMOVUPD", 64, 8},
		{"VMOVDQU8", 64, 1}, {"VMOVDQU16", 64, 2}, {"VMOVDQU32", 64, 4}, {"VMOVDQU64", 64, 8},
	} {
		modes := []string{"unmasked"}
		if row.lane != 0 {
			modes = append(modes, "merge-load", "zero-load", "masked-store")
		}
		for axis, register := range []string{"X0", "Y0", "Z0"} {
			width := 16 << axis
			if width > row.widths {
				break
			}
			for _, mode := range modes {
				cases = append(cases, x86ADJSPVectorCopyCase{row.opcode, register, mode, width, row.lane})
			}
		}
	}
	return append(cases, x86ADJSPVectorCopyCase{"MOVUPS", "X0", "mixed", 16, 0})
}

func (row x86ADJSPVectorCopyCase) want() uint64 {
	const fill = uint64(0x07070707)
	if row.lane == 0 || row.mode == "unmasked" {
		return fill<<32 | fill
	}
	var keep uint64
	if row.mode != "zero-load" {
		keep = 0x22222222
	}
	mask := uint64(0xffffffff)
	if row.lane < 4 {
		mask = uint64(1)<<uint(8*row.lane) - 1
	}
	return keep<<32 | fill&mask | keep&^mask
}

func (row x86ADJSPVectorCopyCase) source(name string) string {
	opcode, register, mode, width := row.opcode, row.register, row.mode, row.width
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),516,$0-8\n", name)
	if mode == "mixed" {
		source.WriteString("PUSHW $0\n")
	}
	source.WriteString("ADJSP $192\n")
	for offset := 0; offset < width; offset += 4 {
		fmt.Fprintf(&source, "MOVL $0x07070707,%d(SP)\n", 1+offset)
		if mode == "merge-load" || mode == "masked-store" {
			fmt.Fprintf(&source, "MOVL $0x22222222,%d(SP)\n", 97+offset)
		}
	}
	if row.lane != 0 && mode != "unmasked" {
		source.WriteString("MOVL $1,AX\nKMOVW AX,K1\n")
	}
	switch mode {
	case "merge-load":
		fmt.Fprintf(&source, "%[1]s 97(SP),%[2]s\n%[1]s 1(SP),K1,%[2]s\n%[1]s %[2]s,97(SP)\n", opcode, register)
	case "zero-load":
		fmt.Fprintf(&source, "%[1]s.Z 1(SP),K1,%[2]s\n%[1]s %[2]s,97(SP)\n", opcode, register)
	case "masked-store":
		fmt.Fprintf(&source, "%[1]s 1(SP),%[2]s\n%[1]s %[2]s,K1,97(SP)\n", opcode, register)
	default:
		fmt.Fprintf(&source, "%[1]s 1(SP),%[2]s\n%[1]s %[2]s,97(SP)\n", opcode, register)
	}
	fmt.Fprintf(&source, "MOVL 97(SP),AX\nMOVL %d(SP),BX\nADJSP $-192\n", 97+width-4)
	if mode == "mixed" {
		source.WriteString("POPW CX\n")
	}
	source.WriteString("MOVL AX,ret+0(FP)\nMOVL BX,ret+4(FP)\nRET\n")
	return source.String()
}

func TestX86ADJSPUnalignedVectorCopies(t *testing.T) {
	const declaration = "func Copy() uint64"
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"386", "i386-unknown-linux-gnu"}, {"amd64", "x86_64-unknown-linux-gnu"},
	} {
		for _, row := range x86ADJSPVectorCopyCases() {
			t.Run(fmt.Sprintf("%s/%s/%s/%s", target.arch, row.opcode, row.register, row.mode), func(t *testing.T) {
				source := row.source("Copy")
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatalf("%s lost the vector stack span: %v", api, err)
					}
					if row.mode == "masked-store" {
						compileLLVMToObject(t, llc, target.triple, api+".ll", api+".o", ir)
					} else {
						x86ScalarFPNamedConstantResult(t, ir, "Copy", []uint64{row.want()})
					}
				}
			})
		}
		source := (x86ADJSPVectorCopyCase{"MOVUPS", "X0", "unmasked", 16, 0}).source("Copy")
		for _, row := range []struct{ name, source string }{
			{"out-of-range", strings.Replace(source, "MOVUPS X0,97(SP)", "MOVUPS X0,177(SP)", 1)},
			{"uninitialized", strings.Replace(source, "MOVL $0x07070707,13(SP)\n", "", 1)},
			{"aligned", strings.ReplaceAll(source, "MOVUPS", "MOVAPS")},
		} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				goAssemblerOracleOutput(t, target.arch, row.source, "", true)
				_, err := x86ScalarFPBitViewAPI(t, row.source, declaration, target.arch, target.triple, "Go")
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("invalid vector stack span was accepted: %v", err)
				}
			})
		}
	}
}
