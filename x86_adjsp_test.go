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
