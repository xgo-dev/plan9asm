package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64CompareTargetAPI(t *testing.T, api, source, triple string) (bool, error) {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return false, err
	}
	options := Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"comparison": {Name: "comparison", Ret: Void}},
	}
	if api == "text" {
		ir, err := Translate(file, options)
		return ir != "", err
	}
	context := llvm.NewContext()
	defer context.Dispose()
	if api == "module" {
		module, err := TranslateModuleInContext(context, file, options)
		present := !module.IsNil()
		if present {
			module.Dispose()
		}
		return present, err
	}
	pkg := mustGoPackage(t, "comparison", "package comparison\nfunc comparison()\n")
	bound, err := translateGoModuleInContext(context, pkg,
		[]byte(strings.ReplaceAll(source, "TEXT comparison", "TEXT ·comparison")),
		GoModuleOptions{GOOS: "linux", GOARCH: "arm64", TargetTriple: triple})
	if bound != nil {
		bound.Module.Dispose()
	}
	return bound != nil, err
}

func TestARM64ScalarCompareRequiresNativeTarget(t *testing.T) {
	var instructions []string
	for _, row := range arm64CompareCases([]int{31}, false) {
		if !row.dead {
			instructions = append(instructions, row.instruction())
		}
	}
	for _, row := range arm64CompareCases([]int{31}, true) {
		if !row.dead {
			instructions = append(instructions, row.instruction())
			if row.bits == 32 {
				row.bits = 16
				instructions = append(instructions, row.instruction())
			}
		}
	}
	for _, api := range []string{"text", "module", "Go"} {
		for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "wasm32-unknown-unknown", "armv7-unknown-linux-gnueabihf", "aarch64_be-unknown-linux-gnu", "aarch64bad-unknown-linux-gnu"} {
			for _, dead := range []bool{false, true} {
				for _, instruction := range instructions {
					t.Run(fmt.Sprintf("%s/%s/dead=%t/%s", api, triple, dead, instruction), func(t *testing.T) {
						prefix := ""
						if dead {
							prefix = "RET\n"
						}
						source := "TEXT comparison(SB),4,$0-0\n" + prefix + instruction + "\nRET\n"
						present, err := arm64CompareTargetAPI(t, api, source, triple)
						if present || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("native compare target missing but output=%t err=%v", present, err)
						}
					})
				}
			}
		}
	}
}

func TestARM64ScalarCompareTargetKeepsMalformedSourcePriority(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
			for _, invalid := range []string{"FCMPS F0", "FCMPD R0,F1", "FCMPES $0,F1", "FCMPED.P F0,F1", "WORD $0x1e202001", "WORD $0x1ea02000"} {
				for _, body := range []string{invalid, "FCMPS F0,F1\n" + invalid, "FCMPS F0,F1\nRET\n" + invalid, invalid + "\nFCMPD F0,F1"} {
					source := "TEXT comparison(SB),4,$0-0\n" + body + "\nRET\n"
					present, err := arm64CompareTargetAPI(t, api, source, triple)
					if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s %s malformed source changed to native context/output: %t %v\n%s", api, triple, present, err, source)
					}
				}
			}
		}
	}
}

func TestARM64ScalarCompareTargetKeepsNativeAndOrdinaryForms(t *testing.T) {
	const source = "TEXT comparison(SB),4,$0-0\nFCMPS F0,F1\nFCMPED $(-1.25),F31\nWORD $0x1ee02000\nRET\n"
	for _, api := range []string{"text", "module", "Go"} {
		for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "arm64-apple-darwin", "aarch64-pc-windows-msvc"} {
			present, err := arm64CompareTargetAPI(t, api, source, triple)
			if !present || err != nil {
				t.Fatalf("%s explicit native %s rejected: %v", api, triple, err)
			}
		}
		for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
			present, err := arm64CompareTargetAPI(t, api, "TEXT comparison(SB),4,$0-0\nRET\n", triple)
			if !present || err != nil {
				t.Fatalf("%s non-family portability changed: %v", api, err)
			}
		}
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, goarch := range []string{"amd64", "386", "arm", "wasm"} {
		if err := validateARM64ScalarCompareTarget(file, Options{Goarch: goarch, TargetTriple: "aarch64-unknown-linux-gnu"}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("native target accepted conflicting GOARCH=%s: %v", goarch, err)
		}
	}
}

func TestARM64ScalarCompareTargetLeavesUnidentifiedWordsToGenericValidation(t *testing.T) {
	for _, operands := range [][]Operand{
		nil,
		{{Kind: OpImm, Imm: 1}, {Kind: OpImm, Imm: 2}},
		{{Kind: OpReg, Reg: "R0"}},
		{{Kind: OpImm, ImmRaw: "$(COMPARE_OPCODE)"}},
		{{Kind: OpImm, ImmRaw: "$(COMPARE_BASE | (31 << 5))"}},
		{{Kind: OpImm, ImmIsFloat: true}},
		{{Kind: OpImm, Imm: 0xd503201f}}, // NOP, outside the compare class.
	} {
		file, err := Parse(ArchARM64, "TEXT comparison(SB),4,$0-0\nWORD $0\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if file.Funcs[0].Instrs[1].Op != OpWORD {
			t.Fatal("fixture no longer selects the WORD instruction")
		}
		file.Funcs[0].Instrs[1].Args = operands
		for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
			if err := validateARM64ScalarCompareTarget(file, Options{TargetTriple: triple}); err != nil {
				t.Fatalf("compare preflight claimed unrelated WORD operands %+v: %v", operands, err)
			}
		}
	}
}
