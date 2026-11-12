package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Opcode 63's mode64 memory family has a four-byte source for both the
// default dword copy and effective REX.W sign extension (including 66+REX.W).
// The ordinary 8B dword load shares that exact four-byte input role. SP/BP
// and the Go g register retain their independent physical roles.
func x86SourceStackMOVSXDLiteralProgram() (string, string, string) {
	var assembly, declarations, driver strings.Builder
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	var checks strings.Builder
	count := 0
	for _, encoding := range []struct {
		opcode                byte
		rexW, operandOverride bool
	}{
		{opcode: 0x63},
		{opcode: 0x63, rexW: true},
		{opcode: 0x63, rexW: true, operandOverride: true},
		{opcode: 0x8b},
	} {
		for _, register := range []byte{0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 15} {
			name := fmt.Sprintf("Literal%d", count)
			count++
			var code []byte
			if encoding.operandOverride {
				code = append(code, 0x66)
			}
			rex := byte(0x40)
			if encoding.rexW {
				rex |= 8
			}
			if register >= 8 {
				rex |= 4
			}
			if rex != 0x40 {
				code = append(code, rex)
			}
			// The RIP displacement crosses the complete five-byte result
			// store and the actual native RET, never executable pool data.
			code = append(code, encoding.opcode, (register&7)<<3|5, 6, 0, 0, 0,
				0x48|rex&4, 0x89, (register&7)<<3|0x44, 0x24, 16, 0xc3,
				0, 0, 0, 0x80)
			var body strings.Builder
			for _, value := range code {
				fmt.Fprintf(&body, "BYTE $%#02x\n", value)
			}
			source, _, _ := x86SourceStackNumericalFixture("amd64", body.String())
			assembly.WriteString(strings.ReplaceAll(source, "Value", name))
			fmt.Fprintf(&declarations, "func %s(x uint64) uint64\n", name)
			fmt.Fprintf(&driver, "extern uint64_t %s(uint64_t);\n", name)
			want := "UINT64_C(0xffffffff80000000)"
			if !encoding.rexW {
				want = "UINT64_C(0x80000000)"
			}
			fmt.Fprintf(&checks, "if (%s(UINT64_MAX) != %s) {fprintf(stderr,\"%s failed\\n\"); return 1;}\n", name, want, name)
		}
	}
	driver.WriteString("int main(void) {\n" + checks.String() + "return 0;\n}\n")
	return assembly.String(), declarations.String(), driver.String()
}

func TestX86SourceStackMOVSXDLiteralCompletePhysicalInputs(t *testing.T) {
	source, declarations, _ := x86SourceStackMOVSXDLiteralProgram()
	if strings.Count(source, "TEXT ") != 52 {
		t.Fatal("39 MOVSXD and 13 ordinary dword-load register programs required")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
					if err != nil {
						t.Fatal("exact physical literal/result source rejected", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86SourceStackMOVSXDLiteralPortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	source, declarations, driver := x86SourceStackMOVSXDLiteralProgram()
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "movsxd-literal", triple, text, driver, nil, level)
				}
			}
		})
	}
}

func TestX86SourceStackMOVSXDLiteralReaderDoesNotEscape(t *testing.T) {
	for _, prefix := range [][]byte{nil, {0x48}, {0x66, 0x48}} {
		code := append([]byte(nil), prefix...)
		code = append(code, 0x63, 0x05, 1, 0, 0, 0, 0xc3, 0, 0, 0, 0x80)
		decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "literal", map[string]bool{})
		if err != nil || len(decoded) != 2 {
			t.Fatalf("literal decode %x: %v", code, err)
		}
		state := &x86SourceStackScalarState{}
		if !state.step(decoded[0], "amd64") || state.bytes.gp[0] != 0xff {
			t.Fatalf("exact four-byte literal did not define the complete GP result: %x", code)
		}
		if state.bytes.literalMemoryOperand != nil || state.bytes.literalMemoryBytes != 0 ||
			state.bytes.loweredStaticReads != nil || state.bytes.pointerGP[0] {
			t.Fatal("temporary literal input escaped as memory or pointer permission")
		}
		if x86ResultRead(decoded[0].Args[0], 4, &state.bytes, nil, "amd64") {
			t.Fatal("a later unbound read borrowed the previous instruction's literal")
		}
	}
}
