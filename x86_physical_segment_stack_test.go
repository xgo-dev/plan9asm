package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86PhysicalSegmentStackLeaf(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 required for physical segment stack objects")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			const start = "TEXT leaf(SB),516,$0-0\n"
			body := "PUSHQ FS\nPOPQ FS\nPUSHL GS\nPOPL GS\nPUSHW FS\nPOPW FS\n"
			width := "Q"
			if target.arch == "386" {
				width = "L"
				body += "PUSHL SS\nPUSHL FS\nPOPL FS\nPOPL SS\n"
				body += "PUSHW DS\nPOPW DS\nPUSHL ES\nPOPL ES\nPUSHL CS\nPOPL AX\n"
			}
			body += "PUSH" + width + " GS\nPOP" + width + " AX\nPUSH" + width + " AX\nPOP" + width + " GS\n"
			program := start + body + "RET\n"
			goAssemblerOracleOutput(t, target.arch, program, "", true)
			originalBytes, _ := x86NumericalBoundaryGoBytes(t, target.arch, body+"RET")
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, program, "func leaf()", target.arch, target.triple, api)
					if err != nil || !strings.Contains(ir, "naked noinline") {
						t.Fatalf("could not retain the balanced physical segment stack: %v\n%s", err, ir)
					}
					for _, content := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						assertX86RawTextAssemblyBytes(t, llc, target.triple, content, originalBytes)
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, content, level)
						}
					}
				})
			}
		})
	}
}

func TestX86PhysicalSegmentStackRawLeaf(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 required for raw segment stack objects")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			suffix := "Q"
			if arch == "386" {
				suffix = "L"
			}
			for _, body := range []string{
				"PUSH" + suffix + " FS\nPOP" + suffix + " FS\nRET",
				"PUSHW GS\nPOPW GS\nRET",
			} {
				code, _ := x86NumericalBoundaryGoBytes(t, arch, body)
				source := "TEXT raw(SB),516,$0-0\n" + x86RawDisplacementDirectives(code)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func raw()", arch, testTargetTriple("linux", arch), api)
					if err != nil || !strings.Contains(ir, "naked noinline") {
						t.Fatalf("%s lost straight-line raw segment stack %q: %v", api, body, err)
					}
					assertX86RawTextAssemblyBytes(t, llc, testTargetTriple("linux", arch), ir, code)
				}
			}
		})
	}
}

func TestX86PhysicalSegmentStackRejectsRawEntryAndReturnChanges(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			for label, code := range map[string][]byte{
				"pop-before-push": {0x0f, 0xa1, 0x0f, 0xa0, 0xc3},
				"prefixed-push":   {0x67, 0x0f, 0xa0, 0x0f, 0xa1, 0xc3},
				"ret-imm":         {0x0f, 0xa0, 0x0f, 0xa1, 0xc2, 0, 0},
			} {
				t.Run(label, func(t *testing.T) {
					source := "TEXT raw(SB),516,$0-0\n" + x86RawDisplacementDirectives(code)
					goAssemblerOracleOutput(t, arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func raw()", arch, testTargetTriple("linux", arch), api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("%s accepted changed physical entry/return semantics: %v", api, err)
						}
					}
				})
			}
		})
	}
}

func TestX86PhysicalSegmentStackChecksBothWidths(t *testing.T) {
	for _, test := range []struct{ arch, body string }{
		{"amd64", "PUSHL FS\nPOPW FS\nPOPW FS\n"},
		{"386", "PUSHQ FS\nPOPL FS\nPOPL FS\n"},
	} {
		t.Run(test.arch, func(t *testing.T) {
			program := "TEXT leaf(SB),516,$0-0\n" + test.body + "RET\n"
			goAssemblerOracleOutput(t, test.arch, program, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, program, "func leaf()", test.arch, testTargetTriple("linux", test.arch), api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s accepted a Go-balanced but physically unbalanced return: %v", api, err)
				}
			}
			if test.arch == "amd64" {
				source := strings.Replace(program, "leaf(SB),516", "leaf<>(SB),NOSPLIT|NOFRAME", 1)
				if _, _, err := TranslateNativeSource([]byte(source), NativeOptions{
					GOOS: "linux", GOARCH: "amd64", PackagePath: "probe",
				}); err == nil {
					t.Fatal("native source accepted Go-balanced instructions that move the return SP")
				}
			}
		})
	}
}
