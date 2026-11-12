package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86AMD64ParameterAliasFixture() (string, string, string) {
	var source, declarations, driver strings.Builder
	driver.WriteString("#include <stdint.h>\n#include <stdbool.h>\n#include <stdio.h>\n")
	var checks strings.Builder
	for index, row := range []struct {
		input, output, ctype, move string
		width                      int
		rawBool                    bool
	}{
		{"bool", "uint8", "uint8_t", "MOVB", 1, false},
		{"uint8", "uint8", "uint8_t", "MOVB", 1, false},
		{"uint16", "uint16", "uint16_t", "MOVW", 2, false},
		{"uint32", "uint32", "uint32_t", "MOVL", 4, false},
		{"uint64", "uint64", "uint64_t", "MOVQ", 8, false},
		{"bool", "uint8", "uint8_t", "MOVB", 1, true},
	} {
		name := fmt.Sprint("ParameterAlias", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nLEAQ x+0(FP),AX\nMOVQ AX,SI\n", name, 8+row.width)
		if row.rawBool {
			source.WriteString("MOVB $2,(SI)\n")
		}
		fmt.Fprintf(&source, "%s (SI),BX\n%s BX,ret+8(FP)\nRET\n", row.move, row.move)
		fmt.Fprintf(&declarations, "func %s(x %s) %s\n", name, row.input, row.output)
		input, want := row.ctype, "value"
		if row.input == "bool" {
			input = "bool"
		}
		if row.rawBool {
			want = "2"
		}
		fmt.Fprintf(&driver, "extern %s %s(%s);\n", row.ctype, name, input)
		fmt.Fprintf(&checks, `        {
            %s value=(%s)values[index];
            %s got=%s(value);
            if (got!=(%s)%s) {
                fprintf(stderr,"parameter alias row=%d input=%%llx got=%%llx\n",
                    (unsigned long long)value,(unsigned long long)got);
                return 1;
            }
        }
`, input, input, row.ctype, name, row.ctype, want, index)
	}
	driver.WriteString(`int main(void) {
    const uint64_t values[]={0,1,0x80,255,0x100,0x12345678,UINT64_MAX};
    for (unsigned index=0;index<sizeof(values)/sizeof(values[0]);++index) {
`)
	driver.WriteString(checks.String())
	driver.WriteString("    }\n    return 0;\n}\n")
	return source.String(), declarations.String(), driver.String()
}

func TestX86LogicalAMD64ParameterFieldAliasesThreeTargetsAndAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	source, declarations, _ := x86AMD64ParameterAliasFixture()
	for _, triple := range x86AddressMemoryTargets("amd64") {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
				if err != nil {
					t.Fatal("bounded logical parameter field lost its actual backing", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86LogicalAMD64ParameterAliasesKeepSeparateFieldBounds(t *testing.T) {
	for _, row := range []struct{ name, declaration, body string }{
		{"padding", "func Bound(x byte) uint32", "MOVB 1(AX),BX"},
		{"neighbor", "func Bound(x,y uint32) uint32", "MOVL 4(AX),BX"},
		{"partial-copy", "func Bound(x uint32) uint32", "MOVL AX,SI\nMOVL (SI),BX"},
		{"numeric-address", "func Bound(x uint32) uint32", "TESTQ AX,AX\nMOVL (AX),BX"},
		{"unknown-store", "func Bound(x uint32) uint32", "MOVL DX,(AX)\nMOVL (AX),BX"},
		{"index", "func Bound(x uint32) uint32", "MOVL $0,SI\nMOVL (AX)(SI*1),BX"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				source := "TEXT ·Bound(SB),4,$0-12\nLEAQ x+0(FP),AX\n" + row.body + "\nMOVL BX,ret+8(FP)\nRET\n"
				ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("separate scalar allocas supplied contiguous or numeric address authority", err)
				}
			})
		}
	}
}

func TestX86LogicalAMD64ParameterAliasesPortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	source, declarations, driver := x86AMD64ParameterAliasFixture()
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "parameter-field-values", triple, text, driver, nil, level)
				}
			}
		})
	}
}
