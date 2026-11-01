package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixX86PackedGoCallerNumericalResults(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the separately required Linux/amd64 packed caller runtime oracle")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var goSource, assembly, declarations, checks strings.Builder
	goSource.WriteString("package caller\nimport \"unsafe\"\n")
	for _, specification := range []struct {
		opcode   string
		laneBits int
		vex      bool
		aligned  bool
	}{
		{"VMOVDQA", 8, true, true}, {"VMOVDQU", 8, true, false},
		{"VMOVAPD", 64, false, true}, {"VMOVAPS", 32, false, true},
		{"VMOVUPD", 64, false, false}, {"VMOVUPS", 32, false, false},
		{"VMOVDQA32", 32, false, true}, {"VMOVDQA64", 64, false, true},
		{"VMOVDQU8", 8, false, false}, {"VMOVDQU16", 16, false, false},
		{"VMOVDQU32", 32, false, false}, {"VMOVDQU64", 64, false, false},
	} {
		for _, bank := range []string{"X", "Y", "Z"} {
			if specification.vex && bank == "Z" {
				continue
			}
			for _, mode := range []string{"unmasked", "merge", "zero", "loadmerge", "loadzero"} {
				if specification.vex && mode != "unmasked" || specification.aligned && strings.HasPrefix(mode, "load") {
					continue // Aligned memory has no caller-address alignment witness.
				}
				name := "packed" + specification.opcode + bank + mode
				declaration := strings.ReplaceAll(x86CallerFixtureSource, "float32", "uint32")
				declaration = declaration[strings.Index(declaration, "//go:noescape"):]
				declaration = strings.ReplaceAll(declaration, "kernel", name)
				declaration = strings.Replace(declaration, "func Call(", "func Call"+name+"(", 1)
				goSource.WriteString(declaration)

				body := fmt.Sprintf("VMOVUPS (DI),%s0\nVMOVUPS (SI),%s1\n", bank, bank)
				opcode, source, mask := specification.opcode, bank+"0", ""
				if mode != "unmasked" {
					body += "KMOVQ AX,K1\n"
					mask = "K1,"
				}
				if strings.HasPrefix(mode, "load") {
					source = "(DI)"
				}
				if strings.HasSuffix(mode, "zero") {
					opcode += ".Z"
				}
				body += fmt.Sprintf("%s %s,%s%s1\nVMOVSS X1,(DX)", opcode, source, mask, bank)
				machine := strings.ReplaceAll(x86CallerFixtureAssembly, "·kernel", "·"+name)
				machine = strings.Replace(machine, "MOVL $7,AX", "MOVQ (CX),AX", 1)
				assembly.WriteString(strings.Replace(machine, "MOVL AX,(DX)", body, 1))
				fmt.Fprintf(&declarations, "extern void %s(void*,void*,void*,void*) __asm__(LABEL(\"caller.%s\"));\n", name, name)
				fmt.Fprintf(&checks, "    if (check(%s, %d, %t, %t)) return 1;\n", name, specification.laneBits/8, mode == "unmasked", strings.HasSuffix(mode, "zero"))
			}
		}
	}
	// This is original-Go assembly acceptance and actual typed caller metadata,
	// not native AVX512 execution or a third-party whole-library runtime pass.
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	pkg := x86CallerRuntimePackage(t, goSource.String(), assembly.String())
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	triple := testTargetTriple(runtime.GOOS, "amd64")
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(assembly.String()), GoModuleOptions{
		FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translation.Module.Dispose()
	oracle := `#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
` + declarations.String() + `
static int check(void (*fn)(void*,void*,void*,void*), unsigned lane, bool unmasked, bool zero) {
    for (uint64_t length = 64; length < 68; length++) {
        uint8_t input[512], old[512], output[48], before[48];
        for (unsigned i = 0; i < 512; i++) {
            input[i] = (uint8_t)(i*7 + length*13);
            old[i] = (uint8_t)(i*11 + length*17);
        }
        memset(output, 0xa5, sizeof(output));
        memcpy(before, output, sizeof(output));
        const uint64_t original_length = length;
        fn(input, old, output+16, &length);
        if (length != original_length) return 1;
        for (unsigned i = 0; i < sizeof(output); i++) {
            uint8_t want = before[i];
            if (i >= 16 && i < 20) {
                const unsigned byte = i-16;
                const bool active = unmasked || ((length >> (byte/lane)) & 1);
                want = active ? input[byte] : zero ? 0 : old[byte];
            }
            if (output[i] != want) return 2;
        }
        for (unsigned i = 0; i < 512; i++) {
            if (input[i] != (uint8_t)(i*7 + length*13) ||
                old[i] != (uint8_t)(i*11 + length*17)) return 3;
        }
    }
    return 0;
}

int main(void) {
` + checks.String() + "    return 0;\n}\n"
	var runner []string
	if crossRosetta {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed-caller-numerical", triple, translation.Module.String(), oracle, runner)
}
