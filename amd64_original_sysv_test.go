package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These test-only byte wrappers explicitly consume SysV registers, even on
// Windows. Both declarations and indirect calls must retain that convention;
// translated functions still use their target's ordinary C ABI. This is not a
// production Go ABI contract. See clang.llvm.org/docs/AttributeReference.html#sysv-abi.
const x86OriginalSysVAttribute = "__attribute__((sysv_abi))"

func x86OriginalSysVDeclaration(result, name, arguments string) string {
	return fmt.Sprintf("extern %s %s %s(%s);\n", result, x86OriginalSysVAttribute, name, arguments)
}

func x86OriginalSysVPointer(result, name, arguments string) string {
	return fmt.Sprintf("typedef %s (%s *%s)(%s);\n", result, x86OriginalSysVAttribute, name, arguments)
}

func TestX86OriginalSysVDirectAndPointerTransport(t *testing.T) {
	clang, llc := findLLVM22Tool("clang"), findLLVM22Tool("llc")
	if clang == "" || llc == "" {
		t.Fatal("LLVM 22 clang and llc required")
	}
	var source strings.Builder
	source.WriteString("typedef unsigned char uint8_t; typedef unsigned int uint32_t; typedef unsigned long long uint64_t; typedef long long int64_t;\n")
	for index, signature := range []struct {
		result, parameters, arguments string
	}{
		{"uint64_t", "uint32_t k,uint32_t h", "k,h"},
		{"uint64_t", "uint8_t *out,int64_t index,uint64_t value", "out,index,value"},
		{"void", "uint8_t *out,const uint8_t *input,uint64_t old,uint64_t flags", "out,input,old,flags"},
		{"void", "uint8_t *out,float input,uint64_t old,uint64_t flags", "out,input,old,flags"},
		{"void", "uint8_t *out,double input,uint64_t old,uint64_t flags", "out,input,old,flags"},
		{"void", "uint8_t *out,const uint8_t *a,const uint8_t *b,const uint8_t *old,uint64_t flags,uint32_t csr", "out,a,b,old,flags,csr"},
	} {
		name, pointer := fmt.Sprintf("Original%d", index), fmt.Sprintf("OriginalProgram%d", index)
		source.WriteString(x86OriginalSysVDeclaration(signature.result, name, signature.parameters))
		source.WriteString(x86OriginalSysVPointer(signature.result, pointer, signature.parameters))
		fmt.Fprintf(&source, "extern %s Translated%d(%s);\n", signature.result, index, signature.parameters)
		fmt.Fprintf(&source, "void Check%d(%s pointer,%s) { %s(%s); pointer(%s); Translated%d(%s); }\n",
			index, pointer, signature.parameters, name, signature.arguments, signature.arguments, index, signature.arguments)
	}
	for _, target := range []string{"x86_64-pc-windows-msvc", "x86_64-w64-windows-gnu", "x86_64-unknown-linux-gnu", "x86_64-apple-darwin"} {
		t.Run(target, func(t *testing.T) {
			directory := t.TempDir()
			input, output := filepath.Join(directory, "transport.c"), filepath.Join(directory, "transport.ll")
			if err := os.WriteFile(input, []byte(source.String()), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(ctx, clang, "-target", target, "-nostdinc", "-Werror",
				"-O0", "-S", "-emit-llvm", input, "-o", output)
			if data, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
				t.Fatalf("typed direct/indirect transport: %v\n%s", err, data)
			}
			ir, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(target, "windows") && strings.Count(string(ir), "call x86_64_sysvcc ") != 12 {
				t.Fatal("Windows direct or pointer call erased the original SysV ABI")
			}
			translatedCalls := 0
			for _, line := range strings.Split(string(ir), "\n") {
				if strings.Contains(line, "call ") && strings.Contains(line, "@Translated") {
					translatedCalls++
					if strings.Contains(line, "x86_64_sysvcc") {
						t.Fatal("original byte-wrapper ABI leaked into a translated call")
					}
				}
			}
			if translatedCalls != 6 {
				t.Fatalf("translated call controls = %d, want 6", translatedCalls)
			}
			compileLLVMToObject(t, llc, target, "transport.ll", "transport.o", string(ir))
		})
	}
}
