package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func ordinaryGlobalLoadExpected(row ordinaryGlobalLoadCase, seed uint64) uint64 {
	var storage [40]byte
	for index := 0; index < 5; index++ {
		binary.LittleEndian.PutUint64(storage[8*index:], seed^(uint64(index)*0x9e3779b97f4a7c15))
	}
	var value uint64
	for index := 0; index < row.readBits/8; index++ {
		value |= uint64(storage[1+index]) << uint(8*index)
	}
	if row.signed && value&(uint64(1)<<uint(row.readBits-1)) != 0 && row.readBits < 64 {
		value |= ^uint64(0) << uint(row.readBits)
	}
	if row.highByte {
		return 0x1234567889abcdef&^uint64(0xff00) | (value&255)<<8
	}
	switch row.writeBits {
	case 8:
		return 0x1234567889abcdef&^uint64(255) | value&255
	case 16:
		return 0x1234567889abcdef&^uint64(65535) | value&65535
	case 32:
		return uint64(uint32(value))
	default:
		return value
	}
}

func TestCrossLinuxRuntimeMatrixGoModuleOrdinaryGlobalLoads(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	assembly, declarations := ordinaryGlobalLoadSource("amd64")
	rows := ordinaryGlobalLoadCases("amd64")
	patterns := []uint64{0, 1, 0x7f00, 0x8000, 0xff00, 0x7fff00, 0x800000,
		0xffff00, 0x7fffffff00, 0x8000000000, 0xffffffff00, ^uint64(0), 0x0123456789abcdef}
	var goChecks, cChecks, cDeclarations strings.Builder
	prefix := ""
	if runtime.GOOS == "darwin" {
		prefix = "_"
	}
	// Use a simple linked namespace while retaining the real checked Types
	// package. No SDK/native-storage owner or initializer is substituted.
	const linkedPackage = "ordinaryglobals"
	for index := range rows {
		fmt.Fprintf(&cDeclarations, "extern uint64_t load%d(void) __asm__(\"%s%s.load%d\");\n",
			index, prefix, linkedPackage, index)
	}
	for pattern, seed := range patterns {
		fmt.Fprintf(&goChecks, "for i:=range words { words[i]=uint64(%d)^(uint64(i)*0x9e3779b97f4a7c15) }\n", seed)
		fmt.Fprintf(&cChecks, "for(unsigned i=0;i<5;++i) storage[i]=UINT64_C(%d)^((uint64_t)i*UINT64_C(0x9e3779b97f4a7c15));\n", seed)
		for index, row := range rows {
			want := ordinaryGlobalLoadExpected(row, seed)
			fmt.Fprintf(&goChecks, "if got:=load%d(); got!=uint64(%d) { panic(fmt.Sprintf(\"pattern=%d load=%d got=%%x\",got)) }\n",
				index, want, pattern, index)
			fmt.Fprintf(&cChecks, "if(load%d()!=UINT64_C(%d)) { fprintf(stderr,\"pattern=%d load=%d mismatch\\n\");return 1; }\n",
				index, want, pattern, index)
		}
	}
	want := fmt.Sprintf("%d mutable global loads x %d patterns\n", len(rows), len(patterns))
	goSource := "package main\nimport \"fmt\"\n" + declarations +
		"func main(){\n" + goChecks.String() + fmt.Sprintf("fmt.Print(%q)\n}\n", want)
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module originalglobalload\n\ngo 1.20\n", "main.go": goSource, "original_amd64.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "original")
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	command := exec.Command("go", "build", "-p=2", "-o", executable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=amd64", "CGO_ENABLED=0",
		"GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local")
	x86FloatCompareCaptureCommand(t, command)
	if output := execution.run(t, executable); string(output) != want {
		t.Fatalf("original complete Go-source numerical oracle: %q", output)
	}
	cSource := "#include <stdint.h>\n#include <stdio.h>\n" + cDeclarations.String() +
		fmt.Sprintf("uint64_t storage[5] __asm__(\"%s%s.words\");\n", prefix, linkedPackage) +
		"int main(void){\n" + cChecks.String() + fmt.Sprintf("printf(%q);return 0;\n}\n", want)
	for _, api := range []string{"public", "owned-context"} {
		t.Run(api, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
			pkg.Path = linkedPackage
			ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(assembly), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, pipeline := range []struct{ name, ir, level string }{
				{"backend_O0", ir, "-O0"},
				{"IR_O2/backend_O2", x86MulDivRoundOptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					output := execution.compileAndRunLLVM(t, "ordinary-global-load", pipeline.ir, cSource, pipeline.level)
					if string(output) != want {
						t.Fatalf("mutable global numerical receipt: %q", output)
					}
					t.Log(strings.TrimSpace(want))
				})
			}
		})
	}
}
