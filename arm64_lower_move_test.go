package plan9asm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type arm64VMOVCase struct {
	instruction                        string
	shape                              string
	bytes, sourceLane, destinationLane int
	alias, zero                        bool
}

// Go 1.27 asm7.go has six AVMOV rows, cases 73/78/80/82/83/92.
// Case 92 preserves every other destination lane, including self aliases.
func arm64VMOVCases() []arm64VMOVCase {
	var cases []arm64VMOVCase
	for _, element := range []struct {
		kind  string
		bytes int
	}{{"B", 1}, {"H", 2}, {"S", 4}, {"D", 8}} {
		lanes := 16 / element.bytes
		for source := 0; source < lanes; source++ {
			for destination := 0; destination < lanes; destination++ {
				cases = append(cases, arm64VMOVCase{instruction: fmt.Sprintf("VMOV V0.%s[%d],V1.%s[%d]", element.kind, source, element.kind, destination), shape: "lane", bytes: element.bytes, sourceLane: source, destinationLane: destination})
			}
			cases = append(cases,
				arm64VMOVCase{instruction: fmt.Sprintf("VMOV V0.%s[%d],V0.%s[%d]", element.kind, source, element.kind, lanes-1-source), shape: "lane", bytes: element.bytes, sourceLane: source, destinationLane: lanes - 1 - source, alias: true},
				arm64VMOVCase{instruction: fmt.Sprintf("VMOV V0.%s[%d],V1", element.kind, source), shape: "scalar", bytes: element.bytes, sourceLane: source},
				arm64VMOVCase{instruction: fmt.Sprintf("VMOV V0.%s[%d],R4", element.kind, source), shape: "extract", bytes: element.bytes, sourceLane: source},
				arm64VMOVCase{instruction: fmt.Sprintf("VMOV R3,V1.%s[%d]", element.kind, source), shape: "insert", bytes: element.bytes, destinationLane: source},
				arm64VMOVCase{instruction: fmt.Sprintf("VMOV ZR,V1.%s[%d]", element.kind, source), shape: "insert", bytes: element.bytes, destinationLane: source, zero: true},
			)
		}
	}
	for _, arrangement := range []struct {
		name         string
		bytes, lanes int
	}{{"B8", 1, 8}, {"B16", 1, 16}, {"H4", 2, 4}, {"H8", 2, 8}, {"S2", 4, 2}, {"S4", 4, 4}, {"D2", 8, 2}} {
		for _, zero := range []bool{false, true} {
			reg := "R3"
			if zero {
				reg = "ZR"
			}
			cases = append(cases, arm64VMOVCase{instruction: "VMOV " + reg + ",V1." + arrangement.name, shape: "duplicate", bytes: arrangement.bytes, destinationLane: arrangement.lanes, zero: zero})
		}
	}
	for _, lanes := range []int{8, 16} {
		cases = append(cases, arm64VMOVCase{instruction: fmt.Sprintf("VMOV V0.B%d,V1.B%d", lanes, lanes), shape: "copy", bytes: lanes})
	}
	return cases
}

func arm64VMOVSource(cases []arm64VMOVCase) string {
	var source strings.Builder
	source.WriteString("TEXT ·vmovfamily(SB),$0-32\nMOVD src+0(FP),R0\nMOVD dst+8(FP),R1\nMOVD out+16(FP),R2\nMOVD value+24(FP),R3\n")
	for _, tc := range cases {
		source.WriteString("VLD1 (R0),[V0.B16]\nVLD1 (R1),[V1.B16]\n" + tc.instruction + "\n")
		if tc.shape == "extract" {
			source.WriteString("MOVD R4,(R2)\nMOVD ZR,8(R2)\nADD $16,R2\n")
		} else {
			reg := "V1"
			if tc.alias {
				reg = "V0"
			}
			source.WriteString("VST1.P [" + reg + ".B16],16(R2)\n")
		}
	}
	source.WriteString("RET\n")
	return source.String()
}

func arm64VMOVExpected(cases []arm64VMOVCase, src, dst []byte, value uint64) []byte {
	out := make([]byte, 16*len(cases))
	var scalar [8]byte
	binary.LittleEndian.PutUint64(scalar[:], value)
	for i, tc := range cases {
		part := out[16*i : 16*i+16]
		base := dst
		if tc.alias {
			base = src
		}
		switch tc.shape {
		case "lane":
			copy(part, base)
			copy(part[tc.destinationLane*tc.bytes:], src[tc.sourceLane*tc.bytes:(tc.sourceLane+1)*tc.bytes])
		case "scalar", "extract":
			copy(part, src[tc.sourceLane*tc.bytes:(tc.sourceLane+1)*tc.bytes])
		case "insert":
			copy(part, base)
			bytes := scalar[:tc.bytes]
			if tc.zero {
				bytes = make([]byte, tc.bytes)
			}
			copy(part[tc.destinationLane*tc.bytes:], bytes)
		case "duplicate":
			if !tc.zero {
				for lane := 0; lane < tc.destinationLane; lane++ {
					copy(part[lane*tc.bytes:], scalar[:tc.bytes])
				}
			}
		case "copy":
			copy(part, src[:tc.bytes])
		}
	}
	return out
}

func arm64VMOVInputs(iteration int) ([]byte, []byte, uint64) {
	src, dst := make([]byte, 16), make([]byte, 16)
	for i := range src {
		src[i] = byte(i*29 + iteration*71 + 13)
		dst[i] = byte(i*37 + iteration*11 + 193)
	}
	return src, dst, 0xfedcba9876543210 ^ uint64(iteration)*0x1717171717171717
}

func arm64VMOVIR(t *testing.T, triple string, cases []arm64VMOVCase) string {
	t.Helper()
	pkg := mustGoPackage(t, "vmovoracle", "package main\nfunc vmovfamily(src,dst,out *byte,value uint64)\n")
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	result, err := translateGoModuleInContext(ctx, pkg, []byte(arm64VMOVSource(cases)), GoModuleOptions{FileName: "move_arm64.s", GOOS: "linux", GOARCH: "arm64", TargetTriple: triple, ResolveSym: testResolveSym("vmovoracle")})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Module.Dispose()
	return result.Module.String()
}

func TestARM64VMOVCompleteGoFormatsObjects(t *testing.T) {
	cases := arm64VMOVCases()
	t.Logf("%d cases cover all six Go AVMOV optab rows and all lane indices", len(cases))
	requireARM64GoAssemblerResult(t, arm64VMOVSource(cases), true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc", "aarch64-pc-windows-gnu"} {
		t.Run(triple, func(t *testing.T) {
			compileLLVMToObject(t, llc, triple, "vmov.ll", "vmov.o", arm64VMOVIR(t, triple, cases))
		})
	}
}

func TestARM64VMOVRejectsNonGoFormats(t *testing.T) {
	for _, instruction := range []string{
		"VMOV V0.S[1],V1.H[0]", "VMOV V0.B[16],V1.B[0]",
		"VMOV V0.H[0],V1.H[8]", "VMOV R0,V1.S[4]",
		"VMOV V0.D[2],R0", "VMOV V0.Q[0],V1.Q[0]",
		"VMOV V0,V1", "VMOV V0,R0", "VMOV R0,V1",
		// Retain the two old helper fixtures as actual Go-rejected negatives.
		"VMOV V1,V3", "VMOV V2,R0",
		"VMOV V0.S4,V1.S4", "VMOV V0.B8,V1.B16",
		"VMOV V0.S[1],V1.S4", "VMOV V0.B16,V1.B[0]",
		"VMOV V0.B16,R0", "VMOV RSP,V1.D[0]",
		"VMOV V0.D[0],RSP", "VMOV.P V0.B[0],V1.B[0]",
		"VMOV V0.S[0],V1.S[0],V2.S[0]", "VMOV (R0),V1.B16",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·badmove(SB),$0-0\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", ResolveSym: testResolveSym("vmovoracle"), Sigs: map[string]FuncSig{"vmovoracle.badmove": {Name: "vmovoracle.badmove", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted non-Go VMOV form %q", instruction)
			}
		})
	}
}

func TestARM64VMOVAllTranslationAPIs(t *testing.T) {
	cases := []arm64VMOVCase{
		{instruction: "VMOV V0.S[2],V1.S[0]"},
		{instruction: "VMOV V0.H[7],R4", shape: "extract"},
		{instruction: "VMOV R3,V1.D[1]"},
		{instruction: "VMOV V0.B[15],V1"},
		{instruction: "VMOV R3,V1.S4"},
		{instruction: "VMOV V0.B8,V1.B8"},
	}
	source := arm64VMOVSource(cases)
	pkg := mustGoPackage(t, "vmovoracle", "package main\nfunc vmovfamily(src,dst,out *byte,value uint64)\n")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc", "aarch64-pc-windows-gnu"} {
		t.Run(triple, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			goModule, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{FileName: "move_arm64.s", GOOS: "linux", GOARCH: "arm64", TargetTriple: triple, ResolveSym: testResolveSym("vmovoracle")})
			if err != nil {
				t.Fatal(err)
			}
			defer goModule.Module.Dispose()
			compileLLVMToObject(t, llc, triple, "go-module.ll", "go-module.o", goModule.Module.String())
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: testResolveSym("vmovoracle"), Sigs: goModule.Signatures}
			text, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "text.ll", "text.o", text)
			module, err := TranslateModuleInContext(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			defer module.Dispose()
			compileLLVMToObject(t, llc, triple, "module.ll", "module.o", module.String())
		})
	}
}

func TestARM64VMOVNativeGoRuntime(t *testing.T) {
	cross := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !cross {
		t.Skip("native Go VMOV oracle requires ARM64 or the required Linux/QEMU counterpart")
	}
	cases := arm64VMOVCases()
	var main strings.Builder
	main.WriteString(`package main

import (
    "bytes"
    "encoding/hex"
    "fmt"
)

func vmovfamily(src, dst, out *byte, value uint64)

func main() {
`)
	for iteration := 0; iteration < 4; iteration++ {
		src, dst, value := arm64VMOVInputs(iteration)
		fmt.Fprintf(&main, `{
    src, _ := hex.DecodeString(%q)
    dst, _ := hex.DecodeString(%q)
    want, _ := hex.DecodeString(%q)
    got := make([]byte, len(want))
    vmovfamily(&src[0], &dst[0], &got[0], %d)
    if !bytes.Equal(got, want) {
        for i := range want {
            if got[i] != want[i] {
                panic(fmt.Sprintf("iteration %d case %%d byte %%d got %%02x want %%02x",
                    i/16, i%%16, got[i], want[i]))
            }
        }
    }
}
`, hex.EncodeToString(src), hex.EncodeToString(dst), hex.EncodeToString(arm64VMOVExpected(cases, src, dst, value)), value, iteration)
	}
	main.WriteString("}\n")
	dir := t.TempDir()
	for name, data := range map[string]string{"go.mod": "module vmovoracle\n\ngo 1.20\n", "main.go": main.String(), "move_arm64.s": arm64VMOVSource(cases)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"run", "."}
	if cross {
		if _, err := exec.LookPath("qemu-aarch64"); err != nil {
			t.Fatal(err)
		}
		args = []string{"run", "-exec=qemu-aarch64", "."}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("original Go VMOV runtime: %v\n%s", err, out)
	}
}

func TestARM64VMOVLLVMRuntime(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("LLVM VMOV execution requires ARM64; required Linux ARM64 counterpart executes the same full matrix")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	cases := arm64VMOVCases()
	var main strings.Builder
	symbol := "vmovoracle.vmovfamily"
	if runtime.GOOS == "darwin" {
		symbol = "_" + symbol
	}
	fmt.Fprintf(&main, `#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void vmovfamily(const uint8_t*, const uint8_t*, uint8_t*, uint64_t) __asm__(%q);

int main(void) {
`, symbol)
	for iteration := 0; iteration < 4; iteration++ {
		src, dst, value := arm64VMOVInputs(iteration)
		for _, array := range []struct {
			name  string
			bytes []byte
		}{{"src", src}, {"dst", dst}, {"want", arm64VMOVExpected(cases, src, dst, value)}} {
			if array.name == "src" {
				main.WriteString("{\n")
			}
			fmt.Fprintf(&main, "const uint8_t %s[]={", array.name)
			for _, b := range array.bytes {
				fmt.Fprintf(&main, "%d,", b)
			}
			main.WriteString("};\n")
		}
		fmt.Fprintf(&main, `uint8_t got[sizeof(want)] = {0};
    vmovfamily(src, dst, got, UINT64_C(%d));
    for (unsigned i = 0; i < sizeof(want); i++) {
        if (got[i] != want[i]) {
            fprintf(stderr, "iteration %d case %%u byte %%u got %%02x want %%02x\n",
                i/16, i%%16, got[i], want[i]);
            return 1;
        }
    }
}
`, value, iteration)
	}
	main.WriteString("    return 0;\n}\n")
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vmov", triple, arm64VMOVIR(t, triple, cases), main.String(), nil)
}
