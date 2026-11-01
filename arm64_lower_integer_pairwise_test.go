package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

var arm64VADDPArrangements = []struct {
	name        string
	elementBits int
	lanes       int
}{
	{"B8", 8, 8}, {"B16", 8, 16},
	{"H4", 16, 4}, {"H8", 16, 8},
	{"S2", 32, 2}, {"S4", 32, 4},
	{"D2", 64, 2},
}

func TestARM64VADDPCompleteGoFormsAndRawScalar(t *testing.T) {
	file, sigs, _ := arm64VADDPProgram(t, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "vaddp.ll", "vaddp.o", ir)
		})
	}
}

func TestARM64VADDPRejectsGoInvalidForms(t *testing.T) {
	for _, line := range []string{
		"VADDP V1.D1, V2.D1, V0.D1",
		"VADDP V1.H4, V2.H8, V0.H4",
		"VADDP V1.S2, V2.S2, V0.D2",
		"VADDP V1.D2, V0",
	} {
		source := "TEXT invalidpair(SB),4,$0-0\n" + line + "\nRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		_, err = Translate(file, Options{
			Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"invalidpair": {Name: "invalidpair", Ret: Void}},
		})
		if err == nil {
			t.Errorf("translator accepted Go-rejected form %q", line)
		}
	}
}

func TestARM64RawScalarADDPDecoderRegisterSpace(t *testing.T) {
	for source := 0; source < 32; source++ {
		for destination := 0; destination < 32; destination++ {
			word := uint32(0x5ef1b800 | source<<5 | destination)
			decoded, ok := decodeARM64RawScalarADDP(word)
			if !ok || decoded.source != source || decoded.destination != destination {
				t.Errorf("%#08x decoded as %+v, %v", word, decoded, ok)
			}
		}
	}
	for bit := uint(10); bit < 32; bit++ {
		word := uint32(0x5ef1b800) ^ (1 << bit)
		if decoded, ok := decodeARM64RawScalarADDP(word); ok {
			t.Errorf("accepted mutated fixed bit %d in %#08x as %+v", bit, word, decoded)
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64VADDP(t *testing.T) {
	cross := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !cross {
		t.Skip("ARM64 native execution or required Linux cross-runtime matrix")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compiler := []string{findLLVM22Tool("clang")}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runner []string
	if cross {
		compiler = []string{"aarch64-linux-gnu-gcc"}
		triple = "aarch64-unknown-linux-gnu"
		runner = []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"}
	} else if compiler[0] == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	for _, withScalar := range []bool{false, true} {
		name := "vector"
		if withScalar {
			name = "scalar"
		}
		t.Run(name, func(t *testing.T) {
			file, sigs, oracle := arm64VADDPProgram(t, withScalar)
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "vaddp", triple, ir, oracle, runner)
		})
	}
}

func arm64VADDPProgram(t *testing.T, withScalar bool) (*File, map[string]FuncSig, string) {
	t.Helper()
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for index, shape := range arm64VADDPArrangements {
		name := fmt.Sprintf("pairwise%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\n", name)
		fmt.Fprint(&source, "MOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD out+16(FP),R2\n")
		fmt.Fprint(&source, "VLD1 (R0),[V1.B16]\nVLD1 (R1),[V2.B16]\n")
		fmt.Fprintf(&source, "VADDP V1.%s,V2.%s,V0.%s\n", shape.name, shape.name, shape.name)
		fmt.Fprint(&source, "VST1 [V0.B16],(R2)\nRET\n")
		fmt.Fprintf(&declarations, "extern void %s(const void *,const void *,void *);\n", name)
		fmt.Fprintf(&checks, "    if (check(%s,%d,%d,0,0)) return %d;\n", name, shape.elementBits, shape.lanes, index+1)
		sigs[name] = arm64PairwiseSig(name)

		aliasName := fmt.Sprintf("pairwiseAlias%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\n", aliasName)
		fmt.Fprint(&source, "MOVD a+0(FP),R0\nMOVD out+16(FP),R2\n")
		fmt.Fprint(&source, "VLD1 (R0),[V0.B16]\n")
		fmt.Fprintf(&source, "VADDP V0.%s,V0.%s,V0.%s\n", shape.name, shape.name, shape.name)
		fmt.Fprint(&source, "VST1 [V0.B16],(R2)\nRET\n")
		fmt.Fprintf(&declarations, "extern void %s(const void *,const void *,void *);\n", aliasName)
		fmt.Fprintf(&checks, "    if (check(%s,%d,%d,0,1)) return %d;\n", aliasName, shape.elementBits, shape.lanes, index+9)
		sigs[aliasName] = arm64PairwiseSig(aliasName)
	}
	if withScalar {
		const scalarName = "pairwiseScalar"
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\n", scalarName)
		fmt.Fprint(&source, "MOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD out+16(FP),R2\n")
		fmt.Fprint(&source, "VLD1 (R0),[V1.B16]\nWORD $0x5ef1b820\nVST1 [V0.B16],(R2)\nRET\n")
		fmt.Fprintf(&declarations, "extern void %s(const void *,const void *,void *);\n", scalarName)
		fmt.Fprintf(&checks, "    if (check(%s,64,1,1,0)) return 16;\n", scalarName)
		sigs[scalarName] = arm64PairwiseSig(scalarName)

		const aliasName = "pairwiseScalarAlias"
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\n", aliasName)
		fmt.Fprint(&source, "MOVD a+0(FP),R0\nMOVD out+16(FP),R2\n")
		fmt.Fprint(&source, "VLD1 (R0),[V0.B16]\nWORD $0x5ef1b800\nVST1 [V0.B16],(R2)\nRET\n")
		fmt.Fprintf(&declarations, "extern void %s(const void *,const void *,void *);\n", aliasName)
		fmt.Fprintf(&checks, "    if (check(%s,64,1,1,1)) return 17;\n", aliasName)
		sigs[aliasName] = arm64PairwiseSig(aliasName)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	oracle := arm64VADDPOracleC + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	return file, sigs, oracle
}

func arm64PairwiseSig(name string) FuncSig {
	return FuncSig{
		Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: Ptr, Index: 2, Field: -1},
		}},
	}
}

const arm64VADDPOracleC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t lane(const uint8_t *value, int bits, int index) {
    uint64_t result = 0;
    memcpy(&result, value + index * bits / 8, bits / 8);
    return result;
}

static int check(void (*fn)(const void *,const void *,void *), int bits, int lanes, int scalar, int alias) {
    uint8_t a[16], b[16], got[16], want[16];
    uint32_t seed = 0x734291bcU;
    for (int trial = 0; trial < 256; trial++) {
        for (int byte = 0; byte < 16; byte++) {
            seed = seed * 1664525U + 1013904223U;
            a[byte] = seed >> 24;
            seed = seed * 1664525U + 1013904223U;
            b[byte] = seed >> 16;
        }
        memset(want, 0, 16);
        if (scalar) {
            uint64_t result = lane(a,64,0) + lane(a,64,1);
            memcpy(want, &result, 8);
        } else {
            for (int index = 0; index < lanes; index++) {
                const uint8_t *source = index < lanes / 2 && !alias ? b : a;
                int sourceIndex = (index % (lanes / 2)) * 2;
                uint64_t result = lane(source,bits,sourceIndex) + lane(source,bits,sourceIndex+1);
                memcpy(want + index * bits / 8, &result, bits / 8);
            }
        }
        memset(got, 0xa5, 16);
        fn(a,b,got);
        if (memcmp(got,want,16)) {
            fprintf(stderr,"VADDP mismatch bits=%d lanes=%d scalar=%d alias=%d trial=%d\n",bits,lanes,scalar,alias,trial);
            return 1;
        }
    }
    return 0;
}
`
