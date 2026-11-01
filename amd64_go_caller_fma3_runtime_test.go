package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixX86FMA3GoCallerNumericalFamily(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the separately required Linux/amd64 FMA3 caller runtime oracle")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	formats := x86FMA3NamedFormats("amd64")
	var runner []string
	if crossRosetta {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	x86OriginalFloatingRuntimeRequireCPU(t, "fma-caller", clang, testTargetTriple(runtime.GOOS, "amd64"), runner)
	// Caller proofs fingerprint the complete source selection. Keep that
	// selection bounded instead of repeatedly hashing a giant fixture for
	// every function. Each format still has its own actual typed Go caller,
	// translation and numerical oracle; every batch releases its LLVM objects.
	const batchSize = 64
	attempted, passed := 0, 0
	for start := 0; start < len(formats); start += batchSize {
		end := start + batchSize
		if end > len(formats) {
			end = len(formats)
		}
		t.Run(fmt.Sprintf("formats_%04d_%04d", start, end), func(t *testing.T) {
			attempted += end - start
			runX86FMA3GoCallerNumericalBatch(t, llc, clang, formats[start:end], start, runner)
			passed += end - start
		})
	}
	t.Logf("%d/%d attempted FMA3 formats passed (%d available): numerical low result, directed rounding, unknown-valued initialized mask, read-only inputs and full output canaries", passed, attempted, len(formats))
}

func runX86FMA3GoCallerNumericalBatch(t *testing.T, llc, clang string, formats []string, first int, runner []string) {
	t.Helper()
	var goSource, assembly, declarations, checks strings.Builder
	goSource.WriteString("package caller\nimport \"unsafe\"\n")
	for index, instruction := range formats {
		name := fmt.Sprintf("fmacase%d", first+index)
		opcode := strings.Fields(instruction)[0]
		base := strings.Split(opcode, ".")[0]
		bits := 32
		if strings.HasSuffix(base, "PD") || strings.HasSuffix(base, "SD") {
			bits = 64
		}
		declaration := x86CallerFixtureSource[strings.Index(x86CallerFixtureSource, "//go:noescape"):]
		declaration = strings.ReplaceAll(declaration, "kernel", name)
		declaration = strings.Replace(declaration, "func Call(", "func Call"+name+"(", 1)
		if bits == 64 {
			declaration = strings.ReplaceAll(declaration, "float32", "float64")
		}
		goSource.WriteString(declaration)

		bank := "X"
		if strings.Contains(instruction, "Y1") {
			bank = "Y"
		} else if strings.Contains(instruction, "Z1") {
			bank = "Z"
		}
		body := fmt.Sprintf("VMOVUPS (DI),%s0\nVMOVUPS (SI),%s1\nVMOVUPS 64(SI),%s2\nKMOVQ AX,K1\n", bank, bank, bank)
		body += strings.ReplaceAll(instruction, "(AX)", "(DI)") + "\n"
		store := "VMOVSS X2,(DX)"
		if bits == 64 {
			store = "VMOVSD X2,(DX)"
		}
		body += store
		machine := strings.ReplaceAll(x86CallerFixtureAssembly, "·kernel", "·"+name)
		machine = strings.Replace(machine, "MOVL $7,AX", "MOVQ (CX),AX", 1)
		assembly.WriteString(strings.Replace(machine, "MOVL AX,(DX)", body, 1))
		fmt.Fprintf(&declarations, "extern void %s(void*,void*,void*,void*) __asm__(LABEL(\"caller.%s\"));\n", name, name)

		order, err := strconv.Atoi(base[len(base)-5 : len(base)-2])
		if err != nil {
			t.Fatal(err)
		}
		mode := 0
		switch {
		case strings.HasPrefix(base, "VFMADDSUB"):
			mode = 4
		case strings.HasPrefix(base, "VFMSUBADD"):
			mode = 5
		case strings.HasPrefix(base, "VFNMADD"):
			mode = 2
		case strings.HasPrefix(base, "VFNMSUB"):
			mode = 3
		case strings.HasPrefix(base, "VFMSUB"):
			mode = 1
		}
		rounding := 0
		for suffix, value := range map[string]int{".RD_SAE": 1, ".RU_SAE": 2, ".RZ_SAE": 3} {
			if strings.Contains(opcode, suffix) {
				rounding = value
			}
		}
		fmt.Fprintf(&checks, "    if (check(%s,%q,%d,%d,%d,%t,%t,%d)) return 1;\n",
			name, instruction, bits, order, mode, strings.Contains(instruction, "K1"), strings.HasSuffix(opcode, ".Z"), rounding)
	}
	// Actual Go accepts every original instruction and supplies the exact
	// typed caller. Portable LLVM/C execution is not native AVX512 execution
	// and is not a whole third-party library/ledger pass.
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
	oracle := x86FMA3CallerCOracle + declarations.String() + "\nint main(void) {\n" + checks.String() + "    return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "fma3-caller-numerical", triple, translation.Module.String(), oracle, runner)
}

const x86FMA3CallerCOracle = `#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <fenv.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif

#pragma STDC FENV_ACCESS ON
static int check(void (*fn)(void*,void*,void*,void*), const char *instruction, unsigned bits,
                 unsigned order, unsigned mode, bool masked, bool zero,
                 unsigned rounding) {
    const int modes[] = {FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    for (uint64_t length=64; length<68; length++) {
        uint8_t first[512], second[512], before_first[512], before_second[512];
        uint8_t output[48], expected[48];
        for (unsigned i=0; i<512/(bits/8); i++) {
            if (bits == 32) {
                float a=1.00000011920928955078125f;
                float b=-1.0000002384185791015625f;
                if (i != 0) { a=(float)((int)(i%7)-3)/4; b=(float)((int)(i%5)-2)/8; }
                memcpy(first+i*4,&a,4); memcpy(second+i*4,&b,4);
            } else {
                double a=1.0000000000000002220446049250313;
                double b=-1.0000000000000004440892098500626;
                if (i != 0) { a=(double)((int)(i%7)-3)/4; b=(double)((int)(i%5)-2)/8; }
                memcpy(first+i*8,&a,8); memcpy(second+i*8,&b,8);
            }
        }
        memcpy(before_first,first,512); memcpy(before_second,second,512);
        memset(output,0xa5,48); memcpy(expected,output,48);
        const uint64_t original_length=length;
        fn(first,second,output+16,&length);
        if (length != original_length) return 1;
        if (fesetround(modes[rounding])) return 2;
        if (bits == 32) {
            float first_value, second_value, old, a, b, c, result;
            memcpy(&first_value,first,4); memcpy(&second_value,second,4); memcpy(&old,second+64,4);
            a=old; b=first_value; c=second_value;
            if (order == 213) { a=second_value; b=old; c=first_value; }
            if (order == 231) { a=second_value; b=first_value; c=old; }
            if (mode == 2 || mode == 3) a=-a;
            if (mode == 1 || mode == 3 || mode == 4) c=-c;
            result=fmaf(a,b,c);
            if (masked && !(length&1)) result=zero ? 0 : old;
            memcpy(expected+16,&result,4);
        } else {
            double first_value, second_value, old, a, b, c, result;
            memcpy(&first_value,first,8); memcpy(&second_value,second,8); memcpy(&old,second+64,8);
            a=old; b=first_value; c=second_value;
            if (order == 213) { a=second_value; b=old; c=first_value; }
            if (order == 231) { a=second_value; b=first_value; c=old; }
            if (mode == 2 || mode == 3) a=-a;
            if (mode == 1 || mode == 3 || mode == 4) c=-c;
            result=fma(a,b,c);
            if (masked && !(length&1)) result=zero ? 0 : old;
            memcpy(expected+16,&result,8);
        }
        if (fesetround(FE_TONEAREST)) return 3;
        if (memcmp(output,expected,48) || memcmp(first,before_first,512) ||
            memcmp(second,before_second,512)) {
            fprintf(stderr,"FMA3 %s bits/order/mode/mask/zero/rounding/length %u/%u/%u/%u/%u/%u/%llu\n",
                    instruction,bits,order,mode,masked,zero,rounding,(unsigned long long)length);
            for (unsigned i=16; i<16+bits/8; i++) {
                fprintf(stderr,"%02x/%02x ",output[i],expected[i]);
            }
            fprintf(stderr,"\n");
            return 4;
        }
    }
    return 0;
}
`
