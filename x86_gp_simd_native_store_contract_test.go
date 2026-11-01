package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Independent named store inventory: Go's MOVD and MOVDQ2Q alias MOVQ,
// while VMOVQ's memory width stays eight bytes even in mode32.
var x86GPSIMDNativeStoreRows = []struct {
	op    string
	bytes int64
}{
	{"MOVL", 4}, {"MOVQ", 8}, {"MOVD", 8}, {"MOVDQ2Q", 8},
	{"VMOVD", 4}, {"VMOVQ", 8},
}

func TestX86GPSIMDNativeStoreNumericalContinuation(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86GPSIMDNativeStoreRows {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86YMMReadSource(t, row.op+" X0,(BX)")
				form, known, err := x86GPSIMDTransferProperties(ins, arch)
				if !known || err != nil || !form.memoryWrite || int64(form.bits/8) != row.bytes {
					t.Fatal("complete named store grammar changed", form, err)
				}
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				state.writeVector(0, 64, ^uint64(0), false)
				state.pointerGP[3], state.gp[3], state.masks[1] = true, 0xff, true
				before := state.clone()
				if !x86ResultGPSIMDTransferWithNativeMemory(ins, form, &state, nil, 0, arch, true) || !reflect.DeepEqual(state, before) {
					t.Fatal("paired exact native store lost its input or changed numerical/storage facts")
				}
				if x86ResultGPSIMDTransfer(ins, form, &state, nil, 0, arch) {
					t.Fatal("standalone observer acquired native write permission")
				}
				state = before.clone()
				state.writeVector(0, 64, uint64(1)<<uint(row.bytes)-1, false)
				minimal := state.clone()
				if !x86ResultGPSIMDTransferWithNativeMemory(ins, form, &state, nil, 0, arch, true) || !reflect.DeepEqual(state, minimal) {
					t.Fatal("native store required or invented bytes above its exact scalar width")
				}
				for _, mutation := range []string{"physical", "address-size", "segment"} {
					changed := ins
					switch mutation {
					case "physical":
						changed.x86Encoded = true
					case "address-size":
						changed.x86AddressBits = 32
					case "segment":
						changed.x86SegmentPrefix = 0x64
					}
					state = before.clone()
					if x86ResultGPSIMDTransferWithNativeMemory(changed, form, &state, nil, 0, arch, true) || !reflect.DeepEqual(state, before) {
						t.Fatal("named store granted an unbound physical access", mutation)
					}
				}
				for missing := int64(-1); missing < row.bytes; missing++ {
					state = before.clone()
					if missing < 0 {
						state.pointerGP[3] = false
					} else {
						state.writeVector(0, 64, ^(uint64(1) << uint(missing)), false)
					}
					original := state.clone()
					if x86ResultGPSIMDTransferWithNativeMemory(ins, form, &state, nil, 0, arch, true) || !reflect.DeepEqual(state, original) {
						t.Fatal("missing address/data acquired a native store or changed state", missing)
					}
				}
			})
		}
	}
}

// Retain the original native-read followed by native-store sequence as an
// initialized positive, independently of missing-data/address controls.
func TestX86GPSIMDNativeReadStoreCompositionFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, row := range x86GPSIMDNativeStoreRows {
				assembly, declaration := x86GPSIMDNativeFixture(fmt.Sprint("Copy", index), target.arch, row.op, "(DX)", "X0", 0)
				load := row.op + " (DX),X0"
				source.WriteString(strings.Replace(assembly, load, load+"\n"+row.op+" X0,(DX)", 1))
				declarations.WriteString(declaration)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete paired native read/store rejected", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if strings.Count(text, "load volatile i") != len(x86GPSIMDNativeStoreRows) ||
							strings.Count(text, "store volatile i") != len(x86GPSIMDNativeStoreRows) {
							t.Fatal("original separate volatile read/store effects were removed")
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86GPSIMDNativeStoreVoidCannotInventInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple, move, word := "x86_64-unknown-linux-gnu", "MOVQ", 8
		if arch == "386" {
			triple, move, word = "i386-unknown-linux-gnu", "MOVL", 4
		}
		for _, row := range x86GPSIMDNativeStoreRows {
			for _, unused := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/unused-bool=%t", arch, row.op, unused), func(t *testing.T) {
					declaration, extent := "func Value(p *byte)", word
					if unused {
						declaration, extent = "func Value(p *byte,unused bool)", word+1
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),BX\n%s X0,(BX)\nRET\n", extent, move, row.op)
					x86LEAActualTargetGoObject(t, arch, triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("Void or unused bool invented the stored vector bytes", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86GPSIMDNativeStorePortableBytes(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	arch, originalTriple, move, word := "amd64", "x86_64-unknown-linux-gnu", "MOVQ", 8
	if strconv.IntSize == 32 {
		arch, originalTriple, move, word = "386", "i386-unknown-linux-gnu", "MOVL", 4
	}
	var source, declarations, prototypes, rows strings.Builder
	for index, row := range x86GPSIMDNativeStoreRows {
		name := fmt.Sprint("Store", index)
		fmt.Fprintf(&declarations, "func %s(p *byte,value uint64)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),BX\nMOVQ value+%d(FP),X0\n%s X0,1(BX)\nRET\n",
			name, word+8, move, word, row.op)
		fmt.Fprintf(&prototypes, "extern void %s(void*,uint64_t);\n", name)
		fmt.Fprintf(&rows, "{%s,%d},\n", name, row.bytes)
	}
	x86LEAActualTargetGoObject(t, arch, originalTriple, source.String())
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes.String() + `
static const struct { void (*run)(void*,uint64_t); unsigned width; } cases[] = {
` + rows.String() + `};
int main(void) {
    for (unsigned row = 0; row < sizeof(cases)/sizeof(cases[0]); ++row) {
        for (unsigned sample = 0; sample < 257; ++sample) {
            uint8_t output[16], expected[16];
            uint64_t value = UINT64_C(0x9876543210fedcba) * sample;
            memset(output, 0xa5, sizeof(output));
            memcpy(expected, output, sizeof(output));
            for (unsigned byte = 0; byte < cases[row].width; ++byte)
                expected[byte+2] = (uint8_t)(value >> (byte*8));
            cases[row].run(output+1, value);
            if (memcmp(output, expected, sizeof(output))) {
                fprintf(stderr, "row=%u sample=%u store width or canary mismatch\n", row, sample);
                return 1;
            }
        }
    }
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete numerical native store rejected", err)
			}
			for _, optimized := range []bool{false, true} {
				text := ir
				if optimized {
					text = x86DwordProductIROptimize(t, ir)
				}
				for _, level := range []int{0, 2} {
					t.Run(fmt.Sprintf("IR-O2=%t/backend-O%d", optimized, level), func(t *testing.T) {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "gp-simd-native-store",
							triple, text, driver, nil, level)
					})
				}
			}
		})
	}
}
