package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ImplicitMaskStoreAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86RunImplicitMaskStoreRuntime(t, x86FloatCompareExecutionTools(t), "amd64")
}

func TestCrossLinuxRuntimeMatrixX86ImplicitMaskStore386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required mode32 mask store tools: LLVM 22=%q i686 compiler=%v", llc, err)
	}
	execution := x86FloatCompareExecution{
		llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie"},
	}
	x86RunImplicitMaskStoreRuntime(t, execution, "386")
}

func x86RunImplicitMaskStoreRuntime(t *testing.T, execution x86FloatCompareExecution, arch string) {
	t.Helper()
	execution.requireAVX(t)
	fixtures := x86RawImplicitVectorMaskMoveFixtures(arch)
	var source, declarations, goRows, prototypes, cRows strings.Builder
	for index, fixture := range fixtures {
		for _, raw := range []bool{false, true} {
			name := fmt.Sprintf("Store%dNamed", index)
			if raw {
				name = fmt.Sprintf("Store%dRaw", index)
			}
			body, declaration := fixture.program(arch, name, raw)
			source.WriteString(body)
			declarations.WriteString(declaration)
			sameRegister := fixture.mask == fixture.data
			fmt.Fprintf(&goRows, "{%s, %t},\n", name, sameRegister)
			fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,uint8_t*,uint8_t*);\n", name)
			fmt.Fprintf(&cRows, "{%s, %t},\n", name, sameRegister)
		}
	}
	t.Run("OriginalGo", func(t *testing.T) {
		x86RunOriginalGoNativeSource(t, execution, arch, "package oracle\n"+declarations.String(),
			source.String(), fmt.Sprintf(x86ImplicitMaskStoreOriginal, goRows.String()))
	})
	driver := fmt.Sprintf(x86ImplicitMaskStoreDriver, prototypes.String(), cRows.String())
	want := fmt.Sprintf("checked %d complete masked writes\n", len(fixtures)*2*35)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("initialized mask store source rejected", err)
			}
			for _, stage := range []struct{ stage, ir string }{
				{"IR_O0", ir},
				{"IR_O2", x86DwordProductIROptimize(t, ir)},
			} {
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(stage.stage+"/"+level, func(t *testing.T) {
						binary := execution.compileLLVM(t, "implicit-mask-store", stage.ir, driver, level)
						var output []byte
						if arch == "386" {
							program := x86NativeOracleIA32Executable(t, execution, binary)
							output = x87IA32RunDirect(t, program, nil, os.Environ())
						} else {
							output = execution.run(t, binary)
						}
						if string(output) != want {
							t.Fatal("mask store execution did not check all writes", string(output))
						}
					})
				}
			}
		})
	}
	x87IA32RequireNativeHost(t)
}

const x86ImplicitMaskStoreOriginal = `package oracle

import "testing"

func TestOriginal(t *testing.T) {
	rows := []struct{
		store func(*[16]byte, *[16]byte, *[16]byte)
		sameRegister bool
	}{
%s
	}
	for number, row := range rows {
		for sample := 0; sample < 35; sample++ {
			var output [64]byte
			var mask, data [16]byte
			for lane := range mask {
				selected := sample == 1 ||
					sample >= 2 && sample < 18 && lane == sample - 2 ||
					sample >= 18 && sample < 34 && lane != sample - 18 ||
					sample == 34 && lane %% 3 == 0
				mask[lane] = byte(lane*7 + sample) & 127
				data[lane] = byte(255 - lane*11 - sample)
				if selected {
					mask[lane] |= 128
				}
			}
			beforeMask, beforeData := mask, data
			for i := range output {
				output[i] = byte(97 - i*3 + sample)
			}
			want := output
			active := mask
			if row.sameRegister {
				active = data
			}
			offset := 17 + sample %% 16
			for lane, value := range active {
				if value & 128 != 0 {
					want[offset + lane] = data[lane]
				}
			}
			row.store((*[16]byte)(output[offset:]), &mask, &data)
			if output != want || mask != beforeMask || data != beforeData {
				t.Fatalf("original row %%d sample %%d: output=%%x want=%%x", number, sample, output, want)
			}
		}
	}
}
`

const x86ImplicitMaskStoreDriver = `
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
%s
static const struct {
    void (*store)(uint8_t*, uint8_t*, uint8_t*);
    bool same_register;
} rows[] = {
%s
};

int main(void) {
    unsigned count = 0;
    for (unsigned row = 0; row < sizeof(rows)/sizeof(rows[0]); row++) {
        for (unsigned sample = 0; sample < 35; sample++) {
            uint8_t output[64], expected[64], mask[16], data[16], before_mask[16], before_data[16];
            unsigned offset = 17 + sample %% 16;
            for (unsigned lane = 0; lane < 16; lane++) {
                int selected = sample == 1 ||
                    (sample >= 2 && sample < 18 && lane == sample - 2) ||
                    (sample >= 18 && sample < 34 && lane != sample - 18) ||
                    (sample == 34 && lane %% 3 == 0);
                mask[lane] = (lane*7 + sample) & 127;
                if (selected) mask[lane] |= 128;
                data[lane] = 255 - lane*11 - sample;
            }
            memcpy(before_mask, mask, sizeof(mask));
            memcpy(before_data, data, sizeof(data));
            for (unsigned byte = 0; byte < 64; byte++) {
                expected[byte] = output[byte] = 97 - byte*3 + sample;
            }
            const uint8_t *active = rows[row].same_register ? data : mask;
            for (unsigned lane = 0; lane < 16; lane++) {
                if (active[lane] & 128) expected[offset + lane] = data[lane];
            }
            rows[row].store(output + offset, mask, data);
            if (memcmp(expected, output, sizeof(output)) ||
                memcmp(before_mask, mask, sizeof(mask)) ||
                memcmp(before_data, data, sizeof(data))) {
                fprintf(stderr, "bad masked write: row %%u, sample %%u\n", row, sample);
                return 1;
            }
            count++;
        }
    }
    printf("checked %%u complete masked writes\n", count);
    return 0;
}
`
