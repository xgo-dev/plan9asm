package plan9asm

import (
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// Intel SDM Vol. 2B PSADBW/MPSADBW: VEX VPSADBW/VMPSADBW and EVEX
// VPSADBW are WIG. VDBPSADBW alone requires EVEX.W0. Go emits W0,
// so the named encoder table cannot detect this physical-decoder boundary.
// https://cdrdv2-public.intel.com/868141/253667-089-sdm-vol-2b.pdf
func TestX86SADRawIgnoredWidthAndReservedWidth(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM 22 llvm-mc required")
	}
	for _, encoded := range []Op{"VPSADBW", "VPSADBW.EVEX", "VMPSADBW", "VDBPSADBW"} {
		for width := 0; width < 3; width++ {
			if width == 2 && (encoded == "VPSADBW" || encoded == "VMPSADBW") {
				continue
			}
			for _, memory := range []bool{false, true} {
				for _, mode := range []int{32, 64} {
					t.Run(fmt.Sprintf("%s/width%d/memory%t/mode%d", encoded, width, memory, mode), func(t *testing.T) {
						original := encodeX86RawPackedSAD(encoded, width, 0, 1, 2, 0, false, memory)
						changed := append([]byte(nil), original...)
						changed[2] |= 0x80
						control, length, known, err := decodedX86RawPackedSADInstruction(original, mode)
						if !known || err != nil || length != len(original) {
							t.Fatal("original W0 control failed", err)
						}
						actual, length, known, err := decodedX86RawPackedSADInstruction(changed, mode)
						if encoded == "VDBPSADBW" {
							if !known || err == nil {
								t.Fatal("reserved VDBPSADBW W1 acquired semantics")
							}
							return
						}
						var input strings.Builder
						for _, code := range [][]byte{original, changed} {
							for _, value := range code {
								fmt.Fprintf(&input, "0x%02x ", value)
							}
							input.WriteByte('\n')
						}
						triple := "x86_64-unknown-linux-gnu"
						if mode == 32 {
							triple = "i386-unknown-linux-gnu"
						}
						ctx, cancel := runtimeOracleStageContext(t)
						defer cancel()
						command := exec.CommandContext(ctx, mc, "-triple="+triple, "-disassemble", "-mattr=+avx2,+avx512f,+avx512bw,+avx512vl")
						command.Stdin = strings.NewReader(input.String())
						output, llvmErr := runtimeOracleCombinedOutput(ctx, command)
						name := strings.ToLower(strings.TrimSuffix(string(encoded), ".EVEX"))
						if llvmErr != nil || strings.Contains(string(output), "warning") || strings.Count(string(output), name) != 2 {
							t.Fatalf("LLVM rejected the independent WIG pair: %v\n%s", llvmErr, output)
						}
						if !known || err != nil || length != len(changed) || actual.Op != control.Op || !reflect.DeepEqual(actual.Args, control.Args) {
							t.Fatal("ignored W bit changed the complete physical SAD form", err)
						}
					})
				}
			}
		}
	}
}
