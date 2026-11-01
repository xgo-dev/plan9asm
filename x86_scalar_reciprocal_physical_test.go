package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Intel SDM Vol.2B RCPSS/RSQRTSS: VEX.LIG.F3.0F.WIG. These
// independent literal byte witnesses supplement Go's canonical W0/L0 rows.
func TestX86ScalarReciprocalPhysicalWIGLIGSourceIdentity(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range x86ScalarReciprocalOracle {
			for _, memory := range []bool{false, true} {
				for variant := 0; variant < 4; variant++ {
					if !row.vector && variant != 0 {
						continue
					}
					t.Run(fmt.Sprintf("%s/%s/memory=%t/WL=%d", arch, row.op, memory, variant), func(t *testing.T) {
						modrm := byte(0xd0) // X0 -> X2, with independent VEX base X1.
						if memory {
							modrm = 0x10 // (AX), not a logical field or manufactured backing.
						}
						code := []byte{0xf3, 0x0f, row.opcode, modrm}
						if row.vector {
							control := byte(0x72)
							if variant&1 != 0 {
								control |= 0x80
							}
							if variant&2 != 0 {
								control |= 4
							}
							code = []byte{0xc4, 0xe1, control, row.opcode, modrm}
						}
						var input, directives strings.Builder
						for _, value := range code {
							fmt.Fprintf(&input, "0x%02x ", value)
							fmt.Fprintf(&directives, "BYTE $0x%02x\n", value)
						}
						ctx, cancel := runtimeOracleStageContext(t)
						defer cancel()
						command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+triple, "--mattr=+avx")
						command.Stdin = strings.NewReader(input.String() + "\n")
						output, err := runtimeOracleCombinedOutput(ctx, command)
						if err != nil || strings.Contains(string(output), "warning:") || !strings.Contains(string(output), strings.ToLower(row.op)) {
							t.Fatal("independent LLVM scalar estimate encoding observation failed", code, err, string(output))
						}
						original := "TEXT f(SB),4,$0-0\n" + directives.String() + "RET\n"
						goAssemblerOracleOutput(t, arch, original, "", true)
						parsed, err := Parse(ArchAMD64, original)
						if err != nil {
							t.Fatal(err)
						}
						normalized, err := normalizeX86RawFile(parsed, arch)
						if err != nil {
							t.Fatal("complete physical scalar reciprocal byte identity unrecognized", err)
						}
						matches := 0
						for _, ins := range normalized.Funcs[0].Instrs {
							if ins.Op == Op(row.op) {
								matches++
								if ins.x86SourceRaw == nil || ins.Args[0].Kind == OpMem != memory ||
									ins.Args[len(ins.Args)-1].Reg != "X2" || row.vector && ins.Args[1].Reg != "X1" {
									t.Fatal("WIG/LIG changed complete original source, upper input or physical destination", ins)
								}
							}
						}
						if matches != 1 {
							t.Fatal("physical scalar estimate missing its exact single decoded source", matches)
						}
					})
				}
			}
		}
	}
}
