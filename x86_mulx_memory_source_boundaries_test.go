package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86MULXMemorySourcesKeepTheirSeparateStorageRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86MULXTestOps(arch) {
			rows := []string{op + " 4096(SP),CX,DX"}
			if arch == "amd64" {
				rows = append(rows, op+" (BP),CX,DX", op+" 1(BX)(BP*2),CX,DX")
			}
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nRET\n")
			if len(pcs) != len(rows)+1 {
				t.Fatal("actual Go omitted a physical frame-address source", pcs)
			}
			mode, move := 64, "MOVQ"
			if arch == "386" {
				mode, move = 32, "MOVL"
			}
			x86NumericalVEXGPRequireMC(t, code, mode, len(pcs))
			type program struct {
				name, source, declaration string
				pass                      bool
			}
			var programs []program
			for index, row := range rows {
				for _, raw := range []bool{false, true} {
					instruction := row + "\n"
					if raw {
						instruction = x86RawDisplacementDirectives(code[pcs[index]:pcs[index+1]])
					}
					programs = append(programs, program{
						name: fmt.Sprintf("frame-source%d/raw=%t", index, raw),
						source: "TEXT Value(SB),4,$0-0\nMOVL $3,DX\nMOVL $7,BX\n" +
							instruction + "RET\n",
						declaration: "func Value()",
					})
				}
			}
			// Incoming pointers and independently defined numerical indexes
			// remain distinct from physical SP/BP entry. Mode32 BP is ordinary
			// GP, so retain both its pointer and numerical-index source roles.
			for _, base := range []string{"BX", "BP"} {
				if base == "BP" && arch != "386" {
					continue
				}
				programs = append(programs, program{
					name: "caller-pointer-" + base,
					source: fmt.Sprintf("TEXT Value(SB),4,$0-%d\n%s p+0(FP),%s\nMOVL $3,DX\n%s (%s),CX,DX\nRET\n",
						goWordSize(arch), move, base, op, base),
					declaration: "func Value(p *[64]byte)", pass: true,
				})
			}
			if arch == "386" {
				programs = append(programs, program{
					name: "mode32-numerical-BP-index",
					source: "TEXT Value(SB),4,$0-4\nMOVL p+0(FP),BX\nMOVL $0,BP\nMOVL $3,DX\n" +
						op + " 1(BX)(BP*2),CX,DX\nRET\n",
					declaration: "func Value(p *[64]byte)", pass: true,
				})
			}
			programs = append(programs, program{
				name:        "owned-DATA-dead-unknown-DX",
				source:      "TEXT Value(SB),4,$0-0\n" + op + " table(SB),CX,DX\nRET\n",
				declaration: "func Value()", pass: true,
			})
			const data = "DATA table+0(SB)/8,$7\nGLOBL table(SB),8,$8\n"
			var prior strings.Builder
			for index, program := range programs {
				prior.WriteString(strings.Replace(program.source, "TEXT Value(SB)", fmt.Sprintf("TEXT Source%d(SB)", index), 1))
			}
			x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], prior.String()+data)
			for _, program := range programs {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+op+"/"+program.name+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, program.source+data, program.declaration,
							arch, x86AddressMemoryTargets(arch)[0], api)
						if program.pass {
							if err != nil || ir == "" {
								t.Fatal("MULX lost a separately initialized pointer/index or owned DATA source", err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("physical frame memory borrowed virtual stack/BP storage", err)
						}
					})
				}
			}
		}
	}
}
