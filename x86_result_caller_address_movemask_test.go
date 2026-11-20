package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86CallerAddressMoveMaskPreservesEveryUnwrittenGP(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"PMOVMSKB", "MOVMSKPS", "MOVMSKPD", "VPMOVMSKB", "VMOVMSKPS", "VMOVMSKPD"} {
			banks := []string{"X"}
			if op[0] == 'V' {
				banks = append(banks, "Y")
			}
			limit := 8
			if arch == "amd64" {
				limit = 16
			}
			for _, bank := range banks {
				for destination := 0; destination < limit; destination++ {
					if destination == 4 || destination == 5 {
						continue
					}
					register := []Reg{AX, CX, DX, BX, SP, BP, SI, DI, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}[destination]
					file, err := Parse(ArchAMD64, fmt.Sprintf("TEXT ·effect(SB),4,$0-0\n%s %s1,%s\nRET\n", op, bank, register))
					if err != nil {
						t.Fatal(err)
					}
					var before [16]bool
					for index := 0; index < limit; index++ {
						before[index] = index != 4 && index != 5
					}
					want := before
					want[destination] = false
					if after := x86ResultCallerAddressesAfter(file.Funcs[0].Instrs[1], before, nil, arch); after != want {
						t.Errorf("%s %s/%s writes only %s; unrelated caller addresses lost", arch, op, bank, register)
					}
				}
			}
		}
	}
}

func TestX86CallerAddressMoveMaskCompleteThreeAPIs(t *testing.T) {
	for _, op := range []string{"PMOVMSKB", "MOVMSKPS", "MOVMSKPD", "VPMOVMSKB", "VMOVMSKPS", "VMOVMSKPD"} {
		for _, target := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
			for _, api := range []string{"text", "module", "Go"} {
				body := "MOVQ AX,SI\nPXOR X0,X0\n" + op + " X0,DX\nCMPQ AX,SI\nSETEQ AX"
				if _, err := x86ScalarFPBitViewAPI(t, x86CallerAddressRegisterSource(body), "func view(p *byte) bool\n", "amd64", target, api); err != nil {
					t.Errorf("%s/%s/%s: exact source mask output erased unrelated caller identity: %v", op, target, api, err)
				}
			}
		}
	}
}
