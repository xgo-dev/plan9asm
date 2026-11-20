package plan9asm

import (
	"strings"
	"testing"
)

const arm64CacheMaintenanceForms = `
TEXT cachemaintenanceforms(SB),$0-0
	DC IVAC, R0
	DC ISW, R1
	DC CSW, R2
	DC CISW, R3
	DC ZVA, R4
	DC CVAC, R5
	DC CVAU, R6
	DC CIVAC, R7
	DC IGVAC, R8
	DC IGSW, R9
	DC IGDVAC, R10
	DC IGDSW, R11
	DC CGSW, R12
	DC CGDSW, R13
	DC CIGSW, R14
	DC CIGDSW, R15
	DC GVA, R16
	DC GZVA, R17
	DC CGVAC, ZR
	DC CGDVAC, R19
	DC CGVAP, R20
	DC CGDVAP, R21
	DC CGVADP, R22
	DC CGDVADP, R23
	DC CIGVAC, R24
	DC CIGDVAC, R25
	DC CVAP, R26
	DC CVADP, R27
	RET
`

func TestTranslateARM64CacheMaintenanceCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64CacheMaintenanceForms, true)

	for _, triple := range []string{
		"arm64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, arm64CacheMaintenanceForms)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"cachemaintenanceforms": {Name: "cachemaintenanceforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ll, `asm sideeffect "sys #`); got != 28 {
				t.Fatalf("ARM64 DC lowering emitted %d system operations, want 28:\n%s", got, ll)
			}
			for _, want := range []string{
				`asm sideeffect "sys #0, c7, c6, #1, $0"`,   // IVAC
				`asm sideeffect "sys #3, c7, c4, #1, $0"`,   // ZVA
				`asm sideeffect "sys #3, c7, c14, #1, $0"`,  // CIVAC
				`asm sideeffect "sys #3, c7, c10, #3, xzr"`, // CGVAC ZR
				`asm sideeffect "sys #3, c7, c13, #1, $0"`,  // CVADP
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 DC lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-cache-maintenance.ll", "arm64-cache-maintenance.o", ll)
		})
	}
}

func TestTranslateARM64CacheMaintenanceRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"DC PLDL1KEEP",
		"DC VMALLE1IS",
		"DC VAE1IS, R0",
		"DC IVAC",
		"DC ZVA, SP",
		"DC ZVA, R0, R1",
		"DC.P ZVA, R0",
	} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's DC forms", instruction)
		}
	}
}
