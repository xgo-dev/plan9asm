package plan9asm

import "testing"

func TestX86RawNumericalOriginRequiresOriginalAddressMode(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, line := range []string{
			"MOVBEW (AX),BX", "ANDNL AX,BX,CX", "PDEPL AX,BX,CX", "PEXTL AX,BX,CX",
			"VADDPD X0,X1,X2", "VPSHUFB X0,X1,X2", "CMOVLLE AX,BX",
		} {
			t.Run(arch+"/"+line, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+
					x86RawNumericalInstruction(t, arch, line)+"RET\n")
				if err != nil {
					t.Fatal(err)
				}
				file, err = normalizeX86RawFile(file, arch)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				if !x86RawOrdinaryVectorSource(ins, arch) {
					t.Fatal("original default-mode numerical source rejected", ins)
				}
				origin := *ins.x86SourceRaw
				origin.addressBits = 16
				ins.x86SourceRaw = &origin
				if x86RawOrdinaryVectorSource(ins, arch) {
					t.Fatal("rewritten original address mode borrowed a numerical continuation")
				}
			})
		}
	}
}
