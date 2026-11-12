package plan9asm

import "testing"

func TestX86FeatureDispatchFamilyBoundaries(t *testing.T) {
	for _, row := range []struct {
		instruction, amd64, mode32 string
	}{
		{"ANDPS X0,X1", "", ""},
		{"ANDPS (AX),X1", "+sse", "+sse"},
		{"ANDPD (AX),X1", "+sse2", "+sse2"},
		{"PAND (AX),X1", "+sse2", "+sse2"},
		{"PAND M0,M1", "", ""},
		{"VPAND Z0,Z1,Z2", "", ""},
		{"VXORPS.BCST (AX),X1,X2", "", ""},
		{"VXORPS.Z X0,X1,X2", "", ""},
		{"VMOVAPS (AX),X1", "+avx", "+avx"},
		{"VMOVAPS.Z (AX),K1,X1", "+avx512f,+avx512vl", "+avx512f,+avx512vl"},
		{"VMOVDQA32 (AX),Z1", "+avx512f", "+avx512f"},
		{"VMOVAPS (AX),X16", "+avx512f,+avx512vl", ""},
		{"VMOVDQA (AX),X1", "+avx", "+avx"},
		{"VMOVDQA.Z (AX),K1,X1", "", ""},
		{"VMOVDQU64 (AX),Z1", "", ""},
		{"VMOVDQA32.Z X0,K1,(AX)", "", ""},
		{"VMOVAPS.SAE (AX),X1", "", ""},
		{"VMOVAPD.Z (AX),K0,X1", "", ""},
		{"VCVTSD2SS X0,X1,X2", "+avx", "+avx"},
	} {
		for _, arch := range []string{"amd64", "386"} {
			t.Run(arch+"/"+row.instruction, func(t *testing.T) {
				want := row.amd64
				if arch == "386" {
					want = row.mode32
				}
				file, err := Parse(ArchAMD64, "TEXT before(SB),4,$0-0\nVCVTSD2SS X0,X1,X2\nRET\n"+
					"TEXT isolated(SB),4,$0-0\n"+row.instruction+"\nRET\nTEXT after(SB),4,$0-0\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				for index, expected := range []string{"+avx", want, ""} {
					if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, file.Funcs[index]); got != expected {
						t.Fatalf("function %d: got %q, want %q", index, got, expected)
					}
				}
			})
		}
	}
}
