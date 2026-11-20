package plan9asm

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86NumericalNativeTailFamiliesOriginalGoBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var rows []string
			for _, bank := range []string{"X", "Y"} {
				for _, op := range []string{"VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ"} {
					for _, src := range []string{"X1", "(AX)", "-64(AX)(CX*4)", "feature+7(SB)"} {
						rows = append(rows, fmt.Sprintf("%s %s,%s2", op, src, bank))
					}
				}
				for _, op := range []string{"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ", "VPCMPGTB", "VPCMPGTW", "VPCMPGTD", "VPCMPGTQ"} {
					for _, src := range []string{bank + "1", "(AX)", "-64(AX)(CX*4)", "feature+7(SB)"} {
						rows = append(rows, fmt.Sprintf("%s %s,%s2,%s3", op, src, bank, bank))
					}
				}
				for _, op := range []string{"VMOVMSKPS", "VMOVMSKPD", "VPMOVMSKB"} {
					rows = append(rows, fmt.Sprintf("%s %s1,DX", op, bank))
				}
				for _, op := range []string{"VPTEST", "VTESTPS", "VTESTPD"} {
					for _, src := range []string{bank + "1", "(AX)", "-64(AX)(CX*4)", "feature+7(SB)"} {
						rows = append(rows, fmt.Sprintf("%s %s,%s2", op, src, bank))
					}
				}
			}
			for _, op := range []string{"VMOVD", "VMOVQ"} {
				for _, src := range []string{"(AX)", "-64(AX)(CX*4)", "feature+7(SB)"} {
					rows = append(rows, fmt.Sprintf("%s %s,X2", op, src), fmt.Sprintf("%s X2,%s", op, src))
				}
				if op == "VMOVQ" {
					rows = append(rows, "VMOVQ X1,X2")
				}
				if arch == "amd64" || op == "VMOVD" {
					rows = append(rows, op+" AX,X2", op+" X2,AX")
				}
			}
			if arch == "amd64" {
				for _, bank := range []string{"X", "Y", "Z"} {
					for _, op := range []string{"VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ"} {
						for _, src := range []string{"AX", "X1", "(AX)", "feature+7(SB)"} {
							rows = append(rows, fmt.Sprintf("%s.Z %s,K7,%s2", op, src, bank))
							if bank == "Z" || src == "AX" {
								rows = append(rows, fmt.Sprintf("%s %s,%s2", op, src, bank))
							}
						}
					}
					for _, op := range []string{"VPBROADCASTMB2Q", "VPBROADCASTMW2D"} {
						rows = append(rows, fmt.Sprintf("%s K1,%s2", op, bank))
					}
					for _, op := range []string{"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ", "VPCMPGTB", "VPCMPGTW", "VPCMPGTD", "VPCMPGTQ"} {
						for _, src := range []string{bank + "1", "(AX)", "feature+7(SB)"} {
							rows = append(rows, fmt.Sprintf("%s %s,%s2,K1", op, src, bank), fmt.Sprintf("%s %s,%s2,K7,K1", op, src, bank))
							if src != bank+"1" && (strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q")) {
								rows = append(rows, fmt.Sprintf("%s.BCST %s,%s2,K7,K1", op, src, bank))
							}
						}
					}
				}
				rows = append(rows, "VMOVD AX,X31", "VMOVD X31,AX", "VMOVQ AX,X31", "VMOVQ X31,AX", "VMOVQ X31,X30", "VMOVQ feature+7(SB),X31", "VMOVQ X31,feature+7(SB)")
			}
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nCMPB feature+7(SB),$1\nRET")
			mode := 64
			if arch == "386" {
				mode = 32
			}
			boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
			if err != nil {
				t.Fatal("complete existing native family not observed", err)
			}
			var actual []int64
			for index, boundary := range boundaries {
				actual = append(actual, boundary.PC)
				if index >= len(rows) {
					continue
				}
				if _, exists := scalar[boundary.PC]; exists {
					t.Fatal("vector boundary acquired a scalar numerical read role")
				}
				for cut := 1; cut < boundary.Length; cut++ {
					if values, reads, err := x86NumericalNativeBoundaries(code[boundary.PC:boundary.PC+int64(cut)], mode); err == nil || values != nil || reads != nil {
						t.Fatal("truncated family acquired a partial observation", index, cut)
					}
				}
			}
			if !reflect.DeepEqual(pcs, actual) || len(boundaries) != len(rows)+2 || len(scalar) != 2 {
				t.Fatal("original Go boundary/native scalar identity changed")
			}
		})
	}
}

func TestX86NumericalNativeTailBroadcastOpcodeIsNotLegacyConfusion(t *testing.T) {
	// This formerly forbidden stream is actual VPBROADCASTD, not a legacy
	// instruction after discarding VEX. Observe it only as a complete extent.
	for _, arch := range []string{"386", "amd64"} {
		code, pcs := x86NumericalBoundaryGoBytes(t, arch, "VPBROADCASTD X0,X0\nRET")
		if !bytes.Equal(code, []byte{0xc4, 0xe2, 0x79, 0x58, 0xc0, 0xc3}) || len(pcs) != 2 {
			t.Fatalf("independent original Go broadcast identity changed: %x %v", code, pcs)
		}
		mode := 64
		if arch == "386" {
			mode = 32
		}
		boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
		if err != nil || len(boundaries) != 2 || boundaries[0].Length != 5 || len(scalar) != 1 {
			t.Fatal("known whole vector extent was confused with a scalar/read grant", boundaries, scalar, err)
		}
	}
}
