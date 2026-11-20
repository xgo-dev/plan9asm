package plan9asm

import (
	"strings"
	"testing"
)

// Go's scalar BMI rows are ANDNL and ANDNQ. The 32 packed logical names
// are a separate family even when their source mnemonic starts with ANDN.
func TestX86ANDNFeatureIdentityDoesNotBorrowScalarBMI(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86ScalarFPLogicalOpcodes {
			t.Run(arch+"/"+op, func(t *testing.T) {
				row, _ := x86ScalarFPLogicalRow(op)
				source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, file.Funcs[0])
				for _, feature := range strings.Split(features, ",") {
					if feature == "+bmi" || feature == "+bmi2" {
						t.Errorf("packed opcode %s borrowed scalar ISA: %s", op, features)
					}
				}
			})
		}
	}
}

func TestX86ANDNNativeMemoryKeepsItsOwnISAAndScalarControls(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, tc := range []struct{ row, want string }{
			{"ANDNPS (AX),X1", "+sse"},
			{"ANDNPD (AX),X1", "+sse2"},
			{"ANDNL AX,BX,CX", "+bmi"},
		} {
			t.Run(arch+"/"+tc.row, func(t *testing.T) {
				source := "TEXT f(SB),4,$0-0\n" + tc.row + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, file.Funcs[0]); got != tc.want {
					t.Errorf("native source ISA=%q want=%q", got, tc.want)
				}
			})
		}
	}
	// The Q row is independently retained, not accidentally dropped while
	// removing packed names from the former broad prefix heuristic.
	source := "TEXT f(SB),4,$0-0\nANDNQ AX,BX,CX\nRET\n"
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", file.Funcs[0]); got != "+bmi" {
		t.Fatalf("scalar Q BMI row lost its ISA: %q", got)
	}
}
