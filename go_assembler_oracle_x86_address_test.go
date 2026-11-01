package plan9asm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func TestGoAssemblerOracleX86AddressRewriteSourceRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"MOVL", "MOVQ"} {
			lea := map[string]string{"MOVL": "LEAL", "MOVQ": "LEAQ"}[op]
			for _, address := range []string{
				"slot+8(FP)(CX*2)", "slot-8(SP)(CX*2)",
				"slot+8(SB)(CX*2)", "slot<>+8(SB)(CX*2)",
				"8(AX)(CX*2)", "(AX)(X1*2)",
			} {
				t.Run(arch+"/"+op+"/"+address, func(t *testing.T) {
					source := x86DiagnosticFixture(t, op+" $"+address+",AX")
					output := x86DiagnosticListing(source, lea+" "+address+",AX")
					want := arch == "amd64" || !strings.Contains(address, "(SB)")
					if got := goAssemblerOracleX86SourceDiagnostic(source, arch, output); got != want {
						t.Fatalf("exact progedit source role=%v, want %v", got, want)
					}
					if goasmoracle.SourceDiagnosticLine(source, output, 2) {
						t.Fatal("address rewrite escaped the explicit x86 diagnostic adapter")
					}
					for _, changed := range []string{
						lea + " " + address + ",BX", lea + " " + address,
						lea + " " + address + ",AX,BX", lea + ".Z " + address + ",AX",
					} {
						if goAssemblerOracleX86SourceDiagnostic(source, arch, x86DiagnosticListing(source, changed)) {
							t.Fatalf("changed complete address listing borrowed the source: %q", changed)
						}
					}
				})
			}
		}
	}
	for _, original := range []string{
		"MOVB $8(AX),AX", "MOVW $8(AX),AX", "MOVL 8(AX),AX", "MOVL $8,AX",
		"MOVL $(8),AX", "MOVL $0.0,AX", "MOVL.Z $8(AX),AX", "MOVL $8(AX),AX,BX",
	} {
		source := x86DiagnosticFixture(t, original)
		if goAssemblerOracleX86SourceDiagnostic(source, "amd64", x86DiagnosticListing(source, "LEAL 8(AX),AX")) {
			t.Fatalf("non-address or unrelated opcode acquired a progedit role: %q", original)
		}
	}
}

func TestGoAssemblerOracleActualX86AddressRewriteFamily(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		ops := []string{"MOVL"}
		if arch == "amd64" {
			ops = append(ops, "MOVQ")
		}
		for _, op := range ops {
			for _, test := range []struct {
				name, address string
				accepted      bool
			}{
				{"external-index", "slot+8(SB)(CX*2)", arch == "386"},
				{"static-index", "slot<>+8(SB)(CX*2)", arch == "386"},
				{"physical-index", "8(AX)(CX*2)", true},
				{"vector-index", "8(AX)(X1*2)", false},
			} {
				t.Run(arch+"/"+op+"/"+test.name, func(t *testing.T) {
					source := x86DiagnosticFixture(t, op+" $"+test.address+",AX")
					object := filepath.Join(filepath.Dir(source), "forms.o")
					stage, cancelStage := runtimeOracleStageContext(t)
					defer cancelStage()
					ctx, cancel := context.WithTimeout(stage, time.Minute)
					defer cancel()
					observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
						append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch),
						"go", "tool", "asm", "-o", object, source)
					encoded, encodeErr := json.Marshal(observed)
					if encodeErr != nil {
						t.Fatal(encodeErr)
					}
					t.Logf("ORACLE_CHILD %s", encoded)
					wantExit := 1
					if test.accepted {
						wantExit = 0
					}
					if !observed.Waited || observed.ExitCode != wantExit || ctx.Err() != nil {
						t.Fatalf("original Go address outcome differs: %+v %v", observed, err)
					}
					additional := func(source, output string) bool {
						return goAssemblerOracleX86SourceDiagnostic(source, arch, output)
					}
					if failure := goasmoracle.CheckOutcome(source, object, observed.Stdout, observed.Stderr,
						err, ctx.Err(), test.accepted, 2, additional); failure != nil {
						t.Fatalf("actual complete address observation lost: %v\n%s", failure, observed.Stderr)
					}
				})
			}
		}
	}
}
