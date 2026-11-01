//go:build go1.27

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

func TestGoAssemblerOracleActualX86ZeroOperandAliasListings(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, suffix := range []string{"", ".Z"} {
			t.Run(arch+"_MOVD"+suffix, func(t *testing.T) {
				source := x86DiagnosticFixture(t, "MOVD"+suffix)
				object := filepath.Join(filepath.Dir(source), "forms.o")
				stage, cancelStage := runtimeOracleStageContext(t)
				defer cancelStage()
				ctx, cancel := context.WithTimeout(stage, 5*time.Second)
				defer cancel()
				observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
					append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch),
					"go", "tool", "asm", "-o", object, source)
				encoded, encodeErr := json.Marshal(observed)
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				t.Logf("ORACLE_CHILD %s", encoded)
				if !observed.Waited || observed.ExitCode != 1 ||
					!strings.Contains(string(observed.Stderr), "("+source+":2)\tMOVQ"+suffix+"\n") {
					t.Fatalf("actual zero-operand canonical alias listing absent: %+v %v", observed, err)
				}
				if failure := goasmoracle.CheckOutcome(source, object, observed.Stdout, observed.Stderr,
					err, ctx.Err(), false, 2, func(source, output string) bool {
						return goAssemblerOracleX86SourceDiagnostic(source, arch, output)
					}); failure != nil {
					t.Fatalf("complete zero-operand alias observation lost: %v", failure)
				}
			})
		}
	}
}
