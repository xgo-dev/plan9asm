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

func TestGoAssemblerOracleActualARM64BranchAliasListings(t *testing.T) {
	for _, test := range []struct{ name, instruction string }{
		{"branch-register", "B R0"},
		{"branch-vector", "B V0"},
		{"branch-vector-address", "B (V0)"},
		{"call-displaced-address", "BL 8(R1)"},
		{"call-stack-register", "BL RSP"},
		{"call-vector", "BL V0"},
		{"call-immediate", "BL $1"},
		{"call-suffix", "BL.P R1"},
		{"call-writeback-suffix", "BL.W R1"},
		{"call-mixed-suffix", "BL.W.P R1"},
		{"call-repeated-suffix", "BL.P.P R1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := x86DiagnosticFixture(t, test.instruction)
			object := filepath.Join(filepath.Dir(source), "forms.o")
			stage, cancelStage := runtimeOracleStageContext(t)
			defer cancelStage()
			ctx, cancel := context.WithTimeout(stage, time.Minute)
			defer cancel()
			observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
				append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=arm64"),
				"go", "tool", "asm", "-o", object, source)
			encoded, encodeErr := json.Marshal(observed)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			t.Logf("ORACLE_CHILD %s", encoded)
			if !observed.Waited || observed.ExitCode != 1 || ctx.Err() != nil ||
				!strings.Contains(string(observed.Stderr), "illegal combination:") {
				t.Fatalf("actual original branch-family refusal absent: %+v %v", observed, err)
			}
			if failure := goAssemblerOracleOutcome(source, object, append(observed.Stdout, observed.Stderr...),
				err, ctx.Err(), false, "arm64"); failure != nil {
				t.Fatalf("actual original branch alias refusal lost: %v\n%s", failure, observed.Stderr)
			}
			if goasmoracle.SourceDiagnosticLine(source, string(observed.Stderr), 2) {
				t.Fatal("default diagnostic parser acquired architecture aliases")
			}
		})
	}
}
