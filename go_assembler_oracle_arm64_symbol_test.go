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

func TestGoAssemblerOracleARM64ActualBareFromSymbolFamily(t *testing.T) {
	for _, opcode := range []string{"B", "BL"} {
		for _, name := range []string{"target", "_target2", "世界", "pkg·target", "path∕target"} {
			for _, definition := range []string{"defined", "undefined"} {
				t.Run(opcode+"/"+name+"/"+definition, func(t *testing.T) {
					directory := t.TempDir()
					source := filepath.Join(directory, "forms.s")
					object := filepath.Join(directory, "forms.o")
					body := "TEXT bad(SB),$0-0\n\t" + opcode + " " + name + ",R1\n"
					if definition == "defined" {
						body += name + ":\n"
					}
					body += "\tRET\n"
					if err := os.WriteFile(source, []byte(body), 0600); err != nil {
						t.Fatal(err)
					}

					stage, cancelStage := runtimeOracleStageContext(t)
					defer cancelStage()
					ctx, cancel := context.WithTimeout(stage, 5*time.Second)
					defer cancel()
					observed, err := goasmcmd.Observe(ctx, directory,
						append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=arm64"),
						"go", "tool", "asm", "-o", object, source)
					encoded, encodeErr := json.Marshal(observed)
					if encodeErr != nil {
						t.Fatal(encodeErr)
					}
					t.Logf("ORACLE_CHILD %s", encoded)
					listing := "JMP"
					if opcode == "BL" {
						listing = "CALL"
					}
					if !observed.Waited || observed.ExitCode != 1 || ctx.Err() != nil || len(observed.Stdout) != 0 ||
						!strings.Contains(string(observed.Stderr), source+":2)\t"+listing+"\t0, R1 ZOREG NONE NONE REG") ||
						!strings.Contains(string(observed.Stderr), ", 3 7\n") {
						t.Fatalf("actual From TYPE_MEM/NameNone/zero-offset refusal absent: %+v %v", observed, err)
					}
					failure := goasmoracle.CheckOutcome(source, object, observed.Stdout, observed.Stderr,
						err, ctx.Err(), false, 2, func(source, diagnostic string) bool {
							return goAssemblerOracleARM64SourceDiagnostic(source, "arm64", diagnostic)
						})
					if failure != nil {
						t.Fatalf("actual From symbol diagnostic join lost: %v\n%s", failure, observed.Stderr)
					}
					if goasmoracle.SourceDiagnosticLine(source, string(observed.Stderr), 2) {
						t.Fatal("default diagnostic acquired an operand rewrite")
					}
				})
			}
		}
	}
}

func TestGoAssemblerOracleARM64BareFromSymbolRoles(t *testing.T) {
	for _, alias := range []struct{ original, listed string }{{"B", "JMP"}, {"BL", "CALL"}} {
		for _, suffix := range []struct{ original, listed string }{
			{"", ""}, {".P", ".P"}, {".W", ".W"}, {".W.P", ".P.W"}, {".P.P", ".P"},
		} {
			t.Run(alias.original+suffix.original, func(t *testing.T) {
				source := x86DiagnosticFixture(t, alias.original+suffix.original+" target,R1")
				output := arm64BranchDiagnostic(source, alias.listed+suffix.listed+" 0,R1",
					"ZOREG NONE NONE REG NONE, 3 7")
				if !goAssemblerOracleARM64SourceDiagnostic(source, "arm64", output) {
					t.Error("complete zero-offset From symbol role was lost")
				}
				for _, changed := range []string{
					strings.Replace(output, "0,R1", "1,R1", 1),
					strings.Replace(output, "0,R1", "0,R2", 1),
					strings.Replace(output, "0,R1", "$0,R1", 1),
					strings.Replace(output, "ZOREG", "SBRA", 1),
					strings.Replace(output, ", 3 7", ", 1 7", 1),
					strings.Replace(output, ", 3 7", ", 8 7", 1),
					strings.Replace(output, ", 3 7", ", 3 3", 1),
					strings.Replace(output, source+":2", source+":3", 1),
					strings.Replace(output, source+":2", "foreign"+source+":2", 1),
					strings.Replace(output, "00000", "0", 1),
				} {
					if goAssemblerOracleARM64SourceDiagnostic(source, "arm64", changed) {
						t.Errorf("From symbol borrowed a different role: %q", changed)
					}
				}
			})
		}
	}
	for _, instruction := range []string{
		"BL R0,R1", "BL V0,R1", "BL NZCV,R1", "BL EQ,R1",
		"BL PLDL1KEEP,R1", "BL $target,R1", "BL *target,R1", "BL target+1,R1",
		"BL target(SB),R1", "BL target(FP),R1", "BL (R0),R1", "BL R(0),R1",
		"BL $0,R0,target", "BL target", "BL", "MOVD target,R1",
	} {
		t.Run("wrong-role/"+instruction, func(t *testing.T) {
			source := x86DiagnosticFixture(t, instruction)
			if goAssemblerOracleARM64SourceDiagnostic(source, "arm64", arm64BranchDiagnostic(source,
				"CALL 0,R1", "ZOREG NONE NONE REG NONE, 3 7")) {
				t.Fatal("non-bare-From source borrowed symbol erasure")
			}
		})
	}
}
