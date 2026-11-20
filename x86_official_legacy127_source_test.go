package plan9asm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

type x86Legacy127OriginalCase struct {
	ID, Instruction string
	AMD64Only       bool
}

// This first oracle is independent of the candidate formatter and lowerer.
// Syntax roles come from the complete original Ytab/class group. It records
// source acceptance/refusal, not initialized translation or execution.
func x86Legacy127OriginalCases(t *testing.T) []x86Legacy127OriginalCase {
	t.Helper()
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var cases []x86Legacy127OriginalCase
	counts := map[string]int{}
	for _, entry := range catalog.Optab {
		for _, row := range entry.Rows {
			args, amd64Only := "", false
			switch entry.Ytab {
			case "ymm":
				if row.RowIndex == 0 {
					args, amd64Only = "M0,M1", true
				}
			case "yps":
				if row.RowIndex == 0 {
					args, amd64Only = "M0,M1", true
				} else if row.RowIndex == 1 {
					args, amd64Only = "$-1,M1", true
				}
			case "yxmov":
				if row.RowIndex == 0 {
					args = "(AX),X1"
				} else {
					args = "X1,(AX)"
				}
			case "yxm":
				if strings.Contains(" ADDSUBPD ADDSUBPS COMISD COMISS CVTPD2PS CVTPS2PD CVTSD2SS CVTSS2SD HADDPD HADDPS HSUBPD HSUBPS PSADBW RCPPS RCPSS RSQRTPS RSQRTSS SQRTPD SQRTPS SQRTSD SQRTSS UCOMISD UCOMISS ", " "+entry.Opcode+" ") {
					args = "X0,X1"
				}
			case "ycmpl":
				args = []string{"BX,$1", "AX,$128", "0(SI),$128", "0(SI),BX", "BX,0(SI)"}[row.RowIndex]
				amd64Only = entry.Prefix == "Pw"
			case "ycmpb":
				args = []string{"AL,$128", "0(SI),$128", "0(SI),BL", "BL,0(SI)"}[row.RowIndex]
			case "ytestl":
				args = []string{"$128,AX", "$128,0(SI)", "CX,BX", "0(SI),BX"}[row.RowIndex]
				amd64Only = entry.Prefix == "Pw"
			}
			if args == "" {
				continue
			}
			counts[entry.Ytab]++
			cases = append(cases, x86Legacy127OriginalCase{
				ID:          fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex),
				Instruction: entry.Opcode + " " + args, AMD64Only: amd64Only,
			})
		}
	}
	if len(cases) != 127 || fmt.Sprint(counts) != "map[ycmpb:4 ycmpl:15 ymm:33 yps:16 ytestl:12 yxm:23 yxmov:24]" {
		t.Fatal("original source format denominator changed", len(cases), counts)
	}
	return cases
}

func x86Legacy127OriginalListing(t *testing.T, arch, source string, wantSuccess bool) string {
	t.Helper()
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "legacy127.s"), filepath.Join(dir, "legacy127.o")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, time.Minute)
	defer cancel()
	// -e preserves every source-bound refusal in a whole-function batch.
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"),
		"tool", "asm", "-e", "-S", "-p", "literal", "-o", object, asm)
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(asm, object, output, err, ctx.Err(), wantSuccess, arch); failure != nil {
		t.Fatalf("%v\n%s", failure, output)
	}
	if wantSuccess {
		data, err := os.ReadFile(object)
		if err != nil || len(data) == 0 {
			t.Fatal("original Go object missing", err)
		}
		t.Logf("ACTUAL_LEGACY127_SOURCE arch=%s sourceSHA=%x objectSHA=%x bytes=%d listingSHA=%x", arch,
			sha256.Sum256([]byte(source)), sha256.Sum256(data), len(data), sha256.Sum256(output))
	}
	return string(output)
}

func TestX86Legacy127OriginalGoSourceModes(t *testing.T) {
	cases := x86Legacy127OriginalCases(t)
	for _, arch := range []string{"amd64", "386"} {
		for _, accepted := range []bool{true, false} {
			var selected []x86Legacy127OriginalCase
			for _, item := range cases {
				if (arch != "386" || !item.AMD64Only) == accepted {
					selected = append(selected, item)
				}
			}
			if len(selected) == 0 {
				continue
			}
			for start := 0; start < len(selected); start += 32 {
				end := start + 32
				if end > len(selected) {
					end = len(selected)
				}
				t.Run(fmt.Sprintf("%s/accepted=%t/batch%d", arch, accepted, start/32), func(t *testing.T) {
					var source strings.Builder
					batch := selected[start:end]
					for i, item := range batch {
						fmt.Fprintf(&source, "TEXT ·Legacy127_%d(SB),4,$0-0\n%s\nRET\n", i, item.Instruction)
					}
					listing := x86Legacy127OriginalListing(t, arch, source.String(), accepted)
					for i, item := range batch {
						if accepted {
							if !strings.Contains(listing, fmt.Sprintf("Legacy127_%d STEXT", i)) {
								t.Fatal("accepted batch lost an original function", item.ID)
							}
						} else {
							found := false
							for _, diagnostic := range strings.Split(listing, "\n") {
								if strings.Contains(diagnostic, fmt.Sprintf("legacy127.s:%d", 3*i+2)) &&
									strings.Contains(diagnostic, strings.Fields(item.Instruction)[0]) {
									found = true
								}
							}
							if !found {
								t.Fatalf("missing original source-bound mode refusal %s: %s\n%s", item.ID, item.Instruction, listing)
							}
						}
					}
				})
			}
		}
	}
	if path := os.Getenv("PLAN9ASM_LEGACY127_ORIGINAL_OUTPUT"); path != "" {
		data, err := json.MarshalIndent(cases, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
