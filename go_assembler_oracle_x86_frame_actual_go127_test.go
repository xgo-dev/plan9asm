//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func TestGoAssemblerOracleX86FrameRebaseActualSDKRules(t *testing.T) {
	source := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "obj6.go")
	data, ok := goasmoracle.ReadSource(source)
	if !ok {
		t.Fatal("complete actual selected SDK preprocess source unavailable")
	}
	for _, rule := range []string{
		"autoffset := int32(p.To.Offset)",
		"if autoffset < 0 {\n\t\tautoffset = 0\n\t}",
		"if ctxt.Arch.Family == sys.AMD64 &&",
		"p.From.Offset += int64(deltasp) - int64(bpsize)",
		"p.From.Offset += int64(deltasp) + int64(pcsize)",
		"p.GetFrom3().Offset += int64(deltasp) - int64(bpsize)",
		"p.GetFrom3().Offset += int64(deltasp) + int64(pcsize)",
		"p.To.Offset += int64(deltasp) - int64(bpsize)",
		"p.To.Offset += int64(deltasp) + int64(pcsize)",
		"pcsize := ctxt.Arch.RegSize",
		"case APUSHL, APUSHFL:\n\t\t\tdeltasp += 4",
		"case APUSHQ, APUSHFQ:\n\t\t\tdeltasp += 8",
		"case APUSHW, APUSHFW:\n\t\t\tdeltasp += 2",
		"case APOPL, APOPFL:\n\t\t\tdeltasp -= 4",
		"case APOPQ, APOPFQ:\n\t\t\tdeltasp -= 8",
		"case APOPW, APOPFW:\n\t\t\tdeltasp -= 2",
		"deltasp += int32(p.From.Offset)",
		"p.Spadj = +autoffset",
	} {
		if !bytes.Contains(data, []byte(rule)) {
			t.Fatalf("actual SDK source-stack diagnostic rule changed: %q", rule)
		}
	}
}

func TestGoAssemblerOracleActualX86Mode32FrameRebase(t *testing.T) {
	for _, test := range []struct{ name, frame, prefix, suffix, operand string }{
		{"param-zero", "$0-32", "", "", "a+0(FP)"},
		{"param-frame", "$16-32", "", "", "renamed+8(FP)"},
		{"param-negative", "$16-32", "", "", "a-8(FP)"},
		{"negative-frame", "$-4-32", "", "", "a+0(FP)"},
		{"auto-zero", "$16-32", "", "", "local-16(SP)"},
		{"auto-bare", "$16-32", "", "", "tmp(SP)"},
		{"push-long", "$16-32", "PUSHL AX\n", "POPL AX\n", "a+0(FP)"},
		{"push-word", "$0-32", "PUSHW AX\n", "POPW AX\n", "a+0(FP)"},
		{"push-flags", "$0-32", "PUSHFL\n", "POPFL\n", "a+0(FP)"},
		{"adj-positive", "$0-32", "ADJSP $8\n", "ADJSP $-8\n", "a+0(FP)"},
		{"adj-negative", "$16-32", "ADJSP $-8\n", "ADJSP $8\n", "a+0(FP)"},
		{"index-param", "$16-32", "", "", "a+0(FP)(SI*2)"},
	} {
		for _, op := range []string{"MOVOA", "MOVD"} {
			for _, store := range []bool{false, true} {
				direction, operands := "read", test.operand+",X8"
				if store {
					direction, operands = "write", "X15,"+test.operand
				}
				t.Run(test.name+"/"+op+"/"+direction, func(t *testing.T) {
					text := "TEXT probe(SB),4," + test.frame + "\n" + test.prefix + op + " " + operands + "\n" + test.suffix + "RET\n"
					source := x86FrameDiagnosticFixture(t, text)
					object := filepath.Join(filepath.Dir(source), "frame.o")
					stage, cancelStage := runtimeOracleStageContext(t)
					defer cancelStage()
					ctx, cancel := context.WithTimeout(stage, time.Minute)
					defer cancel()
					observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
						append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=386"),
						"go", "tool", "asm", "-o", object, source)
					encoded, encodeErr := json.Marshal(observed)
					if encodeErr != nil {
						t.Fatal(encodeErr)
					}
					t.Logf("ORACLE_CHILD %s", encoded)
					focus := 2 + strings.Count(test.prefix, "\n")
					if !observed.Waited || observed.ExitCode != 1 || ctx.Err() != nil ||
						!bytes.Contains(observed.Stderr, []byte("("+source+":"+strconv.Itoa(focus)+")")) ||
						!bytes.Contains(observed.Stderr, []byte("asmins: illegal in mode 32:")) {
						t.Fatalf("actual complete high-bank/frame diagnostic prerequisite absent: %+v %v", observed, err)
					}
					if failure := goasmoracle.CheckOutcome(source, object, observed.Stdout, observed.Stderr,
						err, ctx.Err(), false, focus, func(source, output string) bool {
							return goAssemblerOracleX86SourceDiagnostic(source, "386", output)
						}); failure != nil {
						t.Errorf("actual original source/frame rewrite did not bind: %v\n%s", failure, observed.Stderr)
					}
				})
			}
		}
	}
}
