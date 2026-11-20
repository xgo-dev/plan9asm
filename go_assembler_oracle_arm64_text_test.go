package plan9asm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func arm64TextFrameDiagnostic(source, listing string, frame int) string {
	return fmt.Sprintf("asm: 00001 (%s:1)\t%s: unaligned frame size %d - must be 16 aligned\nasm: assembly failed\n",
		source, listing, frame)
}

func TestGoAssemblerOracleARM64TextFrameTrailingDiagnostic(t *testing.T) {
	// These are the complete common TEXT flag bits, including bits which
	// InitTextSym deliberately does not project into a printed attribute.
	for _, test := range []struct {
		flag int
		attr string
	}{
		{0, ""}, {1, ""}, {2, "DUPOK"}, {4, "NOSPLIT"}, {8, ""}, {16, ""},
		{32, "WRAPPER"}, {64, "NEEDCTXT"}, {128, ""}, {256, ""},
		{512, "NOFRAME"}, {1024, "REFLECTMETHOD"}, {2048, "TOPFRAME"}, {4096, "ABIWRAPPER"},
		{2 | 4 | 32 | 64 | 1024 | 2048 | 4096, "DUPOK|NOSPLIT|REFLECTMETHOD|WRAPPER|NEEDCTXT|ABIWRAPPER|TOPFRAME"},
	} {
		t.Run(fmt.Sprint(test.flag), func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "forms.s")
			body := fmt.Sprintf("TEXT badWidth(SB),%d,$3-0\nRET\n", test.flag)
			if err := os.WriteFile(source, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			listing := "TEXT badWidth(SB), "
			if test.attr != "" {
				listing += test.attr + ", "
			}
			listing += "$3-0"
			frame := 3
			if test.flag&512 != 0 {
				frame -= 8 // Go's NOFRAME autosize omits the saved LR.
			}
			output := arm64TextFrameDiagnostic(source, listing, frame)
			if !goAssemblerOraclePositionlessDiagnostic(source, "arm64", output) {
				t.Error("complete TEXT/flag/frame trailing diagnostic lost")
			}
			if goasmoracle.SourceDiagnosticLine(source, output, 1) {
				t.Fatal("strict default acquired a bare backend listing")
			}
			for _, changed := range []string{
				strings.Replace(output, source+":1", source+":2", 1),
				strings.Replace(output, source+":1", "foreign"+source+":1", 1),
				strings.Replace(output, "00001", "1", 1),
				strings.Replace(output, "badWidth(SB)", "other(SB)", 1),
				strings.Replace(output, "$3-0", "$4-0", 1),
				strings.Replace(output, "$3-0", "$3-8", 1),
				strings.Replace(output, ": unaligned", ": unknown unaligned", 1),
				strings.Replace(output, "16 aligned", "8 aligned", 1),
				strings.Replace(output, fmt.Sprintf("frame size %d", frame), "frame size 33", 1),
				strings.Replace(output, " aligned\n", " aligned extra\n", 1),
				"asm: 00001 (" + source + ":1) TEXT badWidth(SB), $3-0\n",
				"asm: unaligned frame size 3 - must be 16 aligned\n",
			} {
				if goAssemblerOraclePositionlessDiagnostic(source, "arm64", changed) {
					t.Errorf("changed complete diagnostic borrowed TEXT: %q", changed)
				}
			}
			if goAssemblerOraclePositionlessDiagnostic(source, "amd64", output) ||
				goAssemblerOraclePositionlessDiagnostic(source, "386", output) {
				t.Fatal("ARM64 trailing diagnostic leaked into x86")
			}
		})
	}
}

func TestGoAssemblerOracleARM64ActualTextFrameFlagFamily(t *testing.T) {
	for _, flag := range []int{0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 7270} {
		t.Run(fmt.Sprint(flag), func(t *testing.T) {
			directory := t.TempDir()
			source, object := filepath.Join(directory, "forms.s"), filepath.Join(directory, "forms.o")
			body := fmt.Sprintf("TEXT badWidth(SB),%d,$3-0\nRET\n", flag)
			if err := os.WriteFile(source, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			stage, cancelStage := runtimeOracleStageContext(t)
			defer cancelStage()
			ctx, cancel := context.WithTimeout(stage, time.Minute)
			defer cancel()
			observed, err := goasmcmd.Observe(ctx, directory,
				append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=arm64"),
				"go", "tool", "asm", "-o", object, source)
			encoded, encodeErr := json.Marshal(observed)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			t.Logf("ORACLE_CHILD %s", encoded)
			if !observed.Waited || observed.ExitCode != 1 || ctx.Err() != nil || len(observed.Stdout) != 0 {
				t.Fatalf("actual frame refusal missing: %+v %v", observed, err)
			}
			var diagnostic []byte
			for _, line := range strings.Split(string(observed.Stderr), "\n") {
				if strings.Contains(line, ": unaligned frame size ") {
					if diagnostic != nil {
						t.Fatal("ambiguous actual trailing diagnostic")
					}
					diagnostic = []byte(line + "\n")
				}
			}
			if diagnostic == nil {
				t.Fatalf("actual unaligned-frame line absent:\n%s", observed.Stderr)
			}
			// Probe this exact real diagnostic line, not a separate NOFRAME
			// message which may coexist with it. Full original streams remain
			// above; this is diagnostic-join evidence, never object success.
			failure := goasmoracle.CheckOutcome(source, object, nil, diagnostic, err, ctx.Err(), false, 1,
				func(source, output string) bool {
					return goAssemblerOraclePositionlessDiagnostic(source, "arm64", output)
				})
			if failure != nil {
				t.Fatalf("actual trailing TEXT diagnostic unbound: %v\n%s", failure, observed.Stderr)
			}
		})
	}
}
