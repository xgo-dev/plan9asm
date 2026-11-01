package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Keep targets independently scheduled: each AMD64 root retains 108 original
// initialized witnesses, each mode32 root 36, with at most 36 functions per
// capture. Objects establish translation/encoding, not VNNI CPU execution.
func TestX86VNNIIntegerCompleteLinuxAMD64Objects(t *testing.T) {
	x86VNNICompleteTargetObjects(t, "amd64", "x86_64-unknown-linux-gnu")
}

func TestX86VNNIIntegerCompleteDarwinAMD64Objects(t *testing.T) {
	x86VNNICompleteTargetObjects(t, "amd64", "x86_64-apple-darwin")
}

func TestX86VNNIIntegerCompleteWindowsAMD64Objects(t *testing.T) {
	x86VNNICompleteTargetObjects(t, "amd64", "x86_64-pc-windows-msvc")
}

func TestX86VNNIIntegerCompleteLinux386Objects(t *testing.T) {
	x86VNNICompleteTargetObjects(t, "386", "i386-unknown-linux-gnu")
}

func TestX86VNNIIntegerCompleteWindows386Objects(t *testing.T) {
	x86VNNICompleteTargetObjects(t, "386", "i386-pc-windows-msvc")
}

func x86VNNICompleteTargetObjects(t *testing.T, arch, triple string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows := x86VNNIOracleRows(arch)
	for start := 0; start < len(rows); start += 36 {
		end := start + 36
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprint("batch-", start), func(t *testing.T) {
			var source, declarations strings.Builder
			for i := start; i < end; i++ {
				body, declaration := rows[i].program(arch, fmt.Sprint("Dot", i))
				source.WriteString(body)
				declarations.WriteString(declaration)
			}
			x86LEAActualTargetGoObject(t, arch, triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
					if ir == "" || err != nil {
						t.Fatal("complete initialized integer-dot family lost its public numerical owner", err)
					}
					for _, pipeline := range []struct{ ir, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						x86PackedStringCompileObject(t, llc, triple, pipeline.ir, pipeline.level)
					}
				})
			}
		})
	}
}
