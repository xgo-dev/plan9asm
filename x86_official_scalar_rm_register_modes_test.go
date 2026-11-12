package plan9asm

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Source acceptance/refusal observations only. Bare operands do not supply
// numerical inputs, LLVM object qualification or a native-execution result.
func TestX86ScalarRMRegisterOriginalSourceModes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		accepted, refused, rows := 0, 0, 0
		for _, entry := range catalog.Optab {
			if entry.Ytab != "yml_rl" || strings.HasPrefix(entry.Opcode, "CMOV") {
				continue
			}
			rows++
			for _, input := range []string{"CX", "0(SI)"} {
				t.Run(arch+"/"+entry.Opcode+"/"+input, func(t *testing.T) {
					listing, err := x86ExtensionGoListing(t, arch, entry.Opcode+" "+input+",BX")
					if err == nil {
						if !strings.Contains(listing, "extension.s:2") || !strings.Contains(listing, "0x0000 ") {
							t.Fatal("Go succeeded without the original source/byte-column observation", listing)
						}
						accepted++
						t.Log("actual Go source accepted", runtime.Version(), arch, entry.Opcode, input)
						return
					}
					var exit *exec.ExitError
					if arch == "amd64" || !errors.As(err, &exit) || exit.ExitCode() != 1 ||
						!strings.Contains(listing, "extension.s:2") || !strings.Contains(listing, entry.Opcode) ||
						!strings.Contains(listing, "asm:") {
						t.Fatal("source refusal not established: preserve setup/tool/resource failure separately", err, listing)
					}
					refused++
					t.Log("actual Go source refusal, not an ISA execution or numerical result", runtime.Version(), arch, listing)
				})
			}
		}
		if rows != 28 || accepted+refused != 56 {
			t.Fatal("incomplete original source observation denominator", arch, rows, accepted, refused)
		}
		if arch == "amd64" && (accepted != 56 || refused != 0) {
			t.Fatal("ordinary AMD64 official source alternatives changed", accepted, refused)
		}
		t.Log("actual source mode totals", runtime.Version(), arch, "accepted", accepted, "refused", refused)
	}
}
