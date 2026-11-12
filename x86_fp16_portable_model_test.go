package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// These tests intentionally execute the existing cross-target numerical
// model, even on x86 hosts without AVX512-FP16. Full public source/input checks
// still run. Retarget only the resulting portable LLVM values to the host;
// this is neither native FP16 execution nor a host MXCSR/exception oracle.
// Independent native-object tests use each real x86 target without retargeting.
func x86FP16NumericalModelIR(t *testing.T, file *File, sigs map[string]FuncSig, triple string) string {
	t.Helper()
	const model = "aarch64-unknown-linux-gnu"
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: model, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ir, "asm sideeffect") || strings.Contains(ir, "target-features") {
		t.Fatal("portable FP16 model contains native hardware instructions or features")
	}
	from := fmt.Sprintf("target triple = %q", model)
	if strings.Count(ir, from) != 1 {
		t.Fatal("portable FP16 model lost its exact module target")
	}
	return strings.Replace(ir, from, fmt.Sprintf("target triple = %q", triple), 1)
}
