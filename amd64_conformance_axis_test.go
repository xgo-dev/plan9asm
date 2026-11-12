package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestAMD64ConformanceNativeMoveAssertionsRetainRequiredAxis(t *testing.T) {
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang is required")
	}
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprint(native), func(t *testing.T) {
			command := exec.Command(clang, "-E", "-P", "-x", "c", "-")
			command.Stdin = strings.NewReader(amd64ConformanceRuntimeC(native))
			out, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("actual driver preprocessing: %v\n%s", err, out)
			}
			for _, call := range []string{
				"packedFloatMoveMaskSemantics(move_mask_out, move_src, move_old)",
				"sameWidthPackedConversionSemantics(same_width_out,",
			} {
				if strings.Contains(string(out), call) != native {
					t.Errorf("native=%v has wrong actual call selection for %s", native, call)
				}
			}
			if !strings.Contains(string(out), "packedFloatMoveVEXSemantics(move_vex_out, move_src)") {
				t.Error("portable register-move assertions were lost")
			}
		})
	}
}
