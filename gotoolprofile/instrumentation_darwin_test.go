//go:build darwin

package gotoolprofile

import (
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Darwin race does not require CGO. Unlike the early -find oracle, these
// commands really compile/export the selected assembly and run asmdecl. There
// is no new executable program or claim that a sanitizer runtime was executed.
func TestInstrumentationActualGoDarwinRaceAssemblyExportAndAsmdecl(t *testing.T) {
	rules, err := CaptureInstrumentationSourceRules(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	directory := instrumentationMarkerDirectory(t)
	writeInstrumentationFixture(t, directory, "go.mod", []byte("module example.invalid/instrumentation-assembly\n\ngo 1.20\n"))
	writeInstrumentationFixture(t, directory, "base.go", []byte("package markers\n\nfunc marker()\n"))
	for _, mode := range []string{"race", "msan", "asan"} {
		writeInstrumentationFixture(t, directory, "mode_"+mode+".go", []byte("//go:build "+mode+"\n\npackage markers\n\nconst Mode = \""+mode+"\"\n"))
		writeInstrumentationFixture(t, directory, "mode_"+mode+".s", []byte("//go:build "+mode+"\n\n#include \"textflag.h\"\n\nTEXT ·marker(SB), NOSPLIT, $0-0\n\tRET\n"))
	}
	target := "darwin/" + runtime.GOARCH
	for _, cgo := range []string{"0", "1"} {
		t.Run("CGO="+cgo, func(t *testing.T) {
			env := instrumentationActualEnv(target, cgo)
			stdout, stderr, commandErr := instrumentationActualCommand(t, directory, env, goBinary, "list", "-export", "-json", "-race", "-p=1", "-mod=readonly", ".")
			if commandErr != nil {
				t.Fatalf("actual Go export failed (not source N/A): %s: %v", stderr, commandErr)
			}
			export, goFiles, asmFiles := decodeInstrumentationAssemblySelection(t, stdout)
			if export == "" || !reflect.DeepEqual(goFiles, []string{"base.go", "mode_race.go"}) || !reflect.DeepEqual(asmFiles, []string{"mode_race.s"}) {
				t.Fatalf("wrong actual compile/export selection: export=%q go=%v asm=%v", export, goFiles, asmFiles)
			}
			if _, err := os.Stat(export); err != nil {
				t.Fatalf("actual export is absent: %v", err)
			}
			nm, stderr, commandErr := instrumentationActualCommand(t, directory, env, goBinary, "tool", "nm", export)
			if commandErr != nil || !strings.Contains(string(nm), " T example.invalid/instrumentation-assembly.marker") {
				t.Fatalf("actual selected assembly symbol is absent: %s: %s: %v", nm, stderr, commandErr)
			}
			_, stderr, commandErr = instrumentationActualCommand(t, directory, env, goBinary, "vet", "-race", "-asmdecl", "-p=1", "-mod=readonly", ".")
			if commandErr != nil {
				t.Fatalf("actual same-mode asmdecl failed: %s: %v", stderr, commandErr)
			}
		})
	}
	if err := rules.Recheck(); err != nil {
		t.Fatal(err)
	}
}
