package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestCPPObservationSourcePathBudget(t *testing.T) {
	source := "TEXT ·Entry(SB),4,$0-0\n" + strings.Repeat("MOVQ $1, AX\n", 40000) + "RET\n"
	var first string
	for _, file := range []string{"entry.s", "/" + strings.Repeat("selected-source-directory/", 8) + "entry.s"} {
		observed, tokens, err := ObserveAssemblyCPPOutput(source, AssemblyPreprocessOptions{FileName: file})
		if err != nil {
			t.Fatalf("unchanged bounded source with %d-byte origin: %v", len(file), err)
		}
		if first == "" {
			first = observed.Output
		} else if observed.Output != first {
			t.Fatal("changing only the source path changed expanded assembly")
		}
		for _, token := range tokens {
			if token.Position.File != file {
				t.Fatal("physical source identity was shortened or substituted")
			}
		}
	}
}

func TestSDKCPPPositionSourcePathBudget(t *testing.T) {
	file := "/" + strings.Repeat("selected-source-directory/", 8) + "entry.s"
	source := strings.Repeat("MOVQ $1, AX\n", 15000) + "RET\n"
	observed, positions, err := observeSDKAssemblyCPP(source, AssemblyPreprocessOptions{FileName: file})
	if err != nil {
		t.Fatal("bounded source position tape depends on source path length:", err)
	}
	if len(positions.Tokens) == 0 || !strings.Contains(positions.Mapped, file) {
		t.Fatal("mapped source lost its actual source origin")
	}
	for _, token := range positions.Tokens {
		if token.Position.File != file || token.Position.Base.File != file || token.Position.FinalBase.File != file {
			t.Fatal("physical or logical filename was shortened or substituted")
		}
	}
	replayed, err := PreprocessAssemblySource(positions.Mapped, AssemblyPreprocessOptions{FileName: file})
	if err != nil || replayed != observed.Output {
		t.Fatalf("mapped output no longer replays exactly: %v", err)
	}
}

func TestCPPObservationDistinctPathBudget(t *testing.T) {
	var source strings.Builder
	for index := 0; index < 34; index++ {
		fmt.Fprintf(&source, "#include \"header%d.h\"\n", index)
	}
	observed, tokens, err := ObserveAssemblyCPPOutput(source.String(), AssemblyPreprocessOptions{
		FileName: "entry.s",
		ReadInclude: func(_, name string) (string, []byte, error) {
			return strings.Repeat("x", 512<<10) + name, []byte("RET\n"), nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "bound") || len(tokens) != 0 || !reflect.DeepEqual(observed, AssemblyCPPObservation{}) {
		t.Fatal("distinct retained filenames escaped the shared byte budget:", err)
	}
}

func TestCPPObservationRepeatedIncludePathStorage(t *testing.T) {
	file := strings.Repeat("selected-source-directory/", 64) + "header.h"
	observed, tokens, err := ObserveAssemblyCPPOutput(strings.Repeat("#include \"header.h\"\n", 3), AssemblyPreprocessOptions{
		FileName: "entry.s",
		ReadInclude: func(_, _ string) (string, []byte, error) {
			return strings.Clone(file), []byte("RET\n"), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var canonical *byte
	for _, source := range observed.Sources {
		if source.File == file {
			canonical = unsafe.StringData(source.File)
		}
	}
	if canonical == nil {
		t.Fatal("included source identity is missing")
	}
	includes := 0
	for _, event := range observed.Events {
		if event.Included == file {
			includes++
			if unsafe.StringData(event.Included) != canonical {
				t.Fatal("repeated include retained an uncharged filename allocation")
			}
		}
	}
	if includes != 3 {
		t.Fatalf("included source events = %d, want 3", includes)
	}
	for _, token := range tokens {
		if token.Position.File == file && unsafe.StringData(token.Position.File) != canonical {
			t.Fatal("output position retained a second filename allocation")
		}
	}
}
