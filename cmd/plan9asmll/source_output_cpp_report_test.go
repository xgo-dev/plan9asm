package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestFeatureCPPReadReportRetainsOnlyActiveSearchMisses(t *testing.T) {
	root := t.TempDir()
	physical, err := sourcepath.Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	const source = "#include \"textflag.h\"\n#include \"local.inc\"\n#include \"go_asm.h\"\n#ifdef MISSING_INACTIVE\n#include \"inactive.inc\"\n#endif\nTEXT ·Leaf(SB),NOSPLIT,$0-0\nRET\n"
	const local = "#define BIAS 7\n"
	for name, data := range map[string]string{"p_amd64.s": source, "local.inc": local} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tool := "pkg/include/textflag.h"
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(tool)))
	if err != nil {
		t.Fatal(err)
	}
	consumer := &featureConsumer{Dir: physical, Root: runtime.GOROOT(), Input: &featureInput{
		Sources:     map[string]string{"p_amd64.s": featureBytesSHA256([]byte(source)), "local.inc": featureBytesSHA256([]byte(local))},
		ToolSources: map[string]string{tool: featureBytesSHA256(data)},
	}}
	// This controlled generated callback tests read inventory only. It makes no
	// generated-header compiler, declaration, object, or native-frame claim.
	header := func() ([]byte, error) { return []byte("#define Generated 7\n"), nil }
	var report plan9asm.GoAssemblySourceReadReport
	observed, inputs, err := consumer.preprocessCPPSource(filepath.Join(physical, "p_amd64.s"), "example.com/readreport", nil, header, false, &report)
	plain, plainInputs, plainErr := consumer.preprocessCPPWithHeader(filepath.Join(physical, "p_amd64.s"), "example.com/readreport", nil, header)
	if err != nil || plainErr != nil || !reflect.DeepEqual(observed, plain) || !reflect.DeepEqual(inputs, plainInputs) {
		t.Fatalf("report altered existing registered CPP expansion: %v %v", err, plainErr)
	}
	want := []string{filepath.Join(physical, "textflag.h"), filepath.Join(physical, "go_asm.h")}
	if !reflect.DeepEqual(report.SearchMisses, want) {
		t.Fatalf("active actual resolver miss inventory differs: got=%v want=%v", report.SearchMisses, want)
	}
	files, err := compileCPPInputFiles(consumer, inputs)
	if err != nil || len(files) != 3 {
		t.Fatalf("actual module/tool reads lost or generated file invented: %v %v", files, err)
	}
	for _, file := range files {
		if filepath.Base(file) == "go_asm.h" {
			t.Fatal("in-memory generated header became a physical input")
		}
	}
}
