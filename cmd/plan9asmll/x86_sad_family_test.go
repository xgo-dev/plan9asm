package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractSupportedOpsRetainsCompleteSADSpecTable(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("../..", "amd64_lower_sad.go"))
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"amd64_lower_sad.go": data, "translate.go": []byte("package plan9asm\n")} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		ops, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"PSADBW", "VPSADBW", "MPSADBW", "VMPSADBW", "VDBPSADBW"} {
			if _, present := ops[name]; !present {
				t.Fatalf("%s typed SAD table omitted %s", arch, name)
			}
		}
	}
}

func TestX86SADCLIActualSelectedSourceEffects(t *testing.T) {
	dir := x86CallerCLIFixture(t)
	// Four uint64 input elements bind one full native Y read. Original
	// LONG eaf6d5c5 is the retained Weaviate instruction, with this fixture's
	// independently defined registers and unchanged scalar result envelope.
	body := "MOVQ (CX),AX\nCMPQ AX,$4\nJL small\nVMOVDQU (DI),Y2\nVMOVDQU (SI),Y5\nLONG $0xeaf6d5c5\nVMOVSS X5,(DX)\nJMP done\nsmall:\nMOVL $0,(DX)\ndone:\n"
	assembly := strings.Replace(x86CallerCLIAssembly, "MOVL (DI),AX\nADDL $7,AX\nMOVL AX,(DX)\n", body, 1)
	if err := os.WriteFile(filepath.Join(dir, "kernel_amd64.s"), []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOMAXPROCS", "2")
	config, err := resolveCompileConfig(true, "", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	config.Context = ctx
	report, tasks, err := runOneTarget(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{"."}, nil, nil,
		"example.com/caller", t.TempDir(), false, 0, true, false, true, "", config)
	if err != nil || report.TotalAsm != 1 || report.Success != 1 || report.Failed != 0 || report.NotApplicable != 0 {
		t.Fatalf("complete source SAD did not produce its actual LLVM object: %+v %v", report, err)
	}
	for _, task := range tasks {
		info, err := os.Stat(strings.TrimSuffix(task.OutLL, ".ll") + ".o")
		if err != nil || info.Size() == 0 {
			t.Fatalf("missing SAD LLVM object: %v", err)
		}
	}
}
