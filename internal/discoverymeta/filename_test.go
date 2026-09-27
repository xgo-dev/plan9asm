package discoverymeta

import (
	"reflect"
	"testing"
)

func TestArchitectureHintsCoverCurrentAndFuturePlan9asmPorts(t *testing.T) {
	files := []string{
		"asm_amd64.s",
		"asm_loong64.s",
		"asm_ppc64le.s",
		"asm_riscv64.s",
		"asm_s390x.s",
		"asm_mips64x.s",
		"portable.s",
	}
	want := []string{"amd64", "loong64", "ppc64le", "riscv64", "s390x", "unknown"}
	if got := ArchitectureHints(files); !reflect.DeepEqual(got, want) {
		t.Fatalf("ArchitectureHints() = %#v, want %#v", got, want)
	}
}

func TestFilterAssemblyFilesForNewTargetIsConservative(t *testing.T) {
	files := []string{
		"asm_amd64.s",
		"asm_linux_riscv64.s",
		"asm_plan9_riscv64.s",
		"asm_linux.s",
		"asm_windows.s",
		"asm_amd64x.s",
		"portable.s",
	}
	want := []string{"asm_amd64x.s", "asm_linux.s", "asm_linux_riscv64.s", "portable.s"}
	got, err := FilterAssemblyFiles(files, []string{"linux/riscv64"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterAssemblyFiles() = %#v, want %#v", got, want)
	}
}

func TestFilterAssemblyFilesAcceptsAPlatformNewerThanKnownLists(t *testing.T) {
	got, err := FilterAssemblyFiles([]string{"asm_newos_newarch.s", "asm_linux_amd64.s"}, []string{"newos/newarch"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"asm_newos_newarch.s"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterAssemblyFiles() = %#v, want %#v", got, want)
	}
}

func TestFilterAssemblyFilesRejectsInvalidTarget(t *testing.T) {
	if _, err := FilterAssemblyFiles([]string{"portable.s"}, []string{"linux"}); err == nil {
		t.Fatal("FilterAssemblyFiles() accepted an invalid target")
	}
}
