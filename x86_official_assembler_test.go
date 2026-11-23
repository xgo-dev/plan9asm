package plan9asm

import (
	"debug/elf"
	"path/filepath"
	"runtime"
	"testing"
)

func x86OfficialAssemblerSourcePaths(t *testing.T, arch string) []string {
	t.Helper()
	root := filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "asm", "testdata")
	var paths []string
	files := []string{"386.s", "386enc.s"}
	if arch == "amd64" {
		var err error
		paths, err = filepath.Glob(filepath.Join(root, "avx512enc", "*.s"))
		if err != nil || len(paths) == 0 {
			t.Fatalf("missing Go AVX512 encoding testdata: %v", err)
		}
		files = []string{"amd64.s", "amd64enc.s", "amd64enc_extra.s"}
	}
	for _, file := range files {
		paths = append(paths, filepath.Join(root, file))
	}
	return paths
}

func requireX86ELFTestFunctions(t *testing.T, arch, path string, names, locations []string) {
	t.Helper()
	object, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := object.Close(); err != nil {
			t.Error(err)
		}
	}()
	machine, class := elf.EM_X86_64, elf.ELFCLASS64
	if arch == "386" {
		machine, class = elf.EM_386, elf.ELFCLASS32
	}
	if object.Type != elf.ET_REL || object.Machine != machine || object.Class != class {
		t.Fatalf("expected a %s relocatable ELF object", arch)
	}
	symbols, err := object.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	emitted := make(map[string]bool, len(symbols))
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || symbol.Size == 0 ||
			symbol.Section == elf.SHN_UNDEF || int(symbol.Section) >= len(object.Sections) {
			continue
		}
		section := object.Sections[symbol.Section]
		if section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_EXECINSTR == 0 || symbol.Value < section.Addr {
			continue
		}
		offset := symbol.Value - section.Addr
		if offset <= section.Size && symbol.Size <= section.Size-offset {
			emitted[symbol.Name] = true
		}
	}
	for i, name := range names {
		if !emitted[name] {
			t.Fatalf("LLVM object omitted executable function %s for %s", name, locations[i])
		}
	}
}
