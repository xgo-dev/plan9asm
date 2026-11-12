package plan9asm

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"
)

// Go20's test binaries omit BuildSettings. Require the actual executable
// machine header on every SDK, not optional GOARCH string metadata. This reads
// only the linked artifact and never starts its process or initializers.
func x86OriginalGoLinkedAMD64(name string) (amd64 bool, result error) {
	file, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			amd64, result = false, errors.Join(result, err)
		}
	}()
	info, err := buildinfo.Read(file)
	if err != nil || info.GoVersion != runtime.Version() {
		return false, fmt.Errorf("linked executable SDK differs: %v, %v", info, err)
	}
	var magic [4]byte
	if _, err := file.ReadAt(magic[:], 0); err != nil {
		return false, err
	}
	switch string(magic[:]) {
	case "\x7fELF":
		image, err := elf.NewFile(file)
		if err != nil {
			return false, err
		}
		return image.Machine == elf.EM_X86_64 && image.Class == elf.ELFCLASS64 &&
			image.Data == elf.ELFDATA2LSB && image.Entry != 0 &&
			(image.Type == elf.ET_EXEC || image.Type == elf.ET_DYN), nil
	case "\xcf\xfa\xed\xfe", "\xce\xfa\xed\xfe":
		image, err := macho.NewFile(file)
		if err != nil {
			return false, err
		}
		return image.Cpu == macho.CpuAmd64 && image.Type == macho.TypeExec, nil
	default:
		if string(magic[:2]) != "MZ" {
			return false, fmt.Errorf("unknown linked executable magic %x", magic)
		}
		image, err := pe.NewFile(file)
		if err != nil {
			return false, err
		}
		header, wide := image.OptionalHeader.(*pe.OptionalHeader64)
		return image.Machine == pe.IMAGE_FILE_MACHINE_AMD64 && wide && header.AddressOfEntryPoint != 0 &&
			image.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE != 0 && image.Characteristics&pe.IMAGE_FILE_DLL == 0, nil
	}
}

func TestX86OriginalGoExecutableReadsActualParentMachine(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	amd64, err := x86OriginalGoLinkedAMD64(executable)
	if err != nil || amd64 != (runtime.GOARCH == "amd64") {
		t.Fatal("actual linked parent architecture differs from its binary header", amd64, err)
	}
}

func TestX86OriginalGoExecutableRejectsMissingAndNonExecutable(t *testing.T) {
	for _, name := range []string{"absent", "header-only"} {
		path := t.TempDir() + "/" + name
		if name == "header-only" {
			if err := os.WriteFile(path, []byte("\x7fELF"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if amd64, err := x86OriginalGoLinkedAMD64(path); amd64 || err == nil {
			t.Fatal("missing/truncated artifact became a linked target", name, amd64, err)
		}
	}
}
