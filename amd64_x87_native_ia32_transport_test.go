package plan9asm

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func TestX87IA32ArtifactModeSeparatesHostAndELFPermissions(t *testing.T) {
	for _, host := range []string{"linux", "darwin", "windows"} {
		for _, mode := range []os.FileMode{0600, 0700, os.ModeDir | 0700, os.ModeSymlink | 0700} {
			want := mode.IsRegular() && (host == "windows" || mode&0111 != 0)
			if got := x87IA32ArtifactMode(mode, host); got != want {
				t.Errorf("host %s mode %v: got %t, want %t", host, mode, got, want)
			}
		}
	}
}

func TestX87IA32RequiredNativeTransportSource(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_x87_flag_compare_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"x87IA32RequireNativeHost":   false,
		"x87IA32NativePreflight":     false,
		"x87IA32OriginalGoDirect":    false,
		"x87IA32CompileAndRunDirect": false,
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.BasicLit:
			if value.Kind == token.STRING {
				text, err := strconv.Unquote(value.Value)
				if err != nil {
					t.Fatal(err)
				}
				if text == "qemu-i386" || text == "-exec" {
					t.Errorf("required native IA32 oracle still selects emulation: %s", text)
				}
			}
		case *ast.CallExpr:
			if function, ok := value.Fun.(*ast.Ident); ok {
				if _, required := want[function.Name]; required {
					want[function.Name] = true
				}
			}
			if method, ok := value.Fun.(*ast.SelectorExpr); ok && method.Sel.Name == "Skip" {
				t.Error("required native IA32 oracle cannot skip failed preflight")
			}
		}
		return true
	})
	for function, found := range want {
		if !found {
			t.Errorf("required native IA32 route lacks %s", function)
		}
	}
}

func TestX87IA32OriginalReferenceMatrixPreserved(t *testing.T) {
	for _, fixture := range []struct {
		name, source, hash string
	}{
		{"386 assembly", x87FlagCompareAssembly("386"), "09ae2f421502ee1f22367d019e98f83767319bf03e414fdf305ad9afb940dea3"},
		{"amd64 assembly", x87FlagCompareAssembly("amd64"), "254191f4443a8d3c24c372c5aa5beb820f77e2a7d96a13179ca7fb2b37799664"},
		{"Go reference", x87FlagCompareOriginalReference, "62784b45ccd0cf0f6c04ec3cb498c744c48f5ba82354a8e2a6041a0067b7ade6"},
		{"C reference", x87FlagCompareCReference, "ea4efe97b695fe4a398422ba3b32148e2456ed6dac3a4c8c88194080dcec4466"},
	} {
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.source))); got != fixture.hash {
			t.Errorf("%s changed: %s", fixture.name, got)
		}
	}
	if got := len(x87FlagCompareCases()); got != 32 {
		t.Fatalf("original 32-kernel matrix changed: %d", got)
	}
}

// This is a synthetic parser fixture, never executed or called native proof.
func x87IA32SyntheticELF() []byte {
	data := make([]byte, 85)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_386))
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint32(data[24:], 0x1000)
	binary.LittleEndian.PutUint32(data[28:], 52)
	binary.LittleEndian.PutUint16(data[40:], 52)
	binary.LittleEndian.PutUint16(data[42:], 32)
	binary.LittleEndian.PutUint16(data[44:], 1)
	binary.LittleEndian.PutUint32(data[52:], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(data[56:], 84)
	binary.LittleEndian.PutUint32(data[60:], 0x1000)
	binary.LittleEndian.PutUint32(data[68:], 1)
	binary.LittleEndian.PutUint32(data[72:], 1)
	binary.LittleEndian.PutUint32(data[76:], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint32(data[80:], 1)
	data[84] = 0xc3
	return data
}

func TestX87IA32StaticELFRejectsUnboundExecutables(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func([]byte)
	}{
		{"wrong machine", func(data []byte) { binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_X86_64)) }},
		{"wrong class", func(data []byte) { data[4] = 2 }},
		{"wrong endian", func(data []byte) { data[5] = 2 }},
		{"relocatable", func(data []byte) { binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_REL)) }},
		{"interpreter", func(data []byte) { binary.LittleEndian.PutUint32(data[52:], uint32(elf.PT_INTERP)) }},
		{"dynamic", func(data []byte) { binary.LittleEndian.PutUint32(data[52:], uint32(elf.PT_DYNAMIC)) }},
		{"truncated load", func(data []byte) { binary.LittleEndian.PutUint32(data[68:], 2) }},
		{"outside load", func(data []byte) { binary.LittleEndian.PutUint32(data[56:], 1000) }},
		{"insufficient mapped memory", func(data []byte) { binary.LittleEndian.PutUint32(data[72:], 0) }},
		{"missing entry", func(data []byte) { binary.LittleEndian.PutUint32(data[24:], 0x1001) }},
		{"non executable entry", func(data []byte) { binary.LittleEndian.PutUint32(data[76:], uint32(elf.PF_R)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := x87IA32SyntheticELF()
			test.edit(data)
			name := filepath.Join(t.TempDir(), "invalid")
			if err := os.WriteFile(name, data, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := x87IA32StaticExecutable(name); err == nil {
				t.Fatal("unbound executable was accepted")
			}
		})
	}
	if _, err := x87IA32StaticExecutable(t.TempDir()); err == nil {
		t.Fatal("directory was accepted as an executable")
	}
	if _, err := x87IA32StaticExecutable(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing executable was accepted")
	}
}

func TestX87IA32StaticELFGuardsChangedBytesAndIdentity(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "executable")
	data := x87IA32SyntheticELF()
	if err := os.WriteFile(name, data, 0700); err != nil {
		t.Fatal(err)
	}
	sealed, err := x87IA32StaticExecutable(name)
	if err != nil || sealed.verify() != nil {
		t.Fatalf("synthetic parser control failed: %v", err)
	}
	changed := append([]byte(nil), data...)
	changed[84] = 0x90
	if err := os.WriteFile(name, changed, 0700); err != nil {
		t.Fatal(err)
	}
	if sealed.verify() == nil {
		t.Fatal("late-byte executable mutation was accepted")
	}
	if err := os.WriteFile(name, data, 0700); err != nil {
		t.Fatal(err)
	}
	sealed, err = x87IA32StaticExecutable(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name, filepath.Join(dir, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0700); err != nil {
		t.Fatal(err)
	}
	if sealed.verify() == nil {
		t.Fatal("equal-byte replacement lost its physical identity")
	}
	if err := os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = x87IA32StaticExecutable(name)
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatal("compiled ELF depends on nonexistent Windows Unix execute bits", err)
		}
	} else if err == nil {
		t.Fatal("native Unix executable lost its required execute permission")
	}
	file, err := os.Create(filepath.Join(dir, "oversize"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate((64 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "oversize"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := x87IA32StaticExecutable(filepath.Join(dir, "oversize")); err == nil {
		t.Fatal("oversize artifact was accepted")
	}
}

func TestX87IA32StaticELFRejectsDynamicSection(t *testing.T) {
	data := append(x87IA32SyntheticELF(), make([]byte, 40)...)
	binary.LittleEndian.PutUint32(data[32:], 85)
	binary.LittleEndian.PutUint16(data[46:], 40)
	binary.LittleEndian.PutUint16(data[48:], 1)
	binary.LittleEndian.PutUint32(data[89:], uint32(elf.SHT_DYNAMIC))
	name := filepath.Join(t.TempDir(), "dynamic")
	if err := os.WriteFile(name, data, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := x87IA32StaticExecutable(name); err == nil {
		t.Fatal("dynamic section was accepted")
	}
}

func TestX87IA32NativeEnvironmentCannotUseGuestLabels(t *testing.T) {
	host := &elf.File{FileHeader: elf.FileHeader{Class: elf.ELFCLASS64, Machine: elf.EM_X86_64}}
	cpuinfo := "vendor_id: GenuineIntel\nflags: fpu cmov\n"
	if err := x87IA32NativeEnvironment("linux", "amd64", "x86_64", cpuinfo, "synthetic native mapping", host); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, goos, arch, kernel, cpuinfo, maps string
		host                                    *elf.File
	}{
		{"Darwin guest", "darwin", "amd64", "x86_64", cpuinfo, "mapping", host},
		{"ARM host", "linux", "arm64", "x86_64", cpuinfo, "mapping", host},
		{"ARM kernel", "linux", "amd64", "aarch64", cpuinfo, "mapping", host},
		{"missing physical host", "linux", "amd64", "x86_64", cpuinfo, "mapping", nil},
		{"unobserved CPU", "linux", "amd64", "x86_64", "processor: 0", "mapping", host},
		{"missing P6", "linux", "amd64", "x86_64", "vendor_id: GenuineIntel\nflags: fpu", "mapping", host},
		{"missing x87", "linux", "amd64", "x86_64", "vendor_id: AuthenticAMD\nflags: cmov", "mapping", host},
		{"QEMU process", "linux", "amd64", "x86_64", cpuinfo, "/usr/bin/qemu-i386", host},
		{"Rosetta process", "linux", "amd64", "x86_64", cpuinfo, "/rosetta/rosetta", host},
		{"missing maps", "linux", "amd64", "x86_64", cpuinfo, "", host},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := x87IA32NativeEnvironment(test.goos, test.arch, test.kernel, test.cpuinfo, test.maps, test.host); err == nil {
				t.Fatal("guest or missing native capability was accepted")
			}
		})
	}
}

func TestX87IA32PreflightPreservesSixFlagRequirement(t *testing.T) {
	output := make([]byte, 64)
	for index := 0; index < 8; index++ {
		binary.LittleEndian.PutUint32(output[index*8:], 0x40)
		output[index*8+4] = 0x42
	}
	if err := x87IA32PreflightStatus(output); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 8; index++ {
		bad := append([]byte(nil), output...)
		binary.LittleEndian.PutUint32(bad[index*8:], 0x8d0)
		bad[index*8+4] = 0xd2
		if x87IA32PreflightStatus(bad) == nil {
			t.Fatalf("QEMU retained AF/SF/OF was accepted at row%d", index)
		}
	}
	if x87IA32PreflightStatus(output[:63]) == nil || x87IA32PreflightStatus(append(output, 0)) == nil {
		t.Fatal("partial or extra observation was accepted")
	}
}

func TestX87IA32OriginalGoStaticELFActualCompile(t *testing.T) {
	executable := x87IA32BuildOriginalGo(t)
	if err := executable.verify(); err != nil {
		t.Fatal(err)
	}
	t.Log("actual original 32-kernel Go386 ELF compiled and rechecked; no native execution claim")
}
