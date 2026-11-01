//go:build linux && (amd64 || arm64)

package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This is a tiny first-party C label/link oracle, not a Go ABI, instruction,
// frame or external-library permission. Linux requires actual GNU and LLVM22
// compilers; host selection is explicit, and missing tools never become skips.
func TestCrossLinuxRuntimeMatrixCAsmLabelGNUExactSymbol(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("required LLVM22 clang is missing")
	}
	gnu, err := exec.LookPath("x86_64-linux-gnu-gcc")
	if err != nil {
		t.Fatal("required actual GNU x86_64 ELF compiler:", err)
	}
	for _, row := range []struct{ name, symbol string }{
		{"ordinary", "framefixture.F0"},
		{"qualified", "example.invalid/framefixture.F0"},
		{"nested", "example.invalid/project/v2/framefixture.F0"},
	} {
		t.Run(row.name, func(t *testing.T) {
			directory := t.TempDir()
			ir := filepath.Join(directory, "original.ll")
			object := filepath.Join(directory, "original.o")
			source := fmt.Sprintf("target triple = \"x86_64-unknown-linux-gnu\"\ndefine i64 @%s(i64 %%a, i64 %%b) {\n %%sum = add i64 %%a, %%b\n ret i64 %%sum\n}\n", strconv.Quote(row.symbol))
			if err := os.WriteFile(ir, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			if output, err := runtimeCAsmLabelCommand(t, directory, execution.llc,
				"-O=0", "-mtriple=x86_64-unknown-linux-gnu", "-filetype=obj", ir, "-o", object); err != nil {
				t.Fatalf("actual LLVM22 ELF object: %v\n%s", err, output)
			}
			runtimeCAsmLabelELF(t, object, row.symbol, true)
			for _, caller := range []struct {
				name, compiler, label string
				arguments             []string
			}{
				{"ClangOriginalRawControl", clang, strconv.Quote(row.symbol), []string{"-target", "x86_64-unknown-linux-gnu"}},
				{"ClangSharedEncoding", clang, runtimeCAsmLabel(row.symbol), []string{"-target", "x86_64-unknown-linux-gnu"}},
				{"GNUSharedEncoding", gnu, runtimeCAsmLabel(row.symbol), nil},
			} {
				t.Run(caller.name, func(t *testing.T) {
					cPath := filepath.Join(directory, caller.name+".c")
					callerObject := filepath.Join(directory, caller.name+".o")
					binary := filepath.Join(directory, caller.name)
					code := runtimeCAsmLabelPreamble + fmt.Sprintf(`#include <stdint.h>
extern uint64_t invoke(uint64_t, uint64_t) __asm__(%s);
int main(void) {
    if (invoke(17, 25) != 42) return 1;
    if (invoke(UINT64_MAX, 20) != 19) return 2;
    return 0;
}
`, caller.label)
					if err := os.WriteFile(cPath, []byte(code), 0600); err != nil {
						t.Fatal(err)
					}
					args := append([]string(nil), caller.arguments...)
					args = append(args, "-O2", "-c", cPath, "-o", callerObject)
					if output, err := runtimeCAsmLabelCommand(t, directory, caller.compiler, args...); err != nil {
						t.Fatalf("actual caller must compile without renaming %q: %v\n%s", row.symbol, err, output)
					}
					runtimeCAsmLabelELF(t, callerObject, row.symbol, false)
					if output, err := runtimeCAsmLabelCommand(t, directory, gnu,
						"-no-pie", object, callerObject, "-o", binary); err != nil {
						t.Fatalf("actual exact-symbol object link: %v\n%s", err, output)
					}
					runtimeCAsmLabelELF(t, binary, row.symbol, true)
					if output := execution.run(t, binary); len(output) != 0 {
						t.Fatalf("actual tiny numerical oracle has unexpected output: %q", output)
					}
					t.Logf("C_LABEL_EXACT_SYMBOL_PASS compiler=%s symbol=%q label=%s", caller.name, row.symbol, caller.label)
				})
			}
			if strings.Contains(row.symbol, "/") {
				t.Run("LegacyRawGNURejectionControl", func(t *testing.T) {
					cPath := filepath.Join(directory, "raw-gnu.c")
					callerObject := filepath.Join(directory, "raw-gnu.o")
					code := fmt.Sprintf("extern unsigned long long invoke(void) __asm__(%s);\nunsigned long long caller(void) { return invoke(); }\n", strconv.Quote(row.symbol))
					if err := os.WriteFile(cPath, []byte(code), 0600); err != nil {
						t.Fatal(err)
					}
					output, err := runtimeCAsmLabelCommand(t, directory, gnu, "-O2", "-c", cPath, "-o", callerObject)
					exit, ok := err.(*exec.ExitError)
					if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "invalid operands") {
						t.Fatalf("unquoted GNU source did not retain its concrete original rejection: %v\n%s", err, output)
					}
					t.Logf("C_LABEL_LEGACY_GNU_REJECTION_ONLY symbol=%q source_sha256=%x\n%s", row.symbol, sha256.Sum256([]byte(code)), output)
				})
			}
		})
	}
}

func runtimeCAsmLabelCommand(t *testing.T, directory, executable string, arguments ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = directory
	t.Logf("ACTUAL_C_LABEL_COMMAND executable=%q argv=%q cwd=%q", executable, arguments, directory)
	return runtimeOracleCombinedOutput(ctx, command)
}

func runtimeCAsmLabelELF(t *testing.T, name, exact string, defined bool) {
	t.Helper()
	before, err := os.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 1024*1024 {
		t.Fatalf("tiny actual ELF artifact is missing, redirected or oversized: %v", err)
	}
	descriptor, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	opened, openErr := descriptor.Stat()
	if openErr != nil || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		descriptor.Close()
		t.Fatal("actual ELF inode/extent changed before bounded read", openErr)
	}
	data, readErr := io.ReadAll(io.LimitReader(descriptor, before.Size()+1))
	closedInfo, statErr := descriptor.Stat()
	closeErr := descriptor.Close()
	current, pathErr := os.Lstat(name)
	if readErr != nil || statErr != nil || closeErr != nil || pathErr != nil ||
		int64(len(data)) != before.Size() || !os.SameFile(before, closedInfo) || !os.SameFile(before, current) ||
		closedInfo.Size() != before.Size() || current.Size() != before.Size() ||
		!closedInfo.ModTime().Equal(before.ModTime()) || !current.ModTime().Equal(before.ModTime()) ||
		current.Mode() != before.Mode() {
		t.Fatalf("actual ELF bytes/inode/extent/EOF did not close: %v/%v/%v/%v", readErr, statErr, closeErr, pathErr)
	}
	object, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	if object.Class != elf.ELFCLASS64 || object.Data != elf.ELFDATA2LSB || object.Machine != elf.EM_X86_64 ||
		object.Type != elf.ET_REL && object.Type != elf.ET_EXEC {
		t.Fatalf("actual ELF object role mismatch: %#v", object.FileHeader)
	}
	symbols, err := object.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	matches := 0
	for _, symbol := range symbols {
		if symbol.Name == exact {
			matches++
			if elf.ST_BIND(symbol.Info) != elf.STB_GLOBAL || (symbol.Section != elf.SHN_UNDEF) != defined {
				t.Fatalf("actual symbol role changed: %#v", symbol)
			}
			if defined && (elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || symbol.Size == 0) {
				t.Fatalf("actual defined function has no exact executable extent: %#v", symbol)
			}
		}
	}
	if matches != 1 {
		t.Fatalf("exact symbol %q has %d entries in complete inventory: %#v", exact, matches, symbols)
	}
	if !defined {
		references := 0
		for _, section := range object.Sections {
			if section.Type != elf.SHT_RELA {
				continue
			}
			data, err := section.Data()
			if err != nil || len(data)%24 != 0 {
				t.Fatalf("incomplete actual ELF64 relocation inventory: %v bytes=%d", err, len(data))
			}
			for offset := 0; offset < len(data); offset += 24 {
				index := binary.LittleEndian.Uint64(data[offset+8:offset+16]) >> 32
				if index > uint64(len(symbols)) {
					t.Fatalf("relocation references missing symbol index %d", index)
				}
				if index != 0 && symbols[index-1].Name == exact {
					references++
				}
			}
		}
		if references == 0 {
			t.Fatalf("actual caller has no relocation to exact %q", exact)
		}
	}
	inventory, err := json.Marshal(symbols)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ACTUAL_C_LABEL_ELF path=%q bytes=%d sha256=%x exact=%q defined=%t symbols=%s", name, len(data), sha256.Sum256(data), exact, defined, inventory)
}
