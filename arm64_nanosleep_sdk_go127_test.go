//go:build go1.27

package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This is an independent full original SDK/archive observation, not a source,
// ABI or memory token. Success here never certifies the whole SDK file's IR.
func TestARM64NanosleepSDKOriginalObjectAndBody(t *testing.T) {
	selection := arm64ABI0RegionCommand(t, "linux", ".", "list", "-json", "-compiled", "-export", "runtime")
	var selected goAMD64FrameSelection
	decoder := json.NewDecoder(bytes.NewReader(selection))
	if err := decoder.Decode(&selected); err != nil {
		t.Fatal(err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || selected.ImportPath != "runtime" || selected.Export == "" {
		t.Fatal("actual complete runtime selection is missing or ambiguous")
	}
	const sourceName = "sys_linux_arm64.s"
	present := false
	for _, name := range selected.SFiles {
		present = present || name == sourceName
	}
	if !present {
		t.Fatal("actual Linux/ARM64 Go selection omitted the original SDK source")
	}
	sourcePath := filepath.Join(selected.Dir, sourceName)
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchARM64, string(data))
	if err != nil {
		t.Fatal("complete original SDK source", err)
	}
	var original strings.Builder
	count := 0
	for _, function := range file.Funcs {
		if function.Sym == "runtime·usleep" {
			count++
			for _, instruction := range function.Instrs {
				original.WriteString(instruction.Raw + "\n")
			}
		}
	}
	if count != 1 {
		t.Fatal("original SDK usleep TEXT membership differs")
	}
	archive, err := os.ReadFile(selected.Export)
	if err != nil {
		t.Fatal(err)
	}
	builtins, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/goobj/builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	// Runtime's compiler member is not an ordinary user-package observer role.
	// Do not broaden that observer: let the actual Go archive tool enumerate
	// every member and extract only this original assembler object. The bytes
	// still supply observation only, not a source capability or an ABI grant.
	inventory := arm64ABI0RegionCommand(t, "linux", ".", "tool", "pack", "t", selected.Export)
	memberName := strings.TrimSuffix(sourceName, ".s") + ".o"
	if len(memberName) > 16 {
		memberName = memberName[:16] // Go's actual ar member-name field.
	}
	members := strings.Fields(string(inventory))
	seen := make(map[string]bool)
	for _, name := range members {
		if seen[name] {
			t.Fatal("ambiguous actual Go archive member inventory")
		}
		seen[name] = true
	}
	if len(members) < 3 || !seen[memberName] {
		t.Fatal("actual original assembler member absent")
	}
	object := arm64ABI0RegionCommand(t, "linux", ".", "tool", "pack", "p", selected.Export, memberName)
	if _, err := gostaticstorage.ObserveARM64AssemblyText(object, builtins, "linux/arm64"); !errors.Is(err, gostaticstorage.ErrContext) {
		t.Fatal("an ordinary observer must not acquire SDK object authority", err)
	}
	objectPath := filepath.Join(t.TempDir(), "original.o")
	if err := os.WriteFile(objectPath, object, 0600); err != nil {
		t.Fatal(err)
	}
	// Stock Go, not an ordinary-role parser with erased flags, reads this SDK
	// object. Keep its complete symbol inventory and every selected body byte.
	symbols := arm64ABI0RegionCommand(t, "linux", ".", "tool", "nm", "-size", objectPath)
	count = 0
	for _, line := range strings.Split(strings.TrimSpace(string(symbols)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 4 && fields[3] == "runtime.usleep" {
			count++
			if fields[1] != "96" || fields[2] != "T" {
				t.Fatal("original ASM symbol extent/type differs")
			}
		}
	}
	if count != 1 {
		t.Fatal("ambiguous original ASM membership; a compiler wrapper is not the body")
	}
	disassembly := arm64ABI0RegionCommand(t, "linux", ".", "tool", "objdump", "-s", "^runtime\\.usleep$", objectPath)
	word := regexp.MustCompile(`^\s+\S+:\d+\s+(0x[0-9a-f]+)\s+([0-9a-f]{8})\s+.+$`)
	var code []byte
	var start uint64
	header := false
	for _, line := range strings.Split(strings.TrimSpace(string(disassembly)), "\n") {
		if strings.HasPrefix(line, "TEXT runtime.usleep(SB) ") && !header {
			header = true
			continue
		}
		match := word.FindStringSubmatch(line)
		if !header || match == nil || strings.Contains(line, "R_") {
			t.Fatalf("unknown/relocated original Go body record %q", line)
		}
		pc, err := strconv.ParseUint(match[1][2:], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) == 0 {
			start = pc
		}
		if pc != start+uint64(len(code)) || len(code) >= 96 {
			t.Fatal("original body PCs have a hole, overlap or excess extent")
		}
		value, err := strconv.ParseUint(match[2], 16, 32)
		if err != nil {
			t.Fatal(err)
		}
		code = binary.LittleEndian.AppendUint32(code, uint32(value))
	}
	const originalCodeSHA = "360f9c85948651b364c9e030e319821df2196aa63fe118e57a856ee2faa4d9ed"
	if len(code) != 96 || fmt.Sprintf("%x", sha256.Sum256(code)) != originalCodeSHA {
		t.Fatal("complete original Go private timespec/SVC0 body bytes differ")
	}
	t.Logf("SDK_ORIGINAL_BODY sourceSHA256=%x archiveSHA256=%x member=%s objectSHA256=%x codeSHA256=%x bytes=%d",
		sha256.Sum256(data), sha256.Sum256(archive), memberName, sha256.Sum256(object), sha256.Sum256(code), len(code))
	declarationPath := filepath.Join(selected.Dir, "stubs2.go")
	declarationBytes, err := os.ReadFile(declarationPath)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	declarations, err := parser.ParseFile(fset, declarationPath, declarationBytes, 0)
	if err != nil {
		t.Fatal(err)
	}
	var declaration bytes.Buffer
	for _, node := range declarations.Decls {
		if function, ok := node.(*ast.FuncDecl); ok && function.Name.Name == "usleep" && function.Body == nil {
			if err := format.Node(&declaration, fset, function); err != nil {
				t.Fatal(err)
			}
		}
	}
	if declaration.Len() == 0 {
		t.Fatal("actual ordinary SDK declaration absent")
	}
	pkg := mustGoPackage(t, "runtime", "package runtime\n"+declaration.String()+"\n")
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			if _, err := arm64NanosleepPackageAPI(t, api, "aarch64-unknown-linux-gnu", original.String(), pkg); err != nil {
				t.Fatal("exact original SDK usleep body (not a whole-file pass)", err)
			}
		})
	}
}

func TestARM64NanosleepInputLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, spelling := range []string{"SVC", "SVC $0"} {
		source := strings.Replace(arm64NanosleepInputSource, "\tSVC\n", "\t"+spelling+"\n", 1)
		requireARM64GoAssemblerResult(t, source, true)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(api+"/"+spelling, func(t *testing.T) {
				ir, err := arm64NanosleepInputAPI(t, api, "aarch64-unknown-linux-gnu", source)
				if err != nil {
					t.Fatal("source-bound Linux input object", err)
				}
				for _, optimization := range []int{0, 2} {
					t.Run(fmt.Sprintf("O%d", optimization), func(t *testing.T) {
						// This shared helper only executes LLVM22 and checks the
						// resulting ELF. It cannot mint a source/kernel proof.
						arm64LinuxSyscallEffectCompileObject(t, llc, ir, optimization)
					})
				}
			})
		}
	}
}
