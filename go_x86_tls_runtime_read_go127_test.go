//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

const x86TLSRuntimeRead386Body = `MOVL (TLS),AX
MOVL 8(TLS),DX
ADDL AX,AX
ADDL DX,AX
MOVL AX,ret+0(FP)
RET`

func TestGoX86TLSRuntimeRead386Relocations(t *testing.T) {
	testGoX86TLSRuntimeReadObjects(t, "func Value() uint32", x86TLSRuntimeRead386Body, []x86TLSRuntimeTestProfile{
		{"linux/386", false, "R_386_TLS_LE runtime.tlsg"},
		{"linux/386", true, "R_386_TLS_GOTIE runtime.tlsg"},
		{"windows/386", false, "IMAGE_REL_I386_DIR32 _runtime.tls_g"},
		{"windows/386", true, "IMAGE_REL_I386_DIR32 _runtime.tls_g"},
	})
}

const x86TLSRuntimeReadAMD64Body = `MOVQ (TLS),AX
MOVQ 8(TLS),DX
ADDQ DX,AX
MOVQ AX,ret+0(FP)
RET`

func TestGoX86TLSRuntimeReadAMD64Objects(t *testing.T) {
	testGoX86TLSRuntimeReadObjects(t, "func Value() uint64", x86TLSRuntimeReadAMD64Body, []x86TLSRuntimeTestProfile{
		{"linux/amd64", false, "R_X86_64_TPOFF32 runtime.tlsg"},
		{"linux/amd64", true, "R_X86_64_GOTTPOFF runtime.tlsg"},
		{"freebsd/amd64", false, "R_X86_64_TPOFF32 runtime.tlsg"},
		{"freebsd/amd64", true, "R_X86_64_GOTTPOFF runtime.tlsg"},
		{"windows/amd64", false, "IMAGE_REL_AMD64_REL32 runtime.tls_g"},
		{"windows/amd64", true, "IMAGE_REL_AMD64_REL32 runtime.tls_g"},
		{"darwin/amd64", false, ""},
		{"darwin/amd64", true, ""},
	})
}

type x86TLSRuntimeTestProfile struct {
	target string
	shared bool
	reloc  string
}

func testGoX86TLSRuntimeReadObjects(t *testing.T, declaration, body string, profiles []x86TLSRuntimeTestProfile) {
	t.Helper()
	llc, readobj, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-readobj"), findLLVM22Tool("llvm-objdump")
	if llc == "" || readobj == "" || objdump == "" {
		t.Fatal("TLS runtime reads require LLVM 22")
	}
	for _, profile := range profiles {
		t.Run(fmt.Sprintf("%s/shared=%v", profile.target, profile.shared), func(t *testing.T) {
			pkg, file, options, original, request := x86TLSMoveSourceFixture(t, profile.target, profile.shared, declaration, body)
			if profile.target == "darwin/amd64" && !profile.shared {
				checkGoAMD64DarwinTLSOffsets(t, original, request)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoX86TLSMoveSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if _, err := source.BindTLSMoves(ctx, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("NOP-only binding borrowed a runtime slot: %v", err)
			}
			if len(source.reads) != 2 {
				t.Fatalf("missing exact original TLS loads: %+v; object: %+v", source.reads, source.texts[1][0].Relocations)
			}
			first, second := source.reads[0], source.reads[1]
			modified := source.texts[1][first.Function]
			modified.Relocations = append([]gostaticstorage.TextRelocation(nil), modified.Relocations...)
			modified.Relocations[0].Add++
			ins := file.Funcs[first.Function].Instrs[first.Instruction]
			if _, ok := x86TLSObservedRuntimeRead(ins, options.Goarch, profile.target, modified, first.PC, second.PC); ok {
				t.Fatal("modified relocation admitted an original TLS read")
			}
			bound, err := source.BindRuntimeTLSReads(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86TLSMoveBoundAPI(t, pkg, file, original, bound, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					dir := t.TempDir()
					input, object := filepath.Join(dir, "tls.ll"), filepath.Join(dir, "tls.o")
					if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
						t.Fatal(err)
					}
					args := []string{level, "-mtriple=" + options.TargetTriple, "-filetype=obj", input, "-o", object}
					if profile.shared {
						args = append(args, "-relocation-model=pic")
					}
					x86FloatCompareCaptureCommand(t, exec.Command(llc, args...))
					if profile.reloc != "" {
						listing := x86FloatCompareCaptureCommand(t, exec.Command(readobj, "--relocations", object))
						if !strings.Contains(string(listing), profile.reloc) {
							t.Fatalf("%s/%s lacks %s:\n%s", api, level, profile.reloc, listing)
						}
					} else {
						listing := x86FloatCompareCaptureCommand(t, exec.Command(objdump, "--disassemble", "--no-print-imm-hex", object))
						if !strings.Contains(string(listing), "%gs:48") || !strings.Contains(string(listing), "%gs:56") {
							t.Fatalf("%s/%s lost the Go Mach-O GS offsets:\n%s", api, level, listing)
						}
					}
				}
			}
		})
	}
}

func checkGoAMD64DarwinTLSOffsets(t *testing.T, source []byte, request GoX86TLSMoveCaptureRequest) {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{
		"go.mod":        []byte("module tlscheck\n\ngo 1.20\n"),
		"main.go":       []byte("package main\nfunc Value() uint64\nfunc main() { println(Value()) }\n"),
		"value_amd64.s": source,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "tlscheck")
	build := exec.Command(request.GoBinary, "build", "-p=1", "-o", executable, ".")
	build.Dir, build.Env = dir, append(append([]string(nil), request.Environment...), "CGO_ENABLED=0")
	x86FloatCompareCaptureCommand(t, build)
	disassemble := exec.Command(request.GoBinary, "tool", "objdump", "-s", "^main.Value.abi0$", executable)
	disassemble.Dir, disassemble.Env = dir, build.Env
	listing := string(x86FloatCompareCaptureCommand(t, disassemble))
	if !strings.Contains(listing, "MOVQ GS:0x30, AX") || !strings.Contains(listing, "MOVQ GS:0x38, DX") {
		t.Fatalf("original Go linker changed the Mach-O GS offsets:\n%s", listing)
	}
}
