package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86LockScalarRMWActualSDKOr8(t *testing.T) {
	var data []byte
	var sourcePath string
	for _, relative := range []string{
		"src/internal/runtime/atomic/atomic_amd64.s",
		"src/runtime/internal/atomic/atomic_amd64.s",
	} {
		path := filepath.Join(runtime.GOROOT(), filepath.FromSlash(relative))
		actual, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue // Actual SDK source layout, not an encoder-version guess.
		}
		if err != nil || sourcePath != "" {
			t.Fatal("actual SDK atomic source is missing or ambiguous", err)
		}
		sourcePath, data = path, actual
	}
	start := strings.Index(string(data), "TEXT ·Or8(SB)")
	if sourcePath == "" || start < 0 {
		t.Fatal("actual SDK lacks the discovering Or8 source")
	}
	end := strings.Index(string(data[start:]), "\nTEXT ")
	if end < 0 {
		t.Fatal("SDK Or8 has no complete next-TEXT boundary")
	}
	body := string(data[start:start+end]) + "\n"
	header, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "pkg/include/textflag.h"))
	if err != nil {
		t.Fatal(err)
	}
	// The original body is unchanged. The actual stock header, not a manual
	// NOSPLIT substitution, supplies the same Go assembler definitions.
	original := string(header) + "\n" + body
	machine := x86LockScalarOriginalInstruction(t, "amd64", original)
	t.Logf("actual %s Or8 source SHA256=%x header SHA256=%x whole native instruction=%x",
		runtime.Version(), sha256.Sum256(data), sha256.Sum256(header), machine)
	expanded, err := PreprocessAssemblySource(original, AssemblyPreprocessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required for the actual SDK sample")
	}
	for _, target := range x86OrderingHintTargets {
		if target.arch != "amd64" {
			continue // This original SDK file is explicitly AMD64.
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86OrderingHintTranslateAPI(t, api, expanded,
					"package ordering\nfunc Or8(ptr *uint8, val uint8)\n", "amd64", target.triple)
				if err != nil || !strings.Contains(ir, "lock; orb") {
					t.Fatal("actual SDK Or8 retains its whole-source atomic effect", err)
				}
				compileLLVMToObject(t, llc, target.triple, "or8.ll", fmt.Sprintf("or8-%s.o", api), ir)
			})
		}
	}
	if after, err := os.ReadFile(sourcePath); err != nil || sha256.Sum256(after) != sha256.Sum256(data) {
		t.Fatal("actual SDK source changed during sample proof", err)
	}
}
