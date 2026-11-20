package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This is a tiny actual-SDK object/source fixture, not a local stdlib/corpus
// replay. Original AES instructions and selected function bodies are retained.
// Dynamic aeskeysched contents alone are not extent, pointer or initialization
// authority. A later global producer must authenticate its own source/layout.
func TestX86AESFamilyOriginalSDKMemhash386GlobalBoundary(t *testing.T) {
	relative := "src/internal/runtime/maps/memhash_386.s"
	names := []string{"·memHash32AES", "·memHash64AES"}
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), relative))
	if errors.Is(err, os.ErrNotExist) {
		relative = "src/runtime/asm_386.s"
		names = []string{"runtime·memhash32", "runtime·memhash64"}
		data, err = os.ReadFile(filepath.Join(runtime.GOROOT(), relative))
	}
	if err != nil {
		t.Fatal(err)
	}
	headerPath := filepath.Join(runtime.GOROOT(), "pkg/include/textflag.h")
	header, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			start := strings.Index(string(data), "TEXT "+name+"(SB)")
			if start < 0 {
				t.Fatal("actual SDK selected function disappeared", relative, name)
			}
			body := string(data[start:])
			if next := strings.Index(body[1:], "\nTEXT "); next >= 0 {
				body = body[:next+1]
			}
			original := "#include \"textflag.h\"\n" + body
			dir := t.TempDir()
			input, object := filepath.Join(dir, "actual-sdk.s"), filepath.Join(dir, "actual-sdk.o")
			if err := os.WriteFile(input, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin/go"), "tool", "asm", "-I", filepath.Dir(headerPath), "-p", "actual-sdk", "-o", object, input)
			command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=386")
			output, err := runtimeOracleCombinedOutput(ctx, command)
			if failure := goAssemblerOracleOutcome(input, object, output, err, ctx.Err(), true, "386"); failure != nil {
				t.Fatal("unchanged SDK function original object", failure, string(output))
			}
			physical, err := os.ReadFile(object)
			if err != nil {
				t.Fatal(err)
			}
			processed, err := PreprocessAssemblySource(original, AssemblyPreprocessOptions{FileName: relative, ReadInclude: func(parent, name string) (string, []byte, error) {
				if name != "textflag.h" {
					return "", nil, fmt.Errorf("unselected header %s", name)
				}
				return "pkg/include/textflag.h", header, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, processed) // shared x86 parser; the typed consumer is explicitly mode386
			if err != nil || len(file.Funcs) != 1 {
				t.Fatal("actual source/include parser", err)
			}
			aes := 0
			for _, ins := range file.Funcs[0].Instrs {
				if ins.Op != "AESENC" {
					continue
				}
				aes++
				form, known, err := x86AESProperties(ins.Op, ins, "386")
				if !known || err != nil || form.byteWidth != 16 || form.memory != 0 {
					t.Fatal("unchanged actual SDK AES source must have registered whole-family grammar", ins, err)
				}
				state := x86ResultState{}
				state.xmm[0] = 0xffff
				if ok, known := x86ResultAESStep(ins, &state, nil, "386"); !known || ok {
					t.Fatal("dynamic SB numerical values borrowed unproved initialized/extent authority", ins)
				}
			}
			if aes != 3 {
				t.Fatal("actual SDK AES inventory changed", aes)
			}
			t.Logf("SDK=%s full-sourceSHA256=%x selected-originalSHA256=%x headerSHA256=%x original-objectSHA256=%x bytes=%d exactAES=%d; global producer absent, not a corpus/version pass", relative, sha256.Sum256(data), sha256.Sum256([]byte(original)), sha256.Sum256(header), sha256.Sum256(physical), len(physical), aes)
		})
	}
}
