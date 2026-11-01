package plan9asm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestLLVMIRMemoryBufferExactBytes(t *testing.T) {
	for _, text := range []string{"", "prefix\x00suffix", "UTF-8: λ\n", strings.Repeat("abcdef\n", 16384)} {
		buffer := llvmIRMemoryBuffer(text)
		if buffer.IsNil() {
			t.Fatal("LLVM returned an absent memory buffer")
		}
		actual := buffer.Bytes()
		buffer.Dispose() // This buffer was inspected, not consumed by ParseIR.
		if !bytes.Equal(actual, []byte(text)) {
			t.Fatalf("IR buffer byte mismatch: got %d bytes, want %d", len(actual), len(text))
		}
	}
}

func unavailableIRTemporaryDirectory(t *testing.T) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "absent")
	for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(variable, missing)
	}
	if filepath.Clean(os.TempDir()) != missing {
		t.Fatalf("temporary directory selection differs: %q", os.TempDir())
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("temporary directory must remain absent: %v", err)
	}
}

func TestLLVMIRParsingWithoutTemporaryDirectory(t *testing.T) {
	unavailableIRTemporaryDirectory(t)
	context := llvm.NewContext()
	defer context.Dispose()
	const valid = "define i32 @answer() { ret i32 7 }\n"
	for iteration := 0; iteration < 8; iteration++ {
		module, err := parseIRModuleInContext(context, valid)
		if err != nil {
			t.Fatal("valid in-memory IR must not require a temporary file", err)
		}
		if module.Context() != context || module.NamedFunction("answer").IsNil() {
			module.Dispose()
			t.Fatal("IR parsing lost its function or caller-owned context")
		}
		verifyErr := llvm.VerifyModule(module, llvm.ReturnStatusAction)
		module.Dispose()
		if verifyErr != nil {
			t.Fatal(verifyErr)
		}

		module, err = parseIRModuleInContext(context, "define i32 @broken() {")
		if !module.IsNil() {
			module.Dispose()
			t.Fatal("failed parsing returned a partial module")
		}
		if err == nil || !strings.Contains(err.Error(), "parse generated ir:") {
			t.Fatalf("malformed IR must retain the LLVM parser diagnostic: %v", err)
		}
	}
}

func TestTranslateAPIsWithoutTemporaryDirectory(t *testing.T) {
	const source = "TEXT ·nop(SB),4,$0-0\nPXOR X0,X0\nPXOR X1,X1\nPADDD X0,X1\nRET\n"
	packageDeclarations := mustGoPackage(t, "memoryir", "package memoryir\nfunc nop()\n")
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
		Sigs:       map[string]FuncSig{"nop": {Name: "nop", Ret: Void}}}
	unavailableIRTemporaryDirectory(t)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			context := llvm.NewContext()
			defer context.Dispose()
			if api == "text" {
				text, err := Translate(file, options)
				if err != nil || !strings.Contains(text, "@nop(") {
					t.Fatalf("text translation failed without temporary storage: %v", err)
				}
				return
			}
			var module llvm.Module
			if api == "module" {
				module, err = TranslateModuleInContext(context, file, options)
			} else {
				result, translateErr := TranslateGoModuleInContext(context, packageDeclarations, []byte(source),
					GoModuleOptions{GOARCH: "amd64", TargetTriple: options.TargetTriple, ResolveSym: options.ResolveSym})
				err = translateErr
				if result != nil {
					module = result.Module
				}
			}
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil || module.IsNil() {
				t.Fatalf("module translation failed without temporary storage: %v", err)
			}
			if module.Context() != context || module.NamedFunction("nop").IsNil() {
				t.Fatal("translation lost its function or caller-owned context")
			}
			if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
				t.Fatal(err)
			}
		})
	}
}
