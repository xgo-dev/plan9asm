package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestARM64NativeScratchSDKHiddenEntryActualObject(t *testing.T) {
	rootOutput, err := arm64MemoryAuditGoCommand(t, "linux", "env", "GOROOT")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(rootOutput)), "src", "cmd", "asm", "internal", "flags", "flags.go"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeFlags := []string(nil)
	if bytes.Contains(flags, []byte(`flag.Bool("compiling-runtime"`)) {
		// Original Go1.20 registers this explicit runtime producer role;
		// current Go uses the actual package path instead. Inspect the selected
		// SDK registration, not runtime.Version or a guessed epoch threshold.
		runtimeFlags = append(runtimeFlags, "-compiling-runtime")
	}
	fixtures := []struct {
		name, body string
		closed     bool
	}{
		{"explicit-word", "MOVD R0,R1", true},
		{"incoming-closure", "MOVD R26,R1", false},
		{"incoming-g", "MOVD g,R1", false},
		{"incoming-ordinary-gp", "MOVD R6,R1", false},
		{"incoming-stack-address", "MOVD RSP,R1", false},
		{"incoming-lr-data", "MOVD R30,R1", false},
		{"incoming-nzcv-branch", "BEQ done\nMOVD R0,R1\ndone:", false},
		{"incoming-nzcv-select", "CSEL EQ,R0,R0,R1", false},
		{"incoming-carry", "ADC R0,R0,R1", false},
		{"defined-nzcv", "CMP $1,R0\nCSEL EQ,R0,R0,R1", true},
		{"transferred-nzcv", "MSR R0,NZCV\nMRS NZCV,R1\nCSET EQ,R2", true},
		{"zero-nzcv", "MSR ZR,NZCV\nMRS NZCV,R1", true},
		{"incoming-nzcv-read", "MRS NZCV,R1", false},
		{"discarded-nzcv-read", "MRS NZCV,ZR", true},
		{"unknown-nzcv-input", "MSR R6,NZCV\nMRS NZCV,R1", false},
		{"one-branch-nzcv", "CBZ R0,join\nMSR R0,NZCV\njoin:\nMRS NZCV,R1", false},
		{"defined-closure-as-data", "MOVD $1,R26\nMOVD R26,R1", true},
		{"full-w-overwrite", "MOVWU R0,R26\nMOVD R26,R1", true},
		{"partial-overwrite", "MOVK $1,R26\nMOVD R26,R1", false},
		{"one-branch-undefined", "CBZ R0,join\nMOVD $1,R6\njoin:\nMOVD R6,R1", false},
		{"both-branches-defined", "CBZ R0,other\nMOVD $1,R6\nB join\nother:\nMOVD $2,R6\njoin:\nMOVD R6,R1", true},
		{"loop-dominating-definition", "MOVD $1,R6\nloop:\nADD $1,R6\nCBNZ R0,loop\nMOVD R6,R1", true},
		{"loop-backedge-only", "loop:\nMOVD R6,R1\nMOVD $1,R6\nCBNZ R0,loop", false},
		{"incoming-system-state", "MRS TPIDR_EL0,R1", false},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			// Stock Go emits every original first-party body and its complete
			// relocations. The SDK/package role below is a unit admission input,
			// not an authenticated SDK, archive pair or factory-created token.
			// ready stays false: this cannot bind or translate any program.
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(root, "src", "fixture")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(directory, "inputs_arm64.s")
			assembly := "TEXT ·Value<ABIInternal>(SB),516,$0-8\n" + fixture.body + "\nRET\n"
			if err := os.WriteFile(input, []byte(assembly), 0600); err != nil {
				t.Fatal(err)
			}
			object := filepath.Join(directory, "original.o")
			arguments := append([]string{"tool", "asm", "-S", "-p", "runtime"}, runtimeFlags...)
			arguments = append(arguments, "-o", object, input)
			listing, err := arm64MemoryAuditGoCommand(t, "linux", arguments...)
			if err != nil {
				t.Fatalf("actual original Go object: %v\n%s", err, listing)
			}
			disassembly, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "objdump", object)
			if err != nil {
				t.Fatalf("actual original native bytes: %v\n%s", err, disassembly)
			}
			t.Logf("actual original listing:\n%s\nactual native body:\n%s", listing, disassembly)
			bodies, err := arm64ScratchObjectBodies(disassembly)
			if err != nil {
				t.Fatal(err)
			}
			body, present := bodies["runtime.Value"]
			if !present {
				t.Fatal("original complete native body missing")
			}
			if filepath.FromSlash(strings.TrimPrefix(body.source, "gofile..")) != input {
				t.Fatalf("actual native source position does not bind unchanged fixture: %q", body.source)
			}
			// This unit isolates machine-input admission, not object source-name
			// transport. The raw SDK observation above remains unchanged. Old
			// cmd/internal/src.FileSymPrefix is bound to this same physical file.
			body.source = input
			file, err := Parse(ArchARM64, assembly)
			if err != nil || len(file.Funcs) != 1 {
				t.Fatalf("whole source: %v", err)
			}
			fset := token.NewFileSet()
			syntax, err := parser.ParseFile(fset, filepath.Join(directory, "decl.go"), "package runtime\nfunc Value(n uint64)\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			typed, err := (&types.Config{Sizes: types.SizesFor("gc", "arm64")}).Check("runtime", fset, []*ast.File{syntax}, nil)
			if err != nil {
				t.Fatal(err)
			}
			source := &GoARM64ScratchSource{
				actual: GoPackage{Path: "example.invalid/caller"}, settings: map[string]string{"GOROOT": root},
				inputs:    map[string][32]byte{input: sha256.Sum256([]byte(assembly))},
				functions: map[string]Func{"runtime.Value": file.Funcs[0]},
				native:    map[string][]arm64ScratchNativeBody{"runtime.Value": {body, body}},
				packages:  map[string]arm64ScratchPackage{"runtime": {ImportPath: "runtime", Dir: directory, Standard: true, Goroot: true}},
				typed:     map[string]GoPackage{"runtime": {Path: "runtime", Types: typed, Syntax: []*ast.File{syntax}}},
				abis:      map[string]string{"runtime.Value": "ABIInternal"},
			}
			if physical, valid := source.originalObjectSource(body.source); !valid || physical != input {
				t.Fatal("unit machine-input test lacks its captured physical source identity")
			}
			got, err := source.closedNativeCallee(context.Background(), "runtime.Value", make(map[string]bool), 0)
			if err != nil || got != fixture.closed {
				t.Fatalf("SDK unit admission over actual Go body=%v, want %v: %v", got, fixture.closed, err)
			}
			if source.ready {
				t.Fatal("unit input manufactured a live source capability")
			}
		})
	}
}
