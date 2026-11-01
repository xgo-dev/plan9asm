//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

// These source facts belong to this object/link oracle, not a source issuer.
// ABI1 remains ABI1 in the compiler object. On actual non-regabi386 the selected
// linker normalizes its symbol version; no record or wrapper is fabricated.
var x86Terminal386CompilerLinkSourcePins = map[string]string{
	"src/internal/buildcfg/exp.go":                "5825d40b47471bca28a00c0c19215930efef22b758120b6d972da1a955f21fa0",
	"src/cmd/internal/obj/link.go":                "918978ac6b04e839f5222282b2526230c6ca95b50248456ba9f73e9083258e1f",
	"src/cmd/compile/internal/ir/func.go":         "185b5f070932048b28c173de6d770ee7415b0490c1130623ab8b69dadd2d8387",
	"src/cmd/compile/internal/ssagen/abi.go":      "35b5cea74c417723ff4778cea5175d3a7bdd9c58584af163229e9624a1ee709c",
	"src/cmd/link/internal/sym/symbol.go":         "46ff2bfa4dec86d6c77c09fa5ef8f11f13d49ba55aee30507f4102a9750cfb04",
	"src/cmd/link/internal/loader/loader.go":      "b85dcd0c6f017f2455ba2d553bc20fd8b29105a98e4b6a6a0293ff32f6eca204",
	"src/cmd/link/internal/ld/main.go":            "0fe8ad02e4b244bbaa82f14a86aaa005155e43c9ba7492c98c9e9650b86cd41e",
	"src/cmd/internal/objabi/reloctype_string.go": "6e1a80d8c32bcb6c599a75e08a1e69d54f88a52941a0c831fb37b8e11ce3fc28",
	"src/cmd/go/internal/work/gc.go":              "13359b8707e78300e8e0ec880b9a8d1af4bafdf32140b56df5f041a52fbc1325",
	"src/cmd/go/internal/work/shell.go":           "ffc69d476c2cde44a64c26693b2c9aeb42830ac2777f9f538ef268c86d57be2f",
}

// This is a complete ordinary own-package Go/compiler/assembler/link oracle.
// It grants no SDK/body/entry or terminal capability, and does not execute the
// resulting Linux program. Runtime qualification is a separate owner.
func TestX86GoPanicTerminal386OriginalABICompileAndLink(t *testing.T) {
	const module = "example.invalid/panicterminal"
	const packagePath = module + "/callee"
	const goSource = `package callee
func ordinaryFailure(){ panic("first failure") }
func stopHere(){ panic("second failure") }
func InvokeFirst()
func InvokeSecond()
`
	const assembly = `TEXT ·InvokeFirst(SB),4,$0-0
CALL ·ordinaryFailure(SB)
RET
TEXT ·InvokeSecond(SB),4,$0-0
CALL ·stopHere(SB)
RET
`
	// Canonicalize only this fresh fixture-owned output directory.
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	calleeDirectory := filepath.Join(directory, "callee")
	if err := os.Mkdir(calleeDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	artifacts := make(map[string][]byte)
	inputHashes := make(map[string][sha256.Size]byte)
	read := func(filename string) []byte {
		info, err := os.Lstat(filename)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			t.Fatal("oracle input/output is not a bounded regular file", filename, err)
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	retainInput := func(filename string) []byte {
		data := read(filename)
		inputHashes[filename] = sha256.Sum256(data)
		return data
	}
	verifyInputs := func() {
		for filename, expected := range inputHashes {
			if sha256.Sum256(read(filename)) != expected {
				t.Fatal("selected source/tool changed during the original compile/link oracle", filename)
			}
		}
	}
	type commandReceipt struct {
		Arguments   []string
		Observation goasmcmd.Observation
		Failure     string
	}
	var commands []commandReceipt
	t.Cleanup(func() {
		encoded, err := json.MarshalIndent(struct {
			Commands []commandReceipt
			Inputs   map[string][sha256.Size]byte
		}{commands, inputHashes}, "", "  ")
		if err != nil {
			t.Error(err)
			return
		}
		artifacts["commands-and-inputs.json"] = encoded
		if output := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); output != "" {
			output = filepath.Join(output, "386-single-panic-original-link")
			if err := os.MkdirAll(output, 0700); err != nil {
				t.Error(err)
				return
			}
			for name, data := range artifacts {
				if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
					t.Error(err)
				}
			}
		}
	})
	for name, source := range map[string]string{
		"go.mod":            "module " + module + "\n\ngo 1.20\n",
		"main.go":           "package main\nimport \"" + packagePath + "\"\nfunc main(){ callee.InvokeFirst(); callee.InvokeSecond() }\n",
		"callee/body.go":    goSource,
		"callee/body_386.s": assembly,
	} {
		filename := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.WriteFile(filename, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		artifacts[strings.ReplaceAll(name, "/", "-")] = retainInput(filename)
	}
	driver, driverHash := x86LEAActualSDKDriver(t)
	inputHashes[driver] = driverHash
	// This independent ordinary fixture selects its explicit target profile.
	// Keep inherited Windows drive-current-directory entries intact too; the
	// actual env query below verifies the resulting last-value command profile.
	environment := append(append([]string(nil), os.Environ()...), "GOOS=linux", "GOARCH=386", "GO386=sse2", "GOTOOLCHAIN=local",
		"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=", "CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off")
	proof, cancel := runtimeOracleProofContext(t)
	defer cancel()
	run := func(trace bool, arguments ...string) []byte {
		verifyInputs()
		stage, cancel := context.WithTimeout(proof, 2*time.Minute)
		defer cancel()
		observed, err := goasmcmd.Observe(stage, directory, environment, driver, arguments...)
		receipt := commandReceipt{Arguments: append([]string(nil), arguments...), Observation: observed}
		if err != nil {
			receipt.Failure = err.Error()
		}
		commands = append(commands, receipt)
		verifyInputs()
		if err != nil || stage.Err() != nil || !observed.Waited || observed.ExitCode != 0 || !trace && len(observed.Stderr) != 0 {
			t.Fatalf("actual owned Go compile/link command %v: %v\n%s", arguments, err, observed.Stderr)
		}
		return observed.Stdout
	}
	actualJSON := run(false, "env", "-json", "GOROOT", "GOTOOLDIR", "GOVERSION", "GOOS", "GOARCH", "GO386", "GOEXPERIMENT", "GOENV", "GOFLAGS", "GOWORK", "GOTOOLCHAIN", "CGO_ENABLED")
	artifacts["actual-environment.json"] = actualJSON
	var actual map[string]string
	if err := json.Unmarshal(actualJSON, &actual); err != nil || actual["GOVERSION"] != runtime.Version() || actual["GOOS"] != "linux" || actual["GOARCH"] != "386" ||
		actual["GO386"] != "sse2" || actual["GOEXPERIMENT"] != "" || actual["GOENV"] != "" || actual["GOFLAGS"] != "" ||
		actual["GOWORK"] != "off" || actual["GOTOOLCHAIN"] != "local" || actual["CGO_ENABLED"] != "0" || filepath.Join(actual["GOROOT"], "bin", gotoolchain.HostExecutable("go")) != driver {
		t.Fatal("actual selected386 compiler/linker profile differs", err)
	}
	for _, tool := range []string{"asm", "compile", "link"} {
		route := strings.TrimSpace(string(run(false, "tool", "-n", tool)))
		if route != filepath.Join(actual["GOTOOLDIR"], gotoolchain.HostExecutable(tool)) {
			t.Fatal("selected tool route is not the actual SDK tool", tool, route)
		}
		retainInput(route)
	}
	for role, expected := range x86Terminal386CompilerLinkSourcePins {
		data := retainInput(filepath.Join(actual["GOROOT"], filepath.FromSlash(role)))
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != expected {
			t.Fatal("unregistered actual compiler/linker normalization source", role)
		}
		artifacts[strings.ReplaceAll(role, "/", "-")] = data
	}
	builtin := retainInput(filepath.Join(actual["GOROOT"], "src", "cmd", "internal", "goobj", "builtinlist.go"))
	selectionJSON := run(false, "list", "-mod=readonly", "-compiled", "-json", "./callee")
	artifacts["selection.json"] = selectionJSON
	var selected struct {
		ImportPath, Dir                  string
		GoFiles, CompiledGoFiles, SFiles []string
		Imports                          []string
		Standard                         bool
		Module                           *struct{ Path, Dir, GoVersion string }
	}
	if err := json.Unmarshal(selectionJSON, &selected); err != nil || selected.Standard || selected.ImportPath != packagePath || selected.Dir != calleeDirectory ||
		!reflect.DeepEqual(selected.GoFiles, []string{"body.go"}) || !reflect.DeepEqual(selected.SFiles, []string{"body_386.s"}) || len(selected.Imports) != 0 ||
		len(selected.CompiledGoFiles) != 1 || filepath.Base(selected.CompiledGoFiles[0]) != "body.go" ||
		selected.Module == nil || selected.Module.Path != module || selected.Module.Dir != directory || selected.Module.GoVersion != "1.20" {
		t.Fatal("the complete ordinary own-package source selection changed", err)
	}
	fset := token.NewFileSet()
	goFilename, asmFilename := filepath.Join(calleeDirectory, "body.go"), filepath.Join(calleeDirectory, "body_386.s")
	goBytes := read(goFilename)
	syntax, err := parser.ParseFile(fset, goFilename, goBytes, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	sizes := types.SizesFor("gc", actual["GOARCH"])
	typed, err := (&types.Config{Sizes: sizes, GoVersion: "go" + selected.Module.GoVersion}).Check(packagePath, fset, []*ast.File{syntax}, info)
	if err != nil {
		t.Fatal("the actual selected own-package bodies could not be independently typed", err)
	}
	file, err := ParseWithDefines(ArchAMD64, string(read(asmFilename)), GoAssemblerDefinesWithEnv("linux", "386", actual))
	if err != nil || len(file.Funcs) != 2 {
		t.Fatal("the complete original two-TEXT own-package source changed", err)
	}
	pkg := GoPackage{Path: packagePath, Types: typed, Syntax: []*ast.File{syntax}, SourceSelection: &GoSourceSelection{
		Fset: fset, Sizes: sizes, TypesInfo: info, SelectedGoFiles: []string{goFilename}, GoSources: map[string][]byte{goFilename: goBytes},
		SelectedAssemblyFiles: []string{asmFilename}, Assembly: map[string]*File{asmFilename: file}}}
	if declarations, err := x86GoPanicTerminalDeclarations(pkg); err != nil || len(declarations) != 2 {
		t.Fatal("the two arbitrary actual bodies are not precisely noarg Void single builtin-panic declarations", declarations, err)
	}
	displayTool := func(tool string) string {
		// This is the pinned work/shell.go joinUnambiguously argument rule.
		quoted := strconv.Quote(tool)
		if tool == "" || strings.ContainsAny(tool, " ()>;") || len(quoted) > len(tool)+2 {
			return quoted
		}
		return tool
	}
	archiveFile := filepath.Join(directory, "original.a")
	run(true, "build", "-mod=readonly", "-x", "-a", "-buildmode=archive", "-o", archiveFile, "./callee")
	buildTrace := commands[len(commands)-1].Observation.Stderr
	compileRoute := filepath.Join(actual["GOTOOLDIR"], gotoolchain.HostExecutable("compile"))
	if !bytes.Contains(buildTrace, []byte(displayTool(compileRoute)+" -o ")) || !bytes.Contains(buildTrace, []byte(" -p "+packagePath+" ")) {
		t.Fatal("the actual archive build did not execute its selected compiler/package route")
	}
	artifacts["original.a"] = retainInput(archiveFile)
	members, err := gostaticstorage.ObserveX86AssemblyArchive(artifacts["original.a"], builtin, "linux/386", selected.SFiles)
	if err != nil || len(members) != 3 || members[1].Name != "_go_.o" || members[1].Flags != 0 || members[2].Flags != 4 {
		t.Fatal("complete ordinary compiler/ASM archive observation, without -std or SDK permission", err)
	}
	objectFile := filepath.Join(directory, "original.o")
	run(false, "tool", "asm", "-p", packagePath, "-D", "GOOS_linux", "-D", "GOARCH_386", "-D", "GO386_sse2", "-o", objectFile, filepath.Join(calleeDirectory, "body_386.s"))
	artifacts["original.o"] = retainInput(objectFile)
	standalone, err := gostaticstorage.ObserveX86AssemblyText(artifacts["original.o"], builtin, "linux/386")
	if err != nil || len(standalone) != 2 || !reflect.DeepEqual(standalone, members[2].Texts) {
		t.Fatal("complete original standalone/driver-assembled objects differ", err)
	}
	artifacts["complete-original-records.json"], err = json.MarshalIndent(struct {
		Members    []gostaticstorage.TextMember
		Standalone []gostaticstorage.TextRecord
	}{members, standalone}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	linkedFile := filepath.Join(directory, "original-linked.elf")
	run(true, "build", "-mod=readonly", "-x", "-o", linkedFile, ".")
	linkRoute := filepath.Join(actual["GOTOOLDIR"], gotoolchain.HostExecutable("link"))
	if !bytes.Contains(commands[len(commands)-1].Observation.Stderr, []byte(displayTool(linkRoute)+" -o ")) {
		t.Fatal("the actual build did not execute the selected linker")
	}
	artifacts["original-linked.elf"] = read(linkedFile)
	linked, err := elf.NewFile(bytes.NewReader(artifacts["original-linked.elf"]))
	if err != nil {
		t.Fatal(err)
	}
	defer linked.Close()
	if linked.Class != elf.ELFCLASS32 || linked.Machine != elf.EM_386 || linked.Data != elf.ELFDATA2LSB || linked.Type != elf.ET_EXEC {
		t.Fatal("the real linked object is not the selected Linux386 executable")
	}
	symbols, err := linked.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	findSymbol := func(name string) elf.Symbol {
		var matches []elf.Symbol
		for _, symbol := range symbols {
			if symbol.Name == name {
				matches = append(matches, symbol)
			}
		}
		if len(matches) != 1 || elf.ST_TYPE(matches[0].Info) != elf.STT_FUNC {
			t.Fatal("linked function lacks its exact unique native symbol", name, len(matches))
		}
		return matches[0]
	}
	for index, row := range []struct{ caller, callee string }{{"InvokeFirst", "ordinaryFailure"}, {"InvokeSecond", "stopHere"}} {
		t.Run(row.callee, func(t *testing.T) {
			var bodies []gostaticstorage.TextRecord
			for _, body := range members[1].Texts {
				if body.Name == packagePath+"."+row.callee {
					bodies = append(bodies, body)
				}
			}
			if len(bodies) != 1 || bodies[0].ABI != 1 || bodies[0].Kind != 1 || len(bodies[0].Code) == 0 {
				t.Fatal("the original compiler ABIInternal body was absent or replaced with ABI0", bodies)
			}
			caller := standalone[index]
			if caller.Name != packagePath+"."+row.caller || caller.ABI != 0 || len(caller.Relocations) != 1 {
				t.Fatal("the original assembler ABI0 caller or complete relocation inventory changed", caller)
			}
			relocation := caller.Relocations[0]
			if relocation.Type != 7 || relocation.Size != 4 || relocation.Add != 0 || relocation.Offset < 1 || relocation.Offset+4 > int64(len(caller.Code)) ||
				caller.Code[relocation.Offset-1] != 0xe8 || relocation.Target.Name != bodies[0].Name || !relocation.Target.ABIKnown || relocation.Target.ABI != 0 {
				t.Fatal("the original complete noarg CALL lacks its genuine ABI0 relocation", relocation)
			}
			callerSymbol, bodySymbol := findSymbol(caller.Name), findSymbol(bodies[0].Name)
			if int(callerSymbol.Section) >= len(linked.Sections) || callerSymbol.Size != uint64(len(caller.Code)) {
				t.Fatal("linked caller extent or section differs from the original object")
			}
			section := linked.Sections[callerSymbol.Section]
			data, err := section.Data()
			start := callerSymbol.Value - section.Addr
			if err != nil || callerSymbol.Value < section.Addr || start > uint64(len(data)) || callerSymbol.Size > uint64(len(data))-start {
				t.Fatal("linked caller bytes lack their actual complete section extent", err)
			}
			code := data[start : start+callerSymbol.Size]
			offset := int(relocation.Offset)
			target := int64(callerSymbol.Value) + relocation.Offset + 4 + int64(int32(binary.LittleEndian.Uint32(code[offset:offset+4])))
			if target < 0 || uint64(target) != bodySymbol.Value || !bytes.Equal(code[:offset], caller.Code[:offset]) || !bytes.Equal(code[offset+4:], caller.Code[offset+4:]) {
				t.Fatal("actual linker did not resolve the ABI0 CALL to its distinct observed ABI1 Go body", target, bodySymbol.Value)
			}
			t.Logf("original compiler ABI=%d ASM caller ABI=%d CALL reference ABI=%d actual linked target=%#x; compile/link only, runtime unexecuted",
				bodies[0].ABI, caller.ABI, relocation.Target.ABI, bodySymbol.Value)
		})
	}
	verifyInputs()
}
