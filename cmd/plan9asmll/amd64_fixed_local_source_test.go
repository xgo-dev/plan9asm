package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestAMD64FixedLocalSourceRoleQueryDoesNotBindSymbols(t *testing.T) {
	pkg := &packages.Package{PkgPath: "example.invalid/query"}
	forward := "CALL ·Callee(SB)\nMOVQ 0(SP),AX\nMOVQ AX,ret+0(FP)\nRET"
	floatForward := "CALL ·Callee(SB)\nMOVSD 0(SP),X0\nMOVSD X0,ret+0(FP)\nRET"
	for _, test := range []struct {
		name, symbol, body string
		result             plan9asm.LLVMType
		forwarder          bool
	}{
		{"complete outgoing", "·Caller", forward, plan9asm.I64, true},
		{"escaped package name", "example.invalid∕query·Caller", forward, plan9asm.I64, true},
		{"linked caller needs binding", "·CallerAlias", forward, plan9asm.I64, false},
		{"linked callee needs binding", "·Caller", strings.Replace(forward, "·Callee", "·CalleeAlias", 1), plan9asm.I64, false},
		{"private without call", "·Caller", "MOVQ $1,0(SP)\nRET", plan9asm.I64, false},
		{"private with call", "·Caller", strings.Replace(forward, "RET", "MOVQ $1,0(SP)\nRET", 1), plan9asm.I64, false},
		// These scalar-lane sources already use the original untyped route.
		{"legacy float linked caller", "·CallerAlias", floatForward, "double", true},
		{"legacy float linked callee", "·Caller", strings.Replace(floatForward, "·Callee", "·CalleeAlias", 1), "double", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sigs := make(map[string]plan9asm.FuncSig)
			resultType := types.Typ[types.Uint64]
			if test.result == "double" {
				resultType = types.Typ[types.Float64]
			}
			for _, name := range []string{"Caller", "Callee", "linkedCaller", "linkedCallee"} {
				resolved := pkg.PkgPath + "." + name
				declaration := types.NewFunc(0, nil, name, types.NewSignatureType(nil, nil, nil, nil,
					types.NewTuple(types.NewVar(0, nil, "", resultType)), false))
				sig, err := plan9asm.DeriveGoFuncABI0Signature(resolved, declaration, "amd64", types.SizesFor("gc", "amd64"))
				if err != nil {
					t.Fatal(err)
				}
				sigs[resolved] = sig
			}
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT "+test.symbol+"(SB),4,$8-8\n"+test.body+"\n")
			if err != nil {
				t.Fatal(err)
			}
			if !test.forwarder && !plan9asm.GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
				t.Fatal("negative control does not require the original private-frame candidate")
			}
			if test.result == "double" && plan9asm.GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
				t.Fatal("legacy scalar-lane control lost its original untyped route")
			}
			calls := 0
			resolve := func(name string) string {
				calls++
				name = strings.Replace(name, "CallerAlias", "linkedCaller", 1)
				name = strings.Replace(name, "CalleeAlias", "linkedCallee", 1)
				return resolveSymFunc(pkg.PkgPath)(name)
			}
			bound, source, err := prepareAMD64FixedLocalSource(pkg, file, "", "linux/amd64",
				targetTriple("linux", "amd64"), "amd64", compileConfig{}, resolve, sigs, nil)
			if calls != 0 {
				t.Fatalf("source-role query invoked the binding callback %d times before source capture", calls)
			}
			if source != nil {
				t.Fatal("query created an uncaptured source owner")
			}
			if test.forwarder {
				if err != nil || !reflect.DeepEqual(bound, sigs) {
					t.Fatalf("complete outgoing source lost its existing route: %v", err)
				}
			} else if bound != nil || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("uncaptured private source acquired authority: %v", err)
			}
		})
	}
}

// The original numeric ABI0 fixture has a real automatic Go frame, explicit
// complete initialization and restoration. Its local addresses are neither
// incoming slice extents nor contiguous virtual FP shadow storage.
func amd64FixedLocalCLIAssembly(operation string) string {
	return fmt.Sprintf(`#include "textflag.h"
TEXT ·Value(SB),NOSPLIT,$160-40
MOVQ a+0(FP),AX
MOVQ b+8(FP),CX
MOVQ c+16(FP),DX
MOVQ d+24(FP),BX
MOVQ SP,R11
MOVQ $31,R9
NOTQ R9
ANDQ R9,SP
ADDQ $32,SP
MOVQ R11,96(SP)
MOVQ AX,16(SP)
MOVQ CX,24(SP)
MOVQ DX,48(SP)
MOVQ BX,56(SP)
MOVOU 48(SP),X0
%s
MOVQ X0,AX
MOVQ 96(SP),R11
MOVQ R11,SP
MOVQ AX,ret+32(FP)
RET
`, operation)
}

func amd64FixedLocalCLIFixture(t *testing.T, operation string) (*packages.Package, string, compileConfig) {
	t.Helper()
	return amd64FixedLocalCLICompleteFixture(t, operation,
		"package fixedlocal\nfunc Value(a, b, c, d uint64) uint64\n")
}

func amd64FixedLocalCLICompleteFixture(t *testing.T, operation, declaration string) (*packages.Package, string, compileConfig) {
	t.Helper()
	return amd64FixedLocalCLISourceFixture(t, amd64FixedLocalCLIAssembly(operation), declaration)
}

func amd64FixedLocalCLISourceFixture(t *testing.T, assembly, declaration string) (*packages.Package, string, compileConfig) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"go.mod":        "module example.invalid/fixedlocal\n\ngo 1.20\n",
		"value.go":      declaration,
		"value_amd64.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOENV", "off")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOEXPERIMENT", "")
	t.Setenv("GOAMD64", "v1")
	// test2json may export the host's CPU settings to the test binary.
	// This fixture explicitly selects linux/amd64, so no inactive target's
	// CPU setting belongs in its original compiler observation.
	for _, key := range []string{"GO386", "GOARM", "GOARM64", "GOWASM"} {
		t.Setenv(key, "")
	}
	t.Setenv("GOPACKAGESDRIVER", "off")
	for _, key := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(os.Getenv(key)) {
			path, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv(key, path)
		}
	}
	ctx := arm64PrivateCLIContext(t)
	env := append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	pkgs, err := packages.Load(&packages.Config{
		Context: ctx, Dir: dir, Env: env,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedModule | packages.NeedDeps | packages.NeedImports |
			packages.NeedTypes | packages.NeedTypesSizes,
	}, ".")
	if err != nil || len(pkgs) != 1 || len(pkgs[0].Errors) != 0 {
		t.Fatalf("actual original selection: %v; %+v", err, pkgs)
	}
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = ctx
	config.x86CallerSelections = captureX86CallerSelectionsInEnvironment(pkgs, "linux/amd64", env)
	input := filepath.Join(dir, "value_amd64.s")
	// Bind the independent actual Go prologue/object before asserting the CLI.
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, "go",
		"list", "-export", "-compiled", "-mod=readonly", "-json", ".")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual original export: %v\n%s%s", err, stdout, stderr)
	}
	t.Logf("original source SHA=%x; actual Go export:\n%s", sha256.Sum256([]byte(assembly)), stdout)
	return pkgs[0], input, config
}

func TestCompileOneAMD64FixedLocalCompleteOrdinaryGoSource(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{"body", "func Reference(a uint64) uint64 { return a + 1 }\n"},
		{"values", "const Bias uint64 = 7\nvar Counter uint64\n"},
		{"sdk-import", "import \"math/bits\"\nfunc Reference(a uint64) uint64 { return bits.RotateLeft64(a, 7) }\n"},
		{"combined", "import \"math/bits\"\nconst Bias uint64 = 7\nvar Counter uint64\n" +
			"func Reference(a uint64) uint64 { return bits.RotateLeft64(a + Bias + Counter, 7) }\n"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			declaration := "package fixedlocal\n" + fixture.source + "func Value(a, b, c, d uint64) uint64\n"
			pkg, input, config := amd64FixedLocalCLICompleteFixture(t, "PADDL 16(SP),X0", declaration)
			output := filepath.Join(t.TempDir(), "complete.ll")
			if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatalf("actual original Go export succeeded but complete-source CLI failed: %v", err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || !strings.Contains(string(ir), "fixed_local_native") || !strings.Contains(string(ir), "asm sideeffect") {
				t.Fatalf("complete original source lost sealed native storage: %v", err)
			}
			if info, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o"); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatalf("complete original-source LLVM22 object missing: %v", err)
			}
		})
	}
}

func TestRunOneTargetFixedLocalWithDefaultCacheEnvironment(t *testing.T) {
	pkg, _, config := amd64FixedLocalCLIFixture(t, "PADDL 16(SP),X0")
	// The existing direct compileOne fixtures supply every environment key.
	// An ordinary CLI invocation does not: its loader must resolve these
	// defaults before capturing the selection, not repair them afterward.
	// Keep the fixture's explicit GOENV=off and CGO_ENABLED=0. A source proof
	// cannot silently replace saved user settings or a native cgo profile.
	for _, key := range []string{"GOWORK", "GOTOOLCHAIN", "GOCACHE", "GOMODCACHE", "GOPATH", "GOTMPDIR"} {
		t.Setenv(key, "")
	}
	t.Chdir(pkg.Dir)
	report, _, err := runOneTarget(targetSpec{Goos: "linux", Goarch: "amd64"},
		[]string{"."}, nil, nil, pkg.Module.Path, t.TempDir(), false, 0, false,
		false, true, "", config)
	if err != nil || report.TotalAsm != 1 || report.Success != 1 || report.Failed != 0 {
		t.Fatalf("ordinary actual-load/frame environment differs: %v; %+v", err, report)
	}
}

func TestRunOneTargetFixedLocalWithFreshModuleCache(t *testing.T) {
	pkg, _, config := amd64FixedLocalCLIFixture(t, "PADDL 16(SP),X0")
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A pure-Go local package need not cause cmd/go to create GOPATH or its
	// default module cache. The ordinary CLI must prepare them before capture.
	path := filepath.Join(parent, "fresh-gopath")
	t.Setenv("GOPATH", path)
	t.Setenv("GOMODCACHE", "")
	t.Chdir(pkg.Dir)
	report, _, err := runOneTarget(targetSpec{Goos: "linux", Goarch: "amd64"},
		[]string{"."}, nil, nil, pkg.Module.Path, t.TempDir(), false, 0, false,
		false, true, "", config)
	if err != nil || report.TotalAsm != 1 || report.Success != 1 || report.Failed != 0 {
		t.Fatalf("fresh actual-load/frame cache environment differs: %v; %+v", err, report)
	}
}

func TestAMD64FixedLocalCompleteSourceRetainsActualLoadIdentity(t *testing.T) {
	for _, axis := range []string{"dependency-types", "missing-dependency", "extra-captured-import", "target", "source-bytes"} {
		t.Run(axis, func(t *testing.T) {
			declaration := "package fixedlocal\nimport \"math/bits\"\n" +
				"func Reference(a uint64) uint64 { return bits.RotateLeft64(a, 7) }\n" +
				"func Value(a, b, c, d uint64) uint64\n"
			pkg, input, config := amd64FixedLocalCLICompleteFixture(t, "PADDL 16(SP),X0", declaration)
			file, err := plan9asm.Parse(plan9asm.ArchAMD64,
				strings.Replace(amd64FixedLocalCLIAssembly("PADDL 16(SP),X0"), "#include \"textflag.h\"", "#define NOSPLIT 4", 1))
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(name string) string { return strings.Replace(name, "·", pkg.PkgPath+".", 1) }
			sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			_, source, err := prepareAMD64FixedLocalSource(pkg, file, input, "linux/amd64",
				"x86_64-unknown-linux-gnu", "amd64", config, resolve, sigs, nil)
			if err != nil || source == nil {
				t.Fatalf("actual original full-source binding failed: %v", err)
			}
			defer func() {
				if err := source.close(); err != nil {
					t.Error(err)
				}
			}()
			switch axis {
			case "dependency-types":
				pkg.Imports["math/bits"].Types = types.NewPackage("math/bits", "bits")
			case "missing-dependency":
				pkg.Imports["math/bits"] = nil
			case "extra-captured-import":
				config.x86CallerSelections[pkg].imports["unselected"] = types.NewPackage("unselected", "unselected")
			case "target":
				config.x86CallerSelections[pkg].target = "darwin/amd64"
			case "source-bytes":
				if err := os.WriteFile(filepath.Join(filepath.Dir(input), "value.go"),
					[]byte(strings.Replace(declaration, "a, 7", "a, 9", 1)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := source.verify(config.Context); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("changed actual-load %s retained the full-source binding: %v", axis, err)
			}
			if err := source.binding.Verify(config.Context); err == nil {
				t.Fatal("failed actual-load verification did not revoke its independent frame binding")
			}
		})
	}
}

func TestCompileOneAMD64FixedLocalOriginalSource(t *testing.T) {
	for _, operation := range []string{
		"PADDB 16(SP),X0", "PADDW 16(SP),X0", "PADDL 16(SP),X0", "PADDQ 16(SP),X0",
		"PMADDWL 16(SP),X0", "CMPPS 16(SP),X0,$0", "CMPPD 16(SP),X0,$0",
	} {
		t.Run(strings.Fields(operation)[0], func(t *testing.T) {
			pkg, input, config := amd64FixedLocalCLIFixture(t, operation)
			output := filepath.Join(t.TempDir(), "local.ll")
			if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatalf("complete original numeric local frame has no CLI consumer: %v", err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || !strings.Contains(string(ir), "fixed_local_native") || !strings.Contains(string(ir), "asm sideeffect") {
				t.Fatalf("original local source was not consumed by sealed native storage: %v", err)
			}
			if info, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o"); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatalf("LLVM22 original-source object missing: %v", err)
			}
		})
	}
}

func TestParseCompleteCLIAssemblyKeepsSourceRoles(t *testing.T) {
	const body = "MOVQ   a+0(FP), AX\nMOVOU   0(SP), X0\nlabel:\nMOVQ X0, AX\nRET\n"
	const data = "DATA literal<>+0(SB)/8, $7\nGLOBL literal<>(SB), 8, $8\n"
	defines := plan9asm.GoAssemblerDefines("linux", "amd64")
	for _, frame := range []string{"0", "32"} {
		source := "TEXT ·Value(SB), 4, $" + frame + "-8\n" + body + data
		legacy, err := plan9asm.ParseWithDefines(plan9asm.ArchAMD64, source, defines)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := parseCompleteCLIAssembly(plan9asm.ArchAMD64, source, defines, "amd64", nil)
		if err != nil {
			t.Fatal(err)
		}
		want := legacy
		if frame == "32" {
			expanded, err := plan9asm.PreprocessAssemblySource(source, plan9asm.AssemblyPreprocessOptions{Defines: defines})
			if err != nil {
				t.Fatal(err)
			}
			want, err = plan9asm.Parse(plan9asm.ArchAMD64, expanded)
			if err != nil {
				t.Fatal(err)
			}
			if want.Funcs[0].Instrs[1].Raw == legacy.Funcs[0].Instrs[1].Raw {
				t.Fatal("fixture did not distinguish historical and canonical CPP spelling")
			}
		}
		gotJSON, err := json.Marshal(actual)
		if err != nil {
			t.Fatal(err)
		}
		wantJSON, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if string(gotJSON) != string(wantJSON) || len(actual.Funcs[0].Instrs) != 6 || len(actual.Data) != 1 || len(actual.Globl) != 1 {
			t.Fatalf("frame=%s changed its complete source representation", frame)
		}
	}
	missing := "#include \"go_asm.h\"\nTEXT ·Value(SB),4,$32-8\n" + body
	if file, err := parseCompleteCLIAssembly(plan9asm.ArchAMD64, missing, defines, "amd64", nil); err == nil || file != nil {
		t.Fatal("unresolved active include was silently discarded", err)
	}
}

func TestParseCompleteCLIAssemblySelectedGeneratedHeader(t *testing.T) {
	const source = `#include "textflag.h"
#include "go_asm.h"
TEXT ·Value(SB),NOSPLIT,$32-16
MOVQ a+0(FP),AX
MOVQ AX,0(SP)
#ifdef const_Offset
MOVQ $const_Offset,CX
#else
MOVQ $0,CX
#endif
#ifdef Layout__size
MOVQ $Layout__size,BX
MOVQ $Layout_Value,DX
#else
MOVQ $0,BX
MOVQ $0,DX
#endif
#ifdef const_Fraction
MOVQ $1,BX
#endif
MOVQ AX,ret+8(FP)
RET
`
	declaration := "package fixedlocal\nconst Offset = 16\nconst Fraction = 0.5\n" +
		"type Layout struct { First uint8; Value uint64 }\nfunc Value(a uint64) uint64\n"
	// Go's initial -gensymabis pass uses an empty bootstrap header. Keep its
	// fallback legal; the final complete CPP must select the nonzero values.
	pkg, input, _ := amd64FixedLocalCLISourceFixture(t, source, declaration)
	read, err := readAsmSource(input, pkg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	selected := plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types}
	expanded := plan9asm.ExpandGoAssemblySource(selected, read, "amd64")
	defines := plan9asm.GoAssemblerDefines("linux", "amd64")
	actual, err := parseCompleteCLIAssembly(plan9asm.ArchAMD64, string(expanded), defines, "amd64", &selected)
	if err != nil {
		t.Fatal("actual original Go export succeeded but complete CPP failed", err)
	}
	wantSource := "TEXT ·Value(SB),4,$32-16\nMOVQ a+0(FP),AX\nMOVQ AX,0(SP)\n" +
		"MOVQ $16,CX\nMOVQ $16,BX\nMOVQ $8,DX\nMOVQ AX,ret+8(FP)\nRET\n"
	wantCPP, err := plan9asm.PreprocessAssemblySource(wantSource, plan9asm.AssemblyPreprocessOptions{Defines: defines})
	if err != nil {
		t.Fatal(err)
	}
	want, err := plan9asm.Parse(plan9asm.ArchAMD64, wantCPP)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("constant presence, struct size or field offset changed: %+v\nwant %+v", actual, want)
	}
	for _, name := range []string{"./go_asm.h", "../go_asm.h", "missing.h"} {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(string(expanded), "\"go_asm.h\"", strconv.Quote(name), 1)
			if file, err := parseCompleteCLIAssembly(plan9asm.ArchAMD64, changed, defines, "amd64", &selected); err == nil || file != nil {
				t.Fatal("generated-header resolver acquired another include identity", err)
			}
		})
	}
}

func TestCompileOneAMD64FixedLocalDoesNotHijackOrdinaryNativeSources(t *testing.T) {
	for _, variant := range []string{"static-data", "incoming-native"} {
		t.Run(variant, func(t *testing.T) {
			_, input, config := amd64FixedLocalCLIFixture(t, "PADDL 16(SP),X0")
			directory := filepath.Dir(input)
			declaration := "package fixedlocal\nfunc Value(p *[4]uint32) uint64\n"
			assembly := "#include \"textflag.h\"\nTEXT ·Value(SB),NOSPLIT,$16-16\n" +
				"MOVQ p+0(FP),AX\nPXOR X0,X0\nPADDL (AX),X0\nMOVQ X0,AX\nMOVQ AX,ret+8(FP)\nRET\n"
			if variant == "static-data" {
				declaration = "package fixedlocal\nfunc Value(p uint64) uint64\n"
				assembly = strings.Replace(assembly, "PADDL (AX),X0", "PADDL constant<>(SB),X0", 1)
				assembly += "DATA constant<>+0(SB)/8,$1\nDATA constant<>+8(SB)/8,$2\nGLOBL constant<>(SB),RODATA|NOPTR,$16\n"
			}
			for name, contents := range map[string]string{"value.go": declaration, "value_amd64.s": assembly} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			env := append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
			stdout, stderr, err := gotoolprofile.RunBounded(config.Context, directory, env, "go",
				"list", "-export", "-compiled", "-mod=readonly", "-json", ".")
			if err != nil || len(stderr) != 0 {
				t.Fatalf("actual ordinary source/export: %v\n%s%s", err, stdout, stderr)
			}
			pkgs, err := packages.Load(&packages.Config{Context: config.Context, Dir: directory, Env: env,
				Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedModule |
					packages.NeedDeps | packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes}, ".")
			if err != nil || len(pkgs) != 1 || len(pkgs[0].Errors) != 0 {
				t.Fatalf("actual ordinary selected package: %v; %+v", err, pkgs)
			}
			config.x86CallerSelections = captureX86CallerSelections(pkgs, "linux/amd64", nil)
			output := filepath.Join(t.TempDir(), "ordinary.ll")
			if err := compileOne(pkgs[0], plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatalf("ordinary native operand was hijacked by narrow local source factory: %v", err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || strings.Contains(string(ir), "fixed_local_native") {
				t.Fatalf("unrelated operand acquired local backing: %v", err)
			}
			if info, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o"); err != nil || info.Size() == 0 {
				t.Fatalf("ordinary LLVM22 object absent: %v", err)
			}
		})
	}
}

func TestAMD64FixedLocalActualOrdinaryCLIEntry(t *testing.T) {
	_, input, config := amd64FixedLocalCLIFixture(t, "PADDL 16(SP),X0")
	output := t.TempDir()
	report := filepath.Join(t.TempDir(), "report.json")
	args := []string{"-targets=linux/amd64", "-patterns=.", "-module-path=example.invalid/fixedlocal",
		"-compile", "-keep-obj", "-out=" + output, "-report=" + report}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "PLAN9ASM_CPUCLI_ARGS="+string(encoded))
	stdout, stderr, err := gotoolprofile.RunBounded(config.Context, filepath.Dir(input), env,
		os.Args[0], "-test.run=^TestFeatureConsumerCLIChild$")
	if err != nil {
		t.Fatalf("actual ordinary CLI entry did not consume original backing: %v\n%s%s", err, stdout, stderr)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded matrixReport
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.Success != 1 || decoded.Failed != 0 ||
		decoded.NotApplicable != 0 || decoded.TotalAsm != 1 || decoded.TotalTargets != 1 {
		t.Fatalf("actual complete ordinary CLI result differs: %v\n%s", err, data)
	}
}

func TestAMD64FixedLocalOrdinaryCLIDeadlineCannotMintObjects(t *testing.T) {
	for _, timeout := range []string{"0", "1ns"} {
		t.Run(timeout, func(t *testing.T) {
			_, input, config := amd64FixedLocalCLIFixture(t, "PADDL 16(SP),X0")
			output := t.TempDir()
			args := []string{"-targets=linux/amd64", "-patterns=.", "-module-path=example.invalid/fixedlocal",
				"-compile", "-keep-obj", "-out=" + output, "-feature-timeout=" + timeout}
			encoded, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			env := append(os.Environ(), "PLAN9ASM_CPUCLI_ARGS="+string(encoded))
			stdout, stderr, err := gotoolprofile.RunBounded(config.Context, filepath.Dir(input), env,
				os.Args[0], "-test.run=^TestFeatureConsumerCLIChild$")
			if err == nil {
				t.Fatalf("expired/unbounded ordinary source context minted an object:\n%s%s", stdout, stderr)
			}
			if err := filepath.WalkDir(output, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.IsDir() && (filepath.Ext(path) == ".ll" || filepath.Ext(path) == ".o") {
					return fmt.Errorf("invalid context emitted %s", path)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCompileOneAMD64FixedLocalSourceRejectsUnprovedInputs(t *testing.T) {
	for _, axis := range []string{"missing-selection", "wrong-target", "changed-selection", "flags", "experiment", "CGO", "expired", "nil-context", "unbounded-context",
		"missing-byte", "unknown-call", "loop", "result-address", "composite"} {
		t.Run(axis, func(t *testing.T) {
			pkg, input, config := amd64FixedLocalCLIFixture(t, "PADDL 16(SP),X0")
			selected := config.x86CallerSelections[pkg]
			source := amd64FixedLocalCLIAssembly("PADDL 16(SP),X0")
			switch axis {
			case "missing-selection":
				config.x86CallerSelections = nil
			case "wrong-target":
				selected.target = "darwin/amd64"
			case "changed-selection":
				pkg.Name = "changed"
			case "flags":
				selected.env = append(selected.env, "GOFLAGS=-tags=unclosed")
			case "experiment":
				selected.env = append(selected.env, "GOEXPERIMENT=arenas")
			case "CGO":
				selected.env = append(selected.env, "CGO_ENABLED=1")
			case "expired":
				ctx, cancel := context.WithCancel(config.Context)
				cancel()
				config.Context = ctx
			case "nil-context":
				config.Context = nil
			case "unbounded-context":
				config.Context = context.Background()
			case "missing-byte":
				source = strings.Replace(source, "MOVQ CX,24(SP)\n", "", 1)
			case "unknown-call":
				source = strings.Replace(source, "PADDL 16(SP),X0", "CALL runtime·Gosched(SB)\nPADDL 16(SP),X0", 1)
			case "loop":
				source = strings.Replace(source, "PADDL 16(SP),X0", "again:\nPADDL 16(SP),X0\nJMP again", 1)
			case "result-address":
				source = strings.Replace(source, "MOVQ X0,AX", "MOVQ SP,AX", 1)
			case "composite":
				// The old selected integer types remain deliberately stale.
				// Actual independent declaration capture must reject the change.
				if err := os.WriteFile(filepath.Join(filepath.Dir(input), "value.go"), []byte("package fixedlocal\nfunc Value(a *uint64,b,c,d uint64) uint64\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(input, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "unbound.ll")
			err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config)
			if err == nil {
				t.Fatal("unproved numeric/source/native contract emitted an object")
			}
			// Infra/context failures are both strict nonpass; source-mutated
			// caller capabilities must never be recovered from frame size.
			if axis == "missing-byte" || axis == "result-address" || axis == "composite" {
				if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("expected sealed source Context, got %v", err)
				}
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("rejected source emitted LLVM: %v", err)
			}
		})
	}
}

func TestCompileOneAMD64FixedLocalWholeFileCannotSplitCertificate(t *testing.T) {
	pkg, input, config := amd64FixedLocalCLIFixture(t, "PADDL 16(SP),X0")
	config.KeepObj = false
	config.MaxFunctions, config.MaxInstructions = 1, 1
	output := filepath.Join(t.TempDir(), "complete.ll")
	if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(data), "fixed_local_native") {
		t.Fatalf("complete bound source disappeared: %v", err)
	}
	if files, err := filepath.Glob(strings.TrimSuffix(output, ".ll") + ".part-*.ll"); err != nil || len(files) != 0 {
		t.Fatalf("complete-file source was split: %v %v", files, err)
	}
	if _, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o"); !os.IsNotExist(err) {
		t.Fatalf("owned validation object was not released: %v", err)
	}
}
