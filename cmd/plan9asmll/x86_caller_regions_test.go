package main

import (
	"context"
	"encoding/json"
	"errors"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

const x86CallerCLISource = `package caller
import "unsafe"

//go:noescape
func kernel(a, b, res, length unsafe.Pointer)

func Call(x, y []uint64) uint32 {
	var res uint32
	length := len(x)
	kernel(
		unsafe.Pointer(unsafe.SliceData(x)),
		unsafe.Pointer(unsafe.SliceData(y)),
		unsafe.Pointer(&res),
		unsafe.Pointer(&length))
	return res
}
`

const x86CallerCLIAssembly = `TEXT ·kernel(SB),4,$0-32
MOVQ a+0(FP),DI
MOVQ b+8(FP),SI
MOVQ res+16(FP),DX
MOVQ length+24(FP),CX
BYTE $0x55
WORD $0x8948
BYTE $0xe5
LONG $0xf8e48348
MOVL (DI),AX
ADDL $7,AX
MOVL AX,(DX)
WORD $0x8948
BYTE $0xec
BYTE $0x5d
BYTE $0xc3
`

func x86CallerCLIFixture(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"go.mod":    "module example.com/caller\n\ngo 1.20\n",
		"caller.go": x86CallerCLISource, "kernel_amd64.s": x86CallerCLIAssembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestX86CallerCLIActualSelectedPackage(t *testing.T) {
	dir := x86CallerCLIFixture(t)
	t.Chdir(dir)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOMAXPROCS", "2")
	config, err := resolveCompileConfig(true, "", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			output := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			originalObject := filepath.Join(output, "original-go.o")
			actualEnv := append(os.Environ(), "GOOS="+goos, "GOARCH=amd64")
			if stdout, stderr, err := gotoolprofile.RunBounded(ctx, dir, actualEnv, "go", "tool", "asm",
				"-p", "example.com/caller", "-o", originalObject, filepath.Join(dir, "kernel_amd64.s")); err != nil {
				t.Fatalf("actual Go object: %v\n%s\n%s", err, stdout, stderr)
			}
			if info, err := os.Stat(originalObject); err != nil || info.Size() == 0 {
				t.Fatalf("actual Go assembler produced no object: %v", err)
			}
			report, tasks, err := runOneTarget(targetSpec{Goos: goos, Goarch: "amd64"},
				[]string{"."}, nil, nil, "example.com/caller", output,
				false, 0, true, false, true, "", config)
			if err != nil || report.TotalAsm != 1 || report.Success != 1 || report.Failed != 0 || report.NotApplicable != 0 {
				t.Fatalf("actual selected caller did not reach LLVM object: %+v, %v", report, err)
			}
			for _, task := range tasks {
				object := strings.TrimSuffix(task.OutLL, ".ll") + ".o"
				info, err := os.Stat(object)
				if err != nil || info.Size() == 0 {
					t.Fatalf("missing actual LLVM object: %v", err)
				}
			}
		})
	}
}

func x86CallerCLILoad(t *testing.T, extra map[string]string) (*packages.Package, *plan9asm.File, compileConfig) {
	t.Helper()
	dir := x86CallerCLIFixture(t)
	for name, source := range extra {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOMAXPROCS", "2")
	pkgs, err := loadPkgs("linux", "amd64", []string{"."}, nil, "example.com/caller", true, false)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("actual package load: %v, packages=%d", err, len(pkgs))
	}
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, x86CallerCLIAssembly)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return pkgs[0], file, compileConfig{
		Context: ctx, x86CallerSelections: captureX86CallerSelections(pkgs, "linux/amd64", nil),
	}
}

func TestX86CallerCLIRejectsAlteredActualLoadAndMissingSources(t *testing.T) {
	for _, change := range []string{
		"missing Go", "missing ASM", "wrong sizes", "missing sizes", "wrong role",
		"module identity", "package types identity", "import types", "unknown effective role", "missing actual snapshot",
	} {
		t.Run(change, func(t *testing.T) {
			pkg, file, config := x86CallerCLILoad(t, map[string]string{
				"extra.go":      "package caller\nvar marker = 7\n",
				"other_amd64.s": "TEXT ·other(SB),4,$0-0\nRET\n",
			})
			resolve := resolveSymFunc(pkg.PkgPath)
			sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "missing Go":
				pkg.CompiledGoFiles = pkg.CompiledGoFiles[:1]
			case "missing ASM":
				pkg.OtherFiles = pkg.OtherFiles[:1]
			case "wrong sizes":
				pkg.TypesSizes = types.SizesFor("gc", "386")
			case "missing sizes":
				pkg.TypesSizes = nil
			case "wrong role":
				pkg.ID += " [example.com/caller.test]"
			case "module identity":
				pkg.Module.Path += "/changed"
			case "package types identity":
				pkg.Types = types.NewPackage(pkg.PkgPath, pkg.Name)
			case "import types":
				pkg.Imports["unsafe"].Types = types.NewPackage("unsafe", "unsafe")
			case "unknown effective role":
				config.x86CallerSelections[pkg].ready = false
			case "missing actual snapshot":
				config.x86CallerSelections = nil
			}
			_, _, err = bindX86CallerRegions(pkg, file, "linux/amd64", "amd64",
				filepath.Join(pkg.Dir, "kernel_amd64.s"), plan9asm.GoAssemblerDefines("linux", "amd64"), config, resolve, sigs)
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("changed %s obtained actual caller authority: %v", change, err)
			}
		})
	}
}

func TestX86CallerCLIRejectsActualSourceAndAssemblyExposures(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"Go value":    {"extra.go": "package caller\nvar exposed = kernel\n"},
		"Go alias":    {"caller.go": strings.Replace(x86CallerCLISource, "return res", "_ = &res\nreturn res", 1)},
		"ASM call":    {"other_amd64.s": "TEXT ·other(SB),4,$0-0\nCALL ·kernel(SB)\nRET\n"},
		"ASM address": {"other_amd64.s": "TEXT ·other(SB),4,$0-0\nLEAQ ·kernel(SB),AX\nRET\n"},
	} {
		t.Run(name, func(t *testing.T) {
			pkg, file, config := x86CallerCLILoad(t, extra)
			resolve := resolveSymFunc(pkg.PkgPath)
			sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = bindX86CallerRegions(pkg, file, "linux/amd64", "amd64",
				filepath.Join(pkg.Dir, "kernel_amd64.s"), plan9asm.GoAssemblerDefines("linux", "amd64"), config, resolve, sigs)
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("actual %s exposure acquired caller-region proof: %v", name, err)
			}
		})
	}
}

func TestX86CallerCLIGuardsSourcesThroughFinalObject(t *testing.T) {
	for _, change := range []string{"Go bytes", "ASM bytes", "CPP include"} {
		t.Run(change, func(t *testing.T) {
			assembly := strings.Replace(x86CallerCLIAssembly, "ADDL $7,AX", "ADDL $BIAS,AX", 1)
			assembly = "#include \"bias.h\"\n" + assembly
			pkg, _, config := x86CallerCLILoad(t, map[string]string{
				"kernel_amd64.s": assembly, "bias.h": "#define BIAS 7\n",
			})
			asm := filepath.Join(pkg.Dir, "kernel_amd64.s")
			defines := plan9asm.GoAssemblerDefines("linux", "amd64")
			source, err := x86CallerAssemblySource(pkg, asm, defines, nil)
			if err != nil {
				t.Fatal(err)
			}
			file, err := plan9asm.ParseWithDefines(plan9asm.ArchAMD64, string(source), defines)
			if err != nil {
				t.Fatal(err)
			}
			resolve := resolveSymFunc(pkg.PkgPath)
			sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			_, loaded, err := bindX86CallerRegions(pkg, file, "linux/amd64", "amd64", asm, defines, config, resolve, sigs)
			if err != nil || loaded == nil {
				t.Fatalf("unchanged actual source failed: %v", err)
			}
			filename, replacement := "caller.go", x86CallerCLISource+"\n// changed\n"
			if change == "ASM bytes" {
				filename, replacement = "kernel_amd64.s", assembly+"\n// changed\n"
			}
			if change == "CPP include" {
				filename, replacement = "bias.h", "#define BIAS 8\n"
			}
			if err := os.WriteFile(filepath.Join(pkg.Dir, filename), []byte(replacement), 0600); err != nil {
				t.Fatal(err)
			}
			if err := loaded.verify(config.Context, defines, nil); err == nil {
				t.Fatalf("changed %s survived final source guard", change)
			}
		})
	}
}

func TestX86CallerCLINonCandidateDoesNotLoadSyntax(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT ·ordinary(SB),4,$0-0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{
		PkgPath: "example.com/caller", CompiledGoFiles: []string{"absent.go"}, OtherFiles: []string{"absent.s"},
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs := map[string]plan9asm.FuncSig{"example.com/caller.ordinary": {
		Name: "example.com/caller.ordinary", Ret: plan9asm.Void,
	}}
	bound, loaded, err := bindX86CallerRegions(pkg, file, "linux/amd64", "amd64", "absent.s", nil,
		compileConfig{}, resolve, sigs)
	if err != nil || loaded != nil || len(bound) != 1 {
		t.Fatalf("ordinary function unnecessarily loaded missing sources: %v", err)
	}
}

func TestX86CallerCLIRechecksActualStandardDependencyTypes(t *testing.T) {
	pkg, file, config := x86CallerCLILoad(t, map[string]string{
		"extra.go": "package caller\nimport \"math\"\nvar marker = math.Float32bits(0)\n",
	})
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	_, loaded, err := bindX86CallerRegions(pkg, file, "linux/amd64", "amd64",
		filepath.Join(pkg.Dir, "kernel_amd64.s"), plan9asm.GoAssemblerDefines("linux", "amd64"), config, resolve, sigs)
	if err != nil || loaded == nil {
		t.Fatalf("actual standard export types failed the source recheck: %v", err)
	}
	if imported := pkg.Imports["math"]; imported == nil || imported.Types != config.x86CallerSelections[pkg].imports["math"] {
		t.Fatal("recheck did not retain the actual loaded dependency identity")
	}
}

func TestX86CallerCLIRejectsEffectiveOverlayFromActualGoEnv(t *testing.T) {
	dir := x86CallerCLIFixture(t)
	t.Chdir(dir)
	metadata := t.TempDir()
	goenv := filepath.Join(metadata, "goenv")
	overlaySource := filepath.Join(metadata, "effective.go")
	overlayPath := filepath.Join(metadata, "overlay.json")
	if err := os.WriteFile(overlaySource, []byte(x86CallerCLISource+"\nvar escapedEntry = kernel\n"), 0600); err != nil {
		t.Fatal(err)
	}
	overlay, err := json.Marshal(struct {
		Replace map[string]string
	}{Replace: map[string]string{filepath.Join(dir, "caller.go"): overlaySource}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-overlay="+overlayPath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", goenv)
	t.Setenv("GOFLAGS", "") // cmd/go falls through an empty value to go/env.
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	pkgs, err := loadPkgs("linux", "amd64", []string{"."}, nil, "example.com/caller", true, false)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("actual overlay package: %v", err)
	}
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, x86CallerCLIAssembly)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkgs[0].PkgPath)
	sigs, _, err := sigsForAsmFile(pkgs[0], file, resolve, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	config := compileConfig{x86CallerSelections: captureX86CallerSelections(pkgs, "linux/amd64", nil)}
	_, _, err = bindX86CallerRegions(pkgs[0], file, "linux/amd64", "amd64", filepath.Join(dir, "kernel_amd64.s"),
		plan9asm.GoAssemblerDefines("linux", "amd64"), config, resolve, sigs)
	if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || !strings.Contains(err.Error(), "overlay") {
		t.Fatalf("original bytes impersonated actual compiled overlay: %v", err)
	}
}
