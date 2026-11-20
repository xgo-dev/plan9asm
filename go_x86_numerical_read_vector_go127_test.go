//go:build go1.27

package plan9asm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func numericalVectorReadRows(arch string) []string {
	var rows []string
	for _, name := range x86AESOracleNames {
		widths := []int{16}
		if strings.HasPrefix(name, "V") && !strings.Contains(name, "IMC") && !strings.Contains(name, "KEYGEN") {
			widths = []int{16, 32, 64}
		}
		for _, width := range widths {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			row, _ := x86AESOracleRow(name, "DATA+0(SB)", bank)
			// The independent oracle selects X1/X2; keep every numerical state
			// source/destination in the fixture's initialized register zero.
			row = strings.ReplaceAll(strings.ReplaceAll(row, bank+"1", bank+"0"), bank+"2", bank+"0")
			rows = append(rows, row)
		}
	}
	for _, opcode := range x86LogicalOpcodeNames() {
		spec := x86PackedLogicalSpecs[opcode]
		legacy := spec.encoding <= x86PackedLogicalLegacyInteger
		widths := []int{16}
		if !legacy {
			widths = append(widths, 32)
			if spec.encoding != x86PackedLogicalVEX {
				widths = append(widths, 64)
			}
		}
		for _, width := range widths {
			reg := map[int]string{16: "X0", 32: "Y0", 64: "Z0"}[width]
			args := " DATA+0(SB)," + reg
			if !legacy {
				args += "," + reg
			}
			rows = append(rows, string(opcode)+args)
		}
		if spec.broadcastBytes != 0 && arch == "amd64" {
			rows = append(rows, string(opcode)+".BCST DATA+0(SB),Z0,Z0",
				string(opcode)+".BCST.Z DATA+0(SB),Z0,K1,Z0",
				string(opcode)+" DATA+0(SB),Z0,K1,Z0")
		}
	}
	return rows
}

func numericalVectorFixture(t *testing.T, arch string, rows []string) (GoPackage, *File, Options, *GoX86NumericalReadSource) {
	t.Helper()
	body := "MOVL $65535,AX\nKMOVW AX,K1\nVPXORD Z0,Z0,Z0\n" + strings.Join(rows, "\n") + "\nPEXTRD $0,X0,AX"
	ownerRequest, readRequest := numericalMutableFixture(t, arch, body)
	name := filepath.Join(ownerRequest.Directory, "value.go")
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte("var Mutable [32]byte"), []byte("var Mutable [128]byte"), 1)
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleProofContext(t)
	t.Cleanup(cancel)
	owner, err := CaptureGoNumericalStorageOwner(ctx, ownerRequest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	readRequest.Owners = []*GoNumericalStorageOwner{owner}
	source, err := CaptureGoX86NumericalReadSource(ctx, readRequest)
	if err != nil {
		t.Fatal("actual complete source/native/vector mutable read join", err)
	}
	t.Cleanup(func() { closeNumericalConsumerSource(t, source) })
	report, err := owner.observation.Readback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exports := make(map[string]string)
	decoder := json.NewDecoder(bytes.NewReader(report.RawSelection))
	for decoder.More() {
		var pkg gostaticstorage.Package
		if err := decoder.Decode(&pkg); err != nil {
			t.Fatal(err)
		}
		exports[pkg.ImportPath] = pkg.Export
	}
	fset := token.NewFileSet()
	var syntax []*ast.File
	for _, name := range source.guard.selection.GoFiles {
		file, err := parser.ParseFile(fset, filepath.Join(readRequest.Directory, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		syntax = append(syntax, file)
	}
	imports := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) { return os.Open(exports[path]) })
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", arch), Importer: imports}).Check(readRequest.PackagePath, fset, syntax, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := GoPackage{Path: typed.Path(), Types: typed, Syntax: syntax, Imports: make(map[string]*types.Package)}
	for _, dependency := range typed.Imports() {
		pkg.Imports[dependency.Path()] = dependency
	}
	sig, err := DeriveGoFuncABI0Signature(pkg.Path+".Feature", typed.Scope().Lookup("Feature").(*types.Func), arch, types.SizesFor("gc", arch))
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: arch, TargetTriple: map[string]string{"386": "i386-unknown-linux-gnu", "amd64": "x86_64-unknown-linux-gnu"}[arch],
		ResolveSym: func(symbol string) string { return numericalNativeName(symbol, pkg.Path) }, Sigs: map[string]FuncSig{sig.Name: sig}}
	file, err := Parse(ArchAMD64, source.cpp.Output)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil {
		t.Fatal("full original typed declarations/vector read binding", err)
	}
	return pkg, file, bound, source
}

func TestGoX86NumericalSBVectorReadOriginalObjectsAndLLVM22(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			rows := numericalVectorReadRows(arch)
			pkg, file, options, source := numericalVectorFixture(t, arch, rows)
			if len(source.reads) != len(rows) {
				t.Fatal("complete original family lost a read", len(source.reads), len(rows))
			}
			for _, api := range []string{"text", "module", "context", "go-module"} {
				t.Run(api, func(t *testing.T) {
					ir := numericalFamilyTranslate(t, api, pkg, file, options)
					if !strings.Contains(ir, "external global [128 x i8]") || strings.Contains(ir, "constant [128") ||
						!strings.Contains(ir, "asm sideeffect") || !strings.Contains(ir, "load volatile") {
						t.Fatal("mutable vector read lost original storage/native alignment/dead-read behavior")
					}
					triples := []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"}
					if arch == "386" {
						triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
					}
					for _, triple := range triples {
						t.Run(triple, func(t *testing.T) { numericalLLVM22Axes(t, ir, triple, nil) })
					}
				})
			}
			t.Logf("complete Go vector rows=%d target=%s original object bytes=%d", len(rows), arch, len(source.native.OriginalObject))
		})
	}
}

func TestGoX86NumericalSBVectorReadUnboundValuesRemainContext(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []string{"AESENC ·mutable(SB),X0", "PXOR ·mutable(SB),X0", "VAESENC ·mutable(SB),Y0,Y0", "VPXORD ·mutable(SB),Z0,Z0"} {
			t.Run(arch+"/"+row, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT ·f(SB),4,$0-4\nPXOR X0,X0\n"+row+"\nPEXTRD $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				sig := FuncSig{Args: nil, Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Name: "ret", Offset: 0, Type: I32, Index: 0, Field: -1}}}}
				if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, arch); err == nil {
					t.Fatal("symbol spelling alone created initialized mutable bytes", fmt.Sprint(row))
				}
			})
		}
	}
}
