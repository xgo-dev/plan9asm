//go:build go1.27

package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestAMD64GoArgumentCompilerCallsiteBanksAndWidths(t *testing.T) {
	fixtures := amd64ArgumentOracleFixtures()
	source, err := amd64ArgumentOracleSource(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	input, object := filepath.Join(directory, "arguments.go"), filepath.Join(directory, "arguments.o")
	if err := os.WriteFile(input, source, 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = sourcepath.Resolve(binary)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "tool", "compile", "-N", "-l", "-S", "-p", "example.invalid/carrieroracle", "-o", object, input)
	command.Dir = directory
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOEXPERIMENT=", "GOFLAGS=", "GOENV=off", "GOWORK=off", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	stdout, stderr, err := runtimeOracleMachineOutput(ctx, command)
	if err != nil {
		t.Fatalf("actual independent ordinary compiler fixture: %v\n%s\n%s", err, stdout, stderr)
	}
	listing := append(append([]byte(nil), stdout...), stderr...)
	functions, err := amd64ArgumentCompilerFunctions(listing)
	if err != nil {
		t.Fatalf("complete actual compiler listing: %v\n%s", err, listing)
	}
	compiled, err := os.ReadFile(object)
	if err != nil || len(compiled) == 0 {
		t.Fatal("missing complete actual compiler object", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, input, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := (&types.Config{Sizes: types.SizesFor("gc", "amd64")}).Check("example.invalid/carrieroracle", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			name := "example.invalid/carrieroracle.Target" + fixture.name
			target, caller := functions[name], functions["example.invalid/carrieroracle.Caller"+fixture.name]
			if target == nil || caller == nil || len(target.code) == 0 || len(caller.code) == 0 ||
				!bytes.Contains(compiled, target.code) || !bytes.Contains(compiled, caller.code) {
				t.Fatalf("original named ABIInternal compiler bodies/code are absent\n%s", listing)
			}
			call, found := caller.calls[name]
			if !found || call < 1 || call > int64(len(caller.code))-4 || caller.code[call-1] != 0xe8 {
				t.Fatal("ordinary original caller lost its unique actual E8/R_CALL target")
			}
			got := append([]amd64ArgumentOracleCarrier(nil), target.spills...)
			bases := make(map[string]int64)
			for _, spill := range got {
				base, found := bases[spill.parameter]
				if !found || spill.offset < base {
					bases[spill.parameter] = spill.offset
				}
			}
			for index := range got {
				got[index].offset -= bases[got[index].parameter]
			}
			if !reflect.DeepEqual(got, fixture.carriers) {
				t.Fatalf("independent actual incoming register spill observations\n got %#v\nwant %#v\n%s", got, fixture.carriers, listing)
			}
			sig := pkg.Scope().Lookup("Target" + fixture.name).Type().(*types.Signature)
			plan, err := planAMD64GoArguments(sig)
			if err != nil {
				t.Fatal(err)
			}
			var modeled []amd64ArgumentOracleCarrier
			for _, argument := range plan.Arguments {
				for _, carrier := range argument.Carriers {
					modeled = append(modeled, amd64ArgumentOracleCarrier{sig.Params().At(argument.Index).Name(), carrier.Offset, carrier.Register, carrier.Width})
				}
			}
			if !reflect.DeepEqual(modeled, fixture.carriers) {
				t.Fatalf("compiler-independent parameter grouping/bank/width matrix differs: %#v", modeled)
			}
			t.Logf("actual original ABIInternal target=%s receivingStores=%+v uniqueE8CallOffset=%d callerCodeSHA=%x targetCodeSHA=%x; no incoming stack/carrier permission", name, got, call, sha256.Sum256(caller.code), sha256.Sum256(target.code))
			if strings.Contains(fixture.name, "Rollback") && plan.requireRegisters() == nil {
				t.Fatal("oracle spill observations became a register-only entry permission")
			}
		})
	}
	after, err := os.ReadFile(input)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(source) {
		t.Fatal("original ordinary fixture changed", err)
	}
	t.Logf("complete original ordinary fixture: %d source functions, %d observed compiler TEXTs, sourceSHA=%x objectSHA=%x; receiving spill stores are NOT incoming stack authority", 2*len(fixtures), len(functions), sha256.Sum256(source), sha256.Sum256(compiled))
}
