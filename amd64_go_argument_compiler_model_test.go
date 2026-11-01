package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

func TestAMD64GoArgumentCompilerFixtureAndListingGuards(t *testing.T) {
	fixtures := amd64ArgumentOracleFixtures()
	source, err := amd64ArgumentOracleSource(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "arguments.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := (&types.Config{Sizes: types.SizesFor("gc", "amd64")}).Check("example.invalid/carrieroracle", fset, []*ast.File{file}, nil)
	if err != nil || len(fixtures) != 9 || len(pkg.Scope().Names()) != 18 {
		t.Fatal("whole independent ordinary fixture inventory", err)
	}
	for _, fixture := range fixtures {
		t.Run("independent-matrix/"+fixture.name, func(t *testing.T) {
			sig := pkg.Scope().Lookup("Target" + fixture.name).Type().(*types.Signature)
			plan, err := planAMD64GoArguments(sig)
			if err != nil {
				t.Fatal(err)
			}
			var got []amd64ArgumentOracleCarrier
			for _, argument := range plan.Arguments {
				for _, carrier := range argument.Carriers {
					got = append(got, amd64ArgumentOracleCarrier{sig.Params().At(argument.Index).Name(), carrier.Offset, carrier.Register, carrier.Width})
				}
			}
			if !reflect.DeepEqual(got, fixture.carriers) {
				t.Fatalf("independent ordinary matrix: %#v != %#v", got, fixture.carriers)
			}
			if strings.Contains(fixture.name, "Rollback") && plan.requireRegisters() == nil {
				t.Fatal("compiler oracle enabled incoming spill storage")
			}
		})
	}
	// Synthetic parser controls never become source/compiler/entry authority.
	const listing = "target STEXT size=1\n\t0x0000 00000 TEXT target(SB), ABIInternal, $0-8\n\t0x0000 00000 MOVB AL, fixture.a+16(SP)\n\t0x0000 c3 \ncaller STEXT size=6\n\t0x0000 00000 TEXT caller(SB), ABIInternal, $0-8\n\t0x0000 e8 00 00 00 00 c3 \n\trel 1+4 t=R_CALL target+0\n"
	observed, err := amd64ArgumentCompilerFunctions([]byte(listing))
	if err != nil || len(observed) != 2 || len(observed["target"].spills) != 1 || observed["target"].spills[0].register != AX || observed["caller"].calls["target"] != 1 {
		t.Fatal("complete compiler parser model", err)
	}
	for _, flags := range []string{"NOSPLIT|ABIInternal", "ABIInternal|NOSPLIT", "DUPOK|NOSPLIT|NOFRAME|ABIInternal"} {
		withFlags := strings.Replace(listing, "TEXT target(SB), ABIInternal,", "TEXT target(SB), "+flags+",", 1)
		if functions, err := amd64ArgumentCompilerFunctions([]byte(withFlags)); err != nil || len(functions) != 2 || functions["target"] == nil {
			t.Errorf("compiler TEXT flags lost an original ABIInternal target (%s): %v", flags, err)
		}
	}
	for name, invalid := range map[string]string{
		"duplicate-flags": strings.Replace(listing, "TEXT target(SB), ABIInternal,", "TEXT target(SB), ABIInternal|ABIInternal,", 1),
		"unknown-flags":   strings.Replace(listing, "TEXT target(SB), ABIInternal,", "TEXT target(SB), ABIInternal|UNKNOWN,", 1),
		"ABI0":            strings.Replace(listing, "TEXT target(SB), ABIInternal,", "TEXT target(SB), ABI0,", 1),
		"duplicate-TEXT":  listing + "\t0x0000 00000 TEXT target(SB), ABIInternal, $0-8\n",
		"code-hole":       strings.Replace(listing, "0x0000 c3", "0x0001 c3", 1),
		"duplicate-call":  listing + "\trel 1+4 t=R_CALL target+0\n",
		"empty":           "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := amd64ArgumentCompilerFunctions([]byte(invalid)); err == nil {
				t.Fatal("partial/ambiguous compiler listing was accepted")
			}
		})
	}
}
