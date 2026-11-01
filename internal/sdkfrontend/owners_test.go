package sdkfrontend

import (
	"go/token"
	"go/types"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestSDKVariableOwnerQueryUsesActualTypedScopes(t *testing.T) {
	primary, imported := types.NewPackage("arbitrary/sdk", "sdk"), types.NewPackage("another/sdk", "sdk")
	for _, pkg := range []*types.Package{primary, imported} {
		pkg.Scope().Insert(types.NewVar(token.NoPos, pkg, "mutable", types.NewArray(types.Typ[types.Uint8], 128)))
		pkg.Scope().Insert(types.NewVar(token.NoPos, pkg, "opaque", types.NewPointer(types.Typ[types.Uint8])))
		pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "constant", types.Typ[types.Uint8], nil))
		pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "function", types.NewSignature(nil, nil, nil, false)))
	}
	pkg := &Package{Path: primary.Path(), Types: primary, Imports: map[string]*Package{
		imported.Path(): {Path: imported.Path(), Types: imported},
	}}
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, `TEXT ·Probe(SB),4,$0-0
AESENC ·mutable+16(SB), X0
AESENC ·mutable(SB), X0
MOVQ another∕sdk·mutable(SB), AX
MOVQ ·opaque(SB), AX
MOVQ ·constant(SB), AX
CALL ·function(SB)
MOVOU ·literal<>(SB), X0
CMPB internal∕cpu·X86+82(SB), $1
RET
`)
	if err != nil {
		t.Fatal(err)
	}
	queries := OwnerRequests(pkg, file, "linux/amd64")
	want := []OwnerRequest{
		{PackagePath: imported.Path(), Variables: []plan9asm.GoNumericalStorageReference{{PackagePath: imported.Path(), Name: "mutable"}}},
		{PackagePath: primary.Path(), Variables: []plan9asm.GoNumericalStorageReference{
			{PackagePath: primary.Path(), Name: "mutable"}, {PackagePath: primary.Path(), Name: "opaque"},
		}},
		{PackagePath: "internal/cpu", CPU: true, Variables: []plan9asm.GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}}},
	}
	if !reflect.DeepEqual(queries, want) {
		t.Fatalf("typed owner query = %+v, want %+v", queries, want)
	}
	// An opaque variable may request the independent observer, but this cost
	// query supplies no pointer-free, initialized storage or memory authority.
	pkg.Module = true
	if len(OwnerRequests(pkg, file, "linux/amd64")) != 0 {
		t.Fatal("a foreign module borrowed the stock SDK cost route")
	}
	pkg.Module = false
	for _, target := range []string{"linux/386", "darwin/amd64", "windows/386", "windows/amd64"} {
		if !reflect.DeepEqual(OwnerRequests(pkg, file, target), want) {
			t.Fatalf("%s cost query lost the original typed SDK variable roles", target)
		}
	}
	for _, target := range []string{"darwin/386", "freebsd/amd64", "linux/arm64", "unknown/amd64"} {
		if len(OwnerRequests(pkg, file, target)) != 0 {
			t.Fatalf("%s borrowed an unobserved x86 SDK source role", target)
		}
	}
}
