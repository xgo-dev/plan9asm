package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestSigsForAsmFileARM64GoInternalSourceContract(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		declarations := "package p\nfunc Count([]byte,byte) int\nfunc CountString(string,byte) int\nfunc Classic(uint64) uint64\nfunc Zero() uint64\n"
		source := "TEXT ·Count<ABIInternal>(SB),4,$0-40\nMOVD R3,R2\nB ·CountString<ABIInternal>(SB)\nTEXT ·CountString<ABIInternal>(SB),4,$0-32\nRET\nTEXT ·Classic(SB),4,$0-16\nCALL ·Zero<ABIInternal>(SB)\nRET\n"
		if overflow {
			declarations += "func Spill(" + strings.TrimSuffix(strings.Repeat("uint64,", 17), ",") + ") uint64\n"
			source += "TEXT ·Forward(SB),4,$0\nCALL ·Spill<ABIInternal>(SB)\nRET\n"
			declarations += "func Forward()\n"
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, "p.go", declarations, 0)
		if err != nil {
			t.Fatal(err)
		}
		typesPkg, err := new(types.Config).Check("test/internalcontract", fset, []*ast.File{parsed}, nil)
		if err != nil {
			t.Fatal(err)
		}
		pkg := &packages.Package{PkgPath: typesPkg.Path(), Types: typesPkg, TypesSizes: types.SizesFor("gc", "arm64")}
		file, err := plan9asm.Parse(plan9asm.ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		sigs, _, err := sigsForAsmFile(pkg, file, resolveSymFunc(pkg.PkgPath), "arm64")
		if overflow {
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("explicit referenced stack contract lost its error: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for name, params := range map[string]int{"Count": 4, "CountString": 3, "Zero": 0} {
			contract := sigs[typesPkg.Path()+"."+name].ARM64GoRegisterABI
			if contract == nil || len(contract.Params) != params || len(contract.Results) != 1 {
				t.Fatalf("%s: missing complete source-derived contract: %+v", name, contract)
			}
		}
		if sigs[typesPkg.Path()+".Classic"].ARM64GoRegisterABI != nil {
			t.Fatal("classic declaration invented an internal entry")
		}
	}
}
