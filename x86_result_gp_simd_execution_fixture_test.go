package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

type x86GPSIMDSparseExecutionRow struct {
	name, declaration string
	kind              int
}

type x86GPSIMDSparseExecutionFixture struct {
	positive, negative, declarations, wrappers, wrapperDeclarations string
	rows                                                            []x86GPSIMDSparseExecutionRow
}

// The same complete positive and negative source files feed both original Go
// and LLVM. Separate original-only callers seed the otherwise unknown incoming
// AX bytes and observe outgoing-slot canaries; they grant no translation role.
func x86GPSIMDSparseExecutionFixtureFor(t *testing.T, arch string, ops []string) x86GPSIMDSparseExecutionFixture {
	t.Helper()
	fixture := x86GPSIMDSparseExecutionFixture{wrappers: "#include \"funcdata.h\"\n"}
	for _, op := range ops {
		for kind, prefix := range []string{"Broadcast", "Copy", "Whole", "Bad"} {
			name, result := prefix+op, "uint32"
			input := "MOVB c+0(FP),AX\n"
			if kind == 1 {
				result = "byte"
			} else if kind == 2 {
				input = "MOVBLZX c+0(FP),AX\n"
			}
			body := input + op + " AX,X0\n"
			if kind == 0 {
				body += "PUNPCKLBW X0,X0\nPUNPCKLBW X0,X0\nPSHUFL $0,X0,X0\nMOVL X0,BX\n"
			} else {
				if kind == 3 {
					body += "MOVL $0,BX\n"
				}
				body += op + " X0,BX\n"
			}
			store := "MOVL"
			if kind == 1 {
				store = "MOVB"
			}
			body += store + " BX,ret+RESULT(FP)"
			declaration := fmt.Sprintf("func %s(c byte) %s\n", name, result)
			source := x86ResultGPSIMDAdmissionSource(t, arch, "func view(c byte) "+result+"\n", body)
			source = strings.Replace(source, "·view", "·"+name, 1)
			if kind == 3 {
				fixture.negative += source
			} else {
				fixture.positive += source
			}
			fixture.declarations += declaration
			fixture.rows = append(fixture.rows, x86GPSIMDSparseExecutionRow{name, declaration, kind})
			wrapperDeclaration := fmt.Sprintf("func Seed%s(c byte,seed uint64)(value uint32,guard uint32)\n", name)
			pkg := mustGoPackage(t, "sparse", "package sparse\n"+wrapperDeclaration)
			sig, err := DeriveGoFuncABI0Signature("Seed"+name, pkg.Types.Scope().Lookup("Seed"+name).(*types.Func), arch, types.SizesFor("gc", arch))
			if err != nil || len(sig.Frame.Params) != 2 || len(sig.Frame.Results) != 2 {
				t.Fatal("original caller must have its actual typed ABI0 layout", err)
			}
			word, seedMove := int64(8), "MOVQ"
			if arch == "386" {
				word, seedMove = 4, "MOVL"
			}
			if sig.Frame.Params[0].Offset != 0 || sig.Frame.Params[1].Offset != word ||
				sig.Frame.Results[0].Offset != word+8 || sig.Frame.Results[1].Offset != word+12 {
				t.Fatalf("original caller layout changed: %#v", sig.Frame)
			}
			load, guard := "MOVL", word+4
			if kind == 1 {
				load, guard = "MOVBLZX", word // Preserve the three bytes after the byte result.
			}
			fixture.wrapperDeclarations += wrapperDeclaration
			fixture.wrappers += fmt.Sprintf(`TEXT ·Seed%s(SB),4,$16-%d
NO_LOCAL_POINTERS
MOVL $0xa7a7a7a7,0(SP)
MOVL $0xa7a7a7a7,4(SP)
MOVL $0xa7a7a7a7,8(SP)
MOVL $0xa7a7a7a7,12(SP)
MOVB c+0(FP),CX
MOVB CX,0(SP)
%s seed+%d(FP),AX
CALL ·%s(SB)
%s %d(SP),BX
MOVL %d(SP),DX
MOVL BX,value+%d(FP)
MOVL DX,guard+%d(FP)
RET
`, name, word+16, seedMove, word, name, load, word, guard, word+8, word+12)
		}
	}
	return fixture
}

var x86GPSIMDSparseRuntimeSeeds = []uint64{
	0, ^uint64(0), 0x1122334455667788, 0x8877665544332211, 0x8000000000000000,
}

func x86GPSIMDSparseExecutionExpected(fixture x86GPSIMDSparseExecutionFixture) string {
	hash, calls := uint64(1469598103934665603), 0
	for value := 0; value < 256; value++ {
		for range x86GPSIMDSparseRuntimeSeeds {
			for _, row := range fixture.rows {
				if row.kind == 3 {
					continue
				}
				result := uint32(value)
				if row.kind == 0 {
					result *= 0x01010101
				}
				hash = (hash ^ uint64(result)) * 1099511628211
				calls++
			}
		}
	}
	return fmt.Sprintf("GP/X positive checks=%d hash=%016x\n", calls, hash)
}

func TestX86ResultGPSIMDSparseExecutionFixturesRetainUnknownBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		op := "MOVD"
		if arch == "386" {
			op = "MOVL"
		}
		fixture := x86GPSIMDSparseExecutionFixtureFor(t, arch, []string{op})
		if strings.Contains(fixture.positive, "PEXTR") || strings.Contains(fixture.positive, "MOVL $0,AX") ||
			strings.Count(fixture.positive, "PUNPCKLBW X0,X0") != 2 || strings.Count(fixture.positive, "PSHUFL $0,X0,X0") != 1 {
			t.Fatal("fixture hid the sparse transfer behind a probe or fake zero")
		}
		if len(fixture.rows) != 4 || strings.Count(fixture.wrappers, "CALL ·") != 4 ||
			len(x86GPSIMDSparseRuntimeSeeds) != 5 || x86GPSIMDSparseRuntimeSeeds[2]&0xffffff00 == 0 {
			t.Fatal("original incoming-byte trap or complete caller inventory missing")
		}
		pkg := mustGoPackage(t, "sparse", "package sparse\n"+fixture.declarations)
		for _, test := range []struct {
			source string
			pass   bool
		}{{fixture.positive, true}, {fixture.negative, false}} {
			file, err := Parse(ArchAMD64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			for _, fn := range file.Funcs {
				name := strings.TrimPrefix(fn.Sym, "·")
				sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), arch, types.SizesFor("gc", arch))
				if err != nil {
					t.Fatal(err)
				}
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					err := check(fn, sig, arch)
					if test.pass && err != nil || !test.pass && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("original fixture changed the unknown-byte boundary", test.pass, err)
					}
				}
			}
		}
		t.Log(arch, strings.TrimSpace(x86GPSIMDSparseExecutionExpected(fixture)))
	}
}
