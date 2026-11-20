package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalLogicalOfficialRows(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	wanted := make(map[string]bool)
	for _, name := range x86LegacyLogicalMemoryNames {
		wanted[name] = true
	}
	xmm, mmx := 0, 0
	for _, opcode := range catalog.Optab {
		if !wanted[opcode.Opcode] {
			continue
		}
		for _, row := range opcode.Rows {
			if row.ZCase != "Zm_r_xm" {
				t.Fatalf("unmodeled original logical row: %+v", row)
			}
			switch strings.Join(row.Classes, ",") {
			case "Yxm,Yxr":
				xmm++
			case "Ymm,Ymr":
				mmx++ // Inventoried, not admitted to the private XMM consumer.
			default:
				t.Fatalf("unmodeled original logical operands: %+v", row)
			}
		}
	}
	if len(wanted) != 12 || xmm != 12 || mmx != 4 {
		t.Fatalf("official logical family changed: names=%d XMM=%d MMX=%d", len(wanted), xmm, mmx)
	}
}

func fixedLocalLogicalZeroName(name string) bool {
	switch name {
	case "PXOR", "XORPS", "XORPD", "PANDN", "ANDNPS", "ANDNPD":
		return true
	}
	return false
}

func fixedLocalLogicalFixture(t *testing.T, name, input string, uninitialized bool) (string, FuncSig) {
	t.Helper()
	source, sig, _ := x86PrivateAlignedFrameAuditFixture(t, "MOVOU 16(SP),X1\n"+name+" "+input+",X0")
	if uninitialized {
		source = strings.Replace(source, "MOVOU 48(SP),X0\n", "", 1)
	}
	return source, sig
}

func fixedLocalLogicalProgram(t *testing.T) (string, string, int) {
	t.Helper()
	var assembly, declarations strings.Builder
	count := 0
	for _, name := range x86LegacyLogicalMemoryNames {
		for _, input := range []string{"16(SP)", "X1", "X0", "zero"} {
			zero := input == "zero"
			if zero && !fixedLocalLogicalZeroName(name) {
				continue
			}
			if zero {
				input = "X0"
			}
			source, _ := fixedLocalLogicalFixture(t, name, input, zero)
			function := fmt.Sprintf("Value%d", count)
			assembly.WriteString(strings.Replace(source, "·Value", "·"+function, 1))
			fmt.Fprintf(&declarations, "func %s(a,b,c,d uint64) uint64\n", function)
			count++
		}
	}
	return assembly.String(), declarations.String(), count
}

func TestGoAMD64FixedLocalLogicalCompleteFamilies(t *testing.T) {
	assembly, _, count := fixedLocalLogicalProgram(t)
	if count != 42 {
		t.Fatal("complete 12-name register/memory/alias and six zero identities changed", count)
	}
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	for _, name := range x86LegacyLogicalMemoryNames {
		for _, input := range []string{"16(SP)", "X1", "X0"} {
			t.Run(name+"/"+input, func(t *testing.T) {
				source, sig := fixedLocalLogicalFixture(t, name, input, false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
					t.Fatal("initialized complete logical family source rejected", err)
				}
			})
		}
		if fixedLocalLogicalZeroName(name) {
			t.Run(name+"/zero identity", func(t *testing.T) {
				source, sig := fixedLocalLogicalFixture(t, name, "X0", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
					t.Fatal("same-register zero identity incorrectly needs old numerical bytes", err)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalLogicalUpperAliasesAndFlags(t *testing.T) {
	for _, name := range x86LegacyLogicalMemoryNames {
		for _, old := range []uint64{0xffff, 0x804020100000ffff, ^uint64(0)} {
			t.Run(fmt.Sprintf("%s/%x", name, old), func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+name+" X1,X0\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				state := x86FixedLocalState{vectors: map[Reg]uint64{"Z0": old, "Z1": 0xffff}, flags: x86ByteFlagsAll}
				if err := fixedLocalVectorStep(&file.Funcs[0].Instrs[1], &state, nil, 0); err != nil {
					t.Fatal(err)
				}
				if state.vectors["Z0"] != old || state.flags != x86ByteFlagsAll {
					t.Fatal("legacy logical operation changed upper bytes or FLAGS", state)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalLogicalBoundaries(t *testing.T) {
	for _, name := range x86LegacyLogicalMemoryNames {
		for _, row := range []struct{ name, input, from, to string }{
			{"unknown destination", "X1", "MOVOU 48(SP),X0", "MOVOU 48(SP),X2"},
			{"unknown source", "X2", "", ""},
			{"missing memory byte", "16(SP)", "MOVQ CX,24(SP)", "MOVB CX,24(SP)"},
			{"unaligned memory", "17(SP)", "", ""},
			{"outside frame", "160(SP)", "", ""},
			{"MMX source", "M0", "", ""},
			{"high bank", "X16", "", ""},
		} {
			t.Run(name+"/"+row.name, func(t *testing.T) {
				source, sig := fixedLocalLogicalFixture(t, name, row.input, false)
				if row.from != "" {
					changed := strings.Replace(source, row.from, row.to, 1)
					if changed == source {
						t.Fatal("negative fixture did not change the source")
					}
					source = changed
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unproved bytes, alignment or physical bank acquired a logical effect", err)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalLogicalObjects(t *testing.T) {
	assembly, declarations, count := fixedLocalLogicalProgram(t)
	if count != 42 {
		t.Fatal("complete-source logical denominator changed", count)
	}
	fixedLocalCompleteVectorObjects(t, assembly, declarations, count)
}

func fixedLocalCompleteVectorObjects(t *testing.T, assembly, declarations string, count int) {
	t.Helper()
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("ordinary vector/private-frame source failed complete translation", err)
					}
					var names []string
					for index := 0; index < count; index++ {
						names = append(names, fmt.Sprintf("%s.Value%d", pkg.Path, index))
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					compileLLVMToObject(t, llc, target.triple, "private-vector.ll", "private-vector.o", ir)
					compileLLVMToObject(t, llc, target.triple, "private-vector-opt.ll", "private-vector-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
}
