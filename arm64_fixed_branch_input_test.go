package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func TestARM64FixedBranchInputs(t *testing.T) {
	const triple = "aarch64-unknown-linux-gnu"
	const goSource = "package compare\nfunc FixedBranch(seed uint64) uint64\n"
	pkg := mustGoPackage(t, "compare", goSource)
	sizes := types.SizesFor("gc", "arm64")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	check := func(t *testing.T, source string, available bool) {
		t.Helper()
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
		if err != nil {
			t.Fatal(err)
		}
		options := Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
		_, textErr := Translate(file, options)
		module, moduleErr := TranslateModule(file, options)
		if !module.IsNil() {
			module.Dispose()
		}
		bound, goErr := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
		})
		if goErr == nil {
			bound.Module.Dispose()
		}
		for _, result := range []struct {
			api string
			err error
		}{{"text", textErr}, {"module", moduleErr}, {"Go", goErr}} {
			if available {
				if result.err != nil {
					t.Errorf("%s rejected a locally defined branch input: %v", result.api, result.err)
				}
			} else if !errors.Is(result.err, ErrProbeNeedsContext) ||
				!strings.Contains(result.err.Error(), "fixed entry register") {
				t.Errorf("%s must require the original fixed entry value: %v", result.api, result.err)
			}
		}
	}

	const header = "TEXT ·FixedBranch(SB),516,$0-16\n"
	const result = "MOVD R0,ret+8(FP)\nRET\n"
	const namedPaths = "MOVD $7,R0\nB done\ntarget:\nMOVD $73,R0\ndone:\n"
	// Use exact one-word instructions around the raw branch so the known
	// displacement ends at the real MOVZ for the taken result.
	const rawPaths = "WORD $0xd28000e0\nWORD $0x14000002\nWORD $0xd2800920\n"
	for _, reg := range []struct {
		name   string
		number uint32
	}{{"R18_PLATFORM", 18}, {"g", 28}, {"R29", 29}} {
		for _, form := range []struct {
			op   string
			word uint32
			bit  string
		}{
			{"CBZ", 0xb4000000, ""}, {"CBNZ", 0xb5000000, ""},
			{"CBZW", 0x34000000, ""}, {"CBNZW", 0x35000000, ""},
			{"TBZ", 0xb6000000, "$32,"}, {"TBNZ", 0xb7000000, "$32,"},
		} {
			named := fmt.Sprintf("%s %s%s,target\n%s", form.op, form.bit, reg.name, namedPaths)
			raw := fmt.Sprintf("WORD $%#08x\n%s", form.word|3<<5|reg.number, rawPaths)
			save := fmt.Sprintf("MOVD %s,R21\nMOVD seed+0(FP),%s\n", reg.name, reg.name)
			restore := fmt.Sprintf("MOVD R21,%s\n", reg.name)
			for _, spelling := range []struct {
				name, body string
			}{{"named", named}, {"raw", raw}} {
				t.Run(reg.name+"/"+form.op+"/"+spelling.name, func(t *testing.T) {
					check(t, header+spelling.body+result, false)
					check(t, header+save+spelling.body+restore+result, true)
				})
			}
		}
	}
	t.Run("copied-input", func(t *testing.T) {
		check(t, header+"MOVD g,R9\nCBZ R9,target\n"+namedPaths+result, false)
	})
	t.Run("computed-input", func(t *testing.T) {
		check(t, header+"MOVW g,R9\nADD $1,R9\nCBZ R9,target\n"+namedPaths+result, false)
	})
	t.Run("private-spill", func(t *testing.T) {
		const save = "WORD $0xa9bf7bfd\n"    // STP R29, R30, [SP, #-16]!
		const restore = "WORD $0xa8c17bfd\n" // LDP R29, R30, [SP], #16
		source := header + save + "MOVD (RSP),R9\nCBZ R9,target\n" + namedPaths + restore + result
		check(t, source, false)
		source = header + save + "MOVD seed+0(FP),R29\nCBZ R29,target\n" + namedPaths + restore + result
		check(t, source, true)
	})
	t.Run("partially-initialized-join", func(t *testing.T) {
		source := header + "MOVD seed+0(FP),R0\nMOVD g,R21\n" +
			"CBZ R0,join\nMOVD R0,g\njoin:\nCBZ g,target\n" +
			namedPaths + "MOVD R21,g\n" + result
		check(t, source, false)
	})
}
