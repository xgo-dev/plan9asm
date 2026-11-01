package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestTranslateAMD64PushPop(t *testing.T) {
	src := `
TEXT ·stackOps(SB),NOSPLIT,$0
POPQ R12
PUSHQ R12
MOVQ R12, AX
RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	const pkgPath = "test/pkg"
	resolve := func(sym string) string {
		if strings.HasPrefix(sym, "·") {
			return pkgPath + "." + strings.TrimPrefix(sym, "·")
		}
		return sym
	}
	sigs := map[string]FuncSig{
		pkgPath + ".stackOps": {
			Name: pkgPath + ".stackOps",
			Ret:  I64,
		},
	}
	if ir, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym:   resolve,
		Sigs:         sigs,
		Goarch:       "amd64",
	}); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("original entry POP and undeclared result acquired a public ABI", err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+src)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, src, "func stackOps() uint64", "amd64", triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original source invented a typed result or initialized stack", api, err)
				}
			}
			ir := x86OriginalStackFormatObject(t, file.Funcs[0], I64, "amd64", triple)
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, text, level)
				}
			}
		})
	}
}
