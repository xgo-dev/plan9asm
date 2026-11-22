package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64ExceptionReturnKeepsPhysicalEntry(t *testing.T) {
	const source = `TEXT eretName(SB),516,$0-0
 ERET
TEXT drpsName(SB),$0-0
 DRPS
 RET
TEXT eretWord(SB),4,$-8-0
 WORD $0xd69f03e0
TEXT drpsWord(SB),516,$0-0
 WORD $0xd6bf03e0
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	// Go asm7 preserves the subsequent RET at its original code offset.
	words := map[string][]uint32{
		"eretName": {0xd69f03e0},
		"eretWord": {0xd69f03e0},
		"drpsName": {0xd6bf03e0, 0xd65f03c0},
		"drpsWord": {0xd6bf03e0},
	}
	sigs := make(map[string]FuncSig, len(words))
	for name := range words {
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	opt := Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple, Sigs: sigs}
	text, err := Translate(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	pkg := mustGoPackage(t, "example.com/entry", "package entry\nfunc anchor()\n")
	inGo, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
		GOOS: "linux", GOARCH: "arm64", TargetTriple: arm64LinuxGNUTriple,
		ResolveSym: func(name string) string { return strings.TrimSuffix(name, "(SB)") },
		ManualSig: func(name string) (FuncSig, bool) {
			sig, known := sigs[name]
			return sig, known
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer inGo.Module.Dispose()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, ir := range []string{text, module.String(), inGo.Module.String()} {
		for _, level := range []string{"-O0", "-O2"} {
			requireARMExceptionReturnObject(t, llc, level, ir, words)
		}
	}
}

func TestARM64ExceptionReturnRequiresUnchangedPhysicalState(t *testing.T) {
	for _, test := range []struct {
		name, triple, source string
	}{
		{"framed ERET", arm64LinuxGNUTriple, "TEXT restore(SB),4,$16-0\n ERET\n"},
		{"framed DRPS", arm64LinuxGNUTriple, "TEXT restore(SB),4,$16-0\n DRPS\n"},
		{"body writes GPR", arm64LinuxGNUTriple, "TEXT restore(SB),516,$0-0\n MOVD $11,R2\n ERET\n"},
		{"body writes GPR before raw return", arm64LinuxGNUTriple,
			"TEXT restore(SB),516,$0-0\n MOVD $11,R2\n WORD $0xd69f03e0\n"},
		{"other backend", "wasm32-unknown-unknown", "TEXT restore(SB),516,$0-0\n ERET\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			requireARM64GoAssemblerResult(t, test.source, true)
			file, err := Parse(ArchARM64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: test.triple,
				Sigs: map[string]FuncSig{"restore": {Name: "restore", Ret: Void}},
			})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("physical exception return with unproved entry must require context: %v", err)
			}
		})
	}
}
