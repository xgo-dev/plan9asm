package plan9asm

import (
	"errors"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestSDKARMABI0TailDefinitions(t *testing.T) {
	const source = `TEXT ·Read(SB),4,$0-8
	MOVW $7,R5
	JMP helper(SB)
TEXT helper(SB),516,$0
	MOVW value+0(FP),R4
	TEQ R5,R4
	BNE other
	MOVW R4,result+4(FP)
	RET
other:
	MOVW R5,result+4(FP)
	RET
`
	pkg := mustGoPackage(t, "test/armsdktail", "package armsdktail\nfunc Read(value uint32) (result uint32)\n")
	pkg.SourceSelection = &GoSourceSelection{Sizes: types.SizesFor("gc", "arm")}
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	scratch := strings.ReplaceAll(source, "R5", "R11")
	scratch = strings.Replace(scratch, "TEQ R11,R4", "ADD $0x12345678,R4,R4\n\tTEQ R11,R4", 1)
	for _, tc := range []struct {
		name, source, failure string
	}{
		{"bound", source, ""},
		{"missing-register", strings.Replace(source, "MOVW $7,R5", "NOP", 1), "reads undefined reg_R5"},
		{"missing-carry", strings.Replace(source, "BNE other", "BCS other", 1), "no initialized"},
		{"missing-result-one-edge", strings.Replace(source, "MOVW R5,result+4(FP)", "NOP", 1), "reads undefined fp_ret_0"},
		{"wrong-frame-slot", strings.Replace(source, "value+0(FP)", "value+12(FP)", 1), "unbound frame"},
		{"implicit-scratch", scratch, "unbound frame, operand or control effect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireARMGoAssemblerResult(t, tc.source, true)
			file, err := Parse(ArchARM, tc.source)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", ResolveSym: resolve}
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("global helper without its SDK source should require context: %v", err)
			}
			helpers := sdkABI0TailHelpers(file)
			projected, err := projectSDKABI0Tail(file, helpers)
			if err != nil {
				t.Fatal(err)
			}
			prepared, sigs, err := prepareSDKARMABI0Tails(pkg, projected, helpers, resolve)
			if err == nil {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				options.Sigs = sigs
				module, translateErr := TranslateModuleInContext(ctx, prepared, options)
				err = translateErr
				if err == nil {
					defer module.Dispose()
					err = proveSDKARMTailDefinitions(module.NamedFunction("Read"))
				}
			}
			if tc.failure == "" && err != nil {
				t.Fatal(err)
			}
			if tc.failure != "" && (!errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), tc.failure)) {
				t.Fatalf("expected context %q, got %v", tc.failure, err)
			}
		})
	}
}
