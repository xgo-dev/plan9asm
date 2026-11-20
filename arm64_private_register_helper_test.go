package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64PrivateRegisterHelperSource(header, call string) string {
	return `TEXT ·Run(SB),4,$0-16
MOVD x+0(FP),R19
MOVD $291,R0
ADDS $1,R19,R9
` + call + `
EOR R0,R20
MOVD R20,ret+8(FP)
RET
TEXT mix<>(SB),` + header + `
ADC $0,R9,R20
MUL R19,R20,R20
RET
`
}

func TestCrossLinuxRuntimeMatrixARM64PrivateRegisterHelper(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	pkg := mustGoPackage(t, "test/privategp", "package privategp\nfunc Run(uint64) uint64\n")
	for _, test := range []struct {
		name, header, call string
		manual             bool
		extra              uint64
		rootFrame          int64
		saveLink           bool
		data26             string
	}{
		{name: "normal-leaf"},
		{name: "default-flags", header: "0,$0-0", call: "BL mix<>(SB)"},
		{name: "no-frame", header: "516,$0-0"},
		{name: "negative-eight-no-frame", header: "4,$-8-0"},
		{name: "two-call-sites", call: "CALL mix<>(SB)\nCALL mix<>(SB)"},
		{name: "branch-call-sites", call: "CBNZ R19,other\nCALL mix<>(SB)\nB done\nother:\nCALL mix<>(SB)\ndone:"},
		{name: "manual-scalar-is-not-source-ABI", manual: true},
		{name: "two-different-helpers", call: "CALL mix<>(SB)\nCALL bump<>(SB)", extra: 5},
		{name: "helper-label-collision", call: "__arm64_private_0:\nCALL mix<>(SB)"},
		{name: "framed-root", rootFrame: 24},
		{name: "no-frame-root-restores-real-lr", saveLink: true},
		{name: "helper-initializes-data26", data26: "helper"},
		{name: "caller-initializes-data26", data26: "caller"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.header == "" {
				test.header = "4,$0-0"
			}
			if test.call == "" {
				test.call = "CALL mix<>(SB)"
			}
			source := arm64PrivateRegisterHelperSource(test.header, test.call)
			if test.data26 == "helper" {
				source = strings.Replace(source, "ADC $0,R9,R20", "ADC $0,R9,R26\nMOVD R26,R20", 1)
			}
			if test.data26 == "caller" {
				source = strings.Replace(source, "CALL mix<>(SB)", "MOVD R9,R26\nCALL mix<>(SB)", 1)
				source = strings.Replace(source, "ADC $0,R9,R20", "ADC $0,R26,R20", 1)
			}
			if test.rootFrame != 0 {
				source = strings.Replace(source, "TEXT ·Run(SB),4,$0-16", fmt.Sprintf("TEXT ·Run(SB),4,$%d-16", test.rootFrame), 1)
			}
			if test.saveLink {
				source = strings.Replace(source, "TEXT ·Run(SB),4,$0-16", "TEXT ·Run(SB),516,$0-16\nMOVD R30,R22", 1)
				source = strings.Replace(source, "EOR R0,R20", "MOVD R22,R30\nEOR R0,R20", 1)
			}
			if test.extra != 0 {
				source += fmt.Sprintf("TEXT bump<>(SB),4,$0-0\nADD $%d,R20\nRET\n", test.extra)
			}
			carry := "if x==^uint64(0) { y++ }"
			if test.manual {
				source = strings.Replace(source, "ADC $0,R9,R20", "MOVD R9,R20", 1)
				carry = ""
			}
			want := fmt.Sprintf("(x*y+%d)^291", test.extra)
			runARM64LocalRegisterGoOracle(t, source, `package main
func Run(uint64) uint64
func main() {
  for _,x:=range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
    y:=x+1
    `+carry+`
    if Run(x)!=`+want+` { panic("private GP/NZCV continuation mismatch") }
  }
}
`, len(runner) != 0)
			inventedHelper := false
			translate := func(target string) string {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				manual := func(name string) (FuncSig, bool) {
					if test.manual && name == "mix<>" {
						return FuncSig{Name: name, Ret: I64}, true
					}
					return FuncSig{}, false
				}
				tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
					ManualSig:  manual,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer tr.Module.Dispose()
				if tr.Module.Context() != ctx {
					t.Fatal("private GP continuation escaped its owned context")
				}
				ir := tr.Module.String()
				_, invented := tr.Signatures["mix<>"]
				inventedHelper = inventedHelper || invented || strings.Contains(ir, "@\"mix<>\"")
				return ir
			}
			for _, target := range []string{
				"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
				"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
				"aarch64-unknown-linux-musl",
			} {
				compileLLVMToObject(t, llc, target, "private-gp.ll", "private-gp.o", translate(target))
			}
			cCarry := "if (x==UINT64_MAX) y++;"
			if test.manual {
				cCarry = ""
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "private_gp", triple, translate(triple), `#include <stdint.h>
extern uint64_t Run(uint64_t);
int main(void) {
  uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};
  for (unsigned i=0;i<5;i++) {
    uint64_t x=inputs[i],y=x+1;
    `+cCarry+`
    if (Run(x)!=(`+want+`)) return 1;
  }
  return 0;
}
`, runner)
			if inventedHelper {
				t.Fatal("private continuation must not acquire a scalar function signature")
			}
		})
	}
}

func TestARM64PrivateRegisterHelperNeedsCompleteContext(t *testing.T) {
	pkg := mustGoPackage(t, "test/privategp", "package privategp\nfunc Run(uint64) uint64\n")
	base := arm64PrivateRegisterHelperSource("4,$0-0", "CALL mix<>(SB)")
	for _, test := range []struct {
		name, source string
	}{
		{"unknown-gp-input", strings.Replace(base, "ADC $0,R9,R20", "ADD R8,R9,R20", 1)},
		{"unknown-flags-input", strings.Replace(base, "ADDS $1,R19,R9", "ADD $1,R19,R9", 1)},
		{"helper-unknown-memory-base", strings.Replace(base, "ADC $0,R9,R20", "MOVD R0,(R8)\nADC $0,R9,R20", 1)},
		{"helper-fp", strings.Replace(base, "ADC $0,R9,R20", "MOVD x+0(FP),R20", 1)},
		{"helper-sp", strings.Replace(base, "ADC $0,R9,R20", "MOVD RSP,R20", 1)},
		{"helper-lr", strings.Replace(base, "ADC $0,R9,R20", "MOVD R30,R20", 1)},
		{"helper-frame", strings.Replace(base, "TEXT mix<>(SB),4,$0-0", "TEXT mix<>(SB),4,$8-0", 1)},
		{"helper-call", strings.Replace(base, "ADC $0,R9,R20", "CALL foreign(SB)\nADC $0,R9,R20", 1)},
		{"helper-raw", strings.Replace(base, "ADC $0,R9,R20", "WORD $0x91000414", 1)},
		{"helper-system", strings.Replace(base, "ADC $0,R9,R20", "SVC $0", 1)},
		{"helper-vector", strings.Replace(base, "ADC $0,R9,R20", "VEOR V0.B16,V0.B16,V0.B16\nADC $0,R9,R20", 1)},
		{"helper-address-taken", strings.Replace(base, "CALL mix<>(SB)", "MOVD $mix<>(SB),R1\nCALL mix<>(SB)", 1)},
		{"helper-offset-call", strings.Replace(base, "CALL mix<>(SB)", "CALL mix<>+4(SB)", 1)},
		{"helper-tail-branch-use", strings.Replace(base, "CALL mix<>(SB)", "CALL mix<>(SB)\nB mix<>(SB)", 1)},
		{"helper-tail-jump-use", strings.Replace(base, "CALL mix<>(SB)", "CALL mix<>(SB)\nJMP mix<>(SB)", 1)},
		{"helper-foreign-entry-use", base + "TEXT Alternate(SB),4,$0-0\nB mix<>(SB)\n"},
		{"helper-data-relocation", base + "DATA saved<>+0(SB)/8,$mix<>(SB)\nGLOBL saved<>(SB),8,$8\n"},
		{"helper-unreferenced", strings.Replace(base, "CALL mix<>(SB)", "MOVD R9,R20", 1)},
		{"caller-scratch-observable", strings.Replace(base, "MOVD $291,R0", "MOVD $291,R27\nMOVD R27,R0", 1)},
		{"caller-unknown-liveout", strings.Replace(base, "EOR R0,R20", "EOR R8,R20", 1)},
		{"callee-argument-frame", strings.Replace(base, "TEXT mix<>(SB),4,$0-0", "TEXT mix<>(SB),4,$0-8", 1)},
		{"unknown-path-input", strings.Replace(base, "ADDS $1,R19,R9", "CBZ R19,skip\nADDS $1,R19,R9\nskip:", 1)},
		{"helper-branch", strings.Replace(base, "ADC $0,R9,R20", "CBZ R19,done\nADC $0,R9,R20\ndone:", 1)},
		{"root-no-frame-unknown-return-link", strings.Replace(strings.Replace(base, "TEXT ·Run(SB),4,$0-16", "TEXT ·Run(SB),516,$0-16", 1), "EOR R0,R20", "MOVD $8,R30\nEOR R0,R20", 1)},
		{"root-no-source-terminator", strings.Replace(base, "RET\nTEXT mix<>", "TEXT mix<>", 1)},
		{"root-opaque-call", strings.Replace(base, "CALL mix<>(SB)", "CALL foreign(SB)\nCALL mix<>(SB)", 1)},
		{"root-raw", strings.Replace(base, "CALL mix<>(SB)", "WORD $0xd503201f\nCALL mix<>(SB)", 1)},
		{"root-observes-code-layout", strings.Replace(base, "CALL mix<>(SB)", "ADR after,R7\nCALL mix<>(SB)\nafter:", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			requireARM64GoAssemblerResult(t, test.source, true)
			for _, target := range []string{
				"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
				"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
				"aarch64-unknown-linux-musl",
			} {
				ctx := llvm.NewContext()
				tr, err := translateGoModuleInContext(ctx, pkg, []byte(test.source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
				})
				if tr != nil {
					tr.Module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s requires a complete native continuation contract, got %v", target, err)
				}
			}
		})
	}
}

func TestARM64PrivateRegisterHelperKeepFuncCannotHideEscape(t *testing.T) {
	pkg := mustGoPackage(t, "test/privategp", "package privategp\nfunc Run(uint64) uint64\nfunc Escape()\n")
	source := arm64PrivateRegisterHelperSource("4,$0-0", "CALL mix<>(SB)") + `TEXT ·Escape(SB),4,$0-0
MOVD $mix<>(SB),R0
RET
`
	requireARM64GoAssemblerResult(t, source, true)
	tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
		KeepFunc:   func(text, _ string) bool { return text == "·Run" || text == "mix<>" },
	})
	if tr != nil {
		tr.Module.Dispose()
	}
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("excluded sibling still takes the private helper address: %v", err)
	}
}

func TestARM64PrivateRegisterHelperMultipleRoots(t *testing.T) {
	pkg := mustGoPackage(t, "test/privategp", "package privategp\nfunc Run(uint64) uint64\nfunc Other(uint64) uint64\n")
	source := arm64PrivateRegisterHelperSource("4,$0-0", "CALL mix<>(SB)")
	caller := strings.Split(source, "TEXT mix<>")[0]
	source += strings.ReplaceAll(caller, "·Run", "·Other")
	tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	if len(tr.Functions) != 2 || len(tr.Signatures) != 2 {
		t.Fatalf("closed source has two actual entries, not a guessed helper ABI: %s", fmt.Sprint(tr.Functions))
	}
}
