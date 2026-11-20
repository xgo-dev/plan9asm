package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64ClosedTailFoldSource(tail, helperHeader string) string {
	return fmt.Sprintf(`TEXT ·Fold<ABIInternal>(SB),516,$0-32
%s foldbody<>(SB)
TEXT foldbody<>(SB),%s
MOVD $0,R3
CBZ R1,done
loop:
PCALIGN $16
MOVD.P 8(R0),R4
ADD R4,R3,R3
SUB $1,R1
CBNZ R1,loop
done:
MOVD R3,(R2)
MOVD R3,R0
RET
`, tail, helperHeader)
}

func TestCrossLinuxRuntimeMatrixARM64ClosedTailContinuation(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	for _, tc := range []struct{ tail, header string }{
		{"B", "516,$0-0"}, {"JMP", "4,$0"}, {"RET", "4,$0-0"},
	} {
		t.Run(tc.tail, func(t *testing.T) {
			source := arm64ClosedTailFoldSource(tc.tail, tc.header)
			// Identical original assembly executes under the selected actual Go
			// compiler, including its real ABIInternal call and unchanged LR.
			runARM64GoInternalOracle(t, source, `package main
func Fold(*uint64,uint64,*uint64) uint64
func main() {
  data := [10]uint64{0xa55a,0,1,9,0x8000000000000000,^uint64(0),3,17,999,0x5aa5}
  original := data
  for n:=uint64(0); n<=8; n++ {
    out := [3]uint64{0xabc,0xbad,0xdef}
    want := uint64(0)
    for i:=uint64(0); i<n; i++ { want += data[i+1] }
    if Fold(&data[1],n,&out[1])!=want || out[1]!=want { panic("source tail fold mismatch") }
    if out[0]!=0xabc || out[2]!=0xdef || data!=original { panic("source tail canary/input changed") }
  }
}
`, len(runner) != 0)
			translate := func(target string) string {
				ir, err := arm64ClosedTailTranslate(t, source, "func Fold(*uint64,uint64,*uint64) uint64", target, "GoModule")
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(ir, "foldbody") {
					t.Fatal("a source continuation acquired a separate LLVM callee")
				}
				return ir
			}
			for _, target := range []string{
				"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
				"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
			} {
				compileLLVMToObject(t, llc, target, "closed-fold.ll", "closed-fold.o", translate(target))
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "closed_tail", triple, translate(triple), `#include <stdint.h>
#include <string.h>
extern uint64_t Fold(uint64_t *,uint64_t,uint64_t *);
int main(void) {
  uint64_t data[]={0xa55a,0,1,9,UINT64_C(0x8000000000000000),UINT64_MAX,3,17,999,0x5aa5};
  uint64_t original[10];
  memcpy(original,data,sizeof data);
  for (unsigned n=0;n<=8;n++) {
    uint64_t out[]={0xabc,0xbad,0xdef},want=0;
    for (unsigned i=0;i<n;i++) want+=data[i+1];
    if (Fold(data+1,n,out+1)!=want || out[1]!=want) return 1;
    if (out[0]!=0xabc || out[2]!=0xdef || memcmp(data,original,sizeof data)) return 2;
  }
  return 0;
}
`, runner)
		})
	}
}

func TestARM64ClosedTailFinalBindingAndZeroArguments(t *testing.T) {
	const source = `TEXT ·Zero<ABIInternal>(SB),516,$0-8
B zero<>(SB)
TEXT zero<>(SB),516,$0
MOVD $99,R0
RET
`
	llc, _, _ := findLlcAndClang(t)
	for _, api := range []string{"text", "module", "GoModule"} {
		t.Run("zero-arguments/"+api, func(t *testing.T) {
			ir, err := arm64ClosedTailTranslate(t, source, "func Zero() uint64", "aarch64-unknown-linux-gnu", api)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "zero-tail.ll", "zero-tail.o", ir)
		})
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "test/closedtail", "package closedtail\nfunc Zero() uint64\n")
	resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
	sigs, err := goSigsForAsmFile(pkg, prepared, resolve, "arm64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Func, *FuncSig)
	}{
		{"source", func(f *Func, _ *FuncSig) { f.Instrs[3].Raw = "changed original source" }},
		{"frame", func(f *Func, _ *FuncSig) { f.FrameSize = 8 }},
		{"selector", func(f *Func, _ *FuncSig) { f.Sym = "·Zero" }},
		{"resource-count-is-not-permission", func(f *Func, _ *FuncSig) { f.arm64PrivateSourceAdded = 0 }},
		{"missing-register-ABI", func(_ *Func, s *FuncSig) { s.ARM64GoRegisterABI = nil }},
		{"custom-register-ABI", func(_ *Func, s *FuncSig) { s.ArgRegs = []Reg{"R0"} }},
		{"wrong-result", func(_ *Func, s *FuncSig) { s.Ret = Ptr }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := *prepared
			mutated.Funcs = append([]Func(nil), prepared.Funcs...)
			mutated.Funcs[0].Instrs = append([]Instr(nil), prepared.Funcs[0].Instrs...)
			sig := sigs["Zero"]
			tc.edit(&mutated.Funcs[0], &sig)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, &mutated, Options{
				Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", ResolveSym: resolve,
				Sigs: map[string]FuncSig{"Zero": sig},
			})
			if !module.IsNil() {
				defer module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("mutated continuation binding acquired admission: %v", err)
			}
		})
	}
}
