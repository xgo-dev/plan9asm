package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixARM64CallerFPAliasInvalidatesPointer(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	// aliasTarget's real Go frame is 48 bytes; its first FP pointer slot is
	// at entry SP+56. The caller explicitly points p at that pointer slot.
	// An aliased MOVD reconstructs p as the callee saved-LR address. A reload
	// then changes LR to the real caller continuation plus four bytes. Native
	// Go safely skips one witness instruction; synthesizing a normal return
	// would therefore have different semantics. No fabricated link is used.
	const target = `TEXT ·aliasTarget(SB),4,$32-8
CALL ·aliasAnchor(SB)
MOVD (RSP),R22
MOVD p+0(FP),R9
SUB $56,R9,R10
MOVD R10,(R9)
MOVD p+0(FP),R11
ADD $4,R22,R12
MOVD R12,(R11)
RET
`
	const anchor = "TEXT ·aliasAnchor(SB),4,$0-0\nRET\n"
	const caller = `TEXT ·aliasMeasure(SB),516,$0-8
MOVD RSP,R19
MOVD R30,R23
MOVD R29,R24
SUB $64,RSP
ADD $8,RSP,R9
MOVD R9,8(RSP)
MOVD $7,R25
BL ·aliasTarget(SB)
MOVD $11,R25
ADD $100,R25
MOVD $0,R9
MOVD R9,8(RSP)
MOVD R19,RSP
MOVD R24,R29
MOVD R23,R30
MOVD R25,ret+0(FP)
RET
`
	requireARM64GoAssemblerResult(t, caller+target+anchor, true)
	runARM64LocalRegisterGoOracle(t, caller+target+anchor, `package main
func aliasMeasure() uint64
func aliasTarget(*uint64)
func aliasAnchor()
func main() { if got:=aliasMeasure(); got!=107 { println(got); panic("caller FP alias witness mismatch") } }
`, len(runner) != 0)
	pkg := mustGoPackage(t, "test/fpalias", "package fpalias\nfunc aliasTarget(*uint64)\nfunc aliasAnchor()\n")
	for _, triple := range arm64TypedNativeTargets {
		ctx := llvm.NewContext()
		tr, err := translateGoModuleInContext(ctx, pkg, []byte(target+anchor), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: triple,
			ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
		})
		if err == nil {
			tr.Module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s: aliased FP mutation cannot retain the original typed Ptr category: %v", triple, err)
		}
	}
	t.Log("actual native Go alias redirects caller continuation by one instruction; translation must retain Context")
}

func TestARM64PrivateFrameUnknownStoreRetainsMixedCodeUncertainty(t *testing.T) {
	for _, tc := range []struct {
		name     string
		value    arm64ControlValue
		preserve bool
	}{
		{"ordinary_data", arm64ControlExternal(), true},
		{"pure_code", arm64ControlFromMap(map[string]bool{"label:outer": true}), true},
		{"conservative_callee_code", arm64ControlFromMap(map[string]bool{"label:outer": true, "": true}), true},
		{"source_derived_code", arm64ControlFromMap(map[string]bool{"code-derived:": true, "": true}), false},
		{"escaped_frame", arm64ControlFromMap(map[string]bool{"sp:8": true}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller := arm64ControlFromMap(map[string]bool{"label:outer": true})
			state := &arm64ControlState{
				unexposedSP: true,
				regs:        map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R9": arm64ControlExternal()},
				memory:      map[string]arm64ControlValue{"sp:0": caller, "fp:0": arm64ControlExternal()},
			}
			state.write(Operand{Kind: OpMem, Mem: MemRef{Base: "R9"}}, tc.value, false)
			if intact := arm64ControlEqual(state.source(Operand{Kind: OpMem, Mem: MemRef{Base: SP}}, false), caller); intact != tc.preserve {
				t.Fatalf("filtered taint changed the original store uncertainty: preserve=%t, memory=%v, escaped=%v", intact, state.memory, state.escaped)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64TypedPrivateFramePointerStores(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	for _, tc := range []struct {
		name, body, decl, goCallee, goChecks, reference, cCallee string
	}{
		{
			name:      "incoming_pointer_store",
			body:      "MOVD p+0(FP),R9\nMOVD a+8(FP),R10\nMOVD R10,(R9)\nCALL ·X(SB)",
			goChecks:  "if data[0] != a { panic(\"typed data store mismatch\") }",
			reference: "memcpy(want + start, &a, sizeof a);",
		},
		{
			name:      "declared_pointer_callee",
			body:      "MOVD p+0(FP),R9\nMOVD a+8(FP),R10\nMOVD R9,8(RSP)\nMOVD R10,16(RSP)\nCALL ·X(SB)\nMOVD p+0(FP),R9\nMOVD a+8(FP),R10\nMOVD R10,8(R9)",
			decl:      "func X(*uint64,uint64)",
			goCallee:  "func X(p *uint64,a uint64) { *p=a*7+9 }",
			goChecks:  "if data[0] != a*7+9 || data[1]!=a { panic(\"typed pointer callee mismatch\") }",
			reference: "uint64_t changed = a * 7 + 9;\nmemcpy(want + start, &changed, sizeof changed);\nmemcpy(want + start + 8, &a, sizeof a);",
			cCallee:   "void X(void *p, uint64_t a) { uint64_t value = a * 7 + 9; memcpy(p, &value, sizeof value); }",
		},
		{
			name: "narrow_postindexed",
			body: "MOVD p+0(FP),R9\nMOVD a+8(FP),R10\nMOVH.P R10,2(R9)\nMOVW.P R10,4(R9)\nMOVD.P R10,8(R9)\nCALL ·X(SB)",
			goChecks: `bytes:=(*[32]byte)(unsafe.Pointer(&data[0]))
for j:=0;j<32;j++ {
  var want byte
  switch { case j<2: want=byte(a>>uint(j*8)); case j<6: want=byte(a>>uint((j-2)*8)); case j<14: want=byte(a>>uint((j-6)*8)) }
  if bytes[j]!=want { panic("typed postindex bytes mismatch") }
}`,
			reference: `for (int j = 0; j < 14; j++) {
  int source = j < 2 ? j : j < 6 ? j - 2 : j - 6;
  want[start + j] = (unsigned char)(a >> (source * 8));
}`,
		},
		{
			name:      "dynamic_data_offset",
			body:      "MOVD p+0(FP),R9\nMOVD a+8(FP),R10\nAND $3,R10,R11\nLSL $3,R11\nADD R11,R9,R9\nMOVD R10,(R9)\nCALL ·X(SB)",
			goChecks:  "for j,v:=range data { var want uint64; if j==int(a&3) { want=a }; if v!=want { panic(\"typed offset mismatch\") } }",
			reference: "memcpy(want + start + (a & 3) * 8, &a, sizeof a);",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.decl == "" {
				tc.decl, tc.goCallee = "func X()", "func X() {}"
			}
			if tc.cCallee == "" {
				tc.cCallee = "void X(void) {}"
			}
			source := "TEXT ·Y(SB),4,$48-24\n" + tc.body + "\nMOVD a+8(FP),R10\nADD $13,R10\nMOVD R10,ret+16(FP)\nRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			imports := ""
			if strings.Contains(tc.goChecks, "unsafe.") {
				imports = "import \"unsafe\"\n"
			}
			goMain := fmt.Sprintf(`package main
%s
func Y(*uint64, uint64) uint64
%s
func main() {
  for _, a := range []uint64{0, 1, 123, 0x8000000000000000, ^uint64(0)} {
    var data [4]uint64
    if Y(&data[0], a) != a+13 { panic("typed frame result mismatch") }
    %s
  }
}
`, imports, tc.goCallee, tc.goChecks)
			runARM64LocalRegisterGoOracle(t, source, goMain, len(runner) != 0)
			pkg := mustGoPackage(t, "test/privateframe", "package privateframe\nfunc Y(*uint64,uint64) uint64\n"+tc.decl+"\n")
			// The source-wide fresh-SP proof protects only the private saved
			// continuation. It does not make incoming data noalias or preserve
			// FP contents. Confirm real calls and pointer writes against Go,
			// then LLVM, rather than retaining a now-obsolete Context negative.
			for _, target := range arm64TypedNativeTargets {
				ctx := llvm.NewContext()
				tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
				})
				if err != nil {
					ctx.Dispose()
					t.Fatalf("%s: proven private frame with ordinary data stores: %v", target, err)
				}
				ir := tr.Module.String()
				tr.Module.Dispose()
				ctx.Dispose()
				compileLLVMToObject(t, llc, target, tc.name+".ll", tc.name+".o", ir)
			}

			ctx := llvm.NewContext()
			tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: triple,
				ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
			})
			if err != nil {
				ctx.Dispose()
				t.Fatal(err)
			}
			ir := tr.Module.String()
			tr.Module.Dispose()
			ctx.Dispose()
			driver := fmt.Sprintf(`#include <stdint.h>
#include <string.h>
extern uint64_t Y(void *, uint64_t);
%s
int main(void) {
  const uint64_t values[] = {0, 1, 123, UINT64_C(0x8000000000000000), UINT64_MAX};
  const int offsets[] = {0, 1, 3, 9, 15};
  for (unsigned v = 0; v < sizeof values / sizeof values[0]; v++) {
    for (unsigned o = 0; o < sizeof offsets / sizeof offsets[0]; o++) {
      uint64_t a = values[v];
      int start = 16 + offsets[o];
      unsigned char data[96], want[96];
      memset(data, 0xa5, sizeof data);
      memset(data + start, 0, 32);
      memcpy(want, data, sizeof data);
      %s
      if (Y(data + start, a) != a + 13) return 1;
      if (memcmp(data, want, sizeof data) != 0) return 2;
    }
  }
  return 0;
}
`, tc.cCallee, tc.reference)
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, tc.name, triple, ir, driver, runner)
		})
	}
}
