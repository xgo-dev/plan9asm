package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86RoundCompleteGoAssemblerForms(t *testing.T) {
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT roundforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"ROUNDPS", "ROUNDPD", "ROUNDSS", "ROUNDSD"} {
				fmt.Fprintf(&source, "\t%s $0, X0, X1\n", op)
				fmt.Fprintf(&source, "\t%s $255, 8(BX), X2\n", op)
			}
			for _, op := range []string{"VROUNDPS", "VROUNDPD"} {
				fmt.Fprintf(&source, "\t%s $0, X0, X1\n", op)
				fmt.Fprintf(&source, "\t%s $-1, 16(BX), X2\n", op)
				fmt.Fprintf(&source, "\t%s $255, Y0, Y1\n", op)
				fmt.Fprintf(&source, "\t%s $2, 32(BX), Y2\n", op)
			}
			for _, op := range []string{"VROUNDSS", "VROUNDSD"} {
				fmt.Fprintf(&source, "\t%s $0, X0, X1, X2\n", op)
				fmt.Fprintf(&source, "\t%s $-1, 8(BX), X1, X2\n", op)
				fmt.Fprintf(&source, "\t%s $255, X0, X1, X2\n", op)
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"roundforms": {Name: "roundforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "round-"+target.name+".ll", "round-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86RoundRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	tests := []struct {
		goarch      string
		triple      string
		instruction string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "ROUNDSD $-1, X0, X1"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "ROUNDSS $256, X0, X1"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "ROUNDPD $0, Y0, Y1"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "ROUNDPS $0, X0, Y1"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "ROUNDSS.Z $0, X0, X1"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VROUNDPS $-129, X0, X1"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VROUNDPD $256, Y0, Y1"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VROUNDPS $0, X0, Y1"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VROUNDSS $0, X0, X1"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VROUNDSD $0, X0, Y1, X2"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "VROUNDSS $0, X0, X1, Y2"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "ROUNDSS $0, X8, X0"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "VROUNDPS $0, Y8, Y0"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "VROUNDSD $0, X0, X8, X1"},
	}
	for _, test := range tests {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+test.instruction+"\n\tRET\n")
			if err == nil {
				_, err = Translate(file, Options{
					TargetTriple: test.triple,
					Goarch:       test.goarch,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				})
			}
			if err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ROUND tables for %s", test.instruction, test.goarch)
			}
		})
	}
}

func TestAMD64RoundRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT roundsemantics(SB),NOSPLIT,$0-40
	MOVQ out+0(FP), AX
	MOVQ a32+8(FP), BX
	MOVQ a64+16(FP), CX
	MOVQ upper32+24(FP), DX
	MOVQ upper64+32(FP), SI
	ROUNDPS $0, (BX), X0
	MOVUPS X0, 0(AX)
	ROUNDPS $1, (BX), X0
	MOVUPS X0, 16(AX)
	ROUNDPS $2, (BX), X0
	MOVUPS X0, 32(AX)
	ROUNDPS $3, (BX), X0
	MOVUPS X0, 48(AX)
	ROUNDPS $4, (BX), X0
	MOVUPS X0, 64(AX)
	MOVUPS (DX), X1
	VROUNDSS $1, (BX), X1, X2
	MOVUPS X2, 80(AX)
	ROUNDPD $0, (CX), X0
	MOVUPD X0, 96(AX)
	ROUNDPD $1, (CX), X0
	MOVUPD X0, 112(AX)
	ROUNDPD $2, (CX), X0
	MOVUPD X0, 128(AX)
	ROUNDPD $3, (CX), X0
	MOVUPD X0, 144(AX)
	ROUNDPD $4, (CX), X0
	MOVUPD X0, 160(AX)
	MOVUPD (SI), X1
	VROUNDSD $2, (CX), X1, X2
	MOVUPD X2, 176(AX)
	VZEROUPPER
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		{Offset: 16, Type: Ptr, Index: 2, Field: -1},
		{Offset: 24, Type: Ptr, Index: 3, Field: -1},
		{Offset: 32, Type: Ptr, Index: 4, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"roundsemantics": {Name: "roundsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern void roundsemantics(uint8_t *, const float *, const double *, const float *, const double *);
static int check32(const float *got, const float *want, int base) {
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return base+i;
  return 0;
}
static int check64(const double *got, const double *want, int base) {
  for (int i = 0; i < 2; i++) if (got[i] != want[i]) return base+i;
  return 0;
}
int main(void) {
  float a32[4] = {1.5f, -1.5f, 2.75f, -2.75f};
  double a64[2] = {2.5, -2.5};
  float upper32[4] = {99.0f, 10.0f, 20.0f, 30.0f};
  double upper64[2] = {99.0, 40.0};
  float want32[6][4] = {
    {2, -2, 3, -3}, {1, -2, 2, -3}, {2, -1, 3, -2},
    {1, -1, 2, -2}, {2, -2, 3, -3}, {1, 10, 20, 30},
  };
  double want64[6][2] = {
    {2, -2}, {2, -3}, {3, -2}, {2, -2}, {2, -2}, {3, 40},
  };
  uint8_t out[192] = {0};
  roundsemantics(out, a32, a64, upper32, upper64);
  for (int i = 0; i < 6; i++) {
    int failed = check32((const float *)(out + 16*i), want32[i], 10+4*i);
    if (failed) return failed;
  }
  for (int i = 0; i < 6; i++) {
    int failed = check64((const double *)(out + 96 + 16*i), want64[i], 40+2*i);
    if (failed) return failed;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "round_semantics", triple, ll, mainC, runPrefix)
}
