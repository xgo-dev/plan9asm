package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64OpaquePreservationUnclosedEffectBoundaries(t *testing.T) {
	base := arm64OpaquePreservationCases()[3] // Full pair offsets are not a new permission.
	pkg := mustGoPackage(t, "test/opaque", "package opaque\nfunc saveAlias(*uint64,*uint64)\nfunc Unknown()\n")
	for _, tc := range []struct {
		name, old, replacement string
	}{
		{"partial_save", "STP (R22,R21),0(RSP)", "MOVW R22,0(RSP)\nMOVD R21,8(RSP)"},
		{"partial_cell_write", "MOVD $77,R22", "MOVD $0,R4\nMOVW R4,0(RSP)\nMOVD $77,R22"},
		{"partial_restore", "LDP 0(RSP),(R22,R21)", "MOVWU 0(RSP),R22\nMOVD 8(RSP),R21"},
		{"swapped_restore", "LDP 0(RSP),(R22,R21)", "LDP 0(RSP),(R21,R22)"},
		{"missing_restore_branch", "LDP 0(RSP),(R22,R21)", "CBZ R4,skip_restore\nLDP 0(RSP),(R22,R21)\nskip_restore:"},
		{"numeric_use", "MOVD $77,R22", "MOVD R22,(R1)\nMOVD $77,R22"},
		{"address_use", "MOVD $77,R22", "MOVD (R22),R4\nMOVD $77,R22"},
		{"source_pointer_escape", "MOVD $77,R22", "MOVD RSP,R4\nMOVD R4,(R1)\nMOVD $77,R22"},
		{"unknown_call", "MOVD $77,R22", "CALL ·Unknown(SB)\nMOVD $77,R22"},
		{"restore_cell_offset", "LDP 0(RSP),(R22,R21)", "LDP 8(RSP),(R22,R21)"},
		{"restore_omitted", "LDP 0(RSP),(R22,R21)", "MOVD $1,R22\nMOVD $2,R21"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := arm64OpaquePreservationSource(base, arm64OpaqueObservationBody(false))
			if strings.Count(source, tc.old) != 1 {
				t.Fatal("negative mutation does not uniquely match the fresh original source")
			}
			source = strings.Replace(source, tc.old, tc.replacement, 1)
			arm64OpaqueOriginalObject(t, source)
			for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
				ctx := llvm.NewContext()
				tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: triple,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
				})
				if tr != nil && !tr.Module.IsNil() {
					tr.Module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s: unclosed opaque identity must remain Context: %v", triple, err)
				}
				t.Logf("UNGRANTED_BOUNDARY target=%s error=%v", triple, err)
			}
		})
	}
	t.Log("no new identity checker is present: these observations retain current Context, often at the first save; they do not certify a future checker rejects later effects independently")
}

func TestCrossLinuxRuntimeMatrixARM64OpaquePreservationDefinedControl(t *testing.T) {
	llc, nativeTriple, compiler, runner := arm64FPPairRuntimeTools(t)
	pkg := mustGoPackage(t, "test/opaque", "package opaque\nfunc saveAlias(*byte,*byte)\n")
	for _, tc := range arm64OpaquePreservationCases() {
		if strings.HasSuffix(tc.name, "_branch") {
			continue // Its separate original caller/CFG observation executes above.
		}
		t.Run(tc.name, func(t *testing.T) {
			prep := "MOVD (R0),R22\nMOVD 8(R0),R21\nMOVD 16(R0),R20\nMOVD 24(R0),R19\n"
			body := "MOVD $77,R22\nMOVD $88,R21\nMOVD $99,R20\nMOVD $111,R19\n"
			source := arm64OpaquePreservationSource(tc, body)
			source = strings.Replace(source, tc.save, prep+tc.save, 1)
			source = strings.Replace(source, "RET\n", "MOVD R22,(R1)\nMOVD R21,8(R1)\nMOVD R20,16(R1)\nMOVD R19,24(R1)\nRET\n", 1)
			arm64OpaqueOriginalObject(t, source)
			main := `package main
func saveAlias(*byte,*byte)
func main() {
  for offset:=1;offset<=5;offset++ {
    for seed:=0;seed<31;seed++ {
      var input [64]byte
      var output [80]byte
      for i:=range input { input[i]=byte(i*31+seed*17) }
      for i:=range output { output[i]=byte(i*13+0x53) }
      beforeIn,beforeOut:=input,output
      saveAlias(&input[offset],&output[offset+9])
      for i:=range input {
        if input[i]!=beforeIn[i] { panic("original input byte changed") }
      }
      for i:=range output {
        want:=beforeOut[i]
        if i>=offset+9 && i<offset+41 { want=beforeIn[offset+i-(offset+9)] }
        if output[i]!=want { panic("original full output/canary bytes differ") }
      }
    }
  }
}
`
			arm64OpaqueRunOriginalGo(t, source, main, len(runner) != 0)
			for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
				ctx := llvm.NewContext()
				tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: triple,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
				})
				defer ctx.Dispose()
				if tr != nil && !tr.Module.IsNil() {
					defer tr.Module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				ir := tr.Module.String()
				compileLLVMToObject(t, llc, triple, "opaque-defined-control.ll", "opaque-defined-control.o", ir)
				if triple == nativeTriple {
					c := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void saveAlias(const unsigned char *, unsigned char *);
int main(void) {
  for(int offset=1;offset<=5;offset++) {
    for(int seed=0;seed<31;seed++) {
      unsigned char input[64], output[80], beforeIn[64], beforeOut[80];
      for(int i=0;i<64;i++) input[i]=(unsigned char)(i*31+seed*17);
      for(int i=0;i<80;i++) output[i]=(unsigned char)(i*13+0x53);
      memcpy(beforeIn,input,64); memcpy(beforeOut,output,80);
      saveAlias(input+offset,output+offset+9);
      if(memcmp(input,beforeIn,64)) return 1;
      for(int i=0;i<80;i++) {
        unsigned char want=beforeOut[i];
        if(i>=offset+9 && i<offset+41) want=beforeIn[offset+i-(offset+9)];
        if(output[i]!=want) { fprintf(stderr,"byte %d offset %d seed %d\n",i,offset,seed); return 2; }
      }
    }
  }
  return 0;
}
`
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("opaque-defined-%s", tc.name), nativeTriple, ir, c, runner)
				}
			}
		})
	}
}
