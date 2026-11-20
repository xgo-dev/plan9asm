package plan9asm

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const arm64PrivateCallCFGCopySource = `TEXT ·Copy(SB),4,$0-24
MOVD dst+0(FP),R8
MOVD src+8(FP),R1
MOVD n+16(FP),R3
CMP $32,R3
BLS bounded
MOVD $32,R3
bounded:
CALL copy<>(SB)
RET
TEXT copy<>(SB),516,$0-0
CBZ R3,copy0
CMP $16,R3
BLE copy16
LDP (R1),(R21,R22)
ADD R1,R3,R15
LDP -16(R15),(R23,R24)
STP (R21,R22),(R8)
ADD R8,R3,R26
STP (R23,R24),-16(R26)
RET
copy16:
ADD R1,R3,R15
ADD R8,R3,R26
CMP $8,R3
BLT copy7
MOVD (R1),R21
MOVD -8(R15),R22
MOVD R21,(R8)
MOVD R22,-8(R26)
RET
copy7:
TBZ $2,R3,copy3
MOVWU (R1),R21
MOVWU -4(R15),R22
MOVW R21,(R8)
MOVW R22,-4(R26)
RET
copy3:
TBZ $1,R3,copy1
MOVHU (R1),R21
MOVHU -2(R15),R22
MOVH R21,(R8)
MOVH R22,-2(R26)
RET
copy1:
MOVBU (R1),R21
MOVBU R21,(R8)
copy0:
RET
`

func TestARM64PrivateCallCFGSourcePreparation(t *testing.T) {
	register := strings.Replace(arm64PrivateRegisterHelperSource("516,$0-0", "CALL mix<>(SB)"),
		"ADC $0,R9,R20\nMUL R19,R20,R20\nRET", `CBZ R19,zero
ADC $0,R9,R20
MUL R19,R20,R20
RET
zero:
MOVD $7,R20
RET`, 1)
	for _, test := range []struct {
		name, source string
	}{
		{"register_multiple_returns", register},
		{"lexical_backward_acyclic_edge", strings.Replace(register,
			"CBZ R19,zero\nADC", "B forward\nbackward:\nRET\nforward:\nCBZ R19,backward\nADC", 1)},
		{"typed_scalar_pair_copy", arm64PrivateCallCFGCopySource},
		{"two_static_calls", strings.Replace(arm64PrivateCallCFGCopySource,
			"CALL copy<>(SB)", "CALL copy<>(SB)\nCALL copy<>(SB)", 1)},
		{"caller_label_collision", strings.Replace(arm64PrivateCallCFGCopySource,
			"CALL copy<>(SB)", "__arm64_private_0:\ncopy0:\nCALL copy<>(SB)", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			requireARM64GoAssemblerResult(t, test.source, true)
			file, err := Parse(ArchARM64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			original, err := Parse(ArchARM64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
			if err != nil {
				t.Fatal("closed private call CFG did not preserve its source continuation:", err)
			}
			if prepared == file || len(prepared.Funcs) != 1 || !reflect.DeepEqual(file, original) {
				t.Fatal("continuation preparation changed the original file or invented a callable helper")
			}
			repeated, err := CoalesceARM64PrivateRegisterHelpers(prepared)
			if err != nil || !reflect.DeepEqual(prepared, repeated) {
				t.Fatalf("repeated continuation preparation changed its source: %v", err)
			}
		})
	}
}

func TestARM64PrivateCallCFGRejectsUnclosedSource(t *testing.T) {
	for _, test := range []struct {
		name, source string
	}{
		{"cycle", strings.Replace(arm64PrivateCallCFGCopySource, "copy0:\nRET", "copy0:\nB copy0", 1)},
		{"dead_cycle", arm64PrivateCallCFGCopySource + "dead:\nB dead\n"},
		{"unbound_target", strings.Replace(arm64PrivateCallCFGCopySource, "CBZ R3,copy0", "CBZ R3,missing", 1)},
		{"hidden_stack", strings.Replace(arm64PrivateCallCFGCopySource, "LDP (R1)", "LDP (RSP)", 1)},
		{"saved_link", strings.Replace(arm64PrivateCallCFGCopySource, "ADD R8,R3,R26", "ADD R8,R3,R30", 1)},
		{"scratch", strings.Replace(arm64PrivateCallCFGCopySource, "ADD R8,R3,R26", "ADD R8,R3,R27", 1)},
		{"faulting_expansion", strings.Replace(arm64PrivateCallCFGCopySource, "ADD R8,R3,R26", "CMP $1,ZR", 1)},
		{"callout", strings.Replace(arm64PrivateCallCFGCopySource, "copy0:\nRET", "copy0:\nCALL foreign(SB)\nRET", 1)},
		{"address_escape", arm64PrivateCallCFGCopySource + "TEXT observer<>(SB),516,$0\nMOVD $copy<>(SB),R0\nRET\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := CoalesceARM64PrivateRegisterHelpers(file); result != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unclosed source gained a private CALL continuation: %v", err)
			}
		})
	}
}

func TestARM64PrivateCallCFGPreparedSourceCannotBeChanged(t *testing.T) {
	for _, mutation := range []string{"instruction", "argument", "frame", "symbol", "entry", "source_accounting"} {
		t.Run(mutation, func(t *testing.T) {
			file, err := Parse(ArchARM64, arm64PrivateCallCFGCopySource)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
			if err != nil {
				t.Fatal(err)
			}
			root := &prepared.Funcs[0]
			switch mutation {
			case "instruction":
				root.Instrs[1].Op = "MOVW"
			case "argument":
				root.Instrs[1].Args[1].Reg = "R30"
			case "frame":
				root.FrameSize++
			case "symbol":
				root.Sym = "another"
			case "entry":
				root.arm64PrivateRegisterEntry = false
			case "source_accounting":
				root.arm64PrivateSourceAdded--
			}
			if _, err := CoalesceARM64PrivateRegisterHelpers(prepared); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed prepared source kept its original admission: %v", err)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64PrivateCallCFGCopy(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	pkg := mustGoPackage(t, "test/privatecopy", "package privatecopy\nfunc Copy(dst,src *[32]byte,n uint64)\n")
	for _, calls := range []int{1, 2} {
		source := arm64PrivateCallCFGCopySource
		if calls == 2 {
			source = strings.Replace(source, "CALL copy<>(SB)", "CALL copy<>(SB)\nCALL copy<>(SB)", 1)
		}
		t.Run(strconv.Itoa(calls)+"_calls", func(t *testing.T) {
			goProgram := `package main
import "unsafe"
func Copy(dst,src *[32]byte,n uint64)
func main() {
    for _,d := range []int{0,1,7,16,32} {
        for _,s := range []int{0,1,7,16,32} {
            for _,n := range []uint64{0,1,2,3,4,7,8,15,16,17,23,31,32,33,64,^uint64(0)} {
                var data,want [128]byte
                for i := range data { data[i] = byte(i*37+d*11+s*7+int(n)); want[i] = data[i] }
                q := n
                if q > 32 { q = 32 }
                for pass := 0; pass < REPEATS; pass++ {
                    var snapshot [32]byte
                    for i := uint64(0); i < q; i++ { snapshot[i] = want[s+int(i)] }
                    for i := uint64(0); i < q; i++ { want[d+int(i)] = snapshot[i] }
                }
                Copy((*[32]byte)(unsafe.Pointer(&data[d])), (*[32]byte)(unsafe.Pointer(&data[s])), n)
                if data != want { panic("original Go private CFG copy/full-canary mismatch") }
            }
        }
    }
    Copy(nil,nil,0)
}
`
			goProgram = strings.ReplaceAll(goProgram, "REPEATS", strconv.Itoa(calls))
			runARM64LocalRegisterGoOracle(t, source, goProgram, len(runner) != 0)
			translate := func(target string) string {
				context := llvm.NewContext()
				defer context.Dispose()
				result, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target,
					ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
				})
				if err != nil {
					t.Fatal(err)
				}
				defer result.Module.Dispose()
				if len(result.Signatures) != 1 || len(result.Functions) != 1 {
					t.Fatal("private continuation acquired an independent function ABI")
				}
				return result.Module.String()
			}
			for _, target := range arm64TypedNativeTargets {
				compileLLVMToObject(t, llc, target, "private-call-cfg.ll", "private-call-cfg.o", translate(target))
			}
			cProgram := `#include <stdint.h>
#include <string.h>
extern void Copy(void *,const void *,uint64_t);
int main(void) {
    const int offsets[] = {0,1,7,16,32};
    const uint64_t sizes[] = {0,1,2,3,4,7,8,15,16,17,23,31,32,33,64,UINT64_MAX};
    for (unsigned d=0; d<5; d++) for (unsigned s=0; s<5; s++) for (unsigned z=0; z<16; z++) {
        unsigned char data[128],want[128];
        uint64_t n=sizes[z],q=n>32?32:n;
        for (unsigned i=0; i<128; i++) data[i]=want[i]=(unsigned char)(i*37+offsets[d]*11+offsets[s]*7+n);
        for (int pass=0; pass<REPEATS; pass++) memmove(want+offsets[d],want+offsets[s],q);
        Copy(data+offsets[d],data+offsets[s],n);
        if (memcmp(data,want,128)) return 1;
    }
    Copy(0,0,0);
    return 0;
}
`
			cProgram = strings.ReplaceAll(cProgram, "REPEATS", strconv.Itoa(calls))
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "private-call-cfg", triple, translate(triple), cProgram, runner)
		})
	}
}
