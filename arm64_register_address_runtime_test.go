package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64RegisterAddress(t *testing.T) {
	runARM64RegisterAddressRuntime(t, []string{"R2", "R27", "RSP"}, []string{"R2", "R27", "RSP"})
}

func TestCrossLinuxRuntimeMatrixARM64RegisterAddressScratch(t *testing.T) {
	runARM64RegisterAddressRuntime(t, []string{"R27"}, []string{"R2"})
}

func TestCrossLinuxRuntimeMatrixARM64RegisterAddressZeroBase(t *testing.T) {
	// Go classifies a zero base as a constant, not C_AACON/C_LACON. It
	// neither reads SP nor performs the large-address R27 materialization.
	runARM64RegisterAddressRuntime(t, []string{"ZR"}, []string{"R2", "R27"})
}

func runARM64RegisterAddressRuntime(t *testing.T, bases, destinations []string) {
	t.Helper()
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, goDecl, cDecl, goChecks, cChecks strings.Builder
	sigs := make(map[string]FuncSig)
	count := 0
	for _, offset := range []int64{-65537, -65536, -4097, -4096, -1, 0, 1, 4095, 4096, 4097, 5900, 65536, 65537} {
		for _, base := range bases {
			for _, destination := range destinations {
				name := fmt.Sprintf("registerAddress%d", count)
				count++
				fmt.Fprintf(&source, `TEXT ·%s(SB),516,$0-16
MOVD a+0(FP),R0
MOVD out+8(FP),R10
MOVD RSP,R20
MOVD R0,R2
MOVD $73,R27
CMP $1,R0
CSET EQ,R12
CSET MI,R13
CSET CS,R14
CSET VS,R15
MOVD $%d(%s),%s
MOVD %s,R3
MOVD R20,RSP
`, name, offset, base, destination, destination)
				if base == "RSP" {
					source.WriteString("SUB R20,R3\n")
				}
				source.WriteString("MOVD R3,0(R10)\n")
				if base == "RSP" && destination == "R27" {
					// Stack addresses differ between the independent programs.
					// Compare the emitted address relative to its captured SP.
					source.WriteString("SUB R20,R27\n")
				}
				source.WriteString(`MOVD R27,8(R10)
CSET EQ,R3
EOR R12,R3
CSET MI,R4
EOR R13,R4
ORR R4,R3
CSET CS,R4
EOR R14,R4
ORR R4,R3
CSET VS,R4
EOR R15,R4
ORR R4,R3
MOVD R3,16(R10)
RET
`)
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{I64, Ptr}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: I64, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					}},
				}
				fmt.Fprintf(&goDecl, "func %s(uint64,*[3]uint64)\n", name)
				fmt.Fprintf(&cDecl, "extern void %s(uint64_t,uint64_t*);\n", name)
				// The independent oracle follows Go's emitted ADD/SUB and
				// literal-load sequence, including read-after-clobber R27.
				scratch := base != "ZR" && (offset < 0 && !arm64RuntimeAddressSingleImmediate(-offset) || offset > 0xffffff)
				want := "a+uint64(offset)"
				wantC := fmt.Sprintf("a+(uint64_t)(INT64_C(%d))", offset)
				if base == "RSP" || base == "ZR" {
					want, wantC = "uint64(offset)", fmt.Sprintf("(uint64_t)(INT64_C(%d))", offset)
				} else if base == "R27" {
					baseValue := int64(73)
					if scratch {
						baseValue = offset
					}
					want = "uint64(73)+uint64(offset)"
					if scratch {
						want = "uint64(offset)+uint64(offset)"
					}
					wantC = fmt.Sprintf("(uint64_t)(INT64_C(%d))+(uint64_t)(INT64_C(%d))", baseValue, offset)
				}
				wantScratch, wantScratchC := "uint64(73)", "UINT64_C(73)"
				if scratch {
					wantScratch, wantScratchC = "uint64(offset)", fmt.Sprintf("(uint64_t)(INT64_C(%d))", offset)
				}
				if destination == "R27" {
					wantScratch, wantScratchC = want, wantC
				}
				fmt.Fprintf(&goChecks, `
for _,a:=range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
var out [3]uint64
offset:=int64(%d)
%s(a,&out)
if out != [3]uint64{%s,%s,0} { println("%s",a,out[0],out[1],out[2]);panic("register-address Go oracle") }
}
`, offset, name, want, wantScratch, name)
				fmt.Fprintf(&cChecks, `
for(unsigned i=0;i<5;i++) {
uint64_t a=inputs[i],out[3]={0};
%s(a,out);
if(out[0]!=(%s)||out[1]!=(%s)||out[2]!=0) {
fprintf(stderr,"%s address/scratch/flags mismatch: %%llx %%llx %%llx\n",(unsigned long long)out[0],(unsigned long long)out[1],(unsigned long long)out[2]);return 1;
}
}
`, name, wantC, wantScratchC, name)
			}
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	runARM64LocalRegisterGoOracle(t, source.String(), "package main\n"+goDecl.String()+"func main(){\n"+goChecks.String()+"}\n", len(runner) != 0)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n" + cDecl.String() + "int main(void){uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};\n" + cChecks.String() + "return 0;}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "register_address", triple, ir, main, runner)
	t.Logf("%d address functions x 5 inputs match native Go and LLVM/C", count)
}

func arm64RuntimeAddressSingleImmediate(value int64) bool {
	return value >= 0 && (value <= 4095 || value%4096 == 0 && value/4096 <= 4095)
}
