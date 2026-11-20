package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Execute the exact original FP source, not a GP-source substitute. The tiny
// test-only native bridge owns an ABI0 argument/result area for those actual
// Go object bytes and retains the four bytes immediately after the result.
// Neither this bridge nor its initialized bytes grant production native-FP,
// fixed-local, caller or pointer permission.
func TestCrossLinuxRuntimeMatrixX86AESFamilyScalarInsertResult(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	const source = "TEXT ·view(SB),4,$0-12\nMOVL k+0(FP),X0\nPINSRD $1,k+0(FP),X0\nAESENC X0,X0\nMOVL X0,ret+8(FP)\nRET\n"
	code := x86OrderingHintGoBytes(t, "amd64", source)
	var encoded []string
	for _, value := range code {
		encoded = append(encoded, fmt.Sprintf("0x%02x", value))
	}
	original, bridge := "OriginalGoAESScalar", "OriginalGoAESScalarBridge"
	if strings.Contains(execution.triple, "apple") {
		original, bridge = "_"+original, "_"+bridge
	}
	assembly := ".text\n.globl " + original + "\n" + original + ":\n.byte " + strings.Join(encoded, ",") +
		"\n.globl " + bridge + "\n" + bridge + ":\nsubq $24,%rsp\nmovl %edi,0(%rsp)\nmovl %esi,4(%rsp)\nmovl $0xc3c3c3c3,8(%rsp)\nmovl $0x6d6d6d6d,12(%rsp)\ncall " + original + "\nmovq 8(%rsp),%rax\naddq $24,%rsp\nret\n"
	// This reference uses independent FIPS-197 arithmetic. It does not reuse
	// the production grammar, LLVM AES intrinsic or byte-definedness model.
	reference := x86AESIndependentC + fmt.Sprintf("\n__asm__(%q);\n", assembly) +
		x86OriginalSysVDeclaration("uint64_t", "OriginalGoAESScalarBridge", "uint32_t,uint32_t") + `
extern uint32_t view(uint32_t,uint32_t);
int main(void){
 for(unsigned sample=0;sample<64;sample++){
  const uint32_t special[4]={0,0xffffffff,0x80000000,0x01234567};
  uint32_t k=sample<4?special[sample]:sample*0x9137a5c3u+0x87654321u,h=k^0x6b5917d3u;
  uint8_t input[16]={0},expected[16];uint32_t want;
  memcpy(input,&k,4);memcpy(input+4,&k,4);aes(expected,input,input,0,0);memcpy(&want,expected,4);
  uint64_t original=OriginalGoAESScalarBridge(k,h);uint32_t translated=view(k,h);
  if((uint32_t)original!=want||(original>>32)!=0x6d6d6d6du||translated!=want){
   fprintf(stderr,"mixed AES scalar sample%u original%llx translated%x expected%x\n",sample,(unsigned long long)original,translated,want);return 1;
  }
 }
 puts("mixed AES scalar exact Go bytes/FIPS/translated samples 64 result-canary failures 0");return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, "func view(k,h uint32) uint32\n", "amd64", execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, axis := range []struct{ name, level string }{{"backend_O0", "-O0"}, {"backend_O2", "-O2"}, {"IR_O2/backend_O2", "-O2"}} {
			t.Run(api+"/"+axis.name, func(t *testing.T) {
				optimized := ir
				if strings.HasPrefix(axis.name, "IR_O2/") {
					optimized = x86DwordProductIROptimize(t, ir)
				}
				output := execution.compileAndRunLLVM(t, "aes-scalar-result", optimized, reference, axis.level)
				if string(output) != "mixed AES scalar exact Go bytes/FIPS/translated samples 64 result-canary failures 0\n" {
					t.Fatal("unbound mixed-source runtime result", string(output))
				}
			})
		}
	}
	t.Logf("exact original Go FP source bytes %x; 3 translation APIs x3 explicit optimization axes x64 independent result/canary samples (host transport, not native Linux)", code)
}
