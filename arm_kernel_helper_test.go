package plan9asm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const armKernelHelperSource = `
TEXT first<>(SB),$0
 MOVW $0xffff0fc0,R15
TEXT second<>(SB),$0
 MOVW $0xffff0fa0,R15
TEXT oracle(SB),$0-16
 MOVW ptr+0(FP),R2
 MOVW old+4(FP),R0
 MOVW next+8(FP),R1
 MOVW out+12(FP),R4
 BL first<>(SB)
 MOVW CPSR,R7
 AND $(1<<29),R7
 SRL $29,R7
 MOVW R7,16(R4)
 MOVW R0,0(R4)
 MOVW $0,R3
 MOVW.CS $1,R3
 MOVW R3,4(R4)
 MOVW R1,8(R4)
 MOVW (R2),R5
 MOVW R5,12(R4)
 BL second<>(SB)
 MOVW $0,R6
 MOVW.CS $1,R6
 MOVW R6,4(R4)
 MOVW R0,0(R4)
 MOVW R1,8(R4)
 MOVW (R2),R5
 MOVW R5,12(R4)
 RET
`

func armKernelHelperSigs() map[string]FuncSig {
	return map[string]FuncSig{
		"first<>":  {Name: "first<>", Ret: Void},
		"second<>": {Name: "second<>", Ret: Void},
		"oracle": {
			Name: "oracle", Args: []LLVMType{Ptr, I32, I32, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 4, Type: I32, Index: 1, Field: -1},
				{Offset: 8, Type: I32, Index: 2, Field: -1},
				{Offset: 12, Type: Ptr, Index: 3, Field: -1},
			}},
		},
	}
}

func TestARMKernelHelperCallsNeedTypedNativeContract(t *testing.T) {
	requireARMGoAssemblerResult(t, armKernelHelperSource, true)
	file, err := Parse(ArchARM, armKernelHelperSource)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf"} {
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: armKernelHelperSigs()})
		if err != nil {
			t.Fatalf("closed Linux native helper must retain its register/carry/memory contract: %v", err)
		}
		for _, want := range []string{"blx", "mrs", "~{memory}", "{r0}", "{r1}", "{r2}", "extractvalue", "store i32"} {
			if !strings.Contains(ir, want) {
				t.Fatalf("native helper contract missing %q:\n%s", want, ir)
			}
		}
		if strings.Contains(ir, "call void @\"first<>\"") || strings.Contains(ir, "call void @\"second<>\"") {
			t.Fatal("private machine-register helper cannot use the old void C ABI")
		}
		compileLLVMToObject(t, llc, triple, "kernel-helper.ll", "kernel-helper.o", ir)
	}
}

func TestARMKernelHelperGoBindingRequiresRealNativeContract(t *testing.T) {
	pkg := mustGoPackage(t, "example.com/kernel", "package kernel\nfunc oracle(ptr *uint32, old,next uint32,out *[5]uint32)\n")
	resolve := func(name string) string {
		if strings.HasSuffix(name, "<>") {
			return "example.com/kernel." + strings.TrimSuffix(name, "<>") + "$local"
		}
		return "example.com/kernel." + name
	}
	translation, err := TranslateGoModule(pkg, []byte(armKernelHelperSource), GoModuleOptions{
		GOOS: "linux", GOARCH: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", ResolveSym: resolve,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translation.Module.Dispose()
	if !strings.Contains(translation.Module.String(), "blx") {
		t.Fatal("Go binding did not retain the native kernel contract")
	}
}

func TestARMKernelHelperRequiresClosedSourceAndLinuxTarget(t *testing.T) {
	tests := []struct {
		name, source, triple string
		mutate               func(map[string]FuncSig)
	}{
		{"unknown_entry", strings.Replace(armKernelHelperSource, "0xffff0fc0", "0xffff0fc4", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"extra_body", strings.Replace(armKernelHelperSource, "MOVW $0xffff0fc0,R15", "ADD $1,R0\n MOVW $0xffff0fc0,R15", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"helper_frame", strings.Replace(armKernelHelperSource, "TEXT first<>(SB),$0", "TEXT first<>(SB),$4", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"public_entry", strings.ReplaceAll(armKernelHelperSource, "first<>", "first"), "armv7-unknown-linux-gnueabihf", nil},
		{"address_escape", strings.Replace(armKernelHelperSource, "BL first<>(SB)", "MOVW $first<>(SB),R6\n BL first<>(SB)", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"offset_reference", strings.Replace(armKernelHelperSource, "BL first<>(SB)", "BL first<>+4(SB)", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"data_escape", armKernelHelperSource + "DATA escaped+0(SB)/4,$first<>(SB)\nGLOBL escaped(SB),$4\n", "armv7-unknown-linux-gnueabihf", nil},
		{"no_callers", "TEXT first<>(SB),$0\n MOVW $0xffff0fc0,R15\n", "armv7-unknown-linux-gnueabihf", nil},
		{"missing_input", strings.Replace(armKernelHelperSource, "MOVW old+4(FP),R0", "NOP", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"unknown_overwrite", strings.Replace(armKernelHelperSource, "BL first<>(SB)", "ADD R7,R0\n BL first<>(SB)", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"conditional_input", strings.Replace(armKernelHelperSource, "MOVW old+4(FP),R0", "CMP R2,R2\n MOVW.EQ old+4(FP),R0", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"joined_input", strings.Replace(armKernelHelperSource, "MOVW old+4(FP),R0", "CMP $0,R2\n BEQ joined\n MOVW old+4(FP),R0\njoined:", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"unproved_predicate", strings.Replace(armKernelHelperSource, "BL first<>(SB)", "CMP $0,R7\n BL.EQ first<>(SB)", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"unproved_status_write", strings.Replace(armKernelHelperSource, "BL first<>(SB)", "CMP R2,R2\n MOVW R7,CPSR\n BL.CS first<>(SB)", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"undefined_native_flags", strings.Replace(armKernelHelperSource, "MOVW.CS $1,R3", "MOVW.EQ $1,R3", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"unreachable_input", strings.Replace(armKernelHelperSource, "BL first<>(SB)", "RET\n BL first<>(SB)", 1), "armv7-unknown-linux-gnueabihf", nil},
		{"missing_target", armKernelHelperSource, "", nil},
		{"windows", armKernelHelperSource, "thumbv7-pc-windows-msvc", nil},
		{"explicit_go_abi", armKernelHelperSource, "armv7-unknown-linux-gnueabihf", func(sigs map[string]FuncSig) {
			sig := sigs["first<>"]
			sig.Args = []LLVMType{I32}
			sigs["first<>"] = sig
		}},
		{"signature_name_conflict", armKernelHelperSource, "armv7-unknown-linux-gnueabihf", func(sigs map[string]FuncSig) {
			sigs["first<>"] = FuncSig{Name: "other", Ret: Void}
		}},
		{"register_signature_conflict", armKernelHelperSource, "armv7-unknown-linux-gnueabihf", func(sigs map[string]FuncSig) {
			sigs["first<>"] = FuncSig{Name: "first<>", Ret: Void, ArgRegs: []Reg{"R0"}}
		}},
		{"missing_helper_signature", armKernelHelperSource, "armv7-unknown-linux-gnueabihf", func(sigs map[string]FuncSig) {
			delete(sigs, "first<>")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := Parse(ArchARM, test.source)
			if err != nil {
				t.Fatal(err)
			}
			sigs := armKernelHelperSigs()
			if test.name == "public_entry" {
				sigs["first"] = FuncSig{Name: "first", Ret: Void}
			}
			if test.mutate != nil {
				test.mutate(sigs)
			}
			_, err = Translate(file, Options{Goarch: "arm", TargetTriple: test.triple, Sigs: sigs})
			if test.name == "signature_name_conflict" || test.name == "missing_helper_signature" {
				if err == nil || !strings.Contains(err.Error(), "signature") {
					t.Fatalf("invalid signature metadata must fail before native lowering: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved native helper must remain a context failure: %v", err)
			}
		})
	}
}

func TestARMKernelHelperInputProofFollowsAllPredecessors(t *testing.T) {
	for _, source := range []string{
		strings.Replace(armKernelHelperSource, "BL first<>(SB)", "joined:\n BL first<>(SB)", 1),
		strings.Replace(armKernelHelperSource, "MOVW old+4(FP),R0", "CMP $0,R2\n BEQ alternate\n MOVW old+4(FP),R0\n B joined\nalternate:\n MOVW old+4(FP),R0\njoined:", 1),
		strings.Replace(armKernelHelperSource, "BL first<>(SB)", "CMP $0,R2\nloop:\n BL first<>(SB)\n CMP $0,R0\n BNE loop", 1),
	} {
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: armKernelHelperSigs()}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestARMKernelHelperBranchGrammarAndSourceImmutability(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, branch := range []string{"BL", "CALL", "B", "JMP", "BL.EQ", "CALL.NE", "BL.CS", "BL.CC", "BL.HI", "BL.LS", "BL.MI", "BL.PL", "BL.VS", "BL.VC", "BL.GE", "BL.LT", "BL.GT", "BL.LE", "BL.HS", "BL.LO"} {
		t.Run(branch, func(t *testing.T) {
			source := "TEXT unnamed<>(SB),$0\n MOVW $0xffff0fc0,R15\nTEXT caller(SB),$0-12\n MOVW ptr+0(FP),R2\n MOVW old+4(FP),R0\n MOVW next+8(FP),R1\n CMP R0,R0\n " + branch + " unnamed<>(SB)\n RET\n"
			requireARMGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			sig := armKernelHelperSigs()["oracle"]
			sig.Name, sig.Args, sig.Frame.Params = "caller", sig.Args[:3], sig.Frame.Params[:3]
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
				"unnamed<>": {Name: "unnamed<>", Ret: Void}, "caller": sig,
			}})
			if err != nil {
				t.Fatal(err)
			}
			if len(file.Funcs) != 2 || file.Funcs[1].Instrs[5].armKernelCall != nil {
				t.Fatal("closed-helper lowering mutated the source inventory")
			}
			compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "kernel-branch.ll", "kernel-branch.o", ir)
		})
	}
	for _, branch := range []string{"B.EQ", "JMP.NE", "BEQ", "BCC", "BCS", "BHI", "BLS", "BMI", "BPL", "BVS", "BVC", "BGE", "BLT", "BGT", "BLE", "BHS", "BLO"} {
		t.Run("rejected_"+branch, func(t *testing.T) {
			source := strings.Replace(armKernelHelperSource, "BL first<>(SB)", branch+" first<>(SB)", 1)
			requireARMGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: armKernelHelperSigs()}); err == nil {
				t.Fatal("native contract accepted a conditional symbolic tail branch rejected by Go")
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARMKernelHelper(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("set PLAN9ASM_CROSS_EXEC=1 for actual Linux ARM kernel-helper execution")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatal("kernel-helper runtime oracle requires a Linux driver")
	}
	for _, tool := range []string{"arm-linux-gnueabihf-gcc", "qemu-arm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	source := armKernelHelperSource + `
TEXT tail(SB),NOSPLIT|NOFRAME,$0-12
 MOVW ptr+0(FP),R2
 MOVW old+4(FP),R0
 MOVW next+8(FP),R1
 B first<>(SB)
TEXT conditional(SB),$0-16
 MOVW ptr+0(FP),R2
 MOVW old+4(FP),R0
 MOVW next+8(FP),R1
 MOVW out+12(FP),R4
 CMP R0,R0
 BL.NE first<>(SB)
 MOVW R0,0(R4)
 MOVW $0,R3
 MOVW.CS $1,R3
 MOVW R3,4(R4)
 MOVW R1,8(R4)
 MOVW (R2),R5
 MOVW R5,12(R4)
 RET
TEXT status(SB),$0-16
 MOVW ptr+0(FP),R2
 MOVW old+4(FP),R0
 MOVW next+8(FP),R1
 MOVW out+12(FP),R4
 BL first<>(SB)
 MOVW R0,0(R4)
 CMP R2,R2
 MOVW CPSR,R3
 AND $0xf0000000,R3
 SRL $28,R3
 MOVW R3,4(R4)
 RET
`
	sigs := armKernelHelperSigs()
	tailSig := sigs["oracle"]
	tailSig.Name, tailSig.Args, tailSig.Frame.Params = "tail", tailSig.Args[:3], tailSig.Frame.Params[:3]
	sigs["tail"] = tailSig
	conditionalSig := sigs["oracle"]
	conditionalSig.Name = "conditional"
	sigs["conditional"] = conditionalSig
	statusSig := sigs["oracle"]
	statusSig.Name = "status"
	sigs["status"] = statusSig
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const goMain = `package main
func oracle(ptr *uint32, old,next uint32,out *[5]uint32)
func conditional(ptr *uint32, old,next uint32,out *[4]uint32)
func tail(ptr *uint32,old,next uint32)
func status(ptr *uint32,old,next uint32,out *[2]uint32)
func main() {
 for _, initial := range []uint32{0,1,0x80000000,0xffffffff,0x12345678} {
  for _, success := range []bool{true,false} {
   word,old,next := initial,initial,initial^0xabcdef01
   if !success { old ^= 1 }
   var out [5]uint32
   oracle(&word,old,next,&out)
   want,carry := initial,uint32(0)
   if success { want,carry = next,1 }
   if (out[0] == 0) != success || out[1] != carry || out[2] != next || out[3] != want || out[4] != carry || word != want { panic("Go kernel CAS contract") }
   word = initial
   var conditionalOut [4]uint32
   conditional(&word,old,next,&conditionalOut)
   if conditionalOut != [4]uint32{old,1,next,initial} || word != initial { panic("Go predicated native call") }
   tail(&word,old,next)
   if word != want { panic("Go native tail continuation") }
   word = initial
   var statusOut [2]uint32
   status(&word,initial^1,next,&statusOut)
   if statusOut[0] == 0 || statusOut[1] != 6 || word != initial { panic("Go modeled CMP / CPSR contract") }
  }
 }
}
`
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod": "module armkerneloracle\n\ngo 1.20\n", "main.go": goMain,
		"oracle_arm.s": "#include \"textflag.h\"\n" + strings.NewReplacer("TEXT oracle(", "TEXT ·oracle(", "TEXT conditional(", "TEXT ·conditional(", "TEXT tail(", "TEXT ·tail(", "TEXT status(", "TEXT ·status(").Replace(source),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "-p=1", "-exec=qemu-arm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go ARM kernel-helper oracle: %v\n%s", err, output)
	}
	t.Log("actual Go ARM private helper / CAS status / carry / preserved R1 / memory oracle passed")
	const cMain = `#include <stdint.h>
#include <stdio.h>
extern void oracle(uint32_t*,uint32_t,uint32_t,uint32_t*);
extern void conditional(uint32_t*,uint32_t,uint32_t,uint32_t*);
extern void tail(uint32_t*,uint32_t,uint32_t);
extern void status(uint32_t*,uint32_t,uint32_t,uint32_t*);
int main(void) {
 const uint32_t inputs[] = {0,1,0x80000000u,0xffffffffu,0x12345678u};
 for (unsigned i=0;i<5;i++) for (unsigned success=0;success<2;success++) {
  uint32_t word=inputs[i], old=inputs[i]^(success?0:1), next=inputs[i]^0xabcdef01u, out[5]={0};
  uint32_t want=success?next:inputs[i];
  oracle(&word,old,next,out);
  if ((out[0]==0)!=success || out[1]!=success || out[2]!=next || out[3]!=want || out[4]!=success || word!=want) {
   fprintf(stderr,"kernel CAS i=%u success=%u word=%x status=%x C=%u R1=%x postload=%x CPSR.C=%u\n",i,success,word,out[0],out[1],out[2],out[3],out[4]); return 1;
  }
  word=inputs[i]; conditional(&word,old,next,out);
  if (out[0]!=old || out[1]!=1 || out[2]!=next || out[3]!=inputs[i] || word!=inputs[i]) { fprintf(stderr,"predicated native call\n"); return 1; }
  tail(&word,old,next);
  if (word!=want) { fprintf(stderr,"native tail continuation\n"); return 1; }
  word=inputs[i]; status(&word,inputs[i]^1,next,out);
  if (out[0]==0 || out[1]!=6 || word!=inputs[i]) { fprintf(stderr,"modeled CMP / CPSR status=%x NZCV=%x\n",out[0],out[1]); return 1; }
 }
 return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "kernel_helper", "armv7-unknown-linux-gnueabihf", ir, cMain,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}
