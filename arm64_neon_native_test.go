package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestARM64NEONGoAssemblerDifferential(t *testing.T) {
	if runtime.GOARCH != "arm64" || (runtime.GOOS != "linux" && runtime.GOOS != "darwin") {
		t.Skip("native arm64 required for Go assembler differential")
	}
	ins := []string{
		"VREV32 V1.B16,V0.B16", "VREV64 V2.S2,V0.S2", "VSHL $7,V1.B8,V0.B8", "VSRI $12,V2.H8,V0.H8",
		"VUSHR $8,V2.B16,V0.B16", "VZIP1 V2.H8,V1.H8,V0.H8", "VZIP2 V2.S4,V1.S4,V0.S4",
		"VEXT $7,V2.B8,V1.B8,V0.B8", "VDUP V3.B[14],V0", "VDUP V2.S[2],V0.S4", "VDUP R5,V0.H4",
		"VTBL V0.B16,[V1.B16,V2.B16,V3.B16],V0.B16", "VTBX V1.B8,[V2.B16,V3.B16],V0.B8",
		"VLD1.P (R1)(R6),[V0.B16]\nVLD1 (R1),[V0.B16]",
		"VLD4R.P (R1)(R6),[V0.S4,V1.S4,V2.S4,V3.S4]",
		"VLD4R (R1),[V0.S4,V1.S4,V2.S4,V3.S4]", "WORD $0x4dffe820", // LD4R (X1), {V0.4S..V3.4S}, #16
	}
	// Optional extensions are independent of the modeled baseline NEON forms.
	feature := func(linux, darwin string) bool {
		if runtime.GOOS == "darwin" {
			out, _ := exec.Command("sysctl", "-n", "hw.optional.arm.FEAT_"+darwin).Output()
			return strings.TrimSpace(string(out)) == "1"
		}
		data, _ := os.ReadFile("/proc/cpuinfo")
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Features") {
				return strings.Contains(" "+strings.Join(strings.Fields(line), " ")+" ", " "+linux+" ")
			}
		}
		return false
	}
	if feature("aes", "AES") {
		for _, op := range []string{"AESE", "AESD", "AESMC", "AESIMC"} {
			ins = append(ins, op+" V1.B16,V0.B16")
		}
	}
	if feature("pmull", "PMULL") {
		ins = append(ins, "VPMULL V2.D1,V1.D1,V0.Q1", "VPMULL2 V2.D2,V1.D2,V0.Q1", "VPMULL V2.B8,V1.B8,V0.H8", "VPMULL2 V2.B16,V1.B16,V0.H8")
	}
	if feature("sha1", "SHA1") {
		ins = append(ins, "SHA1H V1,V0", "SHA1C V2.S4,V1,V0", "SHA1M V2.S4,V1,V0", "SHA1P V2.S4,V1,V0", "SHA1SU0 V2.S4,V1.S4,V0.S4", "SHA1SU1 V1.S4,V0.S4")
	}
	if feature("sha2", "SHA256") {
		ins = append(ins, "SHA256H V2.S4,V1,V0", "SHA256H2 V2.S4,V1,V0", "SHA256SU0 V1.S4,V0.S4", "SHA256SU1 V2.S4,V1.S4,V0.S4")
	}
	if feature("sha512", "SHA512") {
		ins = append(ins, "SHA512H V2.D2,V1,V0", "SHA512H2 V2.D2,V1,V0", "SHA512SU0 V1.D2,V0.D2", "SHA512SU1 V2.D2,V1.D2,V0.D2")
	}
	if feature("sha3", "SHA3") {
		ins = append(ins, "VEOR3 V3.B16,V2.B16,V1.B16,V0.B16", "VBCAX V3.B16,V2.B16,V1.B16,V0.B16", "VRAX1 V2.D2,V1.D2,V0.D2", "VXAR $51,V2.D2,V1.D2,V0.D2")
	}
	var src strings.Builder
	src.WriteString("TEXT ·neonProbe(SB),4,$0-16\nMOVD out+0(FP),R0\nMOVD in+8(FP),R3\nMOVD $0x44221188,R5\nMOVD $32,R6\n")
	for _, op := range ins {
		fmt.Fprintf(&src, "MOVD R3,R1\nVLD1 (R1),[V0.B16,V1.B16,V2.B16,V3.B16]\n%s\nVST1.P [V0.B16],16(R0)\n", op)
	}
	src.WriteString("RET\n")
	dir := t.TempDir()
	oracle := fmt.Sprintf(`package main
import "fmt"
func neonProbe(out, in *byte)
func main(){
 var in [64]byte
 for i:=range in {in[i]=byte(17*i+3)}
 var out [%d]byte
 neonProbe(&out[0],&in[0])
 fmt.Printf("%%x",out[:])
}`, len(ins)*16)
	for name, data := range map[string]string{"main.go": oracle, "probe_arm64.s": src.String(), "go.mod": "module example.com/neonoracle\n\ngo 1.20\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	native, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Go native: %v\n%s", err, native)
	}
	triple := testTargetTriple(runtime.GOOS, "arm64")
	f, err := Parse(ArchARM64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Name: "neonProbe", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Type: Ptr, Field: -1}, {Type: Ptr, Field: -1, Index: 1, Offset: 8}}}}
	ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") }, Sigs: map[string]FuncSig{"neonProbe": sig}})
	if err != nil {
		t.Fatal(err)
	}
	llc, clang := requireLlcAndClang(t)
	harness := fmt.Sprintf(`#include <stdio.h>
extern void neonProbe(unsigned char *,unsigned char *);
int main(void) {
 unsigned char in[64],out[%d]={0};
 for(unsigned i=0;i<64;i++)in[i]=17*i+3;
 neonProbe(out,in);
 for(unsigned i=0;i<sizeof(out);i++)printf("%%02x",out[i]);
}`, len(ins)*16)
	got := compileAndRunRuntimeTestWithCompilerOutput(t, llc, []string{clang}, "neonProbe", triple, ir, harness, nil)
	if len(native) != len(ins)*32 || len(got) != len(native) {
		t.Fatalf("output sizes: got %d, native %d, expected %d", len(got), len(native), len(ins)*32)
	}
	for i, op := range ins {
		a, b := got[32*i:32*i+32], string(native[32*i:32*i+32])
		if a != b {
			t.Errorf("%s: %s, native %s", op, a, b)
		}
	}
	t.Logf("compared %d full vector results against Go native arm64 assembly", len(ins))
}

// Go 1.20 encoded the middle Rn operand of this SHA1 spelling as Sn.
// Compare the lowered function bodies so that the legacy spelling must read Vn even
// when the general-purpose Rn contains an unrelated value.
func TestARM64LegacySHA1RegisterEncoding(t *testing.T) {
	for _, op := range []string{"SHA1C", "SHA1M", "SHA1P"} {
		for _, rr := range []struct{ old, current string }{{"R1", "V1"}, {"ZR", "V31"}} {
			translate := func(args string) string {
				f, err := Parse(ArchARM64, "TEXT calc(SB),4,$0\n"+op+" "+args+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				out, err := Translate(f, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: map[string]FuncSig{"calc": {Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				return extractLLVMFuncBody(t, out, "calc")
			}
			a := translate("V0, " + rr.old + ", V2")
			b := translate("V0.S4, " + rr.current + ", V2")
			if a != b {
				t.Errorf("%s %s: legacy encoding selected different input state", op, rr.old)
			}
		}
	}
}
