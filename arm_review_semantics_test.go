package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestARM64ImmediateAndPhysicalLaneWrites(t *testing.T) {
	const target = "aarch64-unknown-linux-gnu"
	for _, tc := range []struct {
		name, ops string
		value     int
	}{
		{"conditional-fallthrough", "MOVD $1,R0\nCMP R0,R0\nB.NE taken\nMOVD $2,R0\nRET\ntaken:\nMOVD $3,R0", 2},
		{"restore", "CMP R1,R1\nMSR $0,nZcV\nCSET EQ,R0", 0},
		{"half", "MOVD $-1,R1\nVMOV R1,V0.D[1]\nVSRI $8,V1.B8,V0.B8\nVMOV V0.D[1],R0", 0},
		{"scalar", "MOVD $-1,R1\nVMOV R1,V14.D[1]\nVMOV R1,V20.D[1]\nWORD $0x7f7305d4\nVMOV V20.D[1],R0", 0},
		{"raw-sign-shift", "MOVD $-1,R1\nVMOV R1,V14.D[1]\nVMOV R1,V20.D[1]\nWORD $0x5f7305d4\nVMOV V20.D[1],R0", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse(ArchARM64, "TEXT value(SB),NOSPLIT,$0-0\n"+tc.ops+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: target, Sigs: map[string]FuncSig{"value": {Name: "value", Ret: I64}}})
			if err != nil {
				t.Fatal(err)
			}
			ir = runOptO2(t, ir)
			verifyLLVMWithTargetLLC(t, ir, target)
			if got := extractLLVMFuncBody(t, ir, "value"); !strings.Contains(got, fmt.Sprintf("ret i64 %d\n", tc.value)) {
				t.Fatal(got)
			}
		})
	}
}

func TestARMReviewControlTransfers(t *testing.T) {
	const target = "armv7-unknown-linux-gnueabihf"
	for _, op := range []string{"B.NE", "BNE", "B.AL"} {
		src := "TEXT f(SB),NOSPLIT,$0-0\nCMP $1,R0\n" + op + " out(SB)\nMOVW $2,R0\nRET\nout:\nMOVW $777,R0\nRET\n"
		f, err := Parse(ArchARM, src)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(f, Options{Goarch: "arm", TargetTriple: target, Sigs: map[string]FuncSig{"f": {Name: "f", Ret: I32}, "out": {Name: "out", Ret: I32}}})
		if err != nil {
			t.Fatal(err)
		}
		optimized := runOptO2(t, ir)
		verifyLLVMWithTargetLLC(t, optimized, target)
		body := extractLLVMFuncBody(t, optimized, "f")
		if !strings.Contains(body, "@out(") || strings.Contains(body, "777") {
			t.Errorf("%s: %s", op, body)
		}
	}
	f, err := Parse(ArchARM, "TEXT bp(SB),NOSPLIT,$0-0\nWORD $0xe7f001f0\nMOVW $42,R0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(f, Options{Goarch: "arm", TargetTriple: target, Sigs: map[string]FuncSig{"bp": {Name: "bp", Ret: I32}}})
	if err != nil {
		t.Fatal(err)
	}
	if body := extractLLVMFuncBody(t, runOptO2(t, ir), "bp"); !strings.Contains(body, "ret i32 42") {
		t.Fatal(body)
	}
}

func TestARMExclusivePairCodegen(t *testing.T) {
	for _, tc := range []struct {
		arch                     Arch
		triple, ops, load, store string
		word                     LLVMType
	}{
		{ArchARM, "armv7-unknown-linux-gnueabihf", "again:\nLDREX (R0),R3\nCMP R1,R3\nBNE mismatch\nDMB MB_ISHST\nSTREX R2,(R0),R4\nCMP $0,R4\nBNE again\nMOVW $1,R0\nRET\nmismatch:\nMOVW $0,R0", "0xe1903f9f", "0xe1804f92", I32},
		{ArchARM64, "aarch64-unknown-linux-gnu", "again:\nLDAXR (R0),R3\nCMP R1,R3\nB.NE mismatch\nSTLXR R2,(R0),R4\nCBNZ R4,again\nMOVD $1,R0\nRET\nmismatch:\nMOVD $0,R0", "ldaxr", "stlxr", I64},
	} {
		t.Run(string(tc.arch), func(t *testing.T) {
			triple := tc.triple
			if tc.arch == ArchARM64 && runtime.GOARCH == "arm64" && (runtime.GOOS == "darwin" || runtime.GOOS == "linux") {
				triple = testTargetTriple(runtime.GOOS, "arm64")
			}
			f, err := Parse(tc.arch, "TEXT cas(SB),NOSPLIT,$0-0\n"+tc.ops+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			opts := Options{Goarch: string(tc.arch), TargetTriple: triple, Sigs: map[string]FuncSig{"cas": {Name: "cas", Args: []LLVMType{Ptr, tc.word, tc.word}, ArgRegs: []Reg{"R0", "R1", "R2"}, Ret: tc.word}}}
			ir, err := Translate(f, opts)
			if err != nil {
				t.Fatal(err)
			}
			llc, clang := requireLlcAndClang(t)
			for _, level := range []string{"-O0", "-O2"} {
				cmd := exec.Command(llc, level, "-mtriple="+triple, "-o", "-", "-")
				cmd.Stdin = strings.NewReader(ir)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%v: %s", err, out)
				}
				machine := string(out)
				if !exclusivePairInOneAsm(machine, tc.load, tc.store) {
					t.Fatalf("exclusive load/store not found in a single asm block:\n%s", machine)
				}
			}
			if tc.arch == ArchARM64 && runtime.GOARCH == "arm64" && (runtime.GOOS == "darwin" || runtime.GOOS == "linux") {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "reserve_cas", triple, ir, `#include <stdint.h>
extern uint64_t cas(uint64_t*,uint64_t,uint64_t);
int main(void){uint64_t x=4;return cas(&x,7,8)!=0 || x!=4 || cas(&x,4,11)!=1 || x!=11;}`, nil)
			}
		})
	}
}

func TestARM64ReviewInstructionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		op, target, want string
		reject           bool
	}{
		{"SVC $0", "aarch64-unknown-NetBSD", "{x17}", false},
		{"MSR $1,dit", "aarch64-unknown-linux", "(i64 16777216)", false},
		{"WORD $0xd503233f", "aarch64-unknown-linux", "", true},
		{"WORD $0xd50323bf", "aarch64-unknown-linux", "", true},
		{"WORD $0xd503245f", "aarch64-unknown-linux", "", true},
		{"WORD $0xd503229f", "aarch64-unknown-linux", ".inst 0xd503229f", false},
		{"ZDUP Z1.Q[4],Z2.Q", "aarch64-unknown-linux", "", true},
		{"WORD $0xa5ff4000", "aarch64-unknown-linux", "", true},
	} {
		t.Run(tc.op, func(t *testing.T) {
			f, err := Parse(ArchARM64, "TEXT f(SB),NOSPLIT,$0-0\n"+tc.op+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: tc.target, Sigs: map[string]FuncSig{"f": {Name: "f", Ret: Void}}})
			if tc.reject {
				if err == nil {
					t.Fatal("unexpected translation success")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, tc.want) {
				t.Fatalf("IR lacks %q", tc.want)
			}
			verifyLLVMWithTargetLLC(t, ir, tc.target)
		})
	}
}

func exclusivePairInOneAsm(machine, load, store string) bool {
	inAsm, sawLoad, sawStore := false, false, false
	for _, line := range strings.Split(machine, "\n") {
		switch strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(line), "@#;/")) {
		case "APP", "InlineAsm Start":
			inAsm, sawLoad, sawStore = true, false, false
		case "NO_APP", "InlineAsm End":
			if inAsm && sawLoad && sawStore {
				return true
			}
			inAsm = false
		default:
			if inAsm && strings.Contains(line, load) {
				sawLoad = true
			}
			if inAsm && sawLoad && strings.Contains(line, store) {
				sawStore = true
			}
		}
	}
	return false
}

func TestARMExclusiveCodegenBoundaries(t *testing.T) {
	for _, markers := range [][2]string{{"//APP", "//NO_APP"}, {"@APP", "@NO_APP"}, {"; InlineAsm Start", "; InlineAsm End"}} {
		start, end := markers[0]+"\n", markers[1]+"\n"
		if !exclusivePairInOneAsm(start+"ldaxr\nstlxr\n"+end, "ldaxr", "stlxr") ||
			exclusivePairInOneAsm(start+"ldaxr\n"+end+start+"stlxr\n"+end, "ldaxr", "stlxr") ||
			exclusivePairInOneAsm("ldaxr\nstlxr", "ldaxr", "stlxr") {
			t.Fatal(markers)
		}
	}
}

func TestARM64ExclusiveEarlyExitFlags(t *testing.T) {
	triple := "aarch64-unknown-linux-gnu"
	native := runtime.GOARCH == "arm64" && (runtime.GOOS == "darwin" || runtime.GOOS == "linux")
	if native {
		triple = testTargetTriple(runtime.GOOS, "arm64")
	}
	opts := Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"early": {Ret: I64, Args: []LLVMType{Ptr, I64}, ArgRegs: []Reg{"R0", "R2"}}}}
	// The first early exit retains EQ=1, and the second takes EQ=0 from CMP.
	// A store completion reports EQ=1 from that same CMP.
	makeIR := func(before, result string) (string, error) {
		f, err := Parse(ArchARM64, "TEXT early(SB),NOSPLIT,$0-0\nMOVD $0,R3\n"+before+"LDAXR (R0), R1\nCBNZ R1, done\nCMP R3,R2\nB.NE done\nSTLXR R2,(R0),R7\nCSET EQ,R0\nRET\ndone:\n"+result+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		return Translate(f, opts)
	}
	ir, err := makeIR("CMP R2,R2\n", "CSET EQ,R0")
	if err != nil {
		t.Fatal(err)
	}
	verifyLLVMWithTargetLLC(t, ir, triple)
	if native {
		llc, clang := requireLlcAndClang(t)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "early", triple, ir, `#include <stdint.h>
extern uint64_t early(uint64_t*,uint64_t);
int main(void){
 uint64_t x=1;
 if(early(&x,5)!=1 || x!=1) return 1;
 x=0;
 if(early(&x,5)!=0 || x!=0) return 2;
 return early(&x,0)!=1;
}`, nil)
	}
	if _, err := makeIR("", "CSET EQ,R0"); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "EQ") {
		t.Fatalf("early exit EQ: %v", err)
	}
	if _, err := makeIR("", "MOVD $3,R0"); err != nil {
		t.Fatalf("fallthrough EQ: %v", err)
	}
}

func TestARM64ScalarShiftPhysicalResult(t *testing.T) {
	const target = "aarch64-unknown-linux-gnu"
	for _, tc := range []struct {
		op         string
		amount, lo int64
	}{
		{"VURSHR", 64, 1}, {"VURSHR", 1, 9223372036854775807}, {"VSRSRA", 64, -1}, {"VURSRA", 64, 0}, {"VSSRA", 64, -2}, {"VSSHR", 1, -2}, {"VSRSHR", 1, -1}, {"VSRSHR", 64, 0}, {"VSLI", 1, -5}, {"VUSRA", 64, -1}, {"VUSRA", 63, 0},
	} {
		for lane := 0; lane < 2; lane++ {
			source := fmt.Sprintf("TEXT f(SB),NOSPLIT,$0\nMOVD $-1,R0\nVMOV R0,V20.D[0]\nVMOV R0,V20.D[1]\nVMOV R0,V14.D[1]\nMOVD $-3,R0\nVMOV R0,V14.D[0]\n%s $%d,V14,V20\nVMOV V20.D[%d],R0\nRET", tc.op, tc.amount, lane)
			f, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: target, Sigs: map[string]FuncSig{"f": {Ret: I64}}})
			if err != nil {
				t.Fatal(err)
			}
			optimized := runOptO2(t, ir)
			verifyLLVMWithTargetLLC(t, optimized, target)
			want := tc.lo
			if lane == 1 {
				want = 0
			}
			if body := extractLLVMFuncBody(t, optimized, "f"); !strings.Contains(body, fmt.Sprintf("ret i64 %d\n", want)) {
				t.Errorf("%s $%d lane %d: %s", tc.op, tc.amount, lane, body)
			}
		}
	}
}

func TestARM64NEONRegisterShiftExecution(t *testing.T) {
	native := runtime.GOARCH == "arm64" && (runtime.GOOS == "linux" || runtime.GOOS == "darwin")
	triple := "aarch64-unknown-linux-gnu"
	if native {
		triple = testTargetTriple(runtime.GOOS, "arm64")
	}
	sigs := map[string]FuncSig{}
	var source strings.Builder
	for _, op := range []string{"VSSHL", "VUSHL", "VSQSHL", "VUQSHL", "VSRSHL", "VURSHL", "VSQRSHL", "VUQRSHL"} {
		fmt.Fprintf(&source, "TEXT %s(SB),NOSPLIT,$0\nVMOV R0,V0.D[0]\nVMOV R1,V1.D[0]\n%s V1.D2,V0.D2,V2.D2\nVMOV V2.D[0],R0\nRET\n", op, op)
		sigs[op] = FuncSig{Ret: I64, Args: []LLVMType{I64, I64}, ArgRegs: []Reg{"R0", "R1"}}
	}
	source.WriteString("TEXT VSQSHLU(SB),NOSPLIT,$0\nVMOV R0,V0.D[0]\nVSQSHLU $2,V0.D2,V2.D2\nVMOV V2.D[0],R0\nRET\n")
	sigs["VSQSHLU"] = FuncSig{Ret: I64, Args: []LLVMType{I64}, ArgRegs: []Reg{"R0"}}
	f, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	verifyLLVMWithTargetLLC(t, ir, triple)
	if native {
		llc, clang := requireLlcAndClang(t)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "neon_shift", triple, ir, `#include <stdint.h>
extern uint64_t VSSHL(uint64_t,uint64_t),VUSHL(uint64_t,uint64_t),VSQSHL(uint64_t,uint64_t),VUQSHL(uint64_t,uint64_t);
extern uint64_t VSRSHL(uint64_t,uint64_t),VURSHL(uint64_t,uint64_t),VSQRSHL(uint64_t,uint64_t),VUQRSHL(uint64_t,uint64_t),VSQSHLU(uint64_t);
int main(void){
 return VSRSHL(-3,255)!=(uint64_t)-1 || VURSHL(UINT64_MAX,192)!=1 ||
        VSQRSHL(INT64_MAX,1)!=INT64_MAX || VUQRSHL(UINT64_MAX,1)!=UINT64_MAX ||
        VSQSHLU(-5)!=0 || VSQSHLU(INT64_MAX)!=UINT64_MAX || VSQSHLU(4)!=16 ||
        VSSHL(-8,255)!=(uint64_t)-4 || VUSHL(8,255)!=4 || VUSHL(1,64)!=0 ||
        VSQSHL(INT64_MAX,1)!=INT64_MAX || VSQSHL(INT64_MIN,1)!=(uint64_t)INT64_MIN ||
        VUQSHL(UINT64_MAX,1)!=UINT64_MAX || VUQSHL(9,255)!=4;
}`, nil)
	}
}

func TestARMReviewExclusiveTargetBoundaries(t *testing.T) {
	for _, tc := range []struct {
		arch              Arch
		triple, src, want string
	}{
		{ArchARM, "armv7-apple-ios", "LDREX (R0),R7\nSTREX R7,(R0),R1\nRET", "0xe190bf9f"},
		{ArchARM, "armv7-apple-ios", "LDREXD (R0),R6\nSTREXD R6,(R0),R1\nRET", "0xe1b0af9f"},
		{ArchARM64, "aarch64-linux-gnu", "LDXP (R0),(R1,R2)\nSTXP (R1,R1),(R0),R3\nRET", "stxp w3, x1, x1, [x0]"},
		{ArchARM64, "aarch64-linux-gnu", "start:\nLDAXR (R0),R1\nCBNZ R1,start\nSTLXR R2,(R0),R3", "cbnz"},
	} {
		f, err := Parse(tc.arch, "TEXT guard(SB),4,$0\n"+tc.src)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(f, Options{Goarch: string(tc.arch), TargetTriple: tc.triple, Sigs: map[string]FuncSig{"guard": {Args: []LLVMType{Ptr}, ArgRegs: []Reg{"R0"}, Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ir, tc.want) {
			t.Fatalf("%s: missing %s", tc.src, tc.want)
		}
		llc, _ := requireLlcAndClang(t)
		for _, level := range []string{"-O0", "-O2"} {
			cmd := exec.Command(llc, level, "-mtriple="+tc.triple, "-filetype=obj", "-o", filepath.Join(t.TempDir(), "bundle.o"), "-")
			cmd.Stdin = strings.NewReader(ir)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s %s: %v %s", tc.triple, level, err, out)
			}
		}
	}
}

func TestARM64XArchStoreExclusiveAliases(t *testing.T) {
	for _, tc := range []struct{ op, word, reason string }{
		{"STLXR R9,(R7),R9", "", "status overlaps data"},
		{"STXRW R29,(R27),R27", "", "status overlaps address"},
		{"STLXR R7,(R27),R8", "c808ff67", ""},
		{"STXRW R4,(R12),R0", "88007d84", ""},
	} {
		t.Run(tc.op, func(t *testing.T) {
			dir := t.TempDir()
			source := "TEXT f(SB),4,$0\n" + tc.op + "\nRET\n"
			as, obj := filepath.Join(dir, "f.s"), filepath.Join(dir, "f.o")
			if err := os.WriteFile(as, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("go", "tool", "asm", "-o", obj, as)
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
			output, asmErr := cmd.CombinedOutput()
			f, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: map[string]FuncSig{"f": {Ret: Void}}})
			if tc.reason != "" {
				if asmErr == nil || !strings.Contains(string(output), "constrained unpredictable") {
					t.Fatalf("go asm: %v %s", asmErr, output)
				}
				if err == nil || !strings.Contains(err.Error(), tc.reason) {
					t.Fatalf("Translate: %v", err)
				}
				return
			}
			if asmErr != nil || err != nil {
				t.Fatalf("go asm: %v %s; Translate: %v", asmErr, output, err)
			}
			output, err = exec.Command("go", "tool", "objdump", obj).CombinedOutput()
			if err != nil || !strings.Contains(string(output), tc.word) {
				t.Fatalf("go objdump: %v %s", err, output)
			}
			verifyLLVMWithTargetLLC(t, ir, "aarch64-unknown-linux-gnu")
		})
	}

	triple := "aarch64-unknown-linux-gnu"
	native := runtime.GOARCH == "arm64" && (runtime.GOOS == "darwin" || runtime.GOOS == "linux")
	if native {
		triple = testTargetTriple(runtime.GOOS, "arm64")
	}
	var source strings.Builder
	sigs := map[string]FuncSig{}
	for _, tc := range []struct{ name, load, store string }{{"replace64", "LDAXR", "STLXR"}, {"replace32", "LDXRW", "STXRW"}} {
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0\nagain:\n%s (R12),R3\n%s R4,(R12),R0\nCBNZ R0,again\nMOVD R3,R0\nRET\n", tc.name, tc.load, tc.store)
		sigs[tc.name] = FuncSig{Args: []LLVMType{Ptr, I64}, ArgRegs: []Reg{"R12", "R4"}, Ret: I64}
	}
	f, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	verifyLLVMWithTargetLLC(t, ir, triple)
	if native {
		llc, clang := requireLlcAndClang(t)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "exclusive_replace", triple, ir, `#include <stdint.h>
extern uint64_t replace64(uint64_t *, uint64_t), replace32(uint64_t *, uint64_t);
int main(void) {
 uint64_t x=0xfedcba9876543210ULL;
 if (replace64(&x,0x88776655aabbccddULL)!=0xfedcba9876543210ULL || x!=0x88776655aabbccddULL) return 1;
 if (replace32(&x,0x12345678)!=0xaabbccddULL || x!=0x8877665512345678ULL) return 2;
 return 0;
}`, nil)
	}
}
