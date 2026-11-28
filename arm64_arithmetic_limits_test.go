package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestARM64ArithmeticLimits(t *testing.T) {
	const triple = "aarch64-unknown-linux-gnu"
	cases := []struct {
		name, ops string
		want      int64
	}{
		{"branchpc", "MOVD $17, R0\nCMP R0,R0\nBEQ 2(PC)\nMOVD $9, R0", 17},
		{"cbzwpc", "MOVD $17,R0\nCBZW ZR,2(PC)\nMOVD $9,R0", 17},
		{"jmpzero", "MOVD $17,R0\nB 2(PC)\nMOVD $9,R0", 17},
		{"divzero", "MOVD $7, R1\nMOVD $0, R2\nUDIV R2, R1, R0", 0},
		{"remzero", "MOVD $-7, R1\nMOVD $0, R2\nREM R2, R1, R0", -7},
		{"remwzero", "MOVD $-7, R1\nMOVD $0, R2\nREMW R2, R1, R0", 4294967289},
		{"uremzero", "MOVD $7, R0\nMOVD $0, R2\nUREM R2, R0", 7},
		{"uremwzero", "MOVD $7, R0\nMOVD $0, R2\nUREMW R2, R0", 7},
		{"floatnan", "MOVD $0x7ff8000000000001, R1\nFMOVD R1,F1\nFCVTZSD F1,R0", 0},
		{"floatinf", "MOVD $0x7ff0000000000000, R1\nFMOVD R1,F1\nFCVTZUDW F1,R0", 4294967295},
		{"floatneg", "MOVD $-4611686018427387904, R1\nFMOVD R1,F1\nFCVTZUD F1,R0", 0},
	}
	var s strings.Builder
	sigs := map[string]FuncSig{}
	for _, tc := range cases {
		fmt.Fprintf(&s, "TEXT %s(SB),NOSPLIT,$0-8\n%s\nMOVD R0, ret+0(FP)\nRET\n", tc.name, tc.ops)
		sigs[tc.name] = FuncSig{Name: tc.name, Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Type: I64, Field: -1}}}}
	}
	f, err := Parse(ArchARM64, s.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	out := runOptO2(t, ir)
	verifyLLVMWithTargetLLC(t, out, triple)
	for _, tc := range cases {
		body := extractLLVMFuncBody(t, out, tc.name)
		if !strings.Contains(body, fmt.Sprintf("ret i64 %d\n", tc.want)) {
			t.Errorf("%s wants %d: %s", tc.name, tc.want, body)
		}
	}
}

func TestARM64PairAndSystemEffects(t *testing.T) {
	const triple = "aarch64-unknown-linux-gnu"
	for _, tc := range []struct{ name, ops, want string }{
		{"sys", "SYS $32768,R0", "sys #0, c8, c0, #0"},
		{"sysl", "SYSL $285440,R1\nMOVD R1,(R0)", "sysl"},
		{"tlbi", "TLBI VAE1IS,R0", "sys #0, c8, c3, #1"},
		{"aes", "VLD1 (R0),[V0.B16]\nAESE V0.B16,V0.B16\nVST1 [V0.B16],(R0)", ".inst"},
		{"tbl", "VLD1 (R0),[V1.B16]\nVTBL V1.B16,[V1.B16],V2.B16\nVST1 [V2.B16],(R0)", "store "},
		{"splat", "VLD4R (R0),[V0.S4,V1.S4,V2.S4,V3.S4]\nVST1 [V1.S4],(R0)", "load "},
		{"midr", "MRS MIDR_EL1,R1\nMOVD R1,(R0)", "mrs"},
		{"pair", "FLDPD.P 16(R0), (F0, F1)\nFSTPD.W (F0, F1), 8(R0)", "store "},
		{"breakpoint", "BRK $7", "brk"},
		{"udf", "UNDEF", "unreachable"},
		{"barriers", "DMB $11\nDSB $15\nISB $15", "dmb"},
		{"urecip", "VLD1 (R0),[V0.S4]\nVURECPE V0.S4,V1.S4\nVST1 [V1.S4],(R0)", "llvm.aarch64.neon.urecpe"},
		{"ursqrt", "VLD1 (R0),[V0.S4]\nVURSQRTE V0.S4,V1.S4\nVST1 [V1.S4],(R0)", "llvm.aarch64.neon.ursqrte"},
		{"cache", "DC ZVA, R0", "sideeffect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse(ArchARM64, "TEXT kernel(SB),NOSPLIT,$0-8\nMOVD p+0(FP),R0\n"+tc.ops+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"kernel": {Name: "kernel", Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Type: Ptr, Field: -1}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			opt := runOptO2(t, ir)
			body := extractLLVMFuncBody(t, opt, "kernel")
			if !strings.Contains(body, tc.want) {
				t.Errorf("lost %s effect: %s", tc.name, body)
			}
			verifyLLVMWithTargetLLC(t, opt, triple)
		})
	}
}

func TestARM64ExclusiveMonitor(t *testing.T) {
	const ops = "LDAXRB (R0),R1\nSTLXRB R1,(R0),R2\nLDAXPW (R0),(R1,R2)\nCLREX\nSTLXPW (R1,R2),(R0),R3"
	f, err := Parse(ArchARM64, "TEXT kernel(SB),NOSPLIT,$0-8\nMOVD p+0(FP),R0\n"+ops+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: map[string]FuncSig{"kernel": {Name: "kernel", Ret: Void, Args: []LLVMType{Ptr}, Frame: FrameLayout{Params: []FrameSlot{{Type: Ptr, Field: -1}}}}}}
	ir, err := Translate(f, opts)
	if err != nil {
		t.Fatal(err)
	}
	out := runOptO2(t, ir)
	verifyLLVMWithTargetLLC(t, out, opts.TargetTriple)
	for _, name := range []string{"ldaxrb", "stlxrb", "ldaxp", "clrex", "stlxp"} {
		if !strings.Contains(out, name) {
			t.Errorf("exclusive %s missing", name)
		}
	}
	opts.TargetTriple = "x86_64-pc-linux-gnu"
	if _, err := Translate(f, opts); err == nil {
		t.Error("accepted exclusive monitor on x86")
	}
}

func TestARM64NZCVControlFlow(t *testing.T) {
	for _, tc := range []struct {
		name, ops string
		reject    bool
	}{
		{"entry", "ADC R1,R1,R0", true},
		{"branch", "CBZ R0,join\nCMP R1,R1\njoin:\nCSET HS,R0", true},
		{"call", "CMP R1,R1\nCALL helper(SB)\nCSET HS,R0", true},
		{"both", "CBZ R0,other\nCMP R1,R1\nB join\nother:\nADDS R1,R1,R1\njoin:\nCSET HS,R0", false},
		{"restore", "MOVD $0x20000000,R1\nMSR R1,NZCV\nCSET HS,R0", false},
		{"capture", "CMP R1,R1\nMRS NZCV,R1\nMOVD R1,R0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse(ArchARM64, "TEXT kernel(SB),NOSPLIT,$0-0\nMOVD $1,R1\n"+tc.ops+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: map[string]FuncSig{"kernel": {Name: "kernel", Ret: I64}, "helper": {Name: "helper", Ret: Void}}})
			if tc.reject {
				if err == nil {
					t.Fatal("accepted undefined NZCV")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			opt := runOptO2(t, ir)
			body := extractLLVMFuncBody(t, opt, "kernel")
			switch tc.name {
			case "capture":
				if !strings.Contains(body, "ret i64 1610612736") {
					t.Fatal(body)
				}
			case "restore":
				if !strings.Contains(body, "ret i64 1") {
					t.Fatal(body)
				}
			}
		})
	}
}

// The writer completes A -> B -> A after the exclusive load and before the
// store-exclusive. Comparing the original value would falsely report success.
func TestARM64ExclusiveMonitorNativeABA(t *testing.T) {
	if runtime.GOARCH != "arm64" || (runtime.GOOS != "darwin" && runtime.GOOS != "linux") {
		t.Skip("native AArch64 pthread execution")
	}
	triple := testTargetTriple(runtime.GOOS, "arm64")
	var src strings.Builder
	sigs := map[string]FuncSig{}
	for _, tc := range []struct{ name, load, store string }{
		{"single", "LDAXRB (R0),R4", "STLXRB R4,(R0),R3"},
		{"pair", "LDAXP (R0),(R4,R5)", "STLXP (R4,R5),(R0),R3"},
	} {
		fmt.Fprintf(&src, "TEXT %s(SB),NOSPLIT,$0-0\n%s\nMOVD $1,R2\nSTLR R2,(R1)\nwait:\nLDAR (R1),R2\nCMP $2,R2\nBNE wait\n%s\nMOVD R3,R0\nRET\n", tc.name, tc.load, tc.store)
		sigs[tc.name] = FuncSig{Name: tc.name, Args: []LLVMType{Ptr, Ptr}, ArgRegs: []Reg{"R0", "R1"}, Ret: I64}
	}
	f, err := Parse(ArchARM64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	llc, clang := requireLlcAndClang(t)
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang, "-pthread"}, "exclusive_aba", triple, runOptO2(t, ir), `
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
extern uint64_t single(void *,void *), pair(void *,void *);
static _Alignas(256) _Atomic(uint64_t) data[2];
static _Alignas(256) _Atomic(uint64_t) phase;
static void *writer(void *unused) {
	while (atomic_load(&phase)!=1) {}
	atomic_store(&data[0],2);
	atomic_store(&data[0],1);
	atomic_store(&phase,2);
	return 0;
}
int main(void) {
	alarm(10);
	for(int i=0;i<2;i++){
		pthread_t t;
		atomic_store(&data[0],1);
		atomic_store(&phase,0);
		if(pthread_create(&t,0,writer,0)!=0) return 1;
		uint64_t status = (i ? pair : single)(data,&phase);
		if(pthread_join(t,0)!=0 || status!=1 || atomic_load(&data[0])!=1) return 2;
	}
	return 0;
}
`, nil)
}

func TestARM64ExecutableRawDirectives(t *testing.T) {
	for _, tc := range []struct {
		ops    string
		reject bool
	}{
		{"BYTE $0", true}, {"WORD $0xffffffff", true}, {"DWORD $0", true},
		{"B done\nBYTE $0\nWORD $0xffffffff\nDWORD $0\ndone:", false},
		{"WORD $0xf1000400", false},
	} {
		f, err := Parse(ArchARM64, "TEXT raw(SB),NOSPLIT,$0-0\n"+tc.ops+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(f, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: map[string]FuncSig{"raw": {Name: "raw", Ret: Void}}})
		if (err != nil) != tc.reject {
			t.Errorf("%q: got %v, want reject=%v", tc.ops, err, tc.reject)
		}
	}
}

func TestARM64SVEFFRUsesArchitecturalState(t *testing.T) {
	const triple = "aarch64-unknown-linux-gnu"
	const src = "TEXT reset(SB),NOSPLIT,$0-0\nSETFFR\nRET\n" +
		"TEXT test(SB),NOSPLIT,$0-0\nPPFALSE P1.B\nPWRFFR P1.B\nPRDFFRS P1.Z,P2.B\nPSTR P2.B,(R0)\nRET\n"
	f, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"reset": {Name: "reset", Ret: Void}, "test": {Name: "test", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, opname := range []string{"setffr", "wrffr", "rdffr.z"} {
		if !strings.Contains(ir, "@llvm.aarch64.sve."+opname+"(") {
			t.Fatalf("missing %s", opname)
		}
	}
	verifyLLVMWithTargetLLC(t, ir, triple)
}

// Check operand order, immediates, feature selection and executable object
// generation together for the SVE encodings used by Go assembly libraries.
func TestARM64RawScalableVectorsMatchNamed(t *testing.T) {
	cases := []struct {
		word  uint32
		named string
	}{
		{0x04bf5050, "RDVL $2, R16"},
		{0x25d8e3e2, "PPTRUE P2.D"},
		{0x25b8c006, "ZDUP $0, Z6.S"},
		{0x05e039e2, "ZDUP R15, Z2.D"},
		{0x05212042, "ZDUP Z2.B[0], Z2.B"},
		{0x04e30042, "ZADD Z3.D, Z2.D, Z2.D"},
		{0x042230c6, "ZAND Z2.D, Z6.D, Z6.D"},
		{0x04a33080, "ZEOR Z3.D, Z4.D, Z0.D"},
		{0x04e09420, "ZLSR $32, Z1.D, Z0.D"},
		{0x05a6c847, "ZSEL Z6.S, Z2.S, P2, Z7.S"},
		{0x04d004e0, "ZMUL Z7.D, Z0.D, P1.M, Z0.D"},
		{0x05253065, "ZTBL Z5.B, [Z3.B], Z5.B"},
		{0x45c27800, "ZUMULLB Z2.S, Z0.S, Z0.D"},
		{0x85804425, "ZLDR (VL*1)(R1), Z5.B"},
		{0xe58045c1, "ZSTR Z1.B, (VL*1)(R14)"},
		{0xa5e1a402, "ZLD1D (VL*1)(R0), P1.Z, [Z2.D]"},
		{0xe5e3e404, "ZST1D [Z4.D], P1, (VL*3)(R0)"},
		{0xa5ef40c0, "ZLD1D (R15<<3)(R6), P0.Z, [Z0.D]"},
		{0xe5ef40c0, "ZST1D [Z0.D], P0, (R15<<3)(R6)"},
	}
	const triple = "aarch64-unknown-linux-gnu"
	translate := func(raw bool) string {
		var s strings.Builder
		s.WriteString("TEXT vec(SB),NOSPLIT,$0-0\n")
		for _, tc := range cases {
			if raw {
				fmt.Fprintf(&s, "WORD $%#x\n", tc.word)
			} else {
				fmt.Fprintln(&s, tc.named)
			}
		}
		s.WriteString("RET\n")
		f, err := Parse(ArchARM64, s.String())
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(f, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"vec": {Name: "vec", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		return runOptO2(t, ir)
	}
	named, raw := translate(false), translate(true)
	if extractLLVMFuncBody(t, raw, "vec") != extractLLVMFuncBody(t, named, "vec") {
		t.Fatal("WORD and named SVE forms generated different optimized functions")
	}
	verifyLLVMWithTargetLLC(t, raw, triple)
}
