//go:build !llgo

package plan9asm

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func loadAMD64DiffGatePackage(t *testing.T) (GoPackage, []byte) {
	t.Helper()
	goPath := filepath.Join("testdata", "conformance", "amd64", "diff_gate.go")
	asmPath := filepath.Join("testdata", "conformance", "amd64", "diff_gate_amd64.s")
	goSrcBytes, err := os.ReadFile(goPath)
	if err != nil {
		t.Fatalf("read %s: %v", goPath, err)
	}
	asmSrc, err := os.ReadFile(asmPath)
	if err != nil {
		t.Fatalf("read %s: %v", asmPath, err)
	}
	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, goPath, goSrcBytes, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", goPath, err)
	}
	cfg := types.Config{
		Importer: importer.Default(),
		Sizes:    types.SizesFor("gc", "amd64"),
	}
	pkg, err := cfg.Check("amd64conformance", fset, []*ast.File{astFile}, nil)
	if err != nil {
		t.Fatalf("typecheck %s: %v", goPath, err)
	}
	return GoPackage{
		Path:   "amd64conformance",
		Types:  pkg,
		Syntax: []*ast.File{astFile},
	}, asmSrc
}

func parseDiffTranscript(t *testing.T, data string) (map[string]string, string) {
	t.Helper()
	out := map[string]string{}
	hwPending := ""
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed diff transcript line: %q", line)
		}
		if k == "HW_PENDING" {
			hwPending = v
			continue
		}
		out[k] = v
	}
	return out, hwPending
}

// TestAMD64MachineCodeDifferentialGate compiles the exact same Plan 9 amd64
// assembly file (testdata/conformance/amd64/diff_gate_amd64.s) through BOTH:
//  1. plan9asm.TranslateGoModule -> LLVM 22 opt -O2 -> llc -> clang
//  2. Go's native amd64 assembler (`go test ./testdata/conformance/amd64`)
//
// On every host (including arm64), it verifies TranslateGoModule ABI0 safety,
// LLVM 22 -O2 optimization (no undef/poison folding), x86_64 llc codegen, and
// executes the target-independent LLVM IR natively against FIPS SHA-256/SHA-1
// and Round 4/5/6 architectural golden invariants.
//
// On amd64 hosts (and mandatorily when PLAN9ASM_REQUIRE_AMD64_DIFF=1), it runs
// the native Go-assembled oracle on the exact same inputs and asserts 100%
// bit-for-bit equality across every executed case (return values, memory, and
// ISA-defined flags). Setting PLAN9ASM_REQUIRE_AMD64_DIFF=1 fails loudly if
// any prerequisite is missing or zero cases execute.
func TestAMD64MachineCodeDifferentialGate(t *testing.T) {
	requireDiff := os.Getenv("PLAN9ASM_REQUIRE_AMD64_DIFF") == "1"
	if requireDiff && runtime.GOARCH != "amd64" {
		t.Fatalf("PLAN9ASM_REQUIRE_AMD64_DIFF=1 requires GOARCH=amd64, got %s", runtime.GOARCH)
	}

	optTool := findLLVM22Tool("opt")
	llcTool, clangTool, haveTools := findLlcAndClang(t)
	if optTool == "" || !haveTools {
		if requireDiff {
			t.Fatalf("PLAN9ASM_REQUIRE_AMD64_DIFF=1 requires LLVM 22 opt/llc/clang (opt=%q llc=%q clang=%q)", optTool, llcTool, clangTool)
		}
		t.Skipf("LLVM 22 opt/llc/clang unavailable (opt=%q llc=%q clang=%q)", optTool, llcTool, clangTool)
	}

	hostTriple := hostLLVMTriple()
	if hostTriple == "" {
		if requireDiff {
			t.Fatalf("PLAN9ASM_REQUIRE_AMD64_DIFF=1: unsupported host triple for %s/%s", runtime.GOOS, runtime.GOARCH)
		}
		t.Skipf("unsupported host triple for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	pkg, asmSrc := loadAMD64DiffGatePackage(t)
	resolve := func(sym string) string {
		sym = strings.TrimSuffix(sym, "<>")
		sym = strings.TrimPrefix(sym, "·")
		return sym
	}
	res, err := TranslateGoModule(pkg, asmSrc, GoModuleOptions{
		FileName:     "diff_gate_amd64.s",
		GOOS:         "linux",
		GOARCH:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym:   resolve,
	})
	if err != nil {
		t.Fatalf("TranslateGoModule(diff_gate_amd64.s) failed: %v", err)
	}
	rawIR := res.Module.String()
	res.Module.Dispose()

	tmp := t.TempDir()
	rawIRPath := filepath.Join(tmp, "diff_gate_raw.ll")
	optIRPath := filepath.Join(tmp, "diff_gate_opt.ll")
	x86ObjPath := filepath.Join(tmp, "diff_gate_x86.o")
	if err := os.WriteFile(rawIRPath, []byte(rawIR), 0o600); err != nil {
		t.Fatal(err)
	}

	// Step A: Run LLVM 22 -O2 and verify x86_64 llc object compilation.
	optCmd := exec.Command(optTool, "-passes=default<O2>", "-S", rawIRPath, "-o", optIRPath)
	if out, err := optCmd.CombinedOutput(); err != nil {
		t.Fatalf("LLVM 22 opt -O2 failed: %v\n%s", err, out)
	}
	optIRBytes, err := os.ReadFile(optIRPath)
	if err != nil {
		t.Fatal(err)
	}
	optIR := string(optIRBytes)
	if strings.Contains(optIR, "ret i64 undef") || strings.Contains(optIR, "ret i64 poison") {
		t.Fatalf("LLVM 22 -O2 folded a return value to undef/poison:\n%s", optIR)
	}
	if !strings.Contains(optIR, "ret i64 42") {
		t.Fatalf("expected diffZeroArgCaller to fold to ret i64 42 under LLVM 22 -O2:\n%s", optIR)
	}

	llcX86 := exec.Command(llcTool, "-mtriple=x86_64-unknown-linux-gnu", "-filetype=obj", optIRPath, "-o", x86ObjPath)
	if out, err := llcX86.CombinedOutput(); err != nil {
		t.Fatalf("llc x86_64 object compile failed: %v\n%s", err, out)
	}

	// Step B: Re-target the -O2 optimized target-independent IR to the host
	// triple (identical on amd64; executes natively even on arm64!), link with
	// a single batched C harness, and capture the complete transcript.
	hostIR := strings.Replace(optIR, `target triple = "x86_64-unknown-linux-gnu"`, `target triple = "`+hostTriple+`"`, 1)
	hostIRPath := filepath.Join(tmp, "diff_gate_host.ll")
	hostObjPath := filepath.Join(tmp, "diff_gate_host.o")
	if err := os.WriteFile(hostIRPath, []byte(hostIR), 0o600); err != nil {
		t.Fatal(err)
	}
	llcHost := exec.Command(llcTool, "-mtriple="+hostTriple, "-filetype=obj", hostIRPath, "-o", hostObjPath)
	if out, err := llcHost.CombinedOutput(); err != nil {
		t.Fatalf("llc host (%s) compile failed: %v\n%s", hostTriple, err, out)
	}

	harnessC := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __MINGW32__
int _fltused = 0;
#endif

extern void diffArith64(uint64_t a, uint64_t b, uint64_t *out);
extern void diffArithWidths(uint64_t a, uint64_t b, uint64_t *out);
extern void diffMulDiv(uint64_t a, uint64_t b, uint64_t *out);
extern void diffShiftsRotates(uint64_t val, uint64_t cnt, uint64_t *out);
extern void diffDoubleShift16(uint64_t dst, uint64_t src, uint64_t cnt, uint64_t *out);
extern void diffDoubleShift3264(uint64_t dst, uint64_t src, uint64_t cnt, uint64_t *out);
extern void diffFlagsSaveRestore(uint64_t a, uint64_t b, uint64_t *out);
extern uint64_t diffPushfqRawIF(void);
extern void diffBitCond(uint64_t a, uint64_t b, uint64_t *out);
extern void diffAtomicAndString(uint8_t *buf, uint64_t val, uint64_t *out);
extern int64_t diffZeroArgCaller(void);
extern void diffADX(uint64_t a, uint64_t b, uint64_t *out);
extern void diffPCMPESTRI0C(uint8_t *needle, uint8_t *hay, uint64_t nLen, uint64_t hLen, uint64_t *out);
extern void diffSHA256Block(uint32_t *state, uint8_t *block);
extern void diffSHA1Block(uint32_t *state, uint8_t *block);
extern void diffVecByteShifts(uint64_t lo, uint64_t hi, uint64_t *out);

static void print_u64s(const uint64_t *v, int n) {
    for (int i = 0; i < n; i++) {
        if (i > 0) putchar(',');
        printf("%016llx", (unsigned long long)v[i]);
    }
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_be64(uint8_t *p, uint64_t v) {
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)v);
}

int main(void) {
    const uint64_t arithPairs[][2] = {
        {0ULL, 0ULL},
        {15ULL, 1ULL},
        {16ULL, 1ULL},
        {3ULL, 0ULL},
        {0x7fULL, 1ULL},
        {0x80ULL, 1ULL},
        {0xffULL, 1ULL},
        {0x7fffULL, 1ULL},
        {0x8000ULL, 1ULL},
        {0xffffULL, 1ULL},
        {0x7fffffffULL, 1ULL},
        {0x80000000ULL, 1ULL},
        {0xffffffffULL, 1ULL},
        {0x7fffffffffffffffULL, 1ULL},
        {0x8000000000000000ULL, 1ULL},
        {0xffffffffffffffffULL, 1ULL},
        {0x123456789abcdef0ULL, 0x0fedcba987654321ULL},
        {0x8000000000000000ULL, 0x8000000000000000ULL},
    };
    const int nArith = (int)(sizeof(arithPairs) / sizeof(arithPairs[0]));

    for (int i = 0; i < nArith; i++) {
        uint64_t out20[20] = {0};
        diffArith64(arithPairs[i][0], arithPairs[i][1], out20);
        printf("arith64[%d]=", i); print_u64s(out20, 20); putchar('\n');

        uint64_t out24[24] = {0};
        diffArithWidths(arithPairs[i][0], arithPairs[i][1], out24);
        printf("arithw[%d]=", i); print_u64s(out24, 24); putchar('\n');

        uint64_t out16[16] = {0};
        diffMulDiv(arithPairs[i][0], arithPairs[i][1], out16);
        printf("muldiv[%d]=", i); print_u64s(out16, 16); putchar('\n');

        uint64_t flg[16] = {0};
        diffFlagsSaveRestore(arithPairs[i][0], arithPairs[i][1], flg);
        printf("flags[%d]=", i); print_u64s(flg, 16); putchar('\n');

        uint64_t bit[16] = {0};
        diffBitCond(arithPairs[i][0], arithPairs[i][1], bit);
        printf("bit[%d]=", i); print_u64s(bit, 16); putchar('\n');
    }

    const uint64_t shiftVals[] = {
        0ULL, 1ULL, 0x8000ULL, 0x4000000000000000ULL,
        0x8000000000000000ULL, 0xffffffffffffffffULL, 0x0123456789abcdefULL
    };
    const uint64_t shiftCnts[] = {0, 1, 7, 8, 15, 16, 31, 32, 63, 64};
    int idx = 0;
    for (int i = 0; i < (int)(sizeof(shiftVals)/sizeof(shiftVals[0])); i++) {
        for (int j = 0; j < (int)(sizeof(shiftCnts)/sizeof(shiftCnts[0])); j++) {
            uint64_t out24[24] = {0};
            diffShiftsRotates(shiftVals[i], shiftCnts[j], out24);
            printf("shift[%d]=", idx++); print_u64s(out24, 24); putchar('\n');
        }
    }

    const uint64_t dshiftPairs[][2] = {
        {1ULL, 42ULL},
        {0x1234ULL, 0xabcdULL},
        {0x8001ULL, 0x7ffeULL},
        {0x0123456789abcdefULL, 0xfedcba9876543210ULL},
    };
    const uint64_t dshift16Cnts[] = {0, 1, 7, 8, 15, 16};
    int idx16 = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 6; j++) {
            uint64_t out16[16] = {0};
            diffDoubleShift16(dshiftPairs[i][0], dshiftPairs[i][1], dshift16Cnts[j], out16);
            printf("dshift16[%d]=", idx16++); print_u64s(out16, 16); putchar('\n');
        }
    }
    const uint64_t dshift3264Cnts[] = {0, 1, 7, 16, 31, 32, 63, 64};
    int idx3264 = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            uint64_t out16[16] = {0};
            diffDoubleShift3264(dshiftPairs[i][0], dshiftPairs[i][1], dshift3264Cnts[j], out16);
            printf("dshift3264[%d]=", idx3264++); print_u64s(out16, 16); putchar('\n');
        }
    }

    const uint64_t atomicVals[] = {0x1122334455667788ULL, 0x0000000000000042ULL, 0xffffffffffffffffULL};
    for (int i = 0; i < 3; i++) {
        uint8_t buf[64];
        for (int j = 0; j < 64; j++) buf[j] = (uint8_t)(j * 7 + 3);
        uint64_t out16[16] = {0};
        diffAtomicAndString(buf, atomicVals[i], out16);
        printf("atomstr[%d]=", i); print_u64s(out16, 16); putchar('|');
        for (int j = 0; j < 64; j++) printf("%02x", buf[j]);
        putchar('\n');
    }

    printf("zeroarg=%016llx\n", (unsigned long long)(uint64_t)diffZeroArgCaller());
    printf("pushfq_raw_if=%016llx\n", (unsigned long long)diffPushfqRawIF());

    for (int i = 0; i < nArith; i++) {
        uint64_t out8[8] = {0};
        diffADX(arithPairs[i][0], arithPairs[i][1], out8);
        printf("adx[%d]=", i); print_u64s(out8, 8); putchar('\n');
    }

    struct { uint8_t needle[16]; uint8_t hay[16]; uint64_t nLen; uint64_t hLen; } pcmpCases[] = {
        {{'a','b','c'}, {'x','y','a','b','c','z'}, 3, 6},
        {{'a','b','c'}, {'a','b','c','d','e','f'}, 3, 6},
        {{'a','b','c'}, {'x','y','z','a','b','c'}, 3, 4},
        {{'a','b','c'}, {'x','y','z','w'}, 3, 4},
        {{'a','b','c'}, {'x','y','z','w'}, 0, 4},
        {{'a','b','c'}, {'x','y','a','b','c','z','0','1','2','3','4','5','6','7','8','9'}, 3, 16},
        {{'a','b','c'}, {'0','1','2','3','4','5','6','7','8','9','x','y','z','w','a','b'}, 3, 16},
    };
    for (int i = 0; i < 7; i++) {
        uint64_t out8[8] = {0};
        diffPCMPESTRI0C(pcmpCases[i].needle, pcmpCases[i].hay, pcmpCases[i].nLen, pcmpCases[i].hLen, out8);
        printf("pcmpestri0c[%d]=", i); print_u64s(out8, 8); putchar('\n');
    }

    const char *shaMsgs[] = {"", "abc", "0123456789abcdef0123456789abcdef0123456789abcdef"};
    for (int i = 0; i < 3; i++) {
        uint8_t block[64];
        memset(block, 0, sizeof(block));
        size_t n = strlen(shaMsgs[i]);
        memcpy(block, shaMsgs[i], n);
        block[n] = 0x80;
        put_be64(block + 56, (uint64_t)n * 8ULL);

        uint32_t st256[8] = {
            0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
            0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
        };
        diffSHA256Block(st256, block);
        uint8_t d256[32];
        for (int j = 0; j < 8; j++) put_be32(d256 + 4*j, st256[j]);
        printf("sha256[%d]=", i);
        for (int j = 0; j < 32; j++) printf("%02x", d256[j]);
        putchar('\n');

        uint32_t st1[5] = {0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U, 0xc3d2e1f0U};
        diffSHA1Block(st1, block);
        uint8_t d1[20];
        for (int j = 0; j < 5; j++) put_be32(d1 + 4*j, st1[j]);
        printf("sha1[%d]=", i);
        for (int j = 0; j < 20; j++) printf("%02x", d1[j]);
        putchar('\n');
    }
    {
        uint64_t vbs[8] = {0};
        diffVecByteShifts(0x0123456789abcdefULL, 0xfedcba9876543210ULL, vbs);
        printf("vecbshift[0]="); print_u64s(vbs, 8); putchar('\n');
    }
    return 0;
}
`
	cPath := filepath.Join(tmp, "diff_harness.c")
	binPath := filepath.Join(tmp, "diff_harness")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	if err := os.WriteFile(cPath, []byte(harnessC), 0o600); err != nil {
		t.Fatal(err)
	}
	linkCmd := exec.Command(clangTool, "-O1", "-o", binPath, cPath, hostObjPath)
	if out, err := linkCmd.CombinedOutput(); err != nil {
		t.Fatalf("clang link diff_harness failed: %v\n%s", err, out)
	}
	llvmOut, err := exec.Command(binPath).CombinedOutput()
	if err != nil {
		t.Fatalf("diff_harness execution failed: %v\n%s", err, llvmOut)
	}
	llvmMap, _ := parseDiffTranscript(t, string(llvmOut))
	if len(llvmMap) < 200 {
		t.Fatalf("too few LLVM differential cases executed: %d (want >= 200)", len(llvmMap))
	}

	// Step C: Verify critical golden architectural invariants on EVERY host
	// (including SHA-256/SHA-1 against Go crypto stdlib and all Round 4/5/6 P1s!).
	if got := llvmMap["zeroarg"]; got != "000000000000002a" {
		t.Fatalf("zeroarg = %q, want 000000000000002a (42)", got)
	}
	// Round 6 P1 #1: dshift16[5] is dst=1, src=42, cnt=16 -> [4]=42, [6]=42, [8]=42, [10]=42, [12]=42, [13]=42
	ds16 := strings.Split(llvmMap["dshift16[5]"], ",")
	for _, slot := range []int{4, 6, 8, 10, 12, 13} {
		if ds16[slot] != "000000000000002a" {
			t.Fatalf("dshift16[5] slot %d = %q, want 42 (full=%s)", slot, ds16[slot], llvmMap["dshift16[5]"])
		}
	}
	// Round 6 P1 #2 & #3 + Round 7 P1 #2 (IF=0x200 in raw PUSHFQ):
	// flags[1] is a=15, b=1 -> [0]==0x0247 (IF|ZF|PF|1|CF), [1]==0x0247, [2]==1, [3]==0, [8]==0x10 (16)
	fl := strings.Split(llvmMap["flags[1]"], ",")
	if fl[0] != "0000000000000247" || fl[1] != "0000000000000247" || fl[2] != "0000000000000001" || fl[3] != "0000000000000000" || fl[8] != "0000000000000010" {
		t.Fatalf("flags[1] unexpected PUSHFQ(IF=0x200)/POPFQ/LAHF(AF): %s", llvmMap["flags[1]"])
	}
	if got := llvmMap["pushfq_raw_if"]; got != "0000000002000200" {
		t.Fatalf("pushfq_raw_if = %q, want 0000000002000200 (IF=0x200 at entry and after ring-3 POPFQ)", got)
	}
	// Round 5 P1: arith64[14] is a=MinInt64, b=1 -> CMPQ: JMI=0, JLT=1 (bit0=0, bit1=1 in [5])
	ar14 := strings.Split(llvmMap["arith64[14]"], ",")
	if ar14[5] == "" || (ar14[5][len(ar14[5])-1] != '6' && ar14[5][len(ar14[5])-1] != 'e') {
		// Check exact JMI(bit0)=0 and JLT(bit1)=1 via nibble
		var mask uint64
		fmt.Sscanf(ar14[5], "%x", &mask)
		if mask&1 != 0 || mask&2 == 0 {
			t.Fatalf("arith64[14] CMPQ MinInt64, 1 Jcc mask=%#x: want JMI=0, JLT=1", mask)
		}
	}
	// Round 5 P1: arith64[3] is a=3, b=0 -> TESTQ 3,3 JPS=1 ([17]==1)
	ar3 := strings.Split(llvmMap["arith64[3]"], ",")
	if ar3[17] != "0000000000000001" {
		t.Fatalf("arith64[3] TESTQ 3, 3 JPS = %q, want 1", ar3[17])
	}
	// Round 11 P2: PSLLDQ/PSRLDQ $16/$17/$31 all zero the 128-bit lane; $1/$8 shift accurately.
	wantVbs := "0000000000000000,0000000000000000,0000000000000000,0000000000000000,0000000000000000,0000000000000000,23456789abcdef00,fedcba9876543210"
	if got := llvmMap["vecbshift[0]"]; got != wantVbs {
		t.Fatalf("vecbshift[0] = %q, want %q", got, wantVbs)
	}
	// NEGL architectural AF & OF (caught on real amd64 by amd64-diff-gate):
	//   arithw[3]  (a=3):          NEGL 3 -> 0xfffffffd, flags=0x93 (SF|AF|1|CF)
	//   arithw[11] (a=0x80000000): NEGL MinInt32 -> 0x80000000, flags=0x187 (OF|SF|PF|1|CF)
	aw3 := strings.Split(llvmMap["arithw[3]"], ",")
	if aw3[22] != "00000000fffffffd" || aw3[23] != "0000000000000093" {
		t.Fatalf("arithw[3] NEGL 3 = (%s, %s), want (00000000fffffffd, 0000000000000093)", aw3[22], aw3[23])
	}
	aw11 := strings.Split(llvmMap["arithw[11]"], ",")
	if aw11[22] != "0000000080000000" || aw11[23] != "0000000000000187" {
		t.Fatalf("arithw[11] NEGL 0x80000000 = (%s, %s), want (0000000080000000, 0000000000000187)", aw11[22], aw11[23])
	}
	// RCRQ $1 (CF=1, val=0): result=MinInt64, CF=0, OF=1, and prior ZF=1/SF=0/PF=1 preserved -> high16=0x0146
	sh0 := strings.Split(llvmMap["shift[0]"], ",")
	if sh0[22] != "8000000000000000" || sh0[23] != "0000000001460046" {
		t.Fatalf("shift[0] RCLQ/RCRQ $1 (val=0,CF=1) = (%s, %s), want (8000000000000000, 0000000001460046)", sh0[22], sh0[23])
	}
	// PCMPESTRI $0x0c (Intel SDM Equal Ordered):
	//   case 0: "abc" in "xyabcz" (nLen=3, hLen=6) -> ECX=2
	//   case 1: "abc" in "abcdef" (nLen=3, hLen=6) -> ECX=0
	//   case 2: "abc" in "xyza"   (nLen=3, hLen=4) -> ECX=16 (haystack truncated before 16 -> invalid B[4] vs valid A[1] = no match!)
	//   case 3: "abc" in "xyzw"   (nLen=3, hLen=4) -> ECX=16
	//   case 4: nLen=0 -> ECX=0
	//   case 5: "abc" in 16-byte chunk -> ECX=2
	//   case 6: "abc" vs "...ab" at end of 16-byte chunk (hLen=16) -> ECX=14 (partial match at 16-byte register boundary!)
	wantPCMP := []string{
		"0000000000000002",
		"0000000000000000",
		"0000000000000010",
		"0000000000000010",
		"0000000000000000",
		"0000000000000002",
		"000000000000000e",
	}
	for i, wantECX := range wantPCMP {
		fields := strings.Split(llvmMap[fmt.Sprintf("pcmpestri0c[%d]", i)], ",")
		if fields[0] != wantECX || fields[2] != wantECX {
			t.Fatalf("pcmpestri0c[%d] reg=%s mem=%s, want ECX=%s", i, fields[0], fields[2], wantECX)
		}
	}

	// Full SHA-NI FIPS 180-4 verification against Go stdlib crypto/sha256 & crypto/sha1!
	shaMsgs := []string{"", "abc", "0123456789abcdef0123456789abcdef0123456789abcdef"}
	for i, msg := range shaMsgs {
		want256 := sha256.Sum256([]byte(msg))
		got256 := llvmMap[fmt.Sprintf("sha256[%d]", i)]
		if got256 != hex.EncodeToString(want256[:]) {
			t.Fatalf("SHA-NI diffSHA256Block(%q) = %s, want %x", msg, got256, want256)
		}
		want1 := sha1.Sum([]byte(msg))
		got1 := llvmMap[fmt.Sprintf("sha1[%d]", i)]
		if got1 != hex.EncodeToString(want1[:]) {
			t.Fatalf("SHA-NI diffSHA1Block(%q) = %s, want %x", msg, got1, want1)
		}
	}

	// Step D: Native Go amd64 machine-code differential comparison!
	if runtime.GOARCH != "amd64" {
		writeAMD64DiffGateExecutionReport(t, llcTool, false, llvmMap, nil, nil, "")
		t.Logf("portable LLVM -O2 execution + SHA-NI/Round6/Round7 golden checks PASSED (%d cases); native amd64 Go-asm diff runs on amd64 runners", len(llvmMap))
		return
	}

	oraclePath := filepath.Join(tmp, "go_oracle.txt")
	oracleCmd := exec.Command("go", "test", "./testdata/conformance/amd64", "-run", "^TestAMD64DiffGateDumpOracle$", "-count=1")
	oracleCmd.Env = append(os.Environ(), "PLAN9ASM_DIFF_ORACLE_OUT="+oraclePath)
	if out, err := oracleCmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go amd64 oracle execution failed: %v\n%s", err, out)
	}
	oracleBytes, err := os.ReadFile(oraclePath)
	if err != nil {
		t.Fatalf("read oracle transcript %s: %v", oraclePath, err)
	}
	oracleMap, hwPending := parseDiffTranscript(t, string(oracleBytes))
	if len(oracleMap) < 200 {
		t.Fatalf("native Go amd64 oracle executed only %d cases (want >= 200)", len(oracleMap))
	}

	compared := 0
	var mismatches []string
	failedKeys := map[string]bool{}
	for k, want := range oracleMap {
		got, ok := llvmMap[k]
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("%s: missing from LLVM transcript (oracle=%s)", k, want))
			failedKeys[k] = true
			continue
		}
		compared++
		if got != want {
			mismatches = append(mismatches, fmt.Sprintf("%s:\n  go-asm:   %s\n  plan9asm: %s", k, want, got))
			failedKeys[k] = true
		}
	}
	writeAMD64DiffGateExecutionReport(t, llcTool, true, llvmMap, oracleMap, failedKeys, hwPending)
	if compared == 0 {
		t.Fatalf("zero differential cases compared between Go native amd64 and plan9asm")
	}
	if len(mismatches) > 0 {
		limit := len(mismatches)
		if limit > 12 {
			limit = 12
		}
		t.Fatalf("AMD64 machine-code differential mismatch (%d/%d cases failed):\n%s",
			len(mismatches), compared, strings.Join(mismatches[:limit], "\n"))
	}
	t.Logf("AMD64 machine-code differential gate PASSED: total_llvm_cases=%d native_diff_compared=%d hw_pending=%q",
		len(llvmMap), compared, hwPending)
}

type amd64DiffExecutionReport struct {
	SchemaVersion   int                       `json:"schema_version"`
	Goarch          string                    `json:"goarch"`
	Goos            string                    `json:"goos"`
	GoVersion       string                    `json:"go_version"`
	LLVMVersion     string                    `json:"llvm_version,omitempty"`
	NativeOracleRan bool                      `json:"native_oracle_ran"`
	TotalInputs     int                       `json:"total_inputs"`
	ComparedInputs  int                       `json:"compared_inputs"`
	FailedInputs    int                       `json:"failed_inputs"`
	Cases           []amd64DiffCaseExecResult `json:"cases"`
}

type amd64DiffCaseExecResult struct {
	ID                string   `json:"id"`
	Asm               string   `json:"asm"`
	Status            string   `json:"status"`
	VerificationMode  string   `json:"verification_mode,omitempty"`
	ExecutedInputs    int      `json:"executed_inputs"`
	ComparedInputs    int      `json:"compared_inputs"`
	FailedInputs      int      `json:"failed_inputs"`
	MissingHWFeatures []string `json:"missing_hw_features,omitempty"`
	Forms             []string `json:"forms"`
}

func mergeAndWriteAMD64DiffReport(t *testing.T, nativeOracle bool, llvmVersion string, newCases []amd64DiffCaseExecResult) {
	t.Helper()
	reportPath := strings.TrimSpace(os.Getenv("PLAN9ASM_DIFF_REPORT_OUT"))
	if reportPath == "" {
		return
	}
	rep := amd64DiffExecutionReport{
		SchemaVersion:   1,
		Goarch:          "amd64",
		Goos:            runtime.GOOS,
		GoVersion:       runtime.Version(),
		LLVMVersion:     llvmVersion,
		NativeOracleRan: nativeOracle,
	}
	byID := map[string]amd64DiffCaseExecResult{}
	if existing, err := os.ReadFile(reportPath); err == nil && len(existing) > 0 {
		var prev amd64DiffExecutionReport
		if err := json.Unmarshal(existing, &prev); err == nil && prev.SchemaVersion == 1 && prev.Goarch == "amd64" {
			if prev.LLVMVersion != "" && rep.LLVMVersion == "" {
				rep.LLVMVersion = prev.LLVMVersion
			}
			rep.NativeOracleRan = rep.NativeOracleRan || prev.NativeOracleRan
			for _, c := range prev.Cases {
				byID[c.ID] = c
			}
		}
	}
	for _, c := range newCases {
		byID[c.ID] = c
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rep.Cases = make([]amd64DiffCaseExecResult, 0, len(ids))
	for _, id := range ids {
		c := byID[id]
		rep.Cases = append(rep.Cases, c)
		rep.TotalInputs += c.ExecutedInputs
		if c.VerificationMode == "native_diff" {
			rep.ComparedInputs += c.ComparedInputs
		}
		rep.FailedInputs += c.FailedInputs
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("marshal diff report: %v", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o755); err != nil {
		t.Fatalf("mkdir diff report dir: %v", err)
	}
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		t.Fatalf("write diff report %s: %v", reportPath, err)
	}
}

func writeAMD64ManifestDiffExecutionReport(t *testing.T, asmRel, llcTool string, nativeOracle bool, casePrefixes map[string][]string, llvmMap, oracleMap map[string]string, failedKeys map[string]bool, hwPending string) {
	t.Helper()
	if strings.TrimSpace(os.Getenv("PLAN9ASM_DIFF_REPORT_OUT")) == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join("testdata", "conformance", "manifest.json"))
	if err != nil {
		t.Fatalf("read conformance manifest: %v", err)
	}
	var manifest testConformanceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse conformance manifest: %v", err)
	}
	llvmVer := ""
	if llcTool != "" {
		if out, err := exec.Command(llcTool, "--version").CombinedOutput(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "LLVM version ") {
					llvmVer = strings.TrimSpace(line)
					break
				}
			}
		}
	}
	pendingSet := map[string]bool{}
	for _, item := range strings.Split(hwPending, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			pendingSet[item] = true
		}
	}
	matchesAny := func(k string, prefixes []string) bool {
		for _, p := range prefixes {
			if k == p || strings.HasPrefix(k, p) {
				return true
			}
		}
		return false
	}
	var results []amd64DiffCaseExecResult
	for _, tc := range manifest.Cases {
		if tc.Goarch != "amd64" || tc.Asm != asmRel || tc.Validation != "execute" {
			continue
		}
		prefixes := casePrefixes[tc.ID]
		execCnt, cmpCnt, failCnt := 0, 0, 0
		for k := range llvmMap {
			if matchesAny(k, prefixes) {
				execCnt++
			}
		}
		for k := range oracleMap {
			if matchesAny(k, prefixes) {
				cmpCnt++
				if failedKeys[k] {
					failCnt++
				}
			}
		}
		var missingHW []string
		for _, f := range tc.HWFeatures {
			if pendingSet[f] {
				missingHW = append(missingHW, f)
			}
		}
		status := "expected_value_only"
		mode := "expected_value_only"
		if nativeOracle {
			mode = "native_diff"
			switch {
			case failCnt > 0:
				status = "failed"
			case len(missingHW) > 0 && cmpCnt == 0:
				status = "hw_pending"
			case cmpCnt > 0:
				status = "passed"
			default:
				status = "failed"
			}
		}
		results = append(results, amd64DiffCaseExecResult{
			ID:                tc.ID,
			Asm:               tc.Asm,
			Status:            status,
			VerificationMode:  mode,
			ExecutedInputs:    execCnt,
			ComparedInputs:    cmpCnt,
			FailedInputs:      failCnt,
			MissingHWFeatures: missingHW,
			Forms:             append([]string(nil), tc.Forms...),
		})
	}
	mergeAndWriteAMD64DiffReport(t, nativeOracle, llvmVer, results)
}

func writeAMD64ConformanceDiffExecutionReport(t *testing.T, llcTool string, nativeOracle bool, llvmMap, oracleMap map[string]string, failedKeys map[string]bool) {
	t.Helper()
	casePrefixes := map[string][]string{
		"amd64-byte-memory-destinations":           {"byte_memory[", "byte_flags["},
		"amd64-punpcklqdq-sources":                 {"punpck_mem[", "punpck_reg["},
		"amd64-legacy-three-operand-shift":         {"legacy_shll["},
		"amd64-btrq-register":                      {"btrq["},
		"amd64-double-shift-family":                {"dshift32[", "dshift64["},
		"amd64-go-hex-instruction-families":        {"gohex_vec[", "gohex_word["},
		"amd64-packed-arithmetic-shift-saturation": {"psral["},
	}
	writeAMD64ManifestDiffExecutionReport(t, "amd64/conformance_amd64.s", llcTool, nativeOracle, casePrefixes, llvmMap, oracleMap, failedKeys, "")
}

func writeAMD64DiffGateExecutionReport(t *testing.T, llcTool string, nativeOracle bool, llvmMap, oracleMap map[string]string, failedKeys map[string]bool, hwPending string) {
	t.Helper()
	casePrefixes := map[string][]string{
		"amd64-diff-gate-scalar-arith-flags":      {"arith64[", "arithw[", "muldiv["},
		"amd64-diff-gate-shifts-rotates-double16": {"shift[", "dshift16[", "dshift3264[", "vecbshift["},
		"amd64-diff-gate-flags-save-restore":      {"flags[", "pushfq_raw_if"},
		"amd64-diff-gate-bit-atomic-string-abi0":  {"bit[", "atomstr[", "zeroarg"},
		"amd64-diff-gate-adx":                     {"adx["},
		"amd64-diff-gate-sse42-ssse3":             {"pcmpestri0c["},
		"amd64-diff-gate-sha-ni":                  {"sha256[", "sha1["},
	}
	writeAMD64ManifestDiffExecutionReport(t, "amd64/diff_gate_amd64.s", llcTool, nativeOracle, casePrefixes, llvmMap, oracleMap, failedKeys, hwPending)
}

// TestTranslateGoModuleAMD64PopAndPushfqInitPropagation verifies Round 7 P1 #1
// (POP* inherits exact byte-level stack initialization; PUSHF*/POPF* and
// LAHF/SAHF inherit exact flag-init state rather than forging initialized flags)
// and P1 #2 (raw PUSHFQ exports user-mode IF = 0x200).
func TestTranslateGoModuleAMD64PopAndPushfqInitPropagation(t *testing.T) {
	checkCase := func(name, goSrc, asmSrc string, wantErr bool) string {
		t.Helper()
		fset := token.NewFileSet()
		astFile, err := parser.ParseFile(fset, "p.go", goSrc, 0)
		if err != nil {
			t.Fatalf("%s: parse go: %v", name, err)
		}
		cfg := types.Config{Importer: importer.Default(), Sizes: types.SizesFor("gc", "amd64")}
		pkg, err := cfg.Check("p", fset, []*ast.File{astFile}, nil)
		if err != nil {
			t.Fatalf("%s: typecheck go: %v", name, err)
		}
		res, err := TranslateGoModule(GoPackage{Path: "p", Types: pkg, Syntax: []*ast.File{astFile}}, []byte(asmSrc), GoModuleOptions{
			FileName:     "p_amd64.s",
			GOOS:         "linux",
			GOARCH:       "amd64",
			TargetTriple: "x86_64-unknown-linux-gnu",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		})
		if wantErr {
			if err == nil {
				ir := res.Module.String()
				res.Module.Dispose()
				t.Fatalf("%s: expected error, got success:\n%s", name, ir)
			}
			return ""
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		ir := res.Module.String()
		res.Module.Dispose()
		return ir
	}

	goRet64 := "package p\nfunc f() uint64\n"
	goRet8 := "package p\nfunc f() uint8\n"

	// P1 #1a: MOVB $1, AL; PUSHQ AX; POPQ BX -> returning full 64-bit BX MUST FAIL.
	checkCase("partial-pushq-popq-ret64", goRet64, `
TEXT ·f(SB), $0-8
	MOVB $1, AL
	PUSHQ AX
	POPQ BX
	MOVQ BX, ret+0(FP)
	RET
`, true)

	// Positive counterpart: returning only initialized low byte BL MUST PASS.
	checkCase("partial-pushq-popq-ret8", goRet8, `
TEXT ·f(SB), $0-1
	MOVB $1, AL
	PUSHQ AX
	POPQ BX
	MOVB BL, ret+0(FP)
	RET
`, false)

	// Partial 16-bit PUSHW/POPW -> returning full 16-bit word MUST FAIL.
	checkCase("partial-pushw-popw-ret16", "package p\nfunc f() uint16\n", `
TEXT ·f(SB), $0-2
	MOVB $1, AL
	PUSHW AX
	POPW BX
	MOVW BX, ret+0(FP)
	RET
`, true)

	// POPQ from unpushed stack MUST FAIL.
	checkCase("popq-unpushed-stack", goRet64, `
TEXT ·f(SB), $0-8
	POPQ BX
	MOVQ BX, ret+0(FP)
	RET
`, true)

	// P1 #1b: PUSHFQ; POPFQ at entry MUST NOT forge defined CF/OF.
	checkCase("pushfq-popfq-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	checkCase("pushfq-popfq-forges-of", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPFQ
	MOVQ $0, AX
	SETOS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	checkCase("pushfw-popfw-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFW
	POPFW
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)

	// Round-tripping entry PUSHFQ through a GP register or 0(SP) MUST NOT forge CF.
	checkCase("pushfq-popq-pushq-popfq-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ AX
	PUSHQ AX
	POPFQ
	MOVQ $0, BX
	SETCS BL
	MOVQ BX, ret+0(FP)
	RET
`, true)
	checkCase("pushfq-movsp-pushq-popfq-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	MOVQ 0(SP), AX
	POPQ CX
	PUSHQ AX
	POPFQ
	MOVQ $0, BX
	SETCS BL
	MOVQ BX, ret+0(FP)
	RET
`, true)

	// STC defines CF only: PUSHFQ; CLC; POPFQ allows SETCS (CF) but rejects SETOS (OF).
	checkCase("stc-pushfq-popfq-cf-ok", goRet64, `
TEXT ·f(SB), $0-8
	STC
	PUSHFQ
	CLC
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, false)
	checkCase("stc-pushfq-popfq-of-rejected", goRet64, `
TEXT ·f(SB), $0-8
	STC
	PUSHFQ
	CLC
	POPFQ
	MOVQ $0, AX
	SETOS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)

	// LAHF; SAHF at entry MUST NOT forge defined CF.
	checkCase("lahf-sahf-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	LAHF
	SAHF
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)

	// Explicit initialized register pushed and popped into POPFQ initializes flags,
	// whereas partial-byte push leaves OF (bit 11 in byte 1) uninitialized.
	checkCase("movq-pushq-popfq-all-flags-ok", goRet64, `
TEXT ·f(SB), $0-8
	MOVQ $0x203, AX
	PUSHQ AX
	POPFQ
	MOVQ $0, BX
	SETCS BL
	MOVQ BX, ret+0(FP)
	RET
`, false)
	checkCase("movb-pushq-popfq-of-rejected", goRet64, `
TEXT ·f(SB), $0-8
	MOVB $1, AL
	PUSHQ AX
	POPFQ
	MOVQ $0, BX
	SETOS BL
	MOVQ BX, ret+0(FP)
	RET
`, true)

	// Round 8 P1 #1: partial writes to unrelated bytes of a saved flags word
	// (on stack, in GP registers, across CFG joins, or through LAHF/ALU/XMM/XCHG)
	// MUST NOT promote entry-undefined CF/OF to defined!
	checkCase("r8-pushfq-movb-byte7-popfq-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	MOVB $0, 7(SP)
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	checkCase("r8-pushfq-movb-byte7-popfq-forges-of", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	MOVB $0, 7(SP)
	POPFQ
	MOVQ $0, AX
	SETOS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	checkCase("r8-pushfq-popq-movb-bh-pushq-popfq-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ BX
	MOVB $0, BH
	PUSHQ BX
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	// Counterpart: MOVB $0, BH genuinely writes byte 1 (OF=bit 11 -> 0), so SETOS passes!
	checkCase("r8-pushfq-popq-movb-bh-pushq-popfq-of-ok", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ BX
	MOVB $0, BH
	PUSHQ BX
	POPFQ
	MOVQ $0, AX
	SETOS AL
	MOVQ AX, ret+0(FP)
	RET
`, false)
	// Counterpart: MOVB $0, BL genuinely writes byte 0 (CF=bit 0 -> 0), while OF stays undefined.
	checkCase("r8-pushfq-popq-movb-bl-pushq-popfq-cf-ok", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ BX
	MOVB $0, BL
	PUSHQ BX
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, false)
	checkCase("r8-pushfq-popq-movb-bl-pushq-popfq-forges-of", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ BX
	MOVB $0, BL
	PUSHQ BX
	POPFQ
	MOVQ $0, AX
	SETOS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	// CFG join: two branches modify bytes 6 and 7 respectively before merging -> CF MUST stay undefined.
	goParamRet64 := "package p\nfunc f(x uint64) uint64\n"
	checkCase("r8-pushfq-cfg-branch-byte6-byte7-join-forges-cf", goParamRet64, `
TEXT ·f(SB), $0-16
	PUSHFQ
	MOVQ x+0(FP), CX
	CMPQ CX, $0
	JE b2
	MOVB $0, 6(SP)
	JMP join
b2:
	MOVB $0, 7(SP)
join:
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+8(FP)
	RET
`, true)
	// CFG join: branch 1 defines byte 0 (CF), branch 2 defines byte 1 (OF) -> join leaves both undefined!
	checkCase("r8-pushfq-cfg-branch-byte0-byte1-join-cf-rejected", goParamRet64, `
TEXT ·f(SB), $0-16
	PUSHFQ
	MOVQ x+0(FP), CX
	CMPQ CX, $0
	JE b2
	MOVB $0, 0(SP)
	JMP join
b2:
	MOVB $0, 1(SP)
join:
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+8(FP)
	RET
`, true)
	checkCase("r8-pushfq-cfg-branch-byte0-byte1-join-of-rejected", goParamRet64, `
TEXT ·f(SB), $0-16
	PUSHFQ
	MOVQ x+0(FP), CX
	CMPQ CX, $0
	JE b2
	MOVB $0, 0(SP)
	JMP join
b2:
	MOVB $0, 1(SP)
join:
	POPFQ
	MOVQ $0, AX
	SETOS AL
	MOVQ AX, ret+8(FP)
	RET
`, true)
	// Sibling partial-write/laundering checks on LAHF/SAHF, bitwise ops, ALU, XMM, XCHG, direct return:
	checkCase("r8-lahf-movb-al-sahf-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	LAHF
	MOVB $0, AL
	SAHF
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	checkCase("r8-lahf-movb-ah-sahf-cf-ok", goRet64, `
TEXT ·f(SB), $0-8
	LAHF
	MOVB $0, AH
	SAHF
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, false)
	checkCase("r8-pushfq-popq-movb-bl-ah-sahf-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ BX
	MOVB BL, AH
	SAHF
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	checkCase("r8-pushfq-orq-unrelated-bit-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	ORQ $0x100, 0(SP)
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	checkCase("r8-pushfq-orq-bit0-defines-cf-only", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	ORQ $1, 0(SP)
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, false)
	checkCase("r8-pushfq-orq-bit0-leaves-of-undef", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	ORQ $1, 0(SP)
	POPFQ
	MOVQ $0, AX
	SETOS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	checkCase("r8-pushfq-popq-addq0-pushq-popfq-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ BX
	ADDQ $0, BX
	PUSHQ BX
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, ret+0(FP)
	RET
`, true)
	checkCase("r8-pushfq-popq-xmm-roundtrip-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ X0, BX
	PUSHQ BX
	POPFQ
	MOVQ $0, CX
	SETCS CL
	MOVQ CX, ret+0(FP)
	RET
`, true)
	checkCase("r8-pushfq-popq-xchg-pushq-popfq-forges-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ AX
	MOVQ $0, BX
	XCHGQ AX, BX
	PUSHQ BX
	POPFQ
	MOVQ $0, CX
	SETCS CL
	MOVQ CX, ret+0(FP)
	RET
`, true)
	checkCase("r8-pushfq-popq-andq1-returns-undef-cf", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ AX, ret+0(FP)
	RET
`, true)

	// P1 #2: PUSHFQ; POPQ AX; ANDQ $0x200, AX at entry MUST PASS and fold to 512 under LLVM 22 -O2!
	rawIFIR := checkCase("pushfq-raw-if-bit9", goRet64, `
TEXT ·f(SB), $0-8
	PUSHFQ
	POPQ AX
	ANDQ $0x200, AX
	MOVQ AX, ret+0(FP)
	RET
`, false)
	optTool := findLLVM22Tool("opt")
	if optTool == "" {
		t.Fatal("LLVM 22 opt is required for TestTranslateGoModuleAMD64PopAndPushfqInitPropagation (check LLVM_CONFIG / PATH)")
	}
	tmp := t.TempDir()
	inPath := filepath.Join(tmp, "raw_if.ll")
	outPath := filepath.Join(tmp, "raw_if_opt.ll")
	if err := os.WriteFile(inPath, []byte(rawIFIR), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(optTool, "-passes=default<O2>", "-S", inPath, "-o", outPath).CombinedOutput(); err != nil {
		t.Fatalf("LLVM 22 opt -O2 failed: %v\n%s", err, out)
	}
	optBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(optBytes), "ret i64 512") {
		t.Fatalf("expected PUSHFQ; POPQ AX; ANDQ $0x200, AX to fold to ret i64 512 under LLVM 22 -O2:\n%s", string(optBytes))
	}
}

// TestTranslateGoModuleAMD64PrivateSPConfinement verifies Round 8 P1 #2:
// private stack-frame addresses cannot escape to ABI0 result slots through
// direct PUSHQ SP -> POPQ, indirect memory-source PUSHQ 0(SP) stack copies,
// stack MOVQ/XCHGQ loads, parameter FP bounces, or XMM register bounces, while
// non-escaping stack copies and explicitly overwritten clean bytes remain valid.
func TestTranslateGoModuleAMD64PrivateSPConfinement(t *testing.T) {
	checkCase := func(name, goSrc, asmSrc string, wantErr bool) {
		t.Helper()
		fset := token.NewFileSet()
		astFile, err := parser.ParseFile(fset, "p.go", goSrc, 0)
		if err != nil {
			t.Fatalf("%s: parse go: %v", name, err)
		}
		cfg := types.Config{Importer: importer.Default(), Sizes: types.SizesFor("gc", "amd64")}
		pkg, err := cfg.Check("p", fset, []*ast.File{astFile}, nil)
		if err != nil {
			t.Fatalf("%s: typecheck go: %v", name, err)
		}
		res, err := TranslateGoModule(GoPackage{Path: "p", Types: pkg, Syntax: []*ast.File{astFile}}, []byte(asmSrc), GoModuleOptions{
			FileName:     "p_amd64.s",
			GOOS:         "linux",
			GOARCH:       "amd64",
			TargetTriple: "x86_64-unknown-linux-gnu",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		})
		if wantErr {
			if err == nil {
				ir := res.Module.String()
				res.Module.Dispose()
				t.Fatalf("%s: expected private frame escape error, got success:\n%s", name, ir)
			}
			if !strings.Contains(err.Error(), "private frame address escapes") {
				t.Fatalf("%s: unexpected error = %v, want private frame address escapes", name, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		res.Module.Dispose()
	}

	goRet64 := "package p\nfunc f() uint64\n"
	goRet8 := "package p\nfunc f() uint8\n"
	goParamRet64 := "package p\nfunc f(a uint64) uint64\n"

	// Direct copy: PUSHQ SP -> POPQ AX -> ret+0(FP) MUST FAIL.
	checkCase("direct-pushq-sp-popq-escape", goRet64, `
TEXT ·f(SB), $0-8
	PUSHQ SP
	POPQ AX
	MOVQ AX, ret+0(FP)
	RET
`, true)

	// Indirect stack copy (Round 8 P1 #2): PUSHQ SP -> PUSHQ 0(SP) -> POPQ AX -> POPQ BX -> ret+0(FP) MUST FAIL.
	checkCase("indirect-pushq-sp-pushq-0sp-escape", goRet64, `
TEXT ·f(SB), $0-8
	PUSHQ SP
	PUSHQ 0(SP)
	POPQ AX
	POPQ BX
	MOVQ AX, ret+0(FP)
	RET
`, true)

	// Indirect stack copy with partial overwrite of unrelated byte MUST STILL FAIL.
	checkCase("indirect-pushq-sp-partial-overwrite-escape", goRet64, `
TEXT ·f(SB), $0-8
	PUSHQ SP
	MOVB $0, 7(SP)
	PUSHQ 0(SP)
	POPQ AX
	POPQ BX
	MOVQ AX, ret+0(FP)
	RET
`, true)

	// Stack MOVQ read of pushed SP MUST FAIL.
	checkCase("pushq-sp-movq-0sp-escape", goRet64, `
TEXT ·f(SB), $0-8
	PUSHQ SP
	MOVQ 0(SP), AX
	POPQ BX
	MOVQ AX, ret+0(FP)
	RET
`, true)

	// Stack XCHGQ swap with pushed SP MUST FAIL.
	checkCase("pushq-sp-xchgq-0sp-escape", goRet64, `
TEXT ·f(SB), $0-8
	PUSHQ SP
	MOVQ $0, AX
	XCHGQ 0(SP), AX
	POPQ BX
	MOVQ AX, ret+0(FP)
	RET
`, true)

	// Parameter FP slot bounce MUST FAIL.
	checkCase("movq-sp-param-fp-bounce-escape", goParamRet64, `
TEXT ·f(SB), $0-16
	MOVQ SP, a+0(FP)
	MOVQ a+0(FP), AX
	MOVQ AX, ret+8(FP)
	RET
`, true)

	// XMM register bounce MUST FAIL.
	checkCase("movq-sp-xmm-bounce-escape", goRet64, `
TEXT ·f(SB), $0-8
	MOVQ SP, AX
	MOVQ AX, X0
	MOVQ X0, BX
	MOVQ BX, ret+0(FP)
	RET
`, true)

	// MMX register bounce MUST FAIL.
	checkCase("movq-sp-mmx-bounce-escape", goRet64, `
TEXT ·f(SB), $0-8
	MOVQ SP, AX
	MOVQ AX, M0
	MOVQ M0, BX
	EMMS
	MOVQ BX, ret+0(FP)
	RET
`, true)

	// AVX-512 mask register bounce MUST FAIL.
	checkCase("movq-sp-kreg-bounce-escape", goRet64, `
TEXT ·f(SB), $0-8
	MOVQ SP, AX
	KMOVQ AX, K1
	KMOVQ K1, BX
	MOVQ BX, ret+0(FP)
	RET
`, true)

	// Outgoing ABI0 CALL argument escape MUST FAIL.
	checkCase("pushq-sp-abi0-call-escape", "package p\nfunc id(x int64) int64\nfunc f() uint64\n", `
TEXT ·id(SB), $0-16
	MOVQ x+0(FP), AX
	MOVQ AX, ret+8(FP)
	RET

TEXT ·f(SB), $16-8
	PUSHQ SP
	POPQ AX
	MOVQ AX, 0(SP)
	CALL ·id(SB)
	MOVQ 8(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`, true)

	// Positive counterpart: confined indirect copy that never escapes MUST PASS.
	checkCase("confined-indirect-pushq-sp-ok", goRet64, `
TEXT ·f(SB), $0-8
	PUSHQ SP
	PUSHQ 0(SP)
	POPQ AX
	POPQ BX
	MOVQ $42, ret+0(FP)
	RET
`, false)

	// Positive counterpart: per-byte copy returning only an explicitly overwritten clean byte MUST PASS.
	checkCase("per-byte-overwritten-clean-byte-ok", goRet8, `
TEXT ·f(SB), $0-1
	PUSHQ SP
	MOVB $7, 7(SP)
	PUSHQ 0(SP)
	MOVB 7(SP), AL
	POPQ CX
	POPQ DX
	MOVB AL, ret+0(FP)
	RET
`, false)
}

// TestTranslateGoModuleAMD64UndefinedFlagPropagationMatrix verifies Round 9
// P1 #1 (AF round-trip), P1 #2 (MMX M0..M7 round-trip), P1 #3 (outgoing ABI0
// CALL argument boundary), plus sibling paths (K-reg, XMM upper lane, RFLAGS
// DF/ID bits, external memory store, JRCXZ branch, x87 stack) across a 3-mode
// matrix:
//   - entry-undef: entry CF is undefined -> MUST BE REJECTED
//   - clc-zero:    CLC sets CF=0         -> MUST PASS and LLVM 22 -O2 preserves 0
//   - stc-one:     STC sets CF=1         -> MUST PASS and LLVM 22 -O2 preserves 1
func TestTranslateGoModuleAMD64UndefinedFlagPropagationMatrix(t *testing.T) {
	optTool := findLLVM22Tool("opt")
	if optTool == "" {
		t.Fatal("LLVM 22 opt is required for TestTranslateGoModuleAMD64UndefinedFlagPropagationMatrix (check LLVM_CONFIG / PATH)")
	}
	translateAndOpt := func(t *testing.T, name, goSrc, asmSrc string, wantErr bool) string {
		t.Helper()
		fset := token.NewFileSet()
		astFile, err := parser.ParseFile(fset, "p.go", goSrc, 0)
		if err != nil {
			t.Fatalf("%s: parse go: %v", name, err)
		}
		cfg := types.Config{Importer: importer.Default(), Sizes: types.SizesFor("gc", "amd64")}
		pkg, err := cfg.Check("p", fset, []*ast.File{astFile}, nil)
		if err != nil {
			t.Fatalf("%s: typecheck go: %v", name, err)
		}
		res, err := TranslateGoModule(GoPackage{Path: "p", Types: pkg, Syntax: []*ast.File{astFile}}, []byte(asmSrc), GoModuleOptions{
			FileName:     "p_amd64.s",
			GOOS:         "linux",
			GOARCH:       "amd64",
			TargetTriple: "x86_64-unknown-linux-gnu",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		})
		if wantErr {
			if err == nil {
				ir := res.Module.String()
				res.Module.Dispose()
				t.Fatalf("%s: expected error on entry-undefined CF, got success:\n%s", name, ir)
			}
			return ""
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		rawIR := res.Module.String()
		res.Module.Dispose()
		tmp := t.TempDir()
		inPath := filepath.Join(tmp, "in.ll")
		outPath := filepath.Join(tmp, "opt.ll")
		if err := os.WriteFile(inPath, []byte(rawIR), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(optTool, "-passes=default<O2>", "-S", inPath, "-o", outPath).CombinedOutput(); err != nil {
			t.Fatalf("%s: LLVM 22 opt -O2 failed: %v\n%s", name, err, out)
		}
		optBytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		return string(optBytes)
	}

	type pathCase struct {
		name      string
		goSrc     string
		asmPrefix string // helper funcs if any
		header    string
		body      string
		wantZero  string
		wantOne   string
	}

	goRet64 := "package p\nfunc f() int64\n"
	goCallExt := "package p\nfunc id(x int64) int64\nfunc f() int64\n"
	goPtrRet := "package p\nfunc f(p *int64) int64\n"

	paths := []pathCase{
		{
			name:   "direct",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $0-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantZero: "ret i64 0",
			wantOne:  "ret i64 1",
		},
		{
			name:   "af-roundtrip",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $0-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	SHLQ $12, AX
	SAHF
	MOVQ $0, AX
	LAHF
	SHRQ $12, AX
	ANDQ $1, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantZero: "ret i64 0",
			wantOne:  "ret i64 1",
		},
		{
			name:   "mmx-roundtrip",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $0-8",
			body: `
	PUSHFQ
	POPQ BX
	MOVQ BX, M0
	MOVQ M0, AX
	EMMS
	ANDQ $1, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantZero: "ret i64 0",
			wantOne:  "ret i64 1",
		},
		{
			name:   "abi0-call-external",
			goSrc:  goCallExt,
			header: "TEXT ·f(SB), $16-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ AX, 0(SP)
	CALL ·id(SB)
	MOVQ 8(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantZero: "call i64 @id(i64 0)",
			wantOne:  "call i64 @id(i64 1)",
		},
		{
			name:  "abi0-call-local",
			goSrc: goCallExt,
			asmPrefix: `TEXT ·id(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), AX
	MOVQ AX, ret+8(FP)
	RET
`,
			header: "TEXT ·f(SB), $16-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ AX, 0(SP)
	CALL ·id(SB)
	MOVQ 8(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantZero: "ret i64 0",
			wantOne:  "ret i64 1",
		},
		{
			name:   "kreg-roundtrip",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $0-8",
			body: `
	PUSHFQ
	POPQ BX
	KMOVQ BX, K1
	KMOVQ K1, AX
	ANDQ $1, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantZero: "ret i64 0",
			wantOne:  "ret i64 1",
		},
		{
			name:   "xmm-upper-lane-roundtrip",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $16-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ $0, 0(SP)
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X0
	PEXTRQ $1, X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantZero: "ret i64 0",
			wantOne:  "ret i64 1",
		},
		{
			name:   "xmm-upper-lane-xor-roundtrip",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $16-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ $0, 0(SP)
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X0
	PXOR X1, X1
	PXOR X1, X0
	PEXTRQ $1, X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantZero: "ret i64 0",
			wantOne:  "ret i64 1",
		},
		{
			name:   "df-roundtrip",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $0-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	SHLQ $10, AX
	PUSHQ AX
	POPFQ
	PUSHFQ
	POPQ BX
	CLD
	SHRQ $10, BX
	ANDQ $1, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantZero: "ret i64 0",
			wantOne:  "ret i64 1",
		},
		{
			name:   "mem-store-roundtrip",
			goSrc:  goPtrRet,
			header: "TEXT ·f(SB), NOSPLIT, $0-16",
			body: `
	MOVQ p+0(FP), DI
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ AX, (DI)
	MOVQ (DI), BX
	MOVQ BX, ret+8(FP)
	RET
`,
			wantZero: "ret i64 0",
			wantOne:  "ret i64 1",
		},
		{
			name:   "divl-implicit-read",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $0-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVL $0, DX
	MOVL $2, BX
	DIVL BX
	MOVQ DX, ret+0(FP)
	RET
`,
			wantZero: "ret i64 0",
			wantOne:  "ret i64 1",
		},
		{
			name:   "x87-stack-roundtrip",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $24-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FLDZ
	FMOVVP F0, 8(SP)
	FMOVVP F0, 16(SP)
	MOVQ 16(SP), BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantZero: "store i64 0, ptr %x87_hw_scalar",
			wantOne:  "store i64 1, ptr %x87_hw_scalar",
		},
		{
			name:   "x87-arith-sticky-exc-leak",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $16-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	FINIT
	MOVQ AX, 0(SP)
	FLD1
	FMOVV 0(SP), F0
	FDIVDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $4, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantZero: "store i64 0, ptr %x87_hw_scalar",
			wantOne:  "store i64 1, ptr %x87_hw_scalar",
		},
		{
			name:   "x87-fldcw-fldpi-rc-leak",
			goSrc:  goRet64,
			header: "TEXT ·f(SB), NOSPLIT, $24-8",
			body: `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	SHLQ $10, AX
	ORQ $0x037f, AX
	FINIT
	MOVW AX, 0(SP)
	FLDCW 0(SP)
	FLDPI
	FMOVXP F0, 8(SP)
	MOVQ 8(SP), BX
	ANDQ $1, BX
	FINIT
	MOVQ BX, ret+0(FP)
	RET
`,
			wantZero: "store i16 895, ptr %x87_control",
			wantOne:  "store i16 1919, ptr %x87_control",
		},
	}

	modes := []struct {
		name  string
		setup string
		undef bool
	}{
		{name: "entry-undef", setup: "", undef: true},
		{name: "clc-zero", setup: "\tCLC\n", undef: false},
		{name: "stc-one", setup: "\tSTC\n", undef: false},
	}

	for _, p := range paths {
		for _, m := range modes {
			label := p.name + "/" + m.name
			t.Run(label, func(t *testing.T) {
				asmSrc := p.asmPrefix + "\n" + p.header + "\n" + m.setup + p.body
				optIR := translateAndOpt(t, label, p.goSrc, asmSrc, m.undef)
				if m.undef {
					return
				}
				want := p.wantZero
				if m.name == "stc-one" {
					want = p.wantOne
				}
				// Locate @f body so local helper functions (e.g. @id) don't match falsely.
				idx := strings.Index(optIR, "define ")
				fIdx := strings.Index(optIR, "@f(")
				if fIdx >= 0 {
					idx = fIdx
				}
				if idx < 0 || !strings.Contains(optIR[idx:], want) {
					t.Fatalf("%s: expected LLVM 22 -O2 IR for @f to contain %q, got:\n%s", label, want, optIR)
				}
			})
		}
	}
}

// TestTranslateGoModuleAMD64X87StatusAndStackPrecision freezes Round 13 P2
// per-bit x87 status/control-word precision AND Round 14 P1 may-occupied x87
// stack-overflow / empty-stack #IS protection across BOTH X87Hardware and
// X87Software modes:
//  1. On the exact same undef-input division (`1 / entry_CF`):
//     - reading unknown ZE (`FSTSW AX; ANDQ $4, AX`) is REJECTED;
//     - clearing with `FCLEX` then reading ZE (`FCLEX; FSTSW AX; ANDQ $4, AX`)
//     is ACCEPTED and folds under LLVM 22 -O2 to `ret i64 0`;
//     - reading independent TOP (`FSTSW AX; ANDQ $0x3800, AX`) is ACCEPTED and
//     folds under LLVM 22 -O2 to `ret i64 14336` (0x3800).
//  2. Per-bit C1 clearing (`FLD1` clears C1 while preserving unknown sticky ZE)
//     and per-bit FLDCW RC vs non-RC mask bits.
//  3. x87 stack overflow (>8 pushes, dynamic 7/8 + 1 CFG branch joins in BOTH
//     branch polarities, unbounded push loops, FINCSTP rotating occupied ST(0)
//     into ST(7), MMX without EMMS, one-branch FFREE F7) and empty-stack pops
//     reject unmodeled #IS status/value/TOP reads in BOTH X87Hardware and
//     X87Software, while fixed-8, dynamic 6/7+1, balanced loops, MMX+EMMS, and
//     both-branch FFREE F7 stay valid.
//  4. On amd64 hosts, runs TestAMD64X87StackOverflowNativeOracle to record real
//     hardware results for fixed-8 (0x0), fixed-9 (0x41), and both dynamic
//     7/8+1 branch polarities (0x0 / 0x41).
func TestTranslateGoModuleAMD64X87StatusAndStackPrecision(t *testing.T) {
	optTool := findLLVM22Tool("opt")
	if optTool == "" {
		t.Fatal("LLVM 22 opt is required for TestTranslateGoModuleAMD64X87StatusAndStackPrecision (check LLVM_CONFIG / PATH)")
	}
	const defaultGoSrc = "package p\nfunc f() int64\n"
	const paramGoSrc = "package p\nfunc f(x uint64) int64\n"
	const helperGoSrc = "package p\nfunc f() int64\nfunc helper()\n"

	const divUndefPrefix = `
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	FINIT
	MOVQ AX, 0(SP)
	FLD1
	FMOVV 0(SP), F0
	FDIVDP F0, F1
`

	cases := []struct {
		name     string
		goSrc    string
		asm      string
		wantErr  bool
		wantO2   string
		wantO2HW string
		wantO2SW string
	}{
		{
			name: "round13-p2-unknown-ze-rejected",
			asm: "TEXT ·f(SB), NOSPLIT, $16-8" + divUndefPrefix + `
	MOVQ $0, AX
	FSTSW AX
	ANDQ $4, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "round13-p2-fclex-clears-ze-folds-zero",
			asm: "TEXT ·f(SB), NOSPLIT, $16-8" + divUndefPrefix + `
	FCLEX
	MOVQ $0, AX
	FSTSW AX
	ANDQ $4, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 0",
		},
		{
			name: "round13-p2-independent-top-folds-0x3800",
			asm: "TEXT ·f(SB), NOSPLIT, $16-8" + divUndefPrefix + `
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 14336",
		},
		{
			name: "unknown-c1-after-undef-div-rejected",
			asm: "TEXT ·f(SB), NOSPLIT, $16-8" + divUndefPrefix + `
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x0200, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "fld1-clears-c1-while-ze-stays-unknown",
			asm: "TEXT ·f(SB), NOSPLIT, $16-8" + divUndefPrefix + `
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x0200, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 0",
		},
		{
			name: "fldcw-undef-im-bit0-allows-fldpi",
			asm: `TEXT ·f(SB), NOSPLIT, $24-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	ORQ $0x037e, AX
	FINIT
	MOVW AX, 0(SP)
	FLDCW 0(SP)
	FLDPI
	FMOVXP F0, 8(SP)
	MOVQ 8(SP), BX
	ANDQ $1, BX
	FINIT
	MOVQ BX, ret+0(FP)
	RET
`,
			wantO2HW: `asm sideeffect "fldpi; fstpt $0"`,
			wantO2SW: "ret i64 1",
		},
		{
			name: "fldcw-undef-rc-bit10-rejects-fldpi",
			asm: `TEXT ·f(SB), NOSPLIT, $24-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	SHLQ $10, AX
	ORQ $0x037f, AX
	FINIT
	MOVW AX, 0(SP)
	FLDCW 0(SP)
	FLDPI
	FMOVXP F0, 8(SP)
	MOVQ 8(SP), BX
	ANDQ $1, BX
	FINIT
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "stack-overflow-9-pushes-value-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $8-8
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FMOVVP F0, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "stack-overflow-9-pushes-is-status-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x0241, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "fixed-9-pushes-sf-ie-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "fixed-9-pushes-top-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "fixed-8-pushes-sf-ie-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 0",
		},
		{
			name: "empty-stack-pop-is-status-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	FMOVDP F0, F0
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x0041, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "empty-stack-pop-fclex-clears-is-status",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	FMOVDP F0, F0
	FCLEX
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x0041, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 0",
		},
		{
			name: "eight-pushes-valid-top-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 0",
		},
		{
			name:  "round14-p1-dyn-branch-7or8-plus-1-sf-ie-rejected",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JE skip
	FLD1
skip:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round14-p1-dyn-branch-swapped-7or8-plus-1-sf-ie-rejected",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JNE skip
	FLD1
skip:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round14-p1-dyn-branch-7or8-plus-1-value-rejected",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JE skip
	FLD1
skip:
	FLD1
	FMOVVP F0, ret+8(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round14-p1-dyn-branch-7or8-plus-1-top-rejected",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JE skip
	FLD1
skip:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round14-p1-dyn-branch-6or7-plus-1-safe-accepted",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JE skip
	FLD1
skip:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantO2: "ret i64 0",
		},
		{
			name:  "round14-p1-loop-unbounded-push-rejected",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	CMPQ CX, $0
	JE done
loop:
	FLD1
	DECQ CX
	JNE loop
done:
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round14-p1-loop-balanced-push-pop-accepted",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	CMPQ CX, $0
	JE done
loop:
	FLD1
	FMOVDP F0, F0
	DECQ CX
	JNE loop
done:
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantO2: "ret i64 0",
		},
		{
			name: "round14-p1-fincstp-rotates-occ-into-st7-overflow-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	FLD1
	FINCSTP
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "round14-p1-mmx-without-emms-overflow-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	MOVQ $1, AX
	MOVQ AX, M0
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "round14-p1-mmx-with-emms-allows-fld1",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	MOVQ $1, AX
	MOVQ AX, M0
	EMMS
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 0",
		},
		{
			name:  "round14-p1-ffree-one-branch-8-pushes-overflow-rejected",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JE skip
	FFREE F7
skip:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round14-p1-ffree-both-branches-8-pushes-accepted",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JE alt
	FFREE F7
	JMP join
alt:
	FFREE F7
join:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantO2: "ret i64 0",
		},
		{
			name: "round15-p1-x87-fld1-overwrites-m7",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	MOVQ $123, AX
	MOVQ AX, M7
	FINIT
	FLD1
	MOVQ M7, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 -9223372036854775808",
		},
		{
			name: "round15-p1-x87-fld1-preserves-m0",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	MOVQ $123, AX
	MOVQ AX, M0
	FINIT
	FLD1
	MOVQ M0, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 123",
		},
		{
			name: "round15-p2-emms-allows-top-0x3800",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	MOVQ $1, AX
	MOVQ AX, M0
	EMMS
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 14336",
		},
		{
			name: "round15-p2-mmx-resets-nonzero-top-before-emms",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	FLD1
	MOVQ $1, AX
	MOVQ AX, M0
	EMMS
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 14336",
		},
		{
			name: "round15-p1-undef-x87-write-poisons-m7-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ $123, BX
	MOVQ BX, M7
	FINIT
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	MOVQ M7, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "round15-p1-sptaint-x87-write-poisons-m7-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	MOVQ $123, BX
	MOVQ BX, M7
	FINIT
	LEAQ 0(SP), AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	MOVQ M7, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "round15-p1-mmx-without-emms-read-f0-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FINIT
	MOVQ $123, AX
	MOVQ AX, M0
	FMOVVP F0, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		// Round 16 P1: cross-CALL x87/MMX state is unmodeled across function-local
		// x87 slots, so opaque CALL targets (reset, nop, divZero, setRD) invalidate
		// post-CALL x87 SW/CW/TOP/tag state until caller explicitly re-establishes it.
		{
			name:  "round16-p1-call-reset-without-caller-finit-rejected",
			goSrc: helperGoSrc,
			asm: `TEXT ·helper(SB), NOSPLIT, $0-0
	FINIT
	RET
TEXT ·f(SB), NOSPLIT, $8-8
	MOVQ $123, AX
	MOVQ AX, M7
	FDECSTP
	CALL ·helper(SB)
	FLD1
	MOVQ M7, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round16-p1-call-nop-without-caller-finit-rejected",
			goSrc: helperGoSrc,
			asm: `TEXT ·helper(SB), NOSPLIT, $0-0
	RET
TEXT ·f(SB), NOSPLIT, $8-8
	MOVQ $123, AX
	MOVQ AX, M7
	FDECSTP
	CALL ·helper(SB)
	FLD1
	MOVQ M7, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round16-p1-call-nop-empty-top-without-caller-finit-rejected",
			goSrc: helperGoSrc,
			asm: `TEXT ·helper(SB), NOSPLIT, $0-0
	RET
TEXT ·f(SB), NOSPLIT, $8-8
	FINIT
	FDECSTP
	CALL ·helper(SB)
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round16-p1-call-divzero-read-ze-rejected",
			goSrc: helperGoSrc,
			asm: `TEXT ·helper(SB), NOSPLIT, $0-0
	FINIT
	FLD1
	FLDZ
	FDIVDP F0, F1
	FMOVDP F0, F0
	RET
TEXT ·f(SB), NOSPLIT, $8-8
	FINIT
	CALL ·helper(SB)
	MOVQ $0, AX
	FSTSW AX
	ANDQ $4, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round16-p1-call-setrd-fldpi-rejected",
			goSrc: helperGoSrc,
			asm: `TEXT ·helper(SB), NOSPLIT, $8-0
	FINIT
	MOVW $0x077f, 0(SP)
	FLDCW 0(SP)
	RET
TEXT ·f(SB), NOSPLIT, $16-8
	FINIT
	CALL ·helper(SB)
	EMMS
	FLDPI
	FMOVXP F0, 0(SP)
	MOVQ 0(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round16-p1-call-reset-emms-read-top-rejected",
			goSrc: helperGoSrc,
			asm: `TEXT ·helper(SB), NOSPLIT, $0-0
	FINIT
	RET
TEXT ·f(SB), NOSPLIT, $8-8
	FINIT
	FDECSTP
	CALL ·helper(SB)
	EMMS
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "round16-p1-inline-finit-m7-overwritten",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	MOVQ $123, AX
	MOVQ AX, M7
	FDECSTP
	FINIT
	FLD1
	MOVQ M7, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 -9223372036854775808",
		},
		{
			name:  "round16-p1-call-reset-then-finit-m7-overwritten",
			goSrc: helperGoSrc,
			asm: `TEXT ·helper(SB), NOSPLIT, $0-0
	FINIT
	RET
TEXT ·f(SB), NOSPLIT, $8-8
	MOVQ $123, AX
	MOVQ AX, M7
	FDECSTP
	CALL ·helper(SB)
	FINIT
	FLD1
	MOVQ M7, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 -9223372036854775808",
		},
		{
			name:  "round16-p1-call-reset-then-mmx-emms-top-0x3800",
			goSrc: helperGoSrc,
			asm: `TEXT ·helper(SB), NOSPLIT, $0-0
	FINIT
	RET
TEXT ·f(SB), NOSPLIT, $8-8
	CALL ·helper(SB)
	MOVQ $1, AX
	MOVQ AX, M0
	EMMS
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2: "ret i64 14336",
		},
		{
			name:  "round16-p1-call-reset-then-finit-m0-clobbered-rejected",
			goSrc: helperGoSrc,
			asm: `TEXT ·helper(SB), NOSPLIT, $0-0
	FINIT
	RET
TEXT ·f(SB), NOSPLIT, $8-8
	MOVQ $123, AX
	MOVQ AX, M0
	CALL ·helper(SB)
	FINIT
	FLD1
	MOVQ M0, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "round16-p1-entry-read-ze-without-finit-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	MOVQ $0, AX
	FSTSW AX
	ANDQ $4, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "round16-p1-entry-read-top-without-finit-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "round16-p1-entry-read-m7-without-finit-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	FLD1
	MOVQ M7, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		// Round 16 P2: per-reachable-TOP physical slot tracking preserves M7/R7
		// definedness across CFG joins with differing TOP values (including when
		// M7 is written at different instruction positions on each path), while
		// still rejecting uninitialized M6 or undef/SP-tainted first pushes.
		{
			name:  "round16-p2-branch-1or2-pushes-m7-accepted",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	CMPQ CX, $0
	JE skip
	FLD1
skip:
	FLD1
	MOVQ M7, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantO2: "store i64 -9223372036854775808",
		},
		{
			name:  "round16-p2-branch-1or2-pushes-swapped-m7-accepted",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	CMPQ CX, $0
	JNE skip
	FLD1
skip:
	FLD1
	MOVQ M7, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantO2: "store i64 -9223372036854775808",
		},
		{
			name:  "round16-p2-branch-1or2-pushes-before-join-m7-accepted",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	CMPQ CX, $0
	JE one
	FLD1
	FLD1
	JMP done
one:
	FLD1
done:
	MOVQ M7, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantO2: "ret i64 -9223372036854775808",
		},
		{
			name:  "round16-p2-branch-1or2-pushes-m6-uninit-rejected",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	CMPQ CX, $0
	JE skip
	FLD1
skip:
	FLD1
	MOVQ M6, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round16-p2-branch-1or2-pushes-undef-first-push-m7-rejected",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $16-16
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ AX, 0(SP)
	MOVQ x+0(FP), CX
	FINIT
	CMPQ CX, $0
	JE skip
	FMOVV 0(SP), F0
skip:
	FLD1
	MOVQ M7, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantErr: true,
		},
		{
			name:  "round16-p2-branch-1or2-pushes-sptaint-first-push-m7-rejected",
			goSrc: paramGoSrc,
			asm: `TEXT ·f(SB), NOSPLIT, $16-16
	LEAQ 0(SP), AX
	MOVQ AX, 0(SP)
	MOVQ x+0(FP), CX
	FINIT
	CMPQ CX, $0
	JE skip
	FMOVV 0(SP), F0
skip:
	FLD1
	MOVQ M7, AX
	MOVQ AX, ret+8(FP)
	RET
`,
			wantErr: true,
		},
	}

	modes := []struct {
		name string
		mode X87Mode
	}{
		{"hw", X87Hardware},
		{"sw", X87Software},
	}

	for _, tc := range cases {
		goSrc := tc.goSrc
		if goSrc == "" {
			goSrc = defaultGoSrc
		}
		for _, m := range modes {
			t.Run(tc.name+"/"+m.name, func(t *testing.T) {
				fset := token.NewFileSet()
				astFile, err := parser.ParseFile(fset, "p.go", goSrc, 0)
				if err != nil {
					t.Fatal(err)
				}
				cfg := types.Config{Importer: importer.Default(), Sizes: types.SizesFor("gc", "amd64")}
				pkg, err := cfg.Check("p", fset, []*ast.File{astFile}, nil)
				if err != nil {
					t.Fatal(err)
				}
				res, err := TranslateGoModule(GoPackage{Path: "p", Types: pkg, Syntax: []*ast.File{astFile}}, []byte(tc.asm), GoModuleOptions{
					FileName:     "p_amd64.s",
					GOOS:         "linux",
					GOARCH:       "amd64",
					TargetTriple: "x86_64-unknown-linux-gnu",
					X87Mode:      m.mode,
					ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
				})
				if tc.wantErr {
					if err == nil {
						ir := res.Module.String()
						res.Module.Dispose()
						t.Fatalf("%s/%s: expected rejection, got success:\n%s", tc.name, m.name, ir)
					}
					return
				}
				if err != nil {
					t.Fatalf("%s/%s: unexpected error: %v", tc.name, m.name, err)
				}
				rawIR := res.Module.String()
				res.Module.Dispose()
				tmp := t.TempDir()
				inPath := filepath.Join(tmp, "in.ll")
				outPath := filepath.Join(tmp, "opt.ll")
				if err := os.WriteFile(inPath, []byte(rawIR), 0o600); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(optTool, "-passes=default<O2>", "-S", inPath, "-o", outPath).CombinedOutput(); err != nil {
					t.Fatalf("%s/%s: LLVM 22 opt -O2 failed: %v\n%s", tc.name, m.name, err, out)
				}
				optBytes, err := os.ReadFile(outPath)
				if err != nil {
					t.Fatal(err)
				}
				want := tc.wantO2
				if m.mode == X87Hardware && tc.wantO2HW != "" {
					want = tc.wantO2HW
				}
				if m.mode == X87Software && tc.wantO2SW != "" {
					want = tc.wantO2SW
				}
				if want != "" && !strings.Contains(string(optBytes), want) {
					t.Fatalf("%s/%s: expected LLVM 22 -O2 IR to contain %q, got:\n%s", tc.name, m.name, want, string(optBytes))
				}
			})
		}
	}

	// On amd64 hosts, run the native Go amd64 hardware oracle proving fixed-8 (0x0),
	// fixed-9 (0x41), and both dynamic 7/8+1 branch polarities (0x0 / 0x41).
	if runtime.GOARCH == "amd64" {
		cmd := exec.Command("go", "test", "-v", "-count=1", "./testdata/conformance/amd64", "-run", "^TestAMD64X87StackOverflowNativeOracle$")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native amd64 x87 stack-overflow oracle failed: %v\n%s", err, out)
		}
	}
}

// TestTranslateGoModuleAMD64VecLaneSelectPrecision verifies Round 10 P1 #2 and
// sibling lane-select/insert/half-move ops: extracting a defined lane succeeds
// and folds to the exact constant under LLVM 22 -O2 even when an unselected
// lane holds entry-undefined CF (or SP taint), while extracting the undefined
// or SP-tainted lane is still rejected.
func TestTranslateGoModuleAMD64VecLaneSelectPrecision(t *testing.T) {
	optTool := findLLVM22Tool("opt")
	if optTool == "" {
		t.Fatal("LLVM 22 opt is required for TestTranslateGoModuleAMD64VecLaneSelectPrecision (check LLVM_CONFIG / PATH)")
	}
	goSrc := "package p\nfunc f() int64\n"

	runCase := func(t *testing.T, name, asmSrc string, wantErr bool, wantO2 string) {
		t.Helper()
		fset := token.NewFileSet()
		astFile, err := parser.ParseFile(fset, "p.go", goSrc, 0)
		if err != nil {
			t.Fatalf("%s: parse go: %v", name, err)
		}
		cfg := types.Config{Importer: importer.Default(), Sizes: types.SizesFor("gc", "amd64")}
		pkg, err := cfg.Check("p", fset, []*ast.File{astFile}, nil)
		if err != nil {
			t.Fatalf("%s: typecheck go: %v", name, err)
		}
		res, err := TranslateGoModule(GoPackage{Path: "p", Types: pkg, Syntax: []*ast.File{astFile}}, []byte(asmSrc), GoModuleOptions{
			FileName:     "p_amd64.s",
			GOOS:         "linux",
			GOARCH:       "amd64",
			TargetTriple: "x86_64-unknown-linux-gnu",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		})
		if wantErr {
			if err == nil {
				ir := res.Module.String()
				res.Module.Dispose()
				t.Fatalf("%s: expected error, got success:\n%s", name, ir)
			}
			return
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		rawIR := res.Module.String()
		res.Module.Dispose()
		tmp := t.TempDir()
		inPath := filepath.Join(tmp, "in.ll")
		outPath := filepath.Join(tmp, "opt.ll")
		if err := os.WriteFile(inPath, []byte(rawIR), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(optTool, "-passes=default<O2>", "-S", inPath, "-o", outPath).CombinedOutput(); err != nil {
			t.Fatalf("%s: LLVM 22 opt -O2 failed: %v\n%s", name, err, out)
		}
		optBytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(optBytes), wantO2) {
			t.Fatalf("%s: expected LLVM 22 -O2 IR to contain %q, got:\n%s", name, wantO2, string(optBytes))
		}
	}

	cases := []struct {
		name    string
		asm     string
		wantErr bool
		wantO2  string
	}{
		{
			name: "pextrq-lane0-defined-while-lane1-undef-via-movou",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ $41, 0(SP)
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X0
	PEXTRQ $0, X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 41",
		},
		{
			name: "pextrq-lane1-undef-via-movou-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ $41, 0(SP)
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X0
	PEXTRQ $1, X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "pextrq-lane0-defined-while-lane1-undef-via-pinsrq",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	MOVQ $41, AX
	MOVQ AX, X0
	PUSHFQ
	POPQ BX
	ANDQ $1, BX
	PINSRQ $1, BX, X0
	PEXTRQ $0, X0, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 41",
		},
		{
			name: "pextrq-lane1-undef-via-pinsrq-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	MOVQ $41, AX
	MOVQ AX, X0
	PUSHFQ
	POPQ BX
	ANDQ $1, BX
	PINSRQ $1, BX, X0
	PEXTRQ $1, X0, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		// Swapped orientation: low lane holds entry-undef CF, high lane is fixed 41.
		{
			name: "pextrq-lane1-defined-while-lane0-undef-via-movou",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ AX, 0(SP)
	MOVQ $41, 8(SP)
	MOVOU 0(SP), X0
	PEXTRQ $1, X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 41",
		},
		{
			name: "pextrq-lane0-undef-while-lane1-defined-via-movou-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ AX, 0(SP)
	MOVQ $41, 8(SP)
	MOVOU 0(SP), X0
	PEXTRQ $0, X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "pextrq-lane1-defined-while-lane0-undef-via-pinsrq",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ BX
	ANDQ $1, BX
	MOVQ BX, X0
	MOVQ $41, AX
	PINSRQ $1, AX, X0
	PEXTRQ $1, X0, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 41",
		},
		{
			name: "pextrq-lane0-undef-while-lane1-defined-via-pinsrq-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ BX
	ANDQ $1, BX
	MOVQ BX, X0
	MOVQ $41, AX
	PINSRQ $1, AX, X0
	PEXTRQ $0, X0, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "pextrq-lane0-clc-zero-while-lane1-41",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	CLC
	PUSHFQ
	POPQ BX
	ANDQ $1, BX
	MOVQ BX, X0
	MOVQ $41, AX
	PINSRQ $1, AX, X0
	PEXTRQ $0, X0, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "pextrq-lane0-stc-one-while-lane1-41",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	STC
	PUSHFQ
	POPQ BX
	ANDQ $1, BX
	MOVQ BX, X0
	MOVQ $41, AX
	PINSRQ $1, AX, X0
	PEXTRQ $0, X0, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 1",
		},
		{
			name: "pextrd-lane0-defined-while-lane2-undef",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ $41, 0(SP)
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X0
	PEXTRD $0, X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 41",
		},
		{
			name: "pextrd-lane2-undef-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ $41, 0(SP)
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X0
	PEXTRD $2, X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "pextrb-byte0-defined-while-byte8-undef",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ $41, 0(SP)
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X0
	PEXTRB $0, X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 41",
		},
		{
			name: "pextrb-byte8-undef-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ $41, 0(SP)
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X0
	PEXTRB $8, X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "psrldq-8-shifts-high-undef-lane-into-low-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $16-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ $41, 0(SP)
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X0
	PSRLDQ $8, X0
	MOVQ X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "psrldq-8-shifts-defined-high-lane-into-low-ok",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	ANDQ $1, AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	PSRLDQ $8, X0
	MOVQ X0, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 41",
		},
		{
			name: "pextrq-lane0-clean-while-lane1-sp-tainted",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	MOVQ $41, AX
	MOVQ AX, X0
	PUSHQ SP
	POPQ BX
	PINSRQ $1, BX, X0
	PEXTRQ $0, X0, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 41",
		},
		{
			name: "pextrq-lane1-sp-tainted-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	MOVQ $41, AX
	MOVQ AX, X0
	PUSHQ SP
	POPQ BX
	PINSRQ $1, BX, X0
	PEXTRQ $1, X0, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		// Round 11 P2: PSLLDQ / PSRLDQ large counts ($16, $17, $31, $-1) share
		// the same Intel SDM imm8 saturation rule between checker and lowerer,
		// zeroing the entire 128-bit lane even if X0 previously held entry-undef CF.
		{
			name: "pslldq-16-clears-lane-to-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	PSLLDQ $16, X0
	PEXTRQ $0, X0, CX
	PEXTRQ $1, X0, DX
	ORQ DX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "pslldq-17-clears-lane-to-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	PSLLDQ $17, X0
	PEXTRQ $0, X0, CX
	PEXTRQ $1, X0, DX
	ORQ DX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "pslldq-31-clears-lane-to-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	PSLLDQ $31, X0
	PEXTRQ $0, X0, CX
	PEXTRQ $1, X0, DX
	ORQ DX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "psrldq-16-clears-lane-to-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	PSRLDQ $16, X0
	PEXTRQ $0, X0, CX
	PEXTRQ $1, X0, DX
	ORQ DX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "psrldq-17-clears-lane-to-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	PSRLDQ $17, X0
	PEXTRQ $0, X0, CX
	PEXTRQ $1, X0, DX
	ORQ DX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "psrldq-31-clears-lane-to-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	PSRLDQ $31, X0
	PEXTRQ $0, X0, CX
	PEXTRQ $1, X0, DX
	ORQ DX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "pslldq-neg1-unsigned-imm8-255-clears-lane-to-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	PSLLDQ $-1, X0
	PEXTRQ $0, X0, CX
	PEXTRQ $1, X0, DX
	ORQ DX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "psrldq-neg1-unsigned-imm8-255-clears-lane-to-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	PSRLDQ $-1, X0
	PEXTRQ $0, X0, CX
	PEXTRQ $1, X0, DX
	ORQ DX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "vpslldq-31-clears-lane-to-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	VPSLLDQ $31, X0, X1
	PEXTRQ $0, X1, CX
	PEXTRQ $1, X1, DX
	ORQ DX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "vpsrldq-17-clears-lane-to-zero",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	PUSHFQ
	POPQ AX
	MOVQ AX, X0
	MOVQ $41, BX
	PINSRQ $1, BX, X0
	VPSRLDQ $17, X0, X1
	PEXTRQ $0, X1, CX
	PEXTRQ $1, X1, DX
	ORQ DX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantErr: false,
			wantO2:  "ret i64 0",
		},
		{
			name: "pslldq-256-invalid-imm8-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	MOVQ $41, AX
	MOVQ AX, X0
	PSLLDQ $256, X0
	MOVQ X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
		{
			name: "psrldq-neg129-invalid-imm8-rejected",
			asm: `TEXT ·f(SB), NOSPLIT, $0-8
	MOVQ $41, AX
	MOVQ AX, X0
	PSRLDQ $-129, X0
	MOVQ X0, BX
	MOVQ BX, ret+0(FP)
	RET
`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runCase(t, tc.name, tc.asm, tc.wantErr, tc.wantO2)
		})
	}
}

// TestTranslateGoModuleAMD64PerBitEntryFlagDifferential verifies Acceptance
// Criterion #3:
//  1. Per-bit entry-flag flipping across all 6 entry-undefined RFLAGS bits
//     (CF:0, PF:2, AF:4, ZF:6, SF:7, OF:11) — not only all-0 vs all-1 — catches
//     XOR dependencies such as CF^OF that evaluate identically under all-0 and all-1.
//  2. On amd64 hosts, runs the zero-prologue-clobber native Go adapter
//     (TestAMD64EntryFlagsPerBitOracle) proving RFLAGS bits set via POPFQ reach
//     the target's first instruction untouched.
func TestTranslateGoModuleAMD64PerBitEntryFlagDifferential(t *testing.T) {
	optTool := findLLVM22Tool("opt")
	if optTool == "" {
		t.Fatal("LLVM 22 opt is required for TestTranslateGoModuleAMD64PerBitEntryFlagDifferential (check LLVM_CONFIG / PATH)")
	}
	goSrc := "package p\nfunc f() int64\n"

	translateCheck := func(t *testing.T, name, asmSrc string, wantErr bool, wantO2 string) {
		t.Helper()
		fset := token.NewFileSet()
		astFile, err := parser.ParseFile(fset, "p.go", goSrc, 0)
		if err != nil {
			t.Fatal(err)
		}
		cfg := types.Config{Importer: importer.Default(), Sizes: types.SizesFor("gc", "amd64")}
		pkg, err := cfg.Check("p", fset, []*ast.File{astFile}, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := TranslateGoModule(GoPackage{Path: "p", Types: pkg, Syntax: []*ast.File{astFile}}, []byte(asmSrc), GoModuleOptions{
			FileName:     "p_amd64.s",
			GOOS:         "linux",
			GOARCH:       "amd64",
			TargetTriple: "x86_64-unknown-linux-gnu",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		})
		if wantErr {
			if err == nil {
				ir := res.Module.String()
				res.Module.Dispose()
				t.Fatalf("%s: expected error on entry-undefined flag bit, got success:\n%s", name, ir)
			}
			return
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		rawIR := res.Module.String()
		res.Module.Dispose()
		tmp := t.TempDir()
		inPath := filepath.Join(tmp, "in.ll")
		outPath := filepath.Join(tmp, "opt.ll")
		if err := os.WriteFile(inPath, []byte(rawIR), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(optTool, "-passes=default<O2>", "-S", inPath, "-o", outPath).CombinedOutput(); err != nil {
			t.Fatalf("%s: LLVM 22 opt -O2 failed: %v\n%s", name, err, out)
		}
		optBytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(optBytes), wantO2) {
			t.Fatalf("%s: expected LLVM 22 -O2 IR to contain %q, got:\n%s", name, wantO2, string(optBytes))
		}
	}

	// 1. CF ^ OF: identical (0) under all-0 and all-1, but 1 under single-bit CF or OF flip.
	cfXorOFBody := `
	PUSHFQ
	POPQ AX
	MOVQ AX, BX
	SHRQ $11, BX
	XORQ BX, AX
	ANDQ $1, AX
	MOVQ AX, ret+0(FP)
	RET
`
	t.Run("cf-xor-of/entry-undef", func(t *testing.T) {
		translateCheck(t, "cf-xor-of/entry-undef", "TEXT ·f(SB), NOSPLIT, $0-8\n"+cfXorOFBody, true, "")
	})
	for _, combo := range []struct {
		name  string
		flags uint64
		want  string
	}{
		{"cf0-of0", 0x202, "ret i64 0"},
		{"cf1-of0", 0x203, "ret i64 1"},
		{"cf0-of1", 0xa02, "ret i64 1"},
		{"cf1-of1", 0xa03, "ret i64 0"},
	} {
		t.Run("cf-xor-of/"+combo.name, func(t *testing.T) {
			setup := fmt.Sprintf("\tMOVQ $0x%x, CX\n\tPUSHQ CX\n\tPOPFQ\n", combo.flags)
			translateCheck(t, combo.name, "TEXT ·f(SB), NOSPLIT, $0-8\n"+setup+cfXorOFBody, false, combo.want)
		})
	}

	// 2. Per-bit entry-undef rejection + single-bit 0/1 verification for ALL 6 status flags.
	flagBits := []struct {
		name  string
		shift int
		mask  uint64
	}{
		{"CF", 0, 0x001},
		{"PF", 2, 0x004},
		{"AF", 4, 0x010},
		{"ZF", 6, 0x040},
		{"SF", 7, 0x080},
		{"OF", 11, 0x800},
	}
	for _, fb := range flagBits {
		body := fmt.Sprintf("\tPUSHFQ\n\tPOPQ AX\n\tSHRQ $%d, AX\n\tANDQ $1, AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n", fb.shift)
		t.Run("bit-"+fb.name+"/entry-undef", func(t *testing.T) {
			translateCheck(t, fb.name+"/undef", "TEXT ·f(SB), NOSPLIT, $0-8\n"+body, true, "")
		})
		t.Run("bit-"+fb.name+"/zero", func(t *testing.T) {
			setup := "\tMOVQ $0x202, CX\n\tPUSHQ CX\n\tPOPFQ\n"
			translateCheck(t, fb.name+"/zero", "TEXT ·f(SB), NOSPLIT, $0-8\n"+setup+body, false, "ret i64 0")
		})
		t.Run("bit-"+fb.name+"/one", func(t *testing.T) {
			setup := fmt.Sprintf("\tMOVQ $0x%x, CX\n\tPUSHQ CX\n\tPOPFQ\n", 0x202|fb.mask)
			translateCheck(t, fb.name+"/one", "TEXT ·f(SB), NOSPLIT, $0-8\n"+setup+body, false, "ret i64 1")
		})
	}

	// 3. On amd64 hosts, run the zero-prologue-clobber native Go entry-flag oracle!
	if runtime.GOARCH == "amd64" {
		cmd := exec.Command("go", "test", "-v", "-count=1", "./testdata/conformance/amd64", "-run", "^TestAMD64EntryFlagsPerBitOracle$")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native amd64 zero-prologue entry-flag oracle failed: %v\n%s", err, out)
		}
	}
}

// TestStep1ExplicitUnsupportedAuditRegistry verifies that every audited
// unmodeled/approximate/privileged instruction form returns an explicit
// "unsupported" error from the public Translate entry point instead of
// silently emitting placeholder IR or dropping instructions.
func TestStep1ExplicitUnsupportedAuditRegistry(t *testing.T) {
	cases := []struct {
		arch   Arch
		goarch string
		triple string
		ins    string
	}{
		// amd64 AVX-512 unmodeled special FP ops
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VRCP14PS Z0, K1, Z1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VRCP28PD Z0, Z1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VRSQRT14PS Y0, K1, Y1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VRSQRT28SD X0, X1, K2, X2"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VEXP2PS Z0, K1, Z1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VGETEXPPS Z0, K1, Z1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VGETMANTPS $5, Z0, K1, Z1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VRNDSCALEPS $1, Z0, K1, Z1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VREDUCEPS $1, Y0, K1, Y1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VSCALEFPS Z0, Z1, K1, Z2"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VRANGEPS $0, X0, X1, K1, X2"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VFIXUPIMMPS $47, Z0, Z1, K1, Z2"},
		// amd64 unmodeled PCMP*STR* forms
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "PCMPESTRI $0x08, X1, X2"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "PCMPESTRM $0x0c, X1, X2"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "PCMPISTRI $0x0c, X1, X2"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "PCMPISTRM $0x0c, X1, X2"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "VPCMPESTRI $0x0c, X1, X2"},
		// amd64 privileged/system/segment/RTM/legacy-trap/64-bit-invalid BCD stubs
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "LGDT (BX)"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "SGDT (BX)"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "LIDT (BX)"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "SIDT (BX)"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "LLDT DX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "SLDTQ AX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "LMSW DX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "SMSWL BX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "LTR DX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "STRW CX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "TPAUSE BX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "UMWAIT BX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "UMONITOR AX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "ENTER $0, $0"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "RETFL $0"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "INB"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "OUTB"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "XTEST"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "XABORT $1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "INTO"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "BOUNDW AX, (BX)"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "BOUNDL AX, (BX)"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "ARPL AX, BX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "PUSHAW"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "POPAW"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "LFSQ (BX), CX"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "MOVQ DX, CR2"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "MOVW AX, CS"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "MOVW AX, TASK"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "POPW DS"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "AAA"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "AAS"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "DAA"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "DAS"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "AAM"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "AAD"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "DUFFZERO $0"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "DUFFCOPY $0"},
		// 386 & amd64 unmodeled approximate x87 transcendentals/remainders/env/tag-word & system/segment stubs
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FXAM"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FLDENV 0(BX)"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FSTENV 0(BX)"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FSAVE 0(BX)"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FRSTOR 0(BX)"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "F2XM1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FYL2X"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FYL2XP1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FSIN"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FCOS"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FSINCOS"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FPTAN"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FPATAN"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FPREM"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FPREM1"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FSCALE"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "FXTRACT"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FXAM"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FLDENV 0(BX)"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FSTENV 0(BX)"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FSAVE 0(BX)"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FRSTOR 0(BX)"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "F2XM1"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FYL2X"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FYL2XP1"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FSIN"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FCOS"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FSINCOS"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FPTAN"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FPATAN"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FPREM"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FPREM1"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FSCALE"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FXTRACT"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "MOVL AX, CR0"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "POPL SS"},
		// arm64 & arm & wasm unmodeled stubs
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", "AT $4"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", "IC $4"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", "DWORD $0"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf", "DUFFZERO $0"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf", "DUFFCOPY $0"},
		{ArchWASM, "wasm", "wasm32-unknown-unknown", "MemoryInit $0"},
		{ArchWASM, "wasm", "wasm32-unknown-unknown", "DataDrop $0"},
		{ArchWASM, "wasm", "wasm32-unknown-unknown", "TableCopy"},
		{ArchWASM, "wasm", "wasm32-unknown-unknown", "TableFill"},
		{ArchWASM, "wasm", "wasm32-unknown-unknown", "TableSize"},
	}

	for _, tc := range cases {
		src := "TEXT ·audit(SB),NOSPLIT,$0-0\n\t" + tc.ins + "\n\tRET\n"
		file, err := Parse(tc.arch, src)
		if err != nil {
			t.Fatalf("%s parse %q failed: %v", tc.goarch, tc.ins, err)
		}
		_, err = Translate(file, Options{
			TargetTriple: tc.triple,
			Goarch:       tc.goarch,
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"audit": {Name: "audit", Ret: Void}},
		})
		if err == nil {
			t.Errorf("%s %q unexpectedly succeeded; want explicit unsupported error", tc.goarch, tc.ins)
			continue
		}
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "unsupported") && !strings.Contains(low, "not supported") {
			t.Errorf("%s %q error = %v; want explicit unsupported error", tc.goarch, tc.ins, err)
		}
	}
}
