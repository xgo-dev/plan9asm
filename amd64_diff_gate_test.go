//go:build !llgo

package plan9asm

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
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
extern void diffBitCond(uint64_t a, uint64_t b, uint64_t *out);
extern void diffAtomicAndString(uint8_t *buf, uint64_t val, uint64_t *out);
extern int64_t diffZeroArgCaller(void);
extern void diffADX(uint64_t a, uint64_t b, uint64_t *out);
extern void diffPCMPESTRI0C(uint8_t *needle, uint8_t *hay, uint64_t nLen, uint64_t hLen, uint64_t *out);
extern void diffSHA256Block(uint32_t *state, uint8_t *block);
extern void diffSHA1Block(uint32_t *state, uint8_t *block);

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
	// Round 6 P1 #2 & #3: flags[1] is a=15, b=1 -> [0]&1==1, [1]&1==1, [2]==1, [3]==0, [8]==0x10 (16)
	fl := strings.Split(llvmMap["flags[1]"], ",")
	if fl[2] != "0000000000000001" || fl[3] != "0000000000000000" || fl[8] != "0000000000000010" {
		t.Fatalf("flags[1] unexpected PUSHFQ/POPFQ/LAHF(AF): %s", llvmMap["flags[1]"])
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
		t.Logf("portable LLVM -O2 execution + SHA-NI/Round6 golden checks PASSED (%d cases); native amd64 Go-asm diff runs on amd64 runners", len(llvmMap))
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
	for k, want := range oracleMap {
		got, ok := llvmMap[k]
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("%s: missing from LLVM transcript (oracle=%s)", k, want))
			continue
		}
		compared++
		if got != want {
			mismatches = append(mismatches, fmt.Sprintf("%s:\n  go-asm:   %s\n  plan9asm: %s", k, want, got))
		}
	}
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
		// 386 unmodeled FPATAN & system/segment stubs
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "FPATAN"},
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
