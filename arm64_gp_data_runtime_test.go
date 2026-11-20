package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type arm64GPDataOracle struct {
	goValue, cValue string
	goLeft, cLeft   string
	goRight, cRight string
	flagKind, bits  int
}

// These mathematical expressions are independent of the translator's typed
// input selector. Both languages receive original input bytes, not IR outputs.
func arm64GPDataExpected(text string) arm64GPDataOracle {
	parts := strings.SplitN(text, " ", 2)
	op, args := parts[0], strings.Split(parts[1], ",")
	word := strings.HasSuffix(op, "W") && op != "SXTW" && op != "UXTW"
	if word {
		op = strings.TrimSuffix(op, "W")
	}
	bits := 64
	if word {
		bits = 32
	}
	a, b := "a", "b"
	if arm64GPDataReadsDestination(text) && len(args) == 2 {
		b = "c"
	}
	switch args[0] {
	case "$17":
		a = "literal17"
	case "R4<<1":
		a = "(a << 1)"
	case "R4.UXTB<<1":
		a = "((a & 255) << 1)"
	}
	goValue, cValue, left, right, flagKind := "", "", b, a, 0
	switch op {
	case "ADD", "ADDS":
		goValue = "(" + b + " + " + a + ")"
	case "SUB", "SUBS":
		goValue = "(" + b + " - " + a + ")"
	case "AND", "ANDS":
		goValue = "(" + b + " & " + a + ")"
	case "ORR":
		goValue = "(" + b + " | " + a + ")"
	case "EOR":
		goValue = "(" + b + " ^ " + a + ")"
	case "BIC", "BICS":
		goValue, cValue = "("+b+" & ^"+a+")", "("+b+" & ~"+a+")"
	case "ORN":
		goValue, cValue = "("+b+" | ^"+a+")", "("+b+" | ~"+a+")"
	case "EON":
		goValue, cValue = "("+b+" ^ ^"+a+")", "("+b+" ^ ~"+a+")"
	case "NEG", "NEGS":
		goValue, left = "(0 - "+a+")", "0"
	case "MVN":
		goValue, cValue = "(^"+a+")", "(~"+a+")"
	case "LSL", "LSR", "ASR", "ROR":
		amount := fmt.Sprintf("(a & %d)", bits-1)
		if args[0] == "$1" {
			amount = "1"
		}
		base := b
		if word {
			base = "(b & 0xffffffff)"
			if b == "c" {
				base = "(c & 0xffffffff)"
			}
		}
		switch op {
		case "LSL":
			goValue = "(" + base + " << " + amount + ")"
		case "LSR":
			goValue = "(" + base + " >> " + amount + ")"
		case "ASR":
			goValue, cValue = "uint64(int64("+base+") >> "+amount+")", "(uint64_t)((int64_t)"+base+" >> "+amount+")"
			if word {
				goValue, cValue = "uint64(int32("+base+") >> "+amount+")", "(uint64_t)((int32_t)"+base+" >> "+amount+")"
			}
		case "ROR":
			goValue = fmt.Sprintf("rotate(%s, %s, %d)", base, amount, bits)
		}
	case "SXTB", "SXTH", "SXTW", "UXTB", "UXTH", "UXTW":
		width := 32
		if strings.HasSuffix(op, "B") {
			width = 8
		} else if strings.HasSuffix(op, "H") {
			width = 16
		}
		goValue = fmt.Sprintf("(a & %d)", (uint64(1)<<uint(width))-1)
		if strings.HasPrefix(op, "S") {
			goValue = fmt.Sprintf("signedField(a, %d)", width)
		}
	case "BFI":
		goValue, cValue = "((c & ^uint64(254)) | ((a & 127) << 1))", "((c & ~UINT64_C(254)) | ((a & 127) << 1))"
	case "BFXIL":
		goValue, cValue = "((c & ^uint64(127)) | ((a >> 1) & 127))", "((c & ~UINT64_C(127)) | ((a >> 1) & 127))"
	case "UBFIZ":
		goValue = "((a & 127) << 1)"
	case "SBFIZ":
		goValue = "(signedField(a, 7) << 1)"
	case "UBFX":
		goValue = "((a >> 1) & 127)"
	case "SBFX":
		goValue = "signedField(a >> 1, 7)"
	default:
		panic("unobserved GP oracle spelling: " + text)
	}
	if cValue == "" {
		cValue = goValue
	}
	if op == "ADDS" {
		flagKind = 1
	} else if op == "SUBS" || op == "NEGS" {
		flagKind = 2
	} else if op == "ANDS" || op == "BICS" {
		flagKind = 3
	}
	if word {
		goValue = "uint64(uint32(" + goValue + "))"
		cValue = "(uint64_t)(uint32_t)(" + cValue + ")"
	}
	if flagKind == 0 {
		left, right, bits, flagKind = "a", "b", 64, 2 // Original preceding CMP.
	}
	return arm64GPDataOracle{
		goValue: goValue, cValue: cValue, goLeft: left, cLeft: left,
		goRight: right, cRight: right, flagKind: flagKind, bits: bits,
	}
}

func TestCrossLinuxRuntimeMatrixARM64GPDataInputs(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	file, sigs, source := arm64GPDataFamilyFixture(t)
	var goDecls, goChecks, cDecls, cChecks strings.Builder
	for index, form := range arm64GPDataForms() {
		name := fmt.Sprintf("gpDataCaller%d", index)
		oracle := arm64GPDataExpected(form)
		fmt.Fprintf(&goDecls, "func %s(*byte, *byte)\n", name)
		fmt.Fprintf(&goDecls, "func expected%d(a, b, c uint64) (uint64, uint64) {\n result := %s\n return result, flags(%s, %s, result, %d, %d)\n}\n", index,
			oracle.goValue, oracle.goLeft, oracle.goRight, oracle.flagKind, oracle.bits)
		fmt.Fprintf(&cDecls, "extern void %s(const unsigned char *, unsigned char *);\n", name)
		fmt.Fprintf(&cDecls, "static uint64_t expected%d(uint64_t a, uint64_t b, uint64_t c, uint64_t *nzcv) {\n uint64_t result = %s;\n *nzcv = flags(%s, %s, result, %d, %d);\n return result;\n}\n", index,
			oracle.cValue, oracle.cLeft, oracle.cRight, oracle.flagKind, oracle.bits)
		fmt.Fprintf(&goChecks, "check(%s, expected%d)\n", name, index)
		fmt.Fprintf(&cChecks, "if (check(%s, expected%d)) { return 1; }\n", name, index)
	}
	// Insert the same baseline CMP and post-instruction flag read into all
	// original functions. MOVD/ORR/LSL do not change flags. g is restored before
	// returning; actual Go independently reads its caller's g on either side.
	for _, form := range arm64GPDataForms() {
		original := strings.ReplaceAll(form, "R9", "g")
		replacement := "CMP R5,R4\n" + original + "\nMOVD g,(R1)\n" +
			"CSET VS,R7\nCSET CS,R8\nLSL $1,R8\nORR R8,R7\n" +
			"CSET EQ,R8\nLSL $2,R8\nORR R8,R7\nCSET MI,R8\nLSL $3,R8\nORR R8,R7\nMOVD R7,8(R1)"
		source = strings.Replace(source, original+"\nMOVD g,(R1)", replacement, 1)
	}
	var err error
	file, err = Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	requireARM64GoAssemblerResult(t, source, true)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":  "module gpdatacalleroracle\n\ngo 1.20\n",
		"main.go": arm64GPDataOracleGo + goDecls.String() + "func main() {\n" + goChecks.String() + "}\n",
		"oracle_arm64.s": strings.ReplaceAll(source, "TEXT gpDataCaller", "TEXT ·gpDataCaller") +
			"\nTEXT ·readGoG(SB),516,$0-8\nMOVD g,R0\nMOVD R0,ret+0(FP)\nRET\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	args := []string{"run", "-p=1", "."}
	if len(runner) != 0 {
		args = []string{"run", "-p=1", "-exec=qemu-aarch64", "."}
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		cmd.Env = append(cmd.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("actual Go GP data/g/LR/NZCV/canary oracle: %v\n%s", err, output)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "gp_data_caller", triple, ir,
		arm64GPDataOracleC+cDecls.String()+"int main(void) {\n"+cChecks.String()+"return 0;\n}\n", runner)
	t.Logf("actual Go + LLVM22/independent Go/C: %d forms x 128 patterns x 5 unaligned offsets; numeric/NZCV/full canaries, actual fixed-g/caller return", len(file.Funcs))
}

const arm64GPDataOracleGo = `package main
import "encoding/binary"

const literal17 uint64 = 17

func readGoG() uintptr

func signedField(x uint64, width uint) uint64 {
 return uint64(int64(x << (64-width)) >> (64-width))
}

func rotate(x, amount uint64, width uint) uint64 {
 mask := ^uint64(0) >> (64-width)
 x &= mask
 amount &= uint64(width-1)
 return ((x >> amount) | (x << ((0-amount)&uint64(width-1)))) & mask
}

func flags(left, right, result uint64, kind int, width uint) uint64 {
 mask := ^uint64(0) >> (64-width)
 left, right = left&mask, right&mask
 sign := uint64(1) << (width-1)
 r := (left-right)&mask
 if kind == 1 { r = (left+right)&mask }
 if kind == 3 { r = result&mask }
 var value uint64
 if r&sign != 0 { value |= 8 }
 if r == 0 { value |= 4 }
 if kind == 2 && left >= right { value |= 2 }
 if kind == 1 && r < left { value |= 2 }
 if kind == 2 && ((left^right)&(left^r)&sign) != 0 { value |= 1 }
 if kind == 1 && ((^(left^right))&(left^r)&sign) != 0 { value |= 1 }
 return value
}

func check(call func(*byte,*byte), expected func(uint64,uint64,uint64)(uint64,uint64)) {
 var input, output, want [96]byte
 seed := uint64(0x0123456789abcdef)
 for trial := 0; trial < 128; trial++ {
  for _, off := range []int{0,1,3,7,17} {
   for i := range input {
    seed = seed*6364136223846793005+1
    input[i] = byte(seed>>56)
    output[i], want[i] = 0xa5, 0xa5
   }
   a := binary.LittleEndian.Uint64(input[off:])
   b := binary.LittleEndian.Uint64(input[off+8:])
   c := binary.LittleEndian.Uint64(input[off+16:])
   if trial < 64 { a = uint64(1) << trial }
   if trial == 64 { a, b = ^uint64(0), 1 }
   if trial == 65 { a, b = 1<<63, 1 }
   if trial == 66 { a, b = 0, 0 }
   binary.LittleEndian.PutUint64(input[off:], a)
   binary.LittleEndian.PutUint64(input[off+8:], b)
   result, nzcv := expected(a,b,c)
   binary.LittleEndian.PutUint64(want[off:], result)
   binary.LittleEndian.PutUint64(want[off+8:], nzcv)
   snapshot := input
   before := readGoG()
   call(&input[off], &output[off])
   if before == 0 || before != readGoG() || input != snapshot || output != want {
    panic("GP data/NZCV/canary/g/caller mismatch")
   }
  }
 }
}
`

const arm64GPDataOracleC = `#include <stdint.h>
#include <string.h>
#include <stdio.h>

static const uint64_t literal17 = 17;

static uint64_t signedField(uint64_t x, unsigned width) {
 return (uint64_t)((int64_t)(x << (64-width)) >> (64-width));
}

static uint64_t rotate(uint64_t x, uint64_t amount, unsigned width) {
 uint64_t mask = UINT64_MAX >> (64-width);
 x &= mask;
 amount &= width-1;
 return ((x >> amount) | (x << ((0-amount)&(width-1)))) & mask;
}

static uint64_t flags(uint64_t left, uint64_t right, uint64_t result, int kind, unsigned width) {
 uint64_t mask = UINT64_MAX >> (64-width);
 left &= mask;
 right &= mask;
 uint64_t sign = UINT64_C(1) << (width-1);
 uint64_t r = (left-right)&mask;
 if (kind == 1) { r = (left+right)&mask; }
 if (kind == 3) { r = result&mask; }
 uint64_t value = 0;
 if (r&sign) { value |= 8; }
 if (!r) { value |= 4; }
 if (kind == 2 && left >= right) { value |= 2; }
 if (kind == 1 && r < left) { value |= 2; }
 if (kind == 2 && ((left^right)&(left^r)&sign)) { value |= 1; }
 if (kind == 1 && ((~(left^right))&(left^r)&sign)) { value |= 1; }
 return value;
}

static uint64_t readG(void) {
 uint64_t value;
 __asm__ volatile("mov %0,x28" : "=r"(value));
 return value;
}

static int check(void (*call)(const unsigned char *,unsigned char *),
                 uint64_t (*expected)(uint64_t,uint64_t,uint64_t,uint64_t *)) {
 unsigned char input[96], output[96], want[96], snapshot[96];
 const unsigned offsets[] = {0,1,3,7,17};
 uint64_t seed = UINT64_C(0x0123456789abcdef);
 for (unsigned trial = 0; trial < 128; trial++) {
  for (unsigned o = 0; o < 5; o++) {
   unsigned off = offsets[o];
   for (unsigned i = 0; i < 96; i++) {
    seed = seed*UINT64_C(6364136223846793005)+1;
    input[i] = (unsigned char)(seed>>56);
    output[i] = want[i] = 0xa5;
   }
   uint64_t a, b, c;
   memcpy(&a,input+off,8);
   memcpy(&b,input+off+8,8);
   memcpy(&c,input+off+16,8);
   if (trial < 64) { a = UINT64_C(1) << trial; }
   if (trial == 64) { a = UINT64_MAX; b = 1; }
   if (trial == 65) { a = UINT64_C(1) << 63; b = 1; }
   if (trial == 66) { a = b = 0; }
   memcpy(input+off,&a,8);
   memcpy(input+off+8,&b,8);
   uint64_t nzcv, result = expected(a,b,c,&nzcv);
   memcpy(want+off,&result,8);
   memcpy(want+off+8,&nzcv,8);
   memcpy(snapshot,input,96);
   uint64_t before = readG();
   call(input+off,output+off);
   if (before != readG() || memcmp(input,snapshot,96) || memcmp(output,want,96)) {
    fprintf(stderr,"GP data trial/offset %u/%u\n",trial,off);
    return 1;
   }
  }
 }
 return 0;
}
`
