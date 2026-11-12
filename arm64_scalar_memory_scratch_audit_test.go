package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"go/types"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

var arm64MemoryScratchAuditMoves = []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"}

func arm64MemoryScratchAuditSource() string {
	var source strings.Builder
	source.WriteString("TEXT ·DivideRem(SB),4,$0-16\nMOVD input+0(FP),R0\nMOVD output+8(FP),R11\n")
	for direction := 0; direction < 2; direction++ {
		for _, op := range arm64MemoryScratchAuditMoves {
			source.WriteString("MOVD $107,R27\nMOVD $255,R6\nMOVD $1,R7\nCMP R7,R6\n")
			if direction == 0 {
				fmt.Fprintf(&source, "%s 65536(R0),R1\n", op)
			} else {
				source.WriteString("MOVD $0x10203040aa80feff,R1\n")
				fmt.Fprintf(&source, "%s R1,65536(R0)\n", op)
			}
			source.WriteString("MOVD R1,(R11)\nSUB R0,R27,R5\nMOVD R5,8(R11)\n")
			source.WriteString("CSET MI,R2\nCSET EQ,R3\nCSET HS,R4\nCSET VS,R5\nLSL $1,R3\nLSL $2,R4\nLSL $3,R5\nORR R3,R2\nORR R4,R2\nORR R5,R2\nMOVD R2,16(R11)\nADD $24,R11\n")
		}
	}
	source.WriteString("RET\n")
	return source.String()
}

func arm64MemoryScratchAuditPrograms() (string, string) {
	const count = 42
	goSource := fmt.Sprintf(`package main
import (
    "fmt"
    "unsafe"
)
func DivideRem(input *[131072]byte, output *[%d]uint64)
func initialByte(index int) byte { return byte(index*73+128) }
func main() {
    storage := new([131088]byte)
    for i := range storage { storage[i] = 0xa7 }
    input := (*[131072]byte)(unsafe.Pointer(&storage[8]))
    for i := range input { input[i] = initialByte(i) }
    output := struct { left uint64; values [%d]uint64; right uint64 }{left:0x1234,right:0x5678}
    DivideRem(input,&output.values)
    widths := [...]uint{8,8,16,16,32,32,64}
    for i, width := range widths {
        value := uint64(0)
        for j := uint(0); j < width/8; j++ { value |= uint64(initialByte(65536+int(j))) << (j*8) }
        if i%%2 == 0 && width < 64 && value&(uint64(1)<<(width-1)) != 0 { value |= ^uint64(0) << width }
        if got := output.values[i*3]; got != value { panic(fmt.Sprintf("original Go load %%d got %%#x want %%#x",i,got,value)) }
        if got := output.values[(i+7)*3]; got != 0x10203040aa80feff { panic(fmt.Sprintf("original Go store %%d source changed: %%#x",i,got)) }
    }
    for i := 0; i < 14; i++ {
        if output.values[i*3+1] != 65536 || output.values[i*3+2] != 4 { panic(fmt.Sprintf("original Go case %%d R27/NZCV got %%x",i,output.values[i*3:i*3+3])) }
    }
    for i, value := range input {
        want := initialByte(i)
        if i >= 65536 && i < 65544 { want = byte(uint64(0x10203040aa80feff) >> (uint(i-65536)*8)) }
        if value != want { panic(fmt.Sprintf("original Go input byte %%d got %%x want %%x",i,value,want)) }
    }
    for i := 0; i < 8; i++ {
        if storage[i] != 0xa7 || storage[131080+i] != 0xa7 { panic("original Go input canary") }
    }
    if output.left != 0x1234 || output.right != 0x5678 { panic("original Go output canary") }
}
`, count, count)
	cSource := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern void DivideRem(uint8_t *,uint64_t *);
static uint8_t initial_byte(unsigned index) { return (uint8_t)(index*73+128); }
int main(void) {
    uint8_t *storage=malloc(131088);
    if (!storage) return 90;
    memset(storage,0xa7,131088);
    uint8_t *input=storage+8;
    for (unsigned i=0;i<131072;i++) input[i]=initial_byte(i);
    struct { uint64_t left,values[%d],right; } output={.left=0x1234,.right=0x5678};
    DivideRem(input,output.values);
    unsigned failed=0;
    const unsigned widths[]={8,8,16,16,32,32,64};
    for (unsigned i=0;i<7;i++) {
        unsigned width=widths[i];
        uint64_t value=0;
        for (unsigned j=0;j<width/8;j++) value|=(uint64_t)initial_byte(65536+j)<<(j*8);
        if (!(i%%2) && width<64 && (value&(UINT64_C(1)<<(width-1)))) value|=UINT64_MAX<<width;
        if (output.values[i*3]!=value || output.values[(i+7)*3]!=UINT64_C(0x10203040aa80feff)) {
            fprintf(stderr,"LLVM case %%u data mismatch\n",i);
            failed++;
        }
    }
    for (unsigned i=0;i<14;i++) {
        if (output.values[i*3+1]!=65536 || output.values[i*3+2]!=4) {
            fprintf(stderr,"LLVM case %%u R27 delta %%#llx NZCV %%llu; want 0x10000 / 4\n",i,(unsigned long long)output.values[i*3+1],(unsigned long long)output.values[i*3+2]);
            failed++;
        }
    }
    for (unsigned i=0;i<131072;i++) {
        uint8_t want=initial_byte(i);
        if (i>=65536 && i<65544) want=(uint8_t)(UINT64_C(0x10203040aa80feff)>>((i-65536)*8));
        if (input[i]!=want) { fprintf(stderr,"LLVM input byte %%u mismatch\n",i); failed++; break; }
    }
    for (unsigned i=0;i<8;i++) if (storage[i]!=0xa7 || storage[131080+i]!=0xa7) failed++;
    if (output.left!=0x1234 || output.right!=0x5678) failed++;
    free(storage);
    return failed ? 1 : 0;
}
`, count)
	return goSource, cSource
}

func arm64MemoryScratchAuditIRs(t *testing.T, source, target string) []string {
	t.Helper()
	// Match the actual standalone Go oracle's pointer types, not an unrelated
	// numerical fixture whose pointee only happens to have the same ABI width.
	pkg := mustGoPackage(t, "test/memory", "package memory\nfunc DivideRem(input *[131072]byte, output *[42]uint64)\n")
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	sizes := types.SizesFor("gc", "arm64")
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
	ir, err := Translate(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, opt)
	if err != nil {
		t.Fatal(err)
	}
	moduleIR := module.String()
	module.Dispose()
	bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve})
	if err != nil {
		t.Fatal(err)
	}
	boundIR := bound.Module.String()
	bound.Module.Dispose()
	return []string{ir, moduleIR, boundIR}
}

func TestCrossLinuxRuntimeMatrixARM64ScalarMemoryScratchAudit(t *testing.T) {
	llc, target, compiler, runner := arm64FPPairRuntimeTools(t)
	source := arm64MemoryScratchAuditSource()
	goSource, cSource := arm64MemoryScratchAuditPrograms()
	runARM64LocalRegisterGoOracle(t, source, goSource, len(runner) != 0, "1.20")
	for api, ir := range arm64MemoryScratchAuditIRs(t, source, target) {
		t.Run(fmt.Sprintf("API%d", api), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("memory-scratch-%d", api), target, ir, cSource, runner)
		})
	}
}

func TestARM64ScalarMemoryScratchAuditSavedCaller(t *testing.T) {
	pkg := mustGoPackage(t, "test/memory", "package memory\nfunc Scratch(input *[131072]byte)\n")
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	for _, op := range arm64MemoryScratchAuditMoves {
		for _, instruction := range []string{op + " 65536(R0),R1", op + " R1,65536(R0)"} {
			source := "TEXT ·Scratch(SB),4,$0-8\nMOVD input+0(FP),R0\nMOVD $17,R1\nMOVD R30,R27\n" + instruction + "\nMOVD R27,R30\nRET\n"
			requireARM64GoAssemblerResult(t, source, true) // Compile only: deliberately corrupted continuation.
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			sizes := types.SizesFor("gc", "arm64")
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
				opt := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
				if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s %s stale caller LR accepted by Translate: %v", target, instruction, err)
				}
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if err == nil {
					module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s %s stale caller LR accepted by Module: %v", target, instruction, err)
				}
				bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve})
				if err == nil {
					bound.Module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s %s stale caller LR accepted by GoModule: %v", target, instruction, err)
				}
			}
		}
	}
}

func TestARM64ScalarMemoryScratchAuditRawPCWidth(t *testing.T) {
	for _, text := range []string{"MOVD 65536(R0),R1", "MOVD R1,65536(R0)", "MOVD slot+65536(FP),R1"} {
		ins := arm64ImmediateTestInstruction(t, text)
		if width, known := arm64RawKnownSourceWidth(Func{}, ins); known {
			t.Errorf("long source memory pseudo acquired guessed physical width %d: %s", width, text)
		}
		// The raw ADR reaches the second instruction inside Go's expansion,
		// not the next source RET. Its original bytes are accepted, but there
		// is no source label at that physical PC for the current normalizer.
		source := "TEXT uncertain(SB),4,$0-0\nWORD $0x10000040\n" + text + "\ntarget:\nRET\n"
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := normalizeARM64RawPCRelative(file.Funcs[0]); err == nil {
			t.Errorf("raw ADR acquired a false source RET label across long memory pseudo: %s", text)
		}
	}
	decoded, err := decodeARM64RawWordInstruction(arm64ImmediateTestInstruction(t, "WORD $0xf9400361"))
	if err != nil {
		t.Fatal(err)
	}
	if width, known := arm64RawKnownSourceWidth(Func{}, decoded); !known || width != 4 {
		t.Fatal("physical one-WORD load lost exact four-byte width")
	}
}

func TestCrossLinuxRuntimeMatrixARM64ScalarMemoryOriginalGoEncoderState(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	goos := runtime.GOOS
	if len(runner) != 0 {
		goos = "linux"
	}
	positive := arm64ImmediateOriginalGoBytes(t, "TEXT encoder(SB),4,$0-0\nMOVD 32768(R0),R1\nRET\n", goos)
	if len(positive) < 12 {
		t.Fatal("missing positive original Go expansion")
	}
	first := binary.LittleEndian.Uint32(positive)
	var high uint64
	switch first {
	case 0x9100201b: // ADD $8,R0,R27, followed by LDR #4095*8.
		high = 8
	case 0x9140201b: // ADD $32768,R0,R27, followed by LDR #0.
		high = 32768
	default:
		t.Fatalf("unknown actual original Go expansion: %x", positive)
	}
	negative := arm64ImmediateOriginalGoBytes(t, "TEXT encoder(SB),4,$0-0\nMOVD -257(R0),R1\nRET\n", goos)
	if len(negative) < 12 {
		t.Fatal("missing negative original Go expansion")
	}
	first = binary.LittleEndian.Uint32(negative)
	address := first == 0xd104041b // SUB $257,R0,R27.
	if !address && first&0xff00001f != 0x5800001b {
		t.Fatalf("unknown actual original Go pool expansion: %x", negative)
	}
	unaligned := arm64ImmediateOriginalGoBytes(t, "TEXT encoder(SB),4,$0-0\nMOVD 32769(R0),R1\nRET\n", goos)
	if len(unaligned) < 12 {
		t.Fatal("missing unaligned original Go expansion")
	}
	first = binary.LittleEndian.Uint32(unaligned)
	unalignedAddress := first == 0x9100241b // ADD $9,R0,R27.
	if !unalignedAddress && first&0xff00001f != 0x1800001b {
		t.Fatalf("unknown actual original Go unaligned expansion: %x", unaligned)
	}
	literal := arm64ImmediateOriginalGoBytes(t, "TEXT encoder(SB),4,$0-0\nMOVD 65537(R0),R1\nRET\n", goos)
	if len(literal) < 12 || binary.LittleEndian.Uint32(literal)&0xff00001f != 0x1800001b {
		t.Fatalf("65537 is not the independently accepted literal expansion: %x", literal)
	}
	source := `TEXT ·EncoderState(SB),4,$0-16
MOVD input+0(FP),R0
MOVD output+8(FP),R11
MOVD $255,R6
MOVD $1,R7
CMP R7,R6
MOVD $107,R27
MOVD 32768(R0),R1
SUB R0,R27,R5
MOVD R5,(R11)
MOVD R1,8(R11)
MOVD $107,R27
MOVD -257(R0),R1
MOVD R27,16(R11)
MOVD R1,24(R11)
MOVD $107,R27
MOVD -8192(R0),R1
MOVD R27,32(R11)
MOVD R1,40(R11)
MOVD 32769(R0),R1
MOVD R27,48(R11)
MOVD R1,56(R11)
MOVD 65537(R0),R1
MOVD R27,64(R11)
MOVD R1,72(R11)
CSET MI,R2
CSET EQ,R3
CSET HS,R4
CSET VS,R5
LSL $1,R3
LSL $2,R4
LSL $3,R5
ORR R3,R2
ORR R4,R2
ORR R5,R2
MOVD R2,80(R11)
RET
`
	program := fmt.Sprintf(`package main
import "unsafe"
func EncoderState(input *[131072]byte, output *[11]uint64)
func pattern(index int) byte { return byte(index*73+128) }
func main() {
    storage := new([262144]byte)
    for index := range storage { storage[index] = pattern(index) }
    input := (*[131072]byte)(unsafe.Pointer(&storage[65536]))
    output := struct { left uint64; values [11]uint64; right uint64 }{left:0x1234,right:0x5678}
    EncoderState(input,&output.values)
    if output.left != 0x1234 || output.right != 0x5678 { panic("Go encoder output canary") }
    if output.values[0] != %d || output.values[4] != uint64(0xffffffffffffe000) || output.values[8] != 65537 || output.values[10] != 4 {
        panic("Go encoder R27 high/pool/NZCV")
    }
    wantNegative := uint64(0xfffffffffffffeff)
    if %v { wantNegative = uint64(uintptr(unsafe.Pointer(input))) - 257 }
    if output.values[2] != wantNegative { panic("Go encoder negative R27 category") }
    wantUnaligned := uint64(32769)
    if %v { wantUnaligned = uint64(uintptr(unsafe.Pointer(input))) + 9 }
    if output.values[6] != wantUnaligned { panic("Go encoder unaligned R27 category") }
    offsets := [...]int{32768,-257,-8192,32769,65537}
    for index, offset := range offsets {
        value := uint64(0)
        for byteIndex := 0; byteIndex < 8; byteIndex++ {
            value |= uint64(pattern(65536+offset+byteIndex)) << (uint(byteIndex)*8)
        }
        if output.values[index*2+1] != value { panic("Go encoder initialized load") }
    }
    for index, value := range storage {
        if value != pattern(index) { panic("Go encoder input canary/data changed") }
    }
}
`, high, address, unalignedAddress)
	runARM64LocalRegisterGoOracle(t, source, program, len(runner) != 0, "1.20")
	t.Logf("actual original Go bytes/state: 32768 R27=base+%d (%x); -257 address=%v (%x); 32769 address=%v (%x); 65537 literal (%x); -8192 exact signed offset; initialized data/NZCV/canaries passed", high, positive, address, negative, unalignedAddress, unaligned, literal)
}
