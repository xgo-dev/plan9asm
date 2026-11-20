package plan9asm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func x86InsertExtractGoListing(t *testing.T, arch, source string) []byte {
	t.Helper()
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "original.s"), filepath.Join(dir, "original.o")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "oracle", "-o", object, asm)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(asm, object, output, err, ctx.Err(), true, arch); failure != nil {
		t.Fatalf("actual original assembler listing: %v\n%s", failure, output)
	}
	return output
}

// Parse only concrete byte columns, not assembly mnemonic text. Go's listing
// starts its columns with 0xNNNN; llvm-objdump uses NNNN:. Both are independent
// physical object observations, rather than a rendering of the typed table.
func x86InsertExtractListedBytes(line string) []byte {
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "0x") && !strings.HasSuffix(fields[0], ":") {
		return nil
	}
	if strings.HasPrefix(fields[0], "0x") {
		_, code, err := goAssemblyListingByteRow(line)
		if err != nil {
			return nil
		}
		return code
	}
	var result []byte
	for _, field := range fields[1:] {
		if len(field) != 2 {
			break
		}
		value, err := hex.DecodeString(field)
		if err != nil {
			break
		}
		result = append(result, value[0])
	}
	return result
}

func TestX86InsertExtract386HighRegistersKeepPhysicalContext(t *testing.T) {
	const source = "TEXT f(SB),4,$0-0\nVEXTRACTF128 $1,Y8,X9\nVEXTRACTPS $3,X8,AX\nRET\n"
	listing := x86InsertExtractGoListing(t, "386", source)
	var code []byte
	for _, line := range strings.Split(string(listing), "\n") {
		code = append(code, x86InsertExtractListedBytes(line)...)
	}
	if !bytes.Equal(code, []byte{0xc4, 0x43, 0x7d, 0x19, 0xc1, 1, 0xc4, 0x63, 0x79, 0x17, 0xc0, 3, 0xc3}) {
		t.Fatalf("actual Go named mode32 bytes changed: %x", code)
	}
	for _, op := range []Op{"VEXTRACTF128", "VEXTRACTPS"} {
		decode := decodedX86VEXTRACT128Instruction
		if op == "VEXTRACTPS" {
			decode = decodedX86PackedScalarExtractInstruction
		}
		ins, size, recognized, err := decode(code, 64)
		if !recognized || err != nil || ins.Op != op || ins.Args[1].Reg != map[Op]Reg{"VEXTRACTF128": "Y8", "VEXTRACTPS": "X8"}[op] {
			t.Fatalf("actual Go high-register bytes %x lost source identity: %+v/%v", code, ins, err)
		}
		if _, _, recognized, err := decode(code[:size], 32); !recognized || err == nil {
			t.Fatal("mode32 decoder invented high physical SIMD registers")
		}
		t.Logf("actual Go accepted %s bytes %x; mode32 physical binding remains Context", op, code[:size])
		code = code[size:]
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", Sigs: map[string]FuncSig{"f": {Ret: Void}}}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("Go's mode32 accepted bytes acquired ordinary physical meaning: %v", err)
	}
}

func TestX86InsertExtractNativeMaskedStorePhysicalObjects(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM22 llc and llvm-objdump are required")
	}
	var source strings.Builder
	sigs := map[string]FuncSig{}
	want := map[string]int{}
	count := 0
	for _, row := range x86InsertExtractFormats() {
		if !strings.HasPrefix(row, "VEXTRACT") || !strings.Contains(row, "K1,(BX)") {
			continue
		}
		listing := x86InsertExtractGoListing(t, "amd64", "TEXT f(SB),4,$0-0\n"+strings.Replace(row, "1,K1", "0,K1", 1)+"\nRET\n")
		matched := false
		for _, line := range strings.Split(string(listing), "\n") {
			code := x86InsertExtractListedBytes(line)
			ins, _, recognized, err := decodedX86VEXTRACT128Instruction(code, 64)
			if recognized {
				if err != nil || ins.Args[0].Imm != 255 || ins.Args[2].Reg != "K1" || ins.Args[3].Kind != OpMem {
					t.Fatalf("Go masked store identity: %+v/%v", ins, err)
				}
				matched = true
				want[string(ins.Op)+":"+string(ins.Args[1].Reg)]++
			}
		}
		if !matched {
			t.Fatalf("Go listing has no concrete E6NF bytes:\n%s", listing)
		}
		name := fmt.Sprintf("store%d", count)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVQ destination+0(FP),BX\nMOVQ mask+8(FP),AX\nKMOVQ AX,K1\nVPXORD Z1,Z1,Z1\n%s\nRET\n", name, row)
		sigs[name] = FuncSig{Ret: Void, Args: []LLVMType{Ptr, I64}, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}}}}
		count++
	}
	if count != 12 {
		t.Fatalf("incomplete EVEX masked memory width/opcode family: %d", count)
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(ir, "~{zmm0},~{k1},~{memory}") != count || strings.Contains(ir, "target-features") {
			t.Fatal("native instruction bridge lost explicit private clobbers or enabled global ISA")
		}
		dir := t.TempDir()
		input, object := filepath.Join(dir, "store.ll"), filepath.Join(dir, "store.o")
		if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := runtimeOracleStageContext(t)
		command := exec.CommandContext(ctx, llc, "-O2", "-mtriple="+triple, "-filetype=obj", input, "-o", object)
		output, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil {
			t.Fatalf("LLVM22 native E6NF object: %v\n%s", err, output)
		}
		ctx, cancel = runtimeOracleStageContext(t)
		command = exec.CommandContext(ctx, objdump, "-d", object)
		output, err = runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil {
			t.Fatalf("LLVM22 native E6NF disassembly: %v\n%s", err, output)
		}
		observed := 0
		got := map[string]int{}
		for _, line := range strings.Split(string(output), "\n") {
			code := x86InsertExtractListedBytes(line)
			ins, size, recognized, err := decodedX86VEXTRACT128Instruction(code, 64)
			if !recognized {
				continue
			}
			if err != nil || size != len(code) || ins.Args[0].Imm != 255 || ins.Args[1].Reg != "Y0" && ins.Args[1].Reg != "Z0" || ins.Args[2].Reg != "K1" || ins.Args[3].Kind != OpMem {
				t.Fatalf("LLVM native write-only instruction identity %s: %+v/%v", line, ins, err)
			}
			observed++
			got[string(ins.Op)+":"+string(ins.Args[1].Reg)]++
		}
		if observed != count || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: native masked stores observed %d want %d\n%s", triple, observed, count, output)
		}
	}
}

func x86InsertExtractReservedZeroMaskGoObservation(t *testing.T, source string, expectedCode ...byte) {
	t.Helper()
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "reserved.s"), filepath.Join(dir, "reserved.o")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-o", object, asm)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(asm, object, output, err, ctx.Err(), err == nil, "amd64"); failure != nil {
		t.Fatalf("reserved zero-mask source observation: %v\n%s", failure, output)
	}
	if err != nil {
		return // actual concrete source rejection; never an unknown tool failure
	}
	code := []byte{0x62, 0xf3, 0x7d, 0xc8, 0x19, 0xc1, 0}
	decode := decodedX86VEXTRACT128Instruction
	if strings.Contains(source, "VINSERT") {
		code = []byte{0x62, 0xf3, 0xfd, 0xc8, 0x3a, 0xc8, 0}
		decode = decodedX86EVEXPackedInsertInstruction
	}
	if len(expectedCode) != 0 {
		code = expectedCode
	}
	var listing strings.Builder
	for _, value := range code {
		fmt.Fprintf(&listing, "%02x ", value)
	}
	if !bytes.Contains(output, []byte(strings.TrimSpace(listing.String()))) {
		t.Fatalf("accepted old Go reserved bytes changed:\n%s", output)
	}
	if _, _, recognized, err := decode(code, 64); !recognized || err == nil {
		t.Fatal("reserved EVEX.z with aaa=0 acquired valid physical meaning")
	}
}

func TestCrossLinuxRuntimeMatrixX86InsertExtractOriginalGoPSOracle(t *testing.T) {
	_, _, _, _ = x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, checks strings.Builder
	declarations.WriteString("package oracle\n")
	checks.WriteString(`package oracle
import ("encoding/binary";"testing")
func TestOriginalPSBits(t *testing.T) {
 a:=[4]uint32{0x7f812345,0x80000000,0xffc45678,0x01234567}
 b:=[4]uint32{0x89abcdef,0x7fc11111,0x7f800000,1}
`)
	for index, immediate := range []int{0, 16, 32, 48, 64, 128, 192, 1, 2, 4, 8, 15, 255} {
		name := fmt.Sprintf("insert%d", index)
		fmt.Fprintf(&declarations, "func %s(out,a,b *[4]uint32)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVUPS (BX),X0\nMOVUPS (CX),X1\nINSERTPS $%d,X0,X1\nMOVUPS X1,(AX)\nRET\n", name, immediate)
		fmt.Fprintf(&checks, "{var out [4]uint32;want:=b;want[%d]=a[%d];for lane:=0;lane<4;lane++{if %d&(1<<lane)!=0{want[lane]=0}};%s(&out,&a,&b);if out!=want{t.Fatalf(%q, out,want)}}\n", immediate>>4&3, immediate>>6&3, immediate, name, name+" got=%x want=%x")
	}
	for lane := 0; lane < 4; lane++ {
		name := fmt.Sprintf("extract%d", lane)
		fmt.Fprintf(&declarations, "func %s(out *[8]byte,a *[4]uint32)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-16\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVUPS (BX),X0\nEXTRACTPS $%d,X0,CX\nMOVQ CX,(AX)\nRET\n", name, lane)
		fmt.Fprintf(&checks, "{var out [8]byte;%s(&out,&a);if binary.LittleEndian.Uint64(out[:])!=uint64(a[%d]){t.Fatalf(%q,out)}}\n", name, lane, name+" zero-extension got=%x")
	}
	declarations.WriteString("func fpFields(a,b,c,d byte) uint32\nfunc fpStores(a,b,c,d byte) uint32\n")
	// ABI0 aligns the result area to the AMD64 stack word independently of
	// the four byte parameters; the actual Go wrapper reads ret+8(FP).
	assembly.WriteString("TEXT ·fpFields(SB),4,$0-12\nPXOR X0,X0\nINSERTPS $0,a+0(FP),X0\nEXTRACTPS $0,X0,ret+8(FP)\nRET\n" +
		"TEXT ·fpStores(SB),4,$0-12\nMOVL $0x87654321,CX\nMOVD CX,X1\nEXTRACTPS $0,X1,a+0(FP)\nMOVBLZX a+0(FP),AX\nMOVBLZX b+1(FP),BX\nSHLL $8,BX\nORL BX,AX\nMOVBLZX c+2(FP),BX\nSHLL $16,BX\nORL BX,AX\nMOVBLZX d+3(FP),BX\nSHLL $24,BX\nORL BX,AX\nMOVL AX,ret+8(FP)\nRET\n")
	checks.WriteString(`for i:=0;i<256;i++ {
 a,b,c,d:=byte(i),byte(i*37),byte(i*59),byte(i*71)
 want:=uint32(a)|uint32(b)<<8|uint32(c)<<16|uint32(d)<<24
 if got:=fpFields(a,b,c,d);got!=want{t.Fatalf("original Go FP fields got=%x want=%x",got,want)}
 if got:=fpStores(a,b,c,d);got!=0x87654321{t.Fatalf("original Go FP stores got=%x",got)}
}
`)
	checks.WriteString("}\n")
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	dir := t.TempDir()
	for file, contents := range map[string]string{"go.mod": "module oracle\n\ngo 1.20\n", "value.go": declarations.String(), "value_amd64.s": assembly.String(), "value_test.go": checks.String()} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=asmdecl", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go PS original bit-transfer oracle: %v\n%s", err, output)
	}
}
