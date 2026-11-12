package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Intel's ENQCMD family uses F2/F3 0F 38 F8 /r, a 64-byte memory
// source, a GP destination address, and ZF to report retry. Neither
// spelling is present in Go 1.27's x86 opcode tables; ixl-go uses BYTE.
// https://www.intel.com/content/dam/develop/external/us/en/documents/architecture-instruction-set-extensions-programming-reference-737410.pdf
func TestX86RawEnqueueFamilyObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, family := range []struct {
		name   string
		prefix byte
	}{
		{"ENQCMD", 0xf2},
		{"ENQCMDS", 0xf3},
	} {
		for _, target := range []struct {
			arch, triple string
		}{
			{"amd64", "x86_64-apple-darwin"},
			{"amd64", "x86_64-unknown-linux-gnu"},
			{"amd64", "x86_64-pc-windows-msvc"},
			{"386", "i386-unknown-linux-gnu"},
			{"386", "i686-pc-windows-msvc"},
		} {
			t.Run(family.name+"/"+target.triple, func(t *testing.T) {
				source := fmt.Sprintf(`TEXT enqueue(SB),$0-0
	MOVL $0, AX
	MOVL $0, BX
	BYTE $0x%02x; BYTE $0x0f; BYTE $0x38; BYTE $0xf8; BYTE $0x03
	SETEQ AX
	RET
`, family.prefix)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := decodeX86RawDirectives(file.Funcs[0], target.arch)
				if err != nil {
					t.Fatal(err)
				}
				instruction := decoded.Instrs[len(decoded.Instrs)-3]
				if instruction.Op != Op(family.name) || len(instruction.Args) != 2 ||
					instruction.Args[0].Kind != OpMem || instruction.Args[0].Mem.Base != BX ||
					instruction.Args[1].Kind != OpReg || instruction.Args[1].Reg != AX {
					t.Fatalf("wrong command source/destination: %+v", instruction)
				}
				// The original source has no ABI0 result field and uses null
				// device/source addresses. It is a format witness, not a closed
				// public entry or an executable hardware/PASID contract.
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func enqueue() uint32", target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("device format invented an initialized ABI0 return", api, err)
					}
				}
				original := *file
				original.Funcs = []Func{decoded}
				ir := x86ScalarFormatObjectUnit(t, &original,
					map[string]FuncSig{"enqueue": {Name: "enqueue", Ret: I32}}, target.arch, target.triple, 0)
				if !strings.Contains(ir, strings.ToLower(family.name)) {
					t.Fatalf("lost device command %s", family.name)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			})
		}
	}
}

func TestX86RawEnqueueAddressGrammar(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, test := range []struct {
		name        string
		mode        int
		code        []byte
		address     string
		destination Reg
		bits        int
	}{
		{"base64", 64, []byte{0xf2, 0x0f, 0x38, 0xf8, 0x03}, "0(BX)", AX, 64},
		{"base32", 32, []byte{0xf3, 0x0f, 0x38, 0xf8, 0x03}, "0(BX)", AX, 32},
		{"sib_disp8", 64, []byte{0xf2, 0x44, 0x0f, 0x38, 0xf8, 0x54, 0x8b, 0x80}, "-128(BX)(CX*4)", "R10", 64},
		{"extended_base_index", 64, []byte{0xf2, 0x47, 0x0f, 0x38, 0xf8, 0x14, 0x8b}, "0(R11)(R9*4)", "R10", 64},
		{"disp32", 32, []byte{0xf2, 0x0f, 0x38, 0xf8, 0xb0, 0x78, 0x56, 0x34, 0x12}, "305419896(AX)", SI, 32},
		{"absolute32", 32, []byte{0xf2, 0x0f, 0x38, 0xf8, 0x05, 0x00, 0x10, 0x00, 0x00}, "4096()", AX, 32},
		{"override32", 64, []byte{0x67, 0xf2, 0x0f, 0x38, 0xf8, 0x03}, "0(BX)", AX, 32},
		{"override16", 32, []byte{0x67, 0xf2, 0x0f, 0x38, 0xf8, 0x00}, "0(BX)(SI*1)", AX, 16},
		{"fs", 64, []byte{0x64, 0xf2, 0x0f, 0x38, 0xf8, 0x03}, "0(BX)(FS)", AX, 64},
		{"gs", 32, []byte{0x65, 0xf3, 0x0f, 0x38, 0xf8, 0x03}, "0(BX)(GS)", AX, 32},
		{"rex_reset", 64, []byte{0x44, 0xf2, 0x0f, 0x38, 0xf8, 0x03}, "0(BX)", AX, 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			ins, length, ok, err := decodedX86EnqueueInstruction(test.code, test.mode)
			if err != nil || !ok || length != len(test.code) {
				t.Fatalf("decode = %+v, %d, %v, %v", ins, length, ok, err)
			}
			if ins.Args[0].String() != test.address || ins.Args[1].Reg != test.destination || ins.x86AddressBits != test.bits {
				t.Fatalf("decoded %+v address=%s, want %s, %s, %d bits", ins, ins.Args[0], test.address, test.destination, test.bits)
			}
			arch, triple := "amd64", "x86_64-unknown-linux-gnu"
			if test.mode == 32 {
				arch, triple = "386", "i386-unknown-linux-gnu"
			}
			// Retain every original physical address form and its actual Go
			// bytes. This format has no initialized source/device addresses.
			source := "TEXT enqueue(SB),$0-0\n" + x86RawDisplacementDirectives(test.code) + "RET\n"
			ir := x86UnboundVoidRawScalarFormatObject(t, source, arch, triple)
			for _, flag := range []string{"cf", "of", "slt", "pf"} {
				if strings.Count(ir, "store i1 false, ptr %flags_"+flag) < 2 {
					t.Fatalf("missing cleared %s status flag", flag)
				}
			}
			if !strings.Contains(ir, "elementtype([64 x i8])") || !strings.Contains(ir, "; sete $0") {
				t.Fatal("lost command width or device retry status")
			}
			compileLLVMToObject(t, llc, triple, "address.ll", "address.o", ir)
			if segment := ins.Args[0].Mem.Segment; segment != "" {
				cmd := exec.Command(llc, "-O0", "-mtriple="+triple, "-filetype=asm", "-o", "-", "-")
				cmd.Stdin = strings.NewReader(ir)
				assembly, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("emit assembly: %v\n%s", err, assembly)
				}
				if !strings.Contains(string(assembly), "%"+strings.ToLower(string(segment))+":") {
					t.Fatalf("source segment override was lost:\n%s", assembly)
				}
			}
		})
	}
}

func TestX86RawEnqueueRejectsInvalidEncodings(t *testing.T) {
	for _, code := range [][]byte{
		{0xf2, 0x0f, 0x38, 0xf8},
		{0xf2, 0x0f, 0x38, 0xf8, 0xc3},
		{0xf3, 0x0f, 0x38, 0xf8, 0x04},
		{0xf2, 0x0f, 0x38, 0xf8, 0x43},
		{0xf2, 0x0f, 0x38, 0xf8, 0x83, 0x01},
		{0xf0, 0xf2, 0x0f, 0x38, 0xf8, 0x03},
	} {
		for _, mode := range []int{32, 64} {
			if _, _, ok, err := decodedX86EnqueueInstruction(code, mode); !ok || err == nil {
				t.Fatalf("accepted malformed %x in mode %d: recognized=%v err=%v", code, mode, ok, err)
			}
		}
	}
	for _, code := range [][]byte{
		{0x0f, 0x38, 0xf8, 0x03},
		{0xf2, 0x0f, 0x38, 0xf9, 0x03},
		{0xb8, 0xf2, 0x0f, 0x38, 0xf8},
	} {
		if _, _, ok, _ := decodedX86EnqueueInstruction(code, 64); ok {
			t.Fatalf("claimed another instruction: %x", code)
		}
	}
}

func TestX86EnqueueRejectsInvalidOperands(t *testing.T) {
	for _, op := range []string{"ENQCMD", "ENQCMDS"} {
		for _, tail := range []string{" AX, BX", " (AX), X0", " (AX), (BX)", " (AX)", ".Z (AX), BX"} {
			file, err := Parse(ArchAMD64, "TEXT invalid(SB),$0-0\n"+op+tail+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{Goarch: "amd64", Sigs: map[string]FuncSig{
				"invalid": {Name: "invalid", Ret: Void},
			}}); err == nil {
				t.Fatalf("accepted %s%s", op, tail)
			}
		}
	}
}
