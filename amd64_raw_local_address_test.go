package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeX86RawLocalAddressPreservesPointerOffsets(t *testing.T) {
	// Two RIP-relative LEAs address different bytes of one unreachable table.
	code := []byte{
		0x48, 0x8d, 0x05, 0x08, 0, 0, 0, // LEAQ table+0, AX
		0x48, 0x8d, 0x1d, 0x04, 0, 0, 0, // LEAQ table+3, BX
		0xc3,
		1, 2, 3, 4, 5, 6,
	}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "local address table", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 3 || decoded[0].Op != "LEAQ" || decoded[1].Op != "LEAQ" ||
		decoded[0].Args[1].Reg != AX || decoded[1].Args[1].Reg != BX ||
		decoded[0].x86RIPAddressOff != 0 || decoded[1].x86RIPAddressOff != 3 {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
	var source strings.Builder
	source.WriteString("TEXT localAddress(SB),$0-0\n")
	for _, value := range code {
		fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Data) != 1 || len(normalized.Funcs[0].Instrs) != 4 {
		t.Fatalf("shared local address layout: %d globals, %d instructions", len(normalized.Data), len(normalized.Funcs[0].Instrs))
	}
	firstAddress := normalized.Funcs[0].Instrs[1].Args[0].Sym
	secondAddress := normalized.Funcs[0].Instrs[2].Args[0].Sym
	if firstAddress != normalized.Data[0].Sym+"(SB)" ||
		secondAddress != normalized.Data[0].Sym+"+3(SB)" {
		t.Fatalf("shared address offsets = %q, %q", firstAddress, secondAddress)
	}
	for _, triple := range []string{
		"x86_64-apple-darwin",
		"x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"localAddress": {Name: "localAddress", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "raw_address") {
				t.Fatal("shared local-address data global missing")
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "raw-local-address.ll", "raw-local-address.o", ir)
		})
	}
}

func TestDecodeX86RawLocalAddressSharesLiteralPool(t *testing.T) {
	code := []byte{
		0x48, 0x8d, 0x05, 0x09, 0, 0, 0, // LEAQ table, AX
		0x66, 0x0f, 0x6f, 0x05, 0x01, 0, 0, 0, // MOVDQU table, X0
		0xc3,
	}
	for value := byte(0); value < 16; value++ {
		code = append(code, value)
	}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "shared literal pool", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 3 || len(decoded[0].x86RIPAddressData) != 16 ||
		len(decoded[1].x86RIPAddressData) != 16 ||
		decoded[0].x86RIPAddressOff != 0 || decoded[1].x86RIPAddressOff != 0 {
		t.Fatalf("shared pool decoded as %#v", decoded)
	}
	var source strings.Builder
	source.WriteString("TEXT localAddressAndLiteral(SB),$0-0\n")
	for _, value := range code {
		fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Data) != 1 ||
		len(normalized.Funcs[0].Instrs) != 4 ||
		normalized.Funcs[0].Instrs[1].Args[0].Sym != normalized.Data[0].Sym+"(SB)" ||
		normalized.Funcs[0].Instrs[2].Args[0].Sym != normalized.Data[0].Sym+"(SB)" {
		t.Fatalf("local address and literal did not share data: %d globals, %d instructions", len(normalized.Data), len(normalized.Funcs[0].Instrs))
	}
	for _, triple := range []string{
		"x86_64-apple-darwin",
		"x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"localAddressAndLiteral": {Name: "localAddressAndLiteral", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "raw-shared-pool.ll", "raw-shared-pool.o", ir)
		})
	}
}

func TestDecodeX86RawLocalAddressRejectsReachableCode(t *testing.T) {
	code := []byte{
		0x48, 0x8d, 0x05, 0x00, 0, 0, 0, // LEAQ next instruction, AX
		0xc3,
	}
	_, err := decodeX86RawDirectiveGroup(code, 64, 0, "code address", map[string]bool{})
	if err == nil || !strings.Contains(err.Error(), "no preceding RET") {
		t.Fatalf("address of reachable code: %v", err)
	}
}
