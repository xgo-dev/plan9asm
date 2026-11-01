package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86StaticReturnSource(name string, code []byte) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n", name)
	for _, value := range code {
		fmt.Fprintf(&source, "BYTE $0x%02x\n", value)
	}
	return source.String()
}

func TestX86RawReturnSharedRIPReadContract(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	cases := []struct {
		name  string
		code  []byte
		width int
	}{
		{"legacy-i32", []byte{0x8b, 0x05, 1, 0, 0, 0, 0xc3, 1, 2, 3, 4}, 4},
		{"legacy-i64", []byte{0x48, 0x8b, 0x05, 1, 0, 0, 0, 0xc3, 1, 2, 3, 4, 5, 6, 7, 8}, 8},
		{"legacy-vector", x86RawLegacyPackedMoveConstant(0xf3, 0x6f), 16},
		{"vex-vector", x86RawPackedMoveLiteral(false, 32), 32},
		{"evex-vector", x86RawPackedMoveLiteral(true, 64), 64},
		{"broadcast-f32", x86RawBinaryFloatLiteral(0x58, 0, true, 64, true), 4},
		{"broadcast-f64", x86RawBinaryFloatLiteral(0x58, 1, true, 64, true), 8},
		{"scalar-f32", x86RawBinaryFloatLiteral(0x58, 2, false, 16, false), 4},
		{"scalar-f64", x86RawBinaryFloatLiteral(0x58, 3, false, 16, false), 8},
		{"nonfirst-source", x86RawCLMULLiteral("legacy", 16), 16},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			source := x86StaticReturnSource("Bound", test.code)
			requireX86GoAssemblerResult(t, "amd64", source, true)
			prepared, err := NormalizeRawFileForTranslation(mustParseX86RawReturn(t, source), "amd64")
			if err != nil {
				t.Fatal("shared RIP read rejected before materialization:", err)
			}
			if len(prepared.Data) != 1 || prepared.Data[0].Width != int64(test.width) {
				t.Fatalf("materialized data: %+v, want exact width %d", prepared.Data, test.width)
			}
			for _, target := range x86RawReturnTargets {
				if target.arch != "amd64" {
					continue // RIP-relative addressing exists only in 64-bit mode.
				}
				opt := Options{Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: Void}}}
				x86RawReturnPointerAPIs(t, source, opt, false)
				ir, err := Translate(prepared, opt)
				if err != nil {
					t.Fatal("prepartition/final validation disagreed:", err)
				}
				compileLLVMToObject(t, llc, target.triple, "bounded-rip.ll", "bounded-rip.o", ir)
			}
		})
	}
}

func TestX86RawReturnStaticDATAExtents(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		for _, offset := range []int{0, 4, 5} {
			source := fmt.Sprintf("DATA pool<>+4(SB)/4,$0x76543210\nTEXT Bound(SB),4,$0-0\nMOVL pool<>+%d(SB),AX\nBYTE $0xc3\n", offset)
			requireX86GoAssemblerResult(t, target.arch, source, true)
			opt := Options{Goarch: target.arch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: I32}}}
			x86RawReturnPointerAPIs(t, source, opt, offset == 5)
			if offset != 5 {
				ir, err := Translate(mustParseX86RawReturn(t, source), opt)
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "bounded-data.ll", "bounded-data.o", ir)
			}
		}
	}
}

func TestX86RawReturnMaterializedReadCannotAuthorizeChangedSource(t *testing.T) {
	source := x86StaticReturnSource("Bound", x86RawPackedMoveLiteral(false, 32))
	mutations := map[string]func(*File){
		"opcode store": func(file *File) {
			file.Funcs[0].Instrs[1].Op = "VMOVDQU"
			args := file.Funcs[0].Instrs[1].Args
			args[0], args[1] = args[1], args[0]
		},
		"unrecognized opcode": func(file *File) {
			file.Funcs[0].Instrs[1].Op = "UNRECOGNIZED"
		},
		"pointer operand": func(file *File) {
			file.Funcs[0].Instrs[1].Args[0] = Operand{Kind: OpMem, Mem: MemRef{Base: AX}}
		},
		"shifted source": func(file *File) {
			file.Funcs[0].Instrs[1].Args[0].Sym = file.Data[0].Sym + "+1(SB)"
		},
		"missing data": func(file *File) {
			file.Data = nil
		},
		"short object": func(file *File) {
			file.Data[0].Width--
			file.Data[0].Payload = file.Data[0].Payload[:len(file.Data[0].Payload)-1]
		},
		"changed payload": func(file *File) {
			payload := append([]byte(nil), file.Data[0].Payload...)
			payload[0] ^= 0xff
			file.Data[0].Payload = payload
		},
		"extra DATA write": func(file *File) {
			file.Data = append(file.Data, DataStmt{Sym: file.Data[0].Sym, Width: 1, Value: 0xff})
		},
		"wrong pending index": func(file *File) {
			file.Funcs[0].Instrs[1].Args[1] = Operand{Kind: OpSym, Sym: "·__plan9asm_raw_literal_pending(SB)"}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			file, err := NormalizeRawFileForTranslation(mustParseX86RawReturn(t, source), "amd64")
			if err != nil {
				t.Fatal(err)
			}
			mutate(file)
			for _, target := range x86RawReturnTargets {
				if target.arch != "amd64" {
					continue
				}
				opt := Options{Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: Void}}}
				// Test every final API on this exact prepared/changed file.
				if x86RawReturnMemoryBound(file.Funcs[0], file, opt, true) {
					t.Fatal("a decoded read authorized changed source or missing backing")
				}
				for _, api := range []string{"text", "module", "owned-module"} {
					var callErr error
					switch api {
					case "text":
						_, callErr = Translate(file, opt)
					case "module":
						module, err := TranslateModule(file, opt)
						if err == nil {
							module.Dispose()
						}
						callErr = err
					default:
						ctx := llvm.NewContext()
						module, err := TranslateModuleInContext(ctx, file, opt)
						if err == nil {
							module.Dispose()
						}
						ctx.Dispose()
						callErr = err
					}
					if !errors.Is(callErr, ErrProbeNeedsContext) {
						t.Errorf("%s changed prepared source bypassed the read contract: %v", api, callErr)
					}
				}
			}
		})
	}
}

func TestX86RawReturnRIPReadRequires64BitDecodeContext(t *testing.T) {
	source := x86StaticReturnSource("Bound", x86RawPackedMoveLiteral(false, 32))
	file, err := NormalizeRawFileForTranslation(mustParseX86RawReturn(t, source), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: Void}}}
	_, err = Translate(file, opt)
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("64-bit RIP proof was reused as a 32-bit absolute-address proof: %v", err)
	}
}

func TestX86RawReturnSharedAddressPoolRetainsExactReadRange(t *testing.T) {
	code := []byte{
		0x48, 0x8d, 0x05, 0x09, 0, 0, 0, // LEAQ pool,AX.
		0xf3, 0x0f, 0x6f, 0x05, 0x09, 0, 0, 0, // MOVOU pool+8,X0.
		0xc3,
	}
	code = append(code, make([]byte, 32)...)
	source := x86StaticReturnSource("Bound", code)
	requireX86GoAssemblerResult(t, "amd64", source, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue
		}
		file, err := NormalizeRawFileForTranslation(mustParseX86RawReturn(t, source), target.arch)
		if err != nil {
			t.Fatal(err)
		}
		read := file.Funcs[0].Instrs[2]
		if len(read.x86RIPLiteralData) != 0 || read.x86RIPMemoryRead.offset != 8 ||
			read.x86RIPMemoryRead.width != 16 || len(read.x86RIPMemoryRead.object) != 32 {
			t.Fatalf("shared runtime read lost range or acquired specialization: %+v", read)
		}
		opt := Options{Goarch: target.arch, TargetTriple: target.triple,
			Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: Void}}}
		x86RawReturnPointerAPIs(t, source, opt, false)
		ir, err := Translate(file, opt)
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, target.triple, "shared-pool.ll", "shared-pool.o", ir)
		file.Funcs[0].Instrs[2].Args[0].Sym = file.Data[0].Sym + "+17(SB)"
		if x86RawReturnMemoryBound(file.Funcs[0], file, opt, true) {
			t.Fatal("changed read extending outside the shared object retained decoder proof")
		}
	}
}

func TestX86RawReturnReadProofBindsCompleteOperandShape(t *testing.T) {
	source := x86StaticReturnSource("Bound", x86RawPackedMoveLiteral(true, 32))
	file, err := NormalizeRawFileForTranslation(mustParseX86RawReturn(t, source), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	// The same valid EVEX opcode now requests twice the memory width. A
	// private proof tied only to Op/source-index would incorrectly survive.
	read := &file.Funcs[0].Instrs[1]
	read.Args[len(read.Args)-1].Reg = "Z0"
	opt := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: Void}}}
	if x86RawReturnMemoryBound(file.Funcs[0], file, opt, true) {
		t.Error("wider destination inherited a 32-byte decoded read proof")
	}
	_, err = Translate(file, opt)
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Errorf("changed vector width reached final translation without Context: %v", err)
	}
}
