package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ResultValueStackFPStatusRoundTripThreeAPIs(t *testing.T) {
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		word, typ, bytes := "Q", "uint64", 8
		if target.arch == "386" {
			word, typ, bytes = "L", "uint32", 4
		}
		// The typed FP input seeds every modeled status, DF and ID bit. A
		// numerical result observes the packed flags after a defined writer.
		source := fmt.Sprintf("TEXT ·roundtrip(SB),4,$0-%d\nPUSH%s seed+0(FP)\nPOPF%s\nMOVL $1,AX\nPOPCNTL AX,BX\nPUSHF%s\nPOP%s CX\nMOV%s CX,ret+%d(FP)\nRET\n",
			2*bytes, word, word, word, word, word, bytes)
		declaration := fmt.Sprintf("func roundtrip(seed %s) %s\n", typ, typ)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				x86CPUQueryIRFromDeclaration(t, source, declaration, target.arch, target.triple, api)
			})
		}
	}
}

func TestX86ResultValueStackPrivateWordTransport(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, typ, bytes := "Q", I64, int64(8)
		if arch == "386" {
			word, typ, bytes = "L", I32, 4
		}
		source := fmt.Sprintf("TEXT value(SB),4,$0-%d\nPUSH%s value+0(FP)\nPOP%s AX\nMOV%s AX,ret+%d(FP)\nRET\n", 2*bytes, word, word, word, bytes)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		sig := FuncSig{Name: "value", Ret: typ, Args: []LLVMType{typ}, Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: bytes, Type: typ, Index: 0, Field: -1}},
		}}
		t.Run(arch, func(t *testing.T) {
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86ResultValueStackCompleteWidthsAndBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, typ, bytes := "Q", I64, int64(8)
		if arch == "386" {
			word, typ, bytes = "L", I32, 4
		}
		for _, row := range []struct {
			name, body string
			valid      bool
		}{
			{"word", "PUSHW value+0(FP)\nPOPW AX\nMOVW AX,ret+@N(FP)\nMOVW $0,ret+@N2(FP)", true},
			{"flags-word", "PUSHW value+0(FP)\nPOPFW\nPUSHFW\nPOPW AX\nMOVW AX,ret+@N(FP)\nMOVW $0,ret+@N2(FP)", true},
			{"immediate", "PUSH@W $7\nPOP@W AX\nMOV@W AX,ret+@N(FP)", true},
			{"flags", "PUSH@W value+0(FP)\nPOPF@W\nPUSHF@W\nPOP@W AX\nMOV@W AX,ret+@N(FP)", true},
			{"nested", "PUSH@W value+0(FP)\nPUSH@W $1\nPOP@W AX\nPOP@W DX\nMOV@W DX,ret+@N(FP)", true},
			{"underflow", "POP@W AX\nMOV@W AX,ret+@N(FP)", false},
			{"unknown-input", "PUSH@W AX\nPOP@W AX\nMOV@W AX,ret+@N(FP)", false},
			{"unwritten-fp", "PUSH@W ret+@N(FP)\nPOP@W AX\nMOV@W AX,ret+@N(FP)", false},
			{"unknown-flags", "PUSHF@W\nPOP@W AX\nMOV@W AX,ret+@N(FP)", false},
			{"unknown-df", "MOVL $1,AX\nCMPL AX,AX\nPUSHFW\nPOPW AX\nMOVW AX,ret+@N(FP)\nMOVW $0,ret+@N2(FP)", false},
			{"partial-input", "MOVB $1,AX\nPUSHW AX\nPOPW AX\nMOV@W AX,ret+@N(FP)", false},
			{"unbalanced", "PUSH@W value+0(FP)\nMOV@W $1,ret+@N(FP)", false},
			{"overflow", strings.Repeat("PUSH@W $1\n", 64) + strings.Repeat("POP@W AX\n", 64) + "MOV@W $1,ret+@N(FP)", false},
			{"native-read", "PUSH@W (AX)\nPOP@W AX\nMOV@W AX,ret+@N(FP)", false},
			{"native-write", "PUSH@W $1\nPOP@W (AX)\nMOV@W $1,ret+@N(FP)", false},
			{"stack-address", "PUSH@W SP\nPOP@W AX\nMOV@W AX,ret+@N(FP)", false},
			{"segment", "PUSHW FS\nPOPW AX\nMOV@W AX,ret+@N(FP)", false},
			{"input-write", "PUSH@W $1\nPOP@W value+0(FP)\nMOV@W $1,ret+@N(FP)", false},
			{"width-mode", "PUSHL $1\nPOPQ AX\nMOV@W AX,ret+@N(FP)", false},
			{"depth-join", "MOVL $1,AX\nCMPL AX,AX\nJE join\nPUSH@W $1\njoin:\nPOP@W AX\nMOV@W AX,ret+@N(FP)", false},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				body := strings.NewReplacer("@W", word, "@N2", fmt.Sprint(bytes+2), "@N", fmt.Sprint(bytes)).Replace(row.body)
				if row.valid && strings.Contains(body, "MOVW $0,") && arch == "amd64" {
					body += fmt.Sprintf("\nMOVL $0,ret+%d(FP)", bytes+4)
				}
				source := fmt.Sprintf("TEXT value(SB),4,$0-%d\n%s\nRET\n", 2*bytes, body)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				sig := FuncSig{Name: "value", Ret: typ, Args: []LLVMType{typ}, Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: bytes, Type: typ, Index: 0, Field: -1}},
				}}
				err = CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch)
				if row.valid && err != nil || !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("valid=%v: %v\n%s", row.valid, err, source)
				}
			})
		}
	}
}

func TestX86ResultValueStackPackedBitDefinedness(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word := "Q"
		if arch == "386" {
			word = "L"
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\nPUSHF"+word+"\nPOP"+word+" AX\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for flags := uint8(0); flags < 64; flags++ {
			for extra := 0; extra < 4; extra++ {
				t.Run(fmt.Sprintf("%s/status=%02x/DF-ID=%d", arch, flags, extra), func(t *testing.T) {
					state := x86ResultState{flags: flags, valueStack: &x86ResultValueStack{id: extra&2 != 0}}
					if extra&1 != 0 {
						state.direction = x86ResultDirectionEither
					}
					for _, ins := range file.Funcs[0].Instrs[1:3] {
						if !x86ResultTransfer(ins, &state, nil, 0, arch) {
							t.Fatal("packed partial bit transport failed", ins.Raw)
						}
					}
					want := uint8(0xf8) // Constant bits, plus r32 zero-extension.
					if flags&0x1f == 0x1f {
						want |= 1 // CF/PF/AF/ZF/SF share packed byte zero.
					}
					if flags&0x20 != 0 && extra&1 != 0 {
						want |= 2 // OF and the separate DF share byte one.
					}
					if extra&2 != 0 {
						want |= 4 // ID alone affects byte two.
					}
					if state.gp[0] != want || state.flags != flags || len(state.valueStack.bytes) != 0 {
						t.Fatalf("packed flags invented bytes: got=%02x want=%02x flags=%02x", state.gp[0], want, state.flags)
					}
				})
			}
		}
	}
}

func TestX86ResultValueStackOpaqueAndPhysicalBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, typ, bytes := "Q", I64, int64(8)
		if arch == "386" {
			word, typ, bytes = "L", I32, 4
		}
		source := fmt.Sprintf("TEXT f(SB),4,$0-%d\nPUSH%s x+0(FP)\nPOP%s AX\nMOV%s AX,ret+%d(FP)\nRET\n", 2*bytes, word, word, word, bytes)
		for _, role := range []string{"pointer", "partial-fp", "encoded", "raw", "address-size", "segment-prefix"} {
			t.Run(arch+"/"+role, func(t *testing.T) {
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				sig := FuncSig{Name: "f", Ret: typ, Args: []LLVMType{typ}, Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: bytes, Type: typ, Index: 0, Field: -1}},
				}}
				ins := &file.Funcs[0].Instrs[1]
				switch role {
				case "pointer":
					sig.Args[0], sig.Frame.Params[0].Type = Ptr, Ptr
				case "partial-fp":
					sig.Args[0], sig.Frame.Params[0].Type = I8, I8
				case "encoded":
					ins.x86Encoded = true
				case "raw":
					ins.x86SourceRaw = &x86SourceRawInstruction{}
				case "address-size":
					ins.x86AddressBits = 32
				case "segment-prefix":
					ins.x86SegmentPrefix = 0x64
				}
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("physical or unknown source acquired private numerical storage", err)
				}
			})
		}
	}
}
