package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Intel's F3 0F AE /0..3 register encodings correspond to all eight rows in
// Go's asm6.go: RDFSBASE, RDGSBASE, WRFSBASE and WRGSBASE, each with L/Q width.
var rawSegmentBaseTestOps = [...]string{"RDFSBASE", "RDGSBASE", "WRFSBASE", "WRGSBASE"}

func rawSegmentBaseTestEncoding(operation, bits, register int) []byte {
	code := []byte{0xf3}
	rex := byte(0x40)
	if bits == 64 {
		rex |= 8
	}
	if register >= 8 {
		rex |= 1
	}
	if rex != 0x40 {
		code = append(code, rex)
	}
	return append(code, 0x0f, 0xae, byte(0xc0|operation<<3|register&7))
}

func TestX86RawSegmentBaseCompleteRegisterFamily(t *testing.T) {
	if len(amd64SegmentBaseSpecs) != 2*len(rawSegmentBaseTestOps) {
		t.Fatal("raw encoding tests must cover the complete named segment-base grammar")
	}
	registers := [...]Reg{AX, CX, DX, BX, SP, BP, SI, DI, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	for operation, name := range rawSegmentBaseTestOps {
		for _, width := range []struct {
			bits   int
			suffix string
		}{{32, "L"}, {64, "Q"}} {
			for register, wantRegister := range registers {
				wantOp := Op(name + width.suffix)
				t.Run(string(wantOp)+"/"+string(wantRegister), func(t *testing.T) {
					code := rawSegmentBaseTestEncoding(operation, width.bits, register)
					decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "segment-base bytes", nil)
					if err != nil {
						t.Fatal(err)
					}
					if len(decoded) != 1 || decoded[0].Op != wantOp || len(decoded[0].Args) != 1 ||
						decoded[0].Args[0].Kind != OpReg || decoded[0].Args[0].Reg != wantRegister {
						t.Fatalf("%x decoded as %+v, want %s %s", code, decoded, wantOp, wantRegister)
					}
					if _, ok := amd64SegmentBaseSpecs[wantOp]; !ok {
						t.Fatalf("raw opcode %s has no typed named grammar", wantOp)
					}
				})
			}
		}
	}
}

func TestX86RawSegmentBaseIgnoredPrefixesPreserveRegisterWidth(t *testing.T) {
	for operation, name := range rawSegmentBaseTestOps {
		for _, bits := range []int{32, 64} {
			for _, prefix := range []byte{0x66, 0x67, 0x64, 0x65} {
				for _, afterREP := range []bool{false, true} {
					code := rawSegmentBaseTestEncoding(operation, bits, 11)
					if afterREP {
						code = append([]byte{0xf3, prefix}, code[1:]...)
					} else {
						code = append([]byte{prefix}, code...)
					}
					inst, err := x86asm.Decode(code, 64)
					if err != nil || inst.Len != len(code) {
						t.Fatalf("decode %x: %+v, %v", code, inst, err)
					}
					got, err := decodedX86GoSyntax(inst, code)
					width := "L"
					if bits == 64 {
						width = "Q"
					}
					want := name + width + " R11"
					if err != nil || got != want {
						t.Errorf("%x (DataSize=%d): got %q, %v; want %q", code, inst.DataSize, got, err, want)
					}
				}
			}
		}
	}
}

func TestX86RawSegmentBaseRejectsInvalidDecodedForms(t *testing.T) {
	for _, op := range []x86asm.Op{x86asm.RDFSBASE, x86asm.RDGSBASE, x86asm.WRFSBASE, x86asm.WRGSBASE} {
		for _, args := range []x86asm.Args{
			{}, {x86asm.Imm(1)}, {x86asm.Mem{Base: x86asm.RAX}},
			{x86asm.AL}, {x86asm.AX}, {x86asm.X0},
			{x86asm.RAX, x86asm.RBX}, {x86asm.RAX, nil, nil, x86asm.RBX},
		} {
			inst := x86asm.Inst{Op: op, Mode: 64, DataSize: 64, Args: args}
			if got, err := decodedX86GoSyntax(inst, nil); err == nil {
				t.Errorf("accepted invalid %s operands %v as %q", op, args, got)
			}
		}
	}
	for operation := range rawSegmentBaseTestOps {
		code := rawSegmentBaseTestEncoding(operation, 64, 3)
		for _, invalid := range []struct {
			name string
			code []byte
			mode int
		}{
			{"lock", append([]byte{0xf0}, code...), 64},
			{"memory", []byte{0xf3, 0x48, 0x0f, 0xae, byte(operation << 3)}, 64},
			{"truncated", code[:len(code)-1], 64},
			{"32-bit-mode", rawSegmentBaseTestEncoding(operation, 32, 3), 32},
		} {
			t.Run(rawSegmentBaseTestOps[operation]+"/"+invalid.name, func(t *testing.T) {
				if got, err := decodeX86RawDirectiveGroup(invalid.code, invalid.mode, 0, "invalid segment-base bytes", nil); err == nil {
					t.Fatalf("accepted invalid %x as %+v", invalid.code, got)
				}
			})
		}
	}
}

func TestTranslateX86RawSegmentBaseMatchesNamedFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			var raw, named strings.Builder
			for _, source := range []*strings.Builder{&raw, &named} {
				source.WriteString("TEXT segmentbase(SB),$0-0\nMOVQ $-1, BX\n")
			}
			// Keep the whole reported gVisor sequence, including SWAPGS before
			// RDGSBASEQ, as well as every sibling operation and operand width.
			for _, value := range []byte{0x0f, 0x01, 0xf8, 0xf3, 0x48, 0x0f, 0xae, 0xcb} {
				fmt.Fprintf(&raw, "BYTE $%#x\n", value)
			}
			named.WriteString("SWAPGS\nRDGSBASEQ BX\n")
			for operation, name := range rawSegmentBaseTestOps {
				for _, bits := range []int{32, 64} {
					for _, value := range rawSegmentBaseTestEncoding(operation, bits, 3) {
						fmt.Fprintf(&raw, "BYTE $%#x\n", value)
					}
					width := "L"
					if bits == 64 {
						width = "Q"
					}
					fmt.Fprintf(&named, "%s%s BX\n", name, width)
				}
			}
			var irs []string
			for _, source := range []*strings.Builder{&raw, &named} {
				source.WriteString("RET\n")
				requireX86GoAssemblerResult(t, "amd64", source.String(), true)
				file, err := Parse(ArchAMD64, source.String())
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, Options{
					Goarch: "amd64", TargetTriple: triple,
					Sigs: map[string]FuncSig{"segmentbase": {Name: "segmentbase", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				// LLVM assigns a different temporary filename on each parse.
				// Compare every semantic line, excluding only that metadata.
				lines := strings.Split(ir, "\n")
				for index, line := range lines {
					if strings.HasPrefix(line, "; ModuleID = ") || strings.HasPrefix(line, "source_filename = ") {
						lines[index] = ""
					}
				}
				irs = append(irs, strings.Join(lines, "\n"))
			}
			if irs[0] != irs[1] {
				t.Fatalf("raw and named segment-base semantics differ:\nraw:\n%s\nnamed:\n%s", irs[0], irs[1])
			}
			compileLLVMToObject(t, llc, triple, "raw-segment-base.ll", "raw-segment-base.o", irs[0])
		})
	}
}
