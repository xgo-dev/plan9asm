package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86RawDisplacementLEAAddressSizeIdentity(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, addressBits := range []int{mode, mode / 2} {
			for _, width := range []int{16, 32, 64} {
				if width > mode {
					continue
				}
				t.Run(fmt.Sprintf("mode%d/address%d/width%d", mode, addressBits, width), func(t *testing.T) {
					encoding := x86RawLEADisplacementEncoding(mode, width, addressBits, 0, 0, -64)
					instruction := x86RawDisplacementDecodedLEA(t, mode, encoding)
					want := 0
					if addressBits != mode {
						want = addressBits
					}
					if instruction.x86AddressBits != want {
						t.Fatalf("raw LEA lost physical address size: got %d, want %d", instruction.x86AddressBits, want)
					}
				})
			}
		}
	}
}

func TestX86RawDisplacementLEANarrowAddressFiveObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		mode := 64
		if target.arch == "386" {
			mode = 32
		}
		for _, width := range []int{16, 32, 64} {
			if width > mode {
				continue
			}
			t.Run(fmt.Sprintf("%s/width%d", target.triple, width), func(t *testing.T) {
				encoding := x86RawLEADisplacementEncoding(mode, width, mode/2, 0, 0, -64)
				body := "@MOV x+0(FP),AX\n@MOV AX,BX\n@MOV $3,SI\n@MOV $0,CX\n" +
					x86RawDisplacementDirectives(encoding) + "@MOV CX,ret+@WORD(FP)\nRET"
				source, sig, _ := x86SourceStackNumericalFixture(target.arch, body)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, x86SourceStackOptions(target.arch, target.triple, sig))
				if err != nil {
					t.Fatal(err)
				}
				want := "zext i32"
				if mode == 32 {
					want = "zext i16"
				}
				if !strings.Contains(ir, want) {
					t.Fatalf("narrow effective offset was not zero-extended before destination: %s", want)
				}
				compileLLVMToObject(t, llc, target.triple, "raw-lea-address.ll", "raw-lea-address.o", ir)
			})
		}
	}
}

func TestX86RawDisplacementLEARejectsUnboundAddressMarkers(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, bits := range []int{1, 8, 16, 32, 64, 128} {
			if target.arch == "386" && bits == 16 || target.arch == "amd64" && bits == 32 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", target.triple, bits), func(t *testing.T) {
				instruction := Instr{Op: "LEAL", x86AddressBits: bits, Args: []Operand{
					{Kind: OpMem, Mem: MemRef{Base: AX}}, {Kind: OpReg, Reg: CX},
				}}
				if _, err := x86LEAOperandWidth(instruction, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("forged physical address size gained a grammar: %v", err)
				}
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{instruction}}, FuncSig{Ret: Void}, nil)
				ctx.goarch = target.arch
				before := output.String()
				if ok, terminated, err := ctx.lowerArith("LEAL", instruction); !ok || terminated || !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
					t.Fatalf("invalid raw address marker emitted IR: (%v, %v, %v)", ok, terminated, err)
				}
			})
		}
	}
}

func TestX86RawDisplacementLEARelativeAndTruncatedRemainClosed(t *testing.T) {
	for _, encoding := range [][]byte{
		{0x48, 0x8d, 0x0d, 0xc0, 0xff, 0xff, 0xff},
		{0x67, 0x48, 0x8d, 0x0d, 0xc0, 0xff, 0xff, 0xff},
		{0x48, 0x8d}, {0x48, 0x8d, 0x0c},
		{0x48, 0x8d, 0x0c, 0x25, 0xc0, 0xff, 0xff},
	} {
		t.Run(fmt.Sprintf("%x", encoding), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT raw(SB),4,$0-0\n"+x86RawDisplacementDirectives(encoding)+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeX86RawDirectives(file.Funcs[0], "amd64"); err == nil {
				t.Fatal("unbound relative target or truncated LEA became a numerical address")
			}
		})
	}
}

func TestX86RawDisplacementLEAIgnoresSegmentBase(t *testing.T) {
	for _, prefix := range []byte{0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65} {
		t.Run(fmt.Sprintf("prefix%x", prefix), func(t *testing.T) {
			encoding := append([]byte{prefix}, x86RawLEADisplacementEncoding(64, 64, 64, 0, 0, -64)...)
			instruction := x86RawDisplacementDecodedLEA(t, 64, encoding)
			memory := instruction.Args[0].Mem
			if memory.Segment != "" || memory.Base != AX || memory.Off != -64 {
				t.Fatalf("LEA used a segment base instead of its effective offset: %+v", memory)
			}
		})
	}
}

func TestX86RawDisplacementEIPCannotBorrowRIPRelocation(t *testing.T) {
	for _, opcode := range []byte{0x8d, 0x8b, 0x03} {
		t.Run(fmt.Sprintf("opcode%x", opcode), func(t *testing.T) {
			encoding := []byte{0x67, 0x48, opcode, 0x0d, 0xc0, 0xff, 0xff, 0xff}
			inst, err := x86asm.Decode(encoding, 64)
			if err != nil || inst.Len != len(encoding) || inst.AddrSize != 32 || inst.PCRel != 0 {
				t.Fatalf("EIP decoder witness changed: %+v, %v", inst, err)
			}
			if syntax, err := decodedX86GoSyntax(inst, encoding); !errors.Is(err, ErrProbeNeedsContext) || syntax != "" {
				t.Fatalf("unbound EIP-relative address acquired a source relocation: %q, %v", syntax, err)
			}
		})
	}
}

func TestX86RawDisplacementNonLEASegmentOverridesStayPhysical(t *testing.T) {
	for _, prefix := range []byte{0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65} {
		t.Run(fmt.Sprintf("prefix%x", prefix), func(t *testing.T) {
			encoding := []byte{prefix, 0x48, 0x8b, 0x80, 0xc0, 0xff, 0xff, 0xff}
			inst, err := x86asm.Decode(encoding, 64)
			if err != nil || inst.Len != len(encoding) || inst.Op != x86asm.MOV {
				t.Fatalf("physical segmented MOV witness: %+v, %v", inst, err)
			}
			if got := normalizeDecodedX86LEASegments(inst); !reflect.DeepEqual(got, inst) {
				t.Fatal("LEA normalization stripped an actual load's segment")
			}
			original, ok := inst.Args[1].(x86asm.Mem)
			// In 64-bit mode x/arch already ignores ES/CS/SS/DS. FS and
			// GS still carry a physical segment base and must not be erased.
			if !ok || (prefix == 0x64 || prefix == 0x65) && original.Segment == 0 {
				t.Fatalf("physical MOV lost its segment: %+v", inst)
			}
			normalized := normalizeDecodedX86MemoryDisplacements(inst)
			memory := normalized.Args[1].(x86asm.Mem)
			if memory.Segment != original.Segment || memory.Base != original.Base || memory.Disp != -64 {
				t.Fatalf("signed displacement changed actual memory identity: %+v", memory)
			}
		})
	}
}

func TestX86RawDisplacementNarrowLEADoesNotGrantCallerPointerOrStack(t *testing.T) {
	for _, modRM := range []byte{0x87, 0x85} { // DI caller pointer, BP private stack.
		t.Run(fmt.Sprintf("base%x", modRM), func(t *testing.T) {
			encoding := []byte{0x67, 0x48, 0x8d, modRM, 0xc0, 0xff, 0xff, 0xff}
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)",
				x86RawDisplacementDirectives(encoding)+"MOVL AX,(DX)", 1)
			requireLEANativeGoObject(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("narrow physical address borrowed native caller/stack identity: %v", err)
			}
		})
	}
}
