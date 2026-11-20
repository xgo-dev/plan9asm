package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func rawBF16Dot(length byte, source1, source2, destination, mask int, memory, broadcast, zero bool) []byte {
	code := encodeX86EVEXFMA3(0x52, false, length, broadcast, zero, mask, destination, source1, source2)
	code[2] = code[2]&^3 | 2 // EVEX.F3.0F38.W0.
	if memory {
		code[1] |= 0x60
		code[5] = byte(0x40 | (destination&7)<<3)
		code = append(code, 1)
	}
	return code
}

func TestDecodeRawBF16DotCompleteFormats(t *testing.T) {
	for length := byte(0); length < 3; length++ {
		for _, memory := range []bool{false, true} {
			for _, broadcast := range []bool{false, true} {
				if broadcast && !memory {
					continue
				}
				for _, mask := range []int{0, 1, 7} {
					for _, zero := range []bool{false, true} {
						if zero && mask == 0 {
							continue
						}
						code := rawBF16Dot(length, 20, 21, 22, mask, memory, broadcast, zero)
						got, err := decodeX86RawDirectiveGroup(code, 64, 0, "BF16 dot", map[string]bool{})
						if err != nil {
							t.Fatal(err)
						}
						want := Op("VDPBF16PS")
						if broadcast {
							want += ".BCST"
						}
						if zero {
							want += ".Z"
						}
						prefix := [...]string{"X", "Y", "Z"}[length]
						if len(got) != 1 || got[0].Op != want || !got[0].x86Encoded ||
							got[0].Args[1].String() != prefix+"20" || got[0].Args[len(got[0].Args)-1].String() != prefix+"22" {
							t.Fatalf("%x: got %+v, want raw %s %s20 -> %s22", code, got, want, prefix, prefix)
						}
						wantSource := prefix + "21"
						if memory {
							width := 16 << length
							if broadcast {
								width = 4 // Broadcast one BF16 pair, not one 16-bit input.
							}
							wantSource = fmt.Sprintf("%d(AX)", width)
						}
						if got[0].Args[0].String() != wantSource {
							t.Fatalf("%x: source %s, want %s", code, got[0].Args[0], wantSource)
						}
					}
				}
			}
		}
	}
}

func TestDecodeRawBF16DotInvalidFormats(t *testing.T) {
	for _, change := range []struct {
		index int
		bits  byte
	}{
		{2, 0x80}, {2, 0x04}, {3, 0x80}, {3, 0x60}, {3, 0x10},
	} {
		code := rawBF16Dot(0, 1, 2, 3, 0, false, false, false)
		code[change.index] ^= change.bits
		if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "invalid BF16 dot", map[string]bool{}); err == nil {
			t.Fatalf("accepted reserved BF16 dot %x", code)
		}
	}
	for _, code := range [][]byte{
		rawBF16Dot(0, 8, 1, 2, 0, false, false, false),
		rawBF16Dot(1, 1, 8, 2, 0, false, false, false),
		rawBF16Dot(2, 1, 2, 8, 0, false, false, false),
	} {
		if _, err := decodeX86RawDirectiveGroup(code, 32, 0, "386 BF16 extended register", map[string]bool{}); err == nil {
			t.Fatalf("accepted 386 extended register %x", code)
		}
	}
}

func TestTranslateRawBF16DotLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT rawBF16Dot(SB),4,$0-0\n")
	for length := byte(0); length < 3; length++ {
		for _, memory := range []bool{false, true} {
			for _, broadcast := range []bool{false, true} {
				if broadcast && !memory {
					continue
				}
				code := rawBF16Dot(length, 1, 2, 3, 1, memory, broadcast, true)
				for _, b := range code {
					fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
				}
			}
		}
	}
	source.WriteString("RET\n")
	for _, target := range []struct {
		arch, triple string
	}{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawBF16Dot": {Name: "rawBF16Dot", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.x86.avx512bf16.dpbf16ps.128", "@llvm.x86.avx512bf16.dpbf16ps.256",
				"@llvm.x86.avx512bf16.dpbf16ps.512", "@llvm.masked.load.v4i32", "phi i32", "+avx512bf16"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("missing %s", want)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "raw-bf16-dot.ll", "raw-bf16-dot.o", ir)
			cmd := exec.Command(llc, "-O0", "-mtriple="+target.triple, "-filetype=asm", "-o", "-", "-")
			cmd.Stdin = strings.NewReader(ir)
			assembly, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("LLVM 22 assembly: %v\n%s", err, assembly)
			}
			if !strings.Contains(string(assembly), "vdpbf16ps") {
				t.Fatalf("BF16 intrinsic did not lower to the native instruction:\n%s", assembly)
			}
		})
	}
}

func TestRawBF16DotRejectsNamedGoForms(t *testing.T) {
	const source = "TEXT namedBF16Dot(SB),4,$0-0\nVDPBF16PS X0, X1, X2\nRET\n"
	requireX86GoAssemblerResult(t, "amd64", source, false)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"namedBF16Dot": {Name: "namedBF16Dot", Ret: Void}},
	}); err == nil {
		t.Fatal("accepted VDPBF16PS absent from Go's named assembler table")
	}
}

func TestDecodeRawBF16RIPLiteral(t *testing.T) {
	for length := byte(0); length < 3; length++ {
		for _, broadcast := range []bool{false, true} {
			for _, dot := range []bool{false, true} {
				code := rawBF16Dot(length, 1, 0, 2, 1, false, broadcast, true)
				if !dot {
					code = encodeX86RawBF16Convert(int(length), 0, 2, 1, true, broadcast, false)
				}
				code[5] = 0x15
				code = append(code, 1, 0, 0, 0, 0xc3)
				width := 16 << length
				if broadcast {
					width = 4
				}
				for index := 0; index < width; index++ {
					code = append(code, byte(index+1))
				}
				got, err := decodeX86RawDirectiveGroup(code, 64, 0, "BF16 RIP literal", map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 2 || got[0].Args[0].Kind != OpSym || !got[0].x86RIPLiteral || got[1].Op != OpRET {
					t.Fatalf("decoded %x as %+v, want source-local literal and RET", code, got)
				}
				if _, err := decodeX86RawDirectiveGroup(code[:len(code)-1], 64, 0, "truncated BF16 pool", map[string]bool{}); err == nil {
					t.Fatal("accepted truncated source-local BF16 pool")
				}
			}
		}
	}
}
