package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawVEXGatherCorpusEncoding(t *testing.T) {
	const source = "TEXT rawgather(SB),4,$0-0\n\tVPGATHERDD Y2, (R8)(Y0*2), Y1\n\tRET\n"
	code := assembleX87ControlBytes(t, "amd64", source)
	decoded, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	named, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	want := named.Funcs[0].Instrs[1:]
	if len(decoded.Instrs) != len(want) {
		t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
	}
	for i, got := range decoded.Instrs {
		if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
			t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
		}
	}
}

func TestX86RawVEXGatherGoEncoderForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT gatherforms(SB),4,$0-0\n")
			for _, variants := range x86GatherOps {
				for _, op := range variants {
					for width := 0; width < 2; width++ {
						destinationWidth, indexWidth := "X", "X"
						if width == 1 {
							switch amd64GatherSpecs[op].table {
							case amd64GatherDPS:
								destinationWidth, indexWidth = "Y", "Y"
							case amd64GatherDPD:
								destinationWidth = "Y"
							case amd64GatherQPS:
								indexWidth = "Y"
							}
						}
						fmt.Fprintf(&source, "%s %s1, 4(BX)(%s2*2), %s3\n", op, destinationWidth, indexWidth, destinationWidth)
						fmt.Fprintf(&source, "%s %s1, 256(%s4*8), %s3\n", op, destinationWidth, indexWidth, destinationWidth)
						if arch == "amd64" {
							fmt.Fprintf(&source, "%s %s14, -32(R8)(%s13*4), %s15\n", op, destinationWidth, indexWidth, destinationWidth)
						}
					}
				}
			}
			source.WriteString("RET\n")
			code := assembleX87ControlBytes(t, arch, source.String())
			decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
			if err != nil {
				t.Fatal(err)
			}
			named, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			want := named.Funcs[0].Instrs[1:]
			if len(decoded.Instrs) != len(want) {
				t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
			}
			for i, got := range decoded.Instrs {
				if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
				}
			}
		})
	}
}

func TestX86RawEVEXGatherGoEncoderForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT evexgatherforms(SB),4,$0-0\n")
			for _, variants := range x86GatherOps {
				for _, op := range variants {
					for width := 0; width < 3; width++ {
						widths := [...]string{"X", "Y", "Z"}
						destinationWidth := widths[width]
						indexWidth := destinationWidth
						switch amd64GatherSpecs[op].table {
						case amd64GatherDPD:
							if width > 0 {
								indexWidth = widths[width-1]
							}
						case amd64GatherQPS:
							if width > 0 {
								destinationWidth = widths[width-1]
							}
						}
						fmt.Fprintf(&source, "%s 8(BX)(%s2*4), K1, %s3\n", op, indexWidth, destinationWidth)
						if arch == "amd64" {
							fmt.Fprintf(&source, "%s -32(R8)(%s18*2), K7, %s21\n", op, indexWidth, destinationWidth)
						}
					}
				}
			}
			source.WriteString("RET\n")
			code := assembleX87ControlBytes(t, arch, source.String())
			decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
			if err != nil {
				t.Fatal(err)
			}
			named, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			want := named.Funcs[0].Instrs[1:]
			if len(decoded.Instrs) != len(want) {
				t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
			}
			for i, got := range decoded.Instrs {
				if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
				}
			}
		})
	}
}

func TestX86RawVEXGatherRejectsMalformedForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		mode int
	}{
		{"missing SIB", []byte{0xc4, 0xc2, 0x6d, 0x90, 0x0c}, 64},
		{"register source", []byte{0xc4, 0xc2, 0x6d, 0x90, 0xc0, 0x40}, 64},
		{"GP index", []byte{0xc4, 0xc2, 0x6d, 0x90, 0x08, 0x40}, 64},
		{"missing displacement", []byte{0xc4, 0xc2, 0x6d, 0x90, 0x4c, 0x40}, 64},
		{"address override", []byte{0x67, 0xc4, 0xc2, 0x6d, 0x90, 0x0c, 0x40}, 64},
		{"high VSIB index on 386", []byte{0xc4, 0x82, 0x6d, 0x90, 0x0c, 0x40}, 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, matched, err := decodedX86RawGatherInstruction(test.code, test.mode); !matched || err == nil {
				t.Fatalf("invalid %x: matched=%v err=%v", test.code, matched, err)
			}
		})
	}
}

func TestX86RawEVEXGatherRejectsReservedForms(t *testing.T) {
	const source = "TEXT evexgather(SB),4,$0-0\n\tVPGATHERDD 8(BX)(X2*4), K1, X3\n\tRET\n"
	assembled := assembleX87ControlBytes(t, "amd64", source)
	if len(assembled) < 8 || assembled[0] != 0x62 {
		t.Fatalf("Go did not emit an EVEX gather: %x", assembled)
	}
	valid := assembled[:len(assembled)-1]
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"missing mask", func(code []byte) []byte { code[3] &^= 7; return code }},
		{"zeroing", func(code []byte) []byte { code[3] |= 0x80; return code }},
		{"broadcast", func(code []byte) []byte { code[3] |= 0x10; return code }},
		{"reserved length", func(code []byte) []byte { code[3] |= 0x60; return code }},
		{"reserved vvvv", func(code []byte) []byte { code[2] &^= 0x08; return code }},
		{"missing fixed bit", func(code []byte) []byte { code[2] &^= 0x04; return code }},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := test.mutate(append([]byte(nil), valid...))
			if _, _, matched, err := decodedX86RawGatherInstruction(code, 64); !matched || err == nil {
				t.Fatalf("invalid %x: matched=%v err=%v", code, matched, err)
			}
		})
	}
}

func TestTranslateX86RawGatherLLVM22AllTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, form := range []struct {
		name   string
		source string
	}{
		{"VEX", "TEXT rawgather(SB),4,$0-0\n\tVPGATHERDD X2, (BX)(X0*2), X1\n\tRET\n"},
		{"EVEX", "TEXT rawgather(SB),4,$0-0\n\tVPGATHERDD (BX)(X0*2), K1, X2\n\tRET\n"},
	} {
		t.Run(form.name, func(t *testing.T) {
			for _, target := range []struct {
				goarch string
				triple string
			}{
				{"amd64", "x86_64-apple-darwin"},
				{"amd64", "x86_64-unknown-linux-gnu"},
				{"amd64", "x86_64-pc-windows-msvc"},
				{"386", "i386-unknown-linux-gnu"},
				{"386", "i686-pc-windows-msvc"},
			} {
				t.Run(target.triple, func(t *testing.T) {
					code := assembleX87ControlBytes(t, target.goarch, form.source)
					var raw strings.Builder
					raw.WriteString("TEXT rawgather(SB),4,$0-0\n")
					for _, value := range code {
						fmt.Fprintf(&raw, "BYTE $%#02x\n", value)
					}
					file, err := Parse(ArchAMD64, raw.String())
					if err != nil {
						t.Fatal(err)
					}
					ir, err := Translate(file, Options{
						Goarch:       target.goarch,
						TargetTriple: target.triple,
						Sigs:         map[string]FuncSig{"rawgather": {Name: "rawgather", Ret: Void}},
					})
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "raw-gather.ll", "raw-gather.o", ir)
				})
			}
		})
	}
}
