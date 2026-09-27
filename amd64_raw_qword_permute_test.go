package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawQwordPermuteGoEncoderForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawqwordpermute(SB),4,$0-0\n")
			for _, op := range []string{"VPERMQ", "VPERMPD"} {
				fmt.Fprintf(&source, "%s $216, Y2, Y2\n", op)
				fmt.Fprintf(&source, "%s $1, 64(BX), Y3\n", op)
				fmt.Fprintf(&source, "%s $2, Y20, Y21\n", op)
				if arch == "amd64" {
					fmt.Fprintf(&source, "%s $3, Z20, Z21\n", op)
				} else {
					fmt.Fprintf(&source, "%s $3, Z0, Z1\n", op)
				}
				fmt.Fprintf(&source, "%s.BCST $4, 8(BX), Y21\n", op)
				fmt.Fprintf(&source, "%s Y0, Y1, Y2\n", op)
				fmt.Fprintf(&source, "%s (BX), Y1, Y2\n", op)
				fmt.Fprintf(&source, "%s Y20, Y21, Y22\n", op)
				if arch == "amd64" {
					fmt.Fprintf(&source, "%s.BCST 16(BX), Z21, Z22\n", op)
				} else {
					fmt.Fprintf(&source, "%s.BCST 16(BX), Z1, Z2\n", op)
				}
				if arch == "amd64" {
					fmt.Fprintf(&source, "%s.Z $5, -32(R8), K2, Z21\n", op)
					fmt.Fprintf(&source, "%s.Z Z20, Z21, K3, Z22\n", op)
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
			for index, got := range decoded.Instrs {
				if got.Op != want[index].Op || !reflect.DeepEqual(got.Args, want[index].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", index, got, want[index])
				}
			}
		})
	}
}

func TestX86RawQwordPermuteRejectsMalformedForms(t *testing.T) {
	const source = "TEXT rawqwordpermute(SB),4,$0-0\nVPERMQ $1, Y2, Y3\nRET\n"
	assembled := assembleX87ControlBytes(t, "amd64", source)
	if len(assembled) < 7 || assembled[0] != 0xc4 {
		t.Fatalf("Go did not emit a VEX permute: %x", assembled)
	}
	valid := assembled[:len(assembled)-1]
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"missing immediate", func(code []byte) []byte { return code[:len(code)-1] }},
		{"reserved vvvv", func(code []byte) []byte { code[2] &^= 0x08; return code }},
		{"wrong vector length", func(code []byte) []byte { code[2] &^= 0x04; return code }},
		{"address override", func(code []byte) []byte { return append([]byte{0x67}, code...) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := test.mutate(append([]byte(nil), valid...))
			if _, _, recognized, err := decodedX86RawQwordPermuteInstruction(code, 64); !recognized || err == nil {
				t.Fatalf("invalid %x: recognized=%v err=%v", code, recognized, err)
			}
		})
	}
	const evexSource = "TEXT rawqwordpermute(SB),4,$0-0\nVPERMPD.Z Z1, Z2, K1, Z3\nRET\n"
	evex := assembleX87ControlBytes(t, "amd64", evexSource)
	if len(evex) < 7 || evex[0] != 0x62 {
		t.Fatalf("Go did not emit an EVEX permute: %x", evex)
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"missing mask", func(code []byte) []byte { code[3] &^= 7; return code }},
		{"invalid vector length", func(code []byte) []byte { code[3] &^= 0x60; return code }},
		{"missing fixed bit", func(code []byte) []byte { code[2] &^= 4; return code }},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := test.mutate(append([]byte(nil), evex[:len(evex)-1]...))
			if _, _, recognized, err := decodedX86RawQwordPermuteInstruction(code, 64); !recognized || err == nil {
				t.Fatalf("invalid %x: recognized=%v err=%v", code, recognized, err)
			}
		})
	}
}

func TestTranslateX86RawQwordPermuteLLVM22AllTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, form := range []string{
		"VPERMQ $216, Y2, Y3",
		"VPERMPD Z1, Z2, Z3",
	} {
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
			t.Run(form+"/"+target.triple, func(t *testing.T) {
				source := "TEXT rawqwordpermute(SB),4,$0-0\n" + form + "\nRET\n"
				code := assembleX87ControlBytes(t, target.goarch, source)
				var raw strings.Builder
				raw.WriteString("TEXT rawqwordpermute(SB),4,$0-0\n")
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
					Sigs:         map[string]FuncSig{"rawqwordpermute": {Name: "rawqwordpermute", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "raw-qword-permute.ll", "raw-qword-permute.o", ir)
			})
		}
	}
}
