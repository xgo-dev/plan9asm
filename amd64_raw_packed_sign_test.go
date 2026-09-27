package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawPackedSignGoEncoderForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawpackedsign(SB),4,$0-0\n")
			for _, op := range []string{"VPSIGNB", "VPSIGNW", "VPSIGND"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "%s %s2, %s3, %s4\n", op, width, width, width)
					fmt.Fprintf(&source, "%s 24(BX), %s3, %s4\n", op, width, width)
					if arch == "amd64" {
						fmt.Fprintf(&source, "%s %s12, %s13, %s14\n", op, width, width, width)
						fmt.Fprintf(&source, "%s -32(R8), %s13, %s14\n", op, width, width)
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
			for index, got := range decoded.Instrs {
				if got.Op != want[index].Op || !reflect.DeepEqual(got.Args, want[index].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", index, got, want[index])
				}
			}
		})
	}
}

func TestX86RawPackedSignRejectsFormsOutsideGoTable(t *testing.T) {
	const source = "TEXT rawpackedsign(SB),4,$0-0\nVPSIGNB Y2, Y3, Y4\nRET\n"
	assembled := assembleX87ControlBytes(t, "amd64", source)
	if len(assembled) < 6 || assembled[0] != 0xc4 {
		t.Fatalf("Go did not emit a VEX packed sign: %x", assembled)
	}
	valid := assembled[:len(assembled)-1]
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"wrong prefix", func(code []byte) []byte { code[2] &^= 3; return code }},
		{"wrong width", func(code []byte) []byte { code[2] |= 0x80; return code }},
		{"address override", func(code []byte) []byte { return append([]byte{0x67}, code...) }},
		{"missing ModRM", func(code []byte) []byte { return code[:4] }},
		{"high register on 386", func(code []byte) []byte { code[1] &^= 0x80; return code }},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := test.mutate(append([]byte(nil), valid...))
			mode := 64
			if test.name == "high register on 386" {
				mode = 32
			}
			if _, _, recognized, err := decodedX86RawPackedSignInstruction(code, mode); !recognized || err == nil {
				t.Fatalf("invalid %x: recognized=%v err=%v", code, recognized, err)
			}
		})
	}
}

func TestTranslateX86RawPackedSignLLVM22AllTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, form := range []string{
		"VPSIGNB Y2, Y3, Y4",
		"VPSIGNW X2, X3, X4",
		"VPSIGND 16(BX), Y3, Y4",
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
				source := "TEXT rawpackedsign(SB),4,$0-0\n" + form + "\nRET\n"
				code := assembleX87ControlBytes(t, target.goarch, source)
				var raw strings.Builder
				raw.WriteString("TEXT rawpackedsign(SB),4,$0-0\n")
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
					Sigs:         map[string]FuncSig{"rawpackedsign": {Name: "rawpackedsign", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "raw-packed-sign.ll", "raw-packed-sign.o", ir)
			})
		}
	}
}
