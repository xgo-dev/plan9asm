package plan9asm

import (
	"bytes"
	"fmt"
	"os/exec"
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
		{"EVEX outside SIGN", func([]byte) []byte {
			return encodeX86EVEXPackedWordMultiply(2, 0x08, 0, 0, false, false, 4, 3, 2)
		}},
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
				x86RawPackedSignIndependentPhysicalPrior(t, form, code, target.triple)
				var raw strings.Builder
				raw.WriteString("TEXT rawpackedsign(SB),4,$0-0\n")
				for _, value := range code {
					fmt.Fprintf(&raw, "BYTE $%#02x\n", value)
				}
				// All original bytes and RET remain unchanged. A bare raw
				// format has no vector/address inputs: its three public APIs
				// must report Context, while a private emitter proves objects.
				// The independent 114-row initialized family is exercised by
				// TestX86PackedAbsSignInitializedObjectsThreeAPIsFiveTargets.
				file, signatures := x86UnboundVoidFormatSources(t, raw.String(), target.goarch, target.triple)
				if len(file.Funcs) != 1 || len(file.Data) != 0 || len(file.Globl) != 0 {
					t.Fatal("original packed-sign format lost its single byte-only body")
				}
				decoded, err := decodeX86RawDirectives(file.Funcs[0], target.goarch)
				if err != nil || len(decoded.Instrs) != 3 || decoded.Instrs[1].Op != Op(strings.Fields(form)[0]) ||
					decoded.Instrs[2].Op != OpRET || decoded.Instrs[2].x86RawNearReturn == nil {
					t.Fatal("original packed-sign instruction and encoded RET were not retained", err)
				}
				// Private format emission is not the public normalizer's
				// physical return/nonalias contract. In particular the memory
				// row cannot borrow that contract merely to compile its format.
				unit := *file
				unit.Funcs = []Func{decoded}
				ir := x86ScalarFormatObjectUnit(t, &unit, signatures, target.goarch, target.triple, 0)
				for _, operation := range []string{"icmp slt <", "icmp sgt <", "sub <", "select <"} {
					if !strings.Contains(ir, operation) {
						t.Fatal("original raw sign format lost its complete integer operation", operation)
					}
				}
				compileLLVMToObject(t, llc, target.triple, "raw-packed-sign.ll", "raw-packed-sign.o", ir)
			})
		}
	}
}

func x86RawPackedSignIndependentPhysicalPrior(t *testing.T, form string, code []byte, triple string) {
	t.Helper()
	// Independent original Go bytes, including the ordinary encoded RET.
	// Neither a decoder nor a private LLVM format object authenticates these.
	want := map[string][]byte{
		"VPSIGNB Y2, Y3, Y4":     {0xc4, 0xe2, 0x65, 0x08, 0xe2, 0xc3},
		"VPSIGNW X2, X3, X4":     {0xc4, 0xe2, 0x61, 0x09, 0xe2, 0xc3},
		"VPSIGND 16(BX), Y3, Y4": {0xc4, 0xe2, 0x65, 0x0a, 0x63, 0x10, 0xc3},
	}
	if !bytes.Equal(code, want[form]) {
		t.Fatalf("original complete packed-sign Go bytes changed: %s got=%x want=%x", form, code, want[form])
	}
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("independent packed-sign physical prior requires LLVM22 llvm-mc")
	}
	var input strings.Builder
	for _, value := range code {
		fmt.Fprintf(&input, "0x%02x ", value)
	}
	input.WriteByte('\n')
	stage, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+triple, "--mattr=+avx2")
	command.Stdin = strings.NewReader(input.String())
	output, err := runtimeOracleCombinedOutput(stage, command)
	mnemonic := strings.ToLower(strings.Fields(form)[0])
	if err != nil || strings.Contains(string(output), "warning") || strings.Contains(string(output), "invalid") ||
		strings.Count(string(output), mnemonic) != 1 {
		t.Fatalf("independent LLVM22 original packed-sign decoding failed: %v\n%s", err, output)
	}
}
