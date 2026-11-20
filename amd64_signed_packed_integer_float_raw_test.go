package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestX86SignedPackedIntegerFloatRawPhysicalModes(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required")
	}
	for _, op := range []Op{"VCVTDQ2PS", "VCVTDQ2PD"} {
		for _, evex := range []bool{false, true} {
			for length := byte(0); length < 3; length++ {
				if !evex && length == 2 {
					continue
				}
				for _, memory := range []bool{false, true} {
					for _, w := range []byte{0, 0x80} {
						if evex && w != 0 {
							continue
						} // W1 is another EVEX family.
						pp, opcode := byte(0), byte(0x5b)
						if op == "VCVTDQ2PD" {
							pp, opcode = 2, 0xe6
						}
						modrm := byte(0xc1)
						if memory {
							modrm = 0x00
						}
						code := []byte{0xc4, 0xe1, 0x78 | pp | length<<2 | w, opcode, modrm}
						if evex {
							code = []byte{0x62, 0xf1, 0x7c | pp, 0x89 | length<<5, opcode, modrm}
						}
						for _, mode := range []int{32, 64} {
							var bytes strings.Builder
							for _, v := range code {
								fmt.Fprintf(&bytes, "0x%02x ", v)
							}
							triple := "x86_64"
							arch := "amd64"
							if mode == 32 {
								triple, arch = "i386", "386"
							}
							ctx, cancel := runtimeOracleStageContext(t)
							command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+triple, "--mattr=+avx,+avx512f,+avx512vl")
							command.Stdin = strings.NewReader(bytes.String() + "\n")
							out, err := runtimeOracleCombinedOutput(ctx, command)
							cancel()
							if err != nil || !strings.Contains(strings.ToUpper(string(out)), string(op)) {
								t.Fatalf("independent LLVM22 mode%d %x: %v\n%s", mode, code, err, out)
							}
							var ins Instr
							var n int
							var known bool
							if op == "VCVTDQ2PS" {
								ins, n, known, err = decodedX86SameWidthConversionInstruction(code, mode)
							} else {
								ins, n, known, err = decodedX86PackedDoubleDwordInstruction(code, mode)
							}
							if err != nil || !known || n != len(code) {
								t.Fatalf("valid physical mode%d %x: %v", mode, code, err)
							}
							f, known, err := x86SignedPackedFloatProperties(ins, arch)
							if err != nil || !known || f.byteWidth != 16<<length || evex && (!f.zeroing || f.mask != 1) {
								t.Fatalf("physical shape %x: %+v %v", code, f, err)
							}
							if memory {
								want := 16 << length
								if op == "VCVTDQ2PD" {
									want /= 2
								}
								if f.memoryBytes != want {
									t.Fatal("raw physical read tuple", f, want)
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestX86SignedPackedIntegerFloatRawMMXMemoryIdentity(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, code := range [][]byte{{0x0f, 0x2a, 0x00}, {0x66, 0x0f, 0x2a, 0x00}} {
			var row strings.Builder
			for _, value := range code {
				fmt.Fprintf(&row, "BYTE $0x%02x;", value)
			}
			listing, err := x86ExtensionGoListing(t, arch, row.String())
			if err != nil {
				t.Fatal("actual Go raw source rejected", err, listing)
			}
			var object []byte
			for _, line := range strings.Split(listing, "\n") {
				object = append(object, x86InsertExtractListedBytes(line)...)
			}
			if len(object) != len(code)+1 || !bytes.Equal(object[:len(code)], code) {
				t.Fatal("raw Go object changed original bytes", object, code)
			}
			triple, opcode := "x86_64", "cvtpi2ps"
			if arch == "386" {
				triple = "i386"
			}
			if len(code) == 4 {
				opcode = "cvtpi2pd"
			}
			var encoded strings.Builder
			for _, value := range code {
				fmt.Fprintf(&encoded, "0x%02x ", value)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+triple, "--mattr=+mmx,+sse2")
			command.Stdin = strings.NewReader(encoded.String() + "\n")
			out, err := runtimeOracleCombinedOutput(ctx, command)
			cancel()
			if err != nil || !strings.Contains(string(out), opcode) {
				t.Fatalf("independent LLVM22 raw MMX identity %s %x: %v\n%s", arch, code, err, out)
			}
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row.String()+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			opt := Options{Goarch: arch, Sigs: map[string]FuncSig{"f": {Ret: Void}}}
			for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				if _, err := x86SignedPackedFloatTranslate(file, opt, api); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("raw MMX memory was confused with ordinary SSE input", arch, code, api, err)
				}
			}
			decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
			if err != nil || len(decoded.Instrs) != 1 {
				t.Fatal("raw MMX decode", err, decoded.Instrs)
			}
			form, known, err := x86SignedPackedFloatProperties(decoded.Instrs[0], arch)
			if !known || err != nil || !form.mmx || form.memory != 0 || form.memoryBytes != 8 || form.inputBytes != 8 {
				t.Fatal("raw MMX original read/state identity lost", code, form, err)
			}
			// Value-copy normalization must retain this negative state witness.
			copy := decoded.Instrs[0]
			form, _, err = x86SignedPackedFloatProperties(copy, arch)
			if err != nil || !form.mmx {
				t.Fatal("raw MMX clone washed physical state identity", err)
			}
			// The named memory form is instead Go's ordinary SSE opcode.
			// Neither its name nor x86Encoded alone identifies raw MMX state.
			named := copy
			named.x86MMXSourceConversion = false
			named.x86Encoded = true
			form, _, err = x86SignedPackedFloatProperties(named, arch)
			if err != nil || form.mmx || form.sourceBytes != 16 {
				t.Fatal("MMX restriction leaked into named SSE shape", form, err)
			}
			copy.Op = "VCVTDQ2PS"
			if _, _, err := x86SignedPackedFloatProperties(copy, arch); err == nil {
				t.Fatal("contradictory raw MMX provenance accepted as VEX conversion")
			}
		}
	}
}

func TestX86SignedPackedIntegerFloatActualGoObjectSourceWidths(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []string{"CVTPL2PS X1,X0", "CVTPL2PD X1,X0", "VCVTDQ2PS Y1,Y0", "VCVTDQ2PD X1,Y0", "VCVTDQ2PD Y1,Z0", "VCVTDQ2PS.Z (AX),K1,Z0", "VCVTDQ2PD.BCST.Z (AX),K1,Y0"} {
			listing, err := x86ExtensionGoListing(t, arch, row)
			if err != nil {
				t.Fatal(row, err, listing)
			}
			var code []byte
			for _, line := range strings.Split(listing, "\n") {
				code = append(code, x86InsertExtractListedBytes(line)...)
			}
			decoded, err := decodeX86RawDirectives(rawX86Function(code[:len(code)-1]), arch)
			if err != nil || len(decoded.Instrs) != 1 {
				t.Fatal(row, err, decoded.Instrs)
			}
			_, known, err := x86SignedPackedFloatProperties(decoded.Instrs[0], arch)
			if !known || err != nil {
				t.Fatal(row, "raw physical properties", err)
			}
			triple := x86AddressMemoryTargets(arch)[0]
			source := "TEXT f(SB),4,$0-0\n" + x86RawDisplacementDirectives(code[:len(code)-1]) + "RET\n"
			x86UnboundVoidRawScalarFormatObject(t, source, arch, triple)
		}
	}
}
