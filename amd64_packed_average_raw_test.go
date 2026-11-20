package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestX86PackedAverageActualRawPhysicalModes(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	llc := findLLVM22Tool("llc")
	if mc == "" || llc == "" {
		t.Fatal("LLVM22 llvm-mc and llc required")
	}
	for _, op := range x86AverageNames[2:] {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, memory := range []bool{false, true} {
				for mode := 0; mode < 3; mode++ {
					first, name := bank+"1", op
					if memory {
						first = "16(AX)"
					}
					if mode == 2 {
						name += ".Z"
					}
					args := first + "," + bank + "0"
					if mode != 0 {
						args += ",K1"
					}
					row := name + " " + args + "," + bank + "2"
					code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
					if len(code) < 2 || code[len(code)-1] != 0xc3 {
						t.Fatal("original object lacks exact RET", row, code)
					}
					code = code[:len(code)-1]
					for _, arch := range []string{"amd64", "386"} {
						bits, triple := 64, "x86_64-unknown-linux-gnu"
						if arch == "386" {
							bits, triple = 32, "i386-unknown-linux-gnu"
							var bytes, source strings.Builder
							for _, value := range code {
								fmt.Fprintf(&bytes, "0x%02x ", value)
								fmt.Fprintf(&source, "BYTE $0x%02x\n", value)
							}
							goAssemblerOracleOutput(t, arch, "TEXT raw(SB),4,$0-0\n"+source.String()+"RET\n", "", true)
							ctx, cancel := runtimeOracleStageContext(t)
							command := exec.CommandContext(ctx, mc, "-triple="+triple, "-disassemble", "-mattr=+avx2,+avx512f,+avx512bw,+avx512vl")
							command.Stdin = strings.NewReader(bytes.String())
							output, err := runtimeOracleCombinedOutput(ctx, command)
							cancel()
							if err != nil || !strings.Contains(string(output), strings.ToLower(op)) || strings.Contains(string(output), "warning") {
								t.Fatalf("actual mode32 physical instruction invalid: %x: %v\n%s", code, err, output)
							}
						}
						ins, length, known, err := decodedX86PackedAverageInstruction(code, bits)
						if !known || err != nil || length != len(code) || !ins.x86Encoded {
							t.Fatalf("complete physical bytes not bound: %x: %v", code, err)
						}
						if _, known, err := x86PackedAverageProperties(ins.Op, ins, arch); !known || err != nil {
							t.Fatal("physical source rejected", row, arch, err)
						}
						encoded, err := json.Marshal(ins)
						if err != nil {
							t.Fatal(err)
						}
						var copied Instr
						if err := json.Unmarshal(encoded, &copied); err != nil || copied.x86Encoded {
							t.Fatal("private marker survived portable JSON", err)
						}
						if arch == "386" && mode != 0 {
							if _, _, err := x86PackedAverageProperties(copied.Op, copied, arch); err == nil {
								t.Fatal("named/JSON four operands forged physical mode32 authority")
							}
						}
						var source strings.Builder
						for _, value := range code {
							fmt.Fprintf(&source, "BYTE $0x%02x\n", value)
						}
						file, err := Parse(ArchAMD64, "TEXT raw(SB),4,$0-0\n"+source.String()+"RET\n")
						if err != nil {
							t.Fatal(err)
						}
						ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"raw": {Name: "raw", Ret: Void}}})
						if err != nil {
							t.Fatal("complete raw source failed translation", row, arch, err)
						}
						x86ResultInitializationObject(t, llc, triple, ir, "average-raw")
					}
				}
			}
		}
	}
}

func TestX86PackedAverageRawReservedAndPrefixBoundaries(t *testing.T) {
	valid := []byte{0x62, 0xf1, 0x7d, 0x89, 0xe0, 0xd1}
	for _, mutation := range []struct {
		index int
		value byte
	}{{1, 0xf2}, {2, 0x7c}, {3, 0x99}, {3, 0xe9}, {3, 0x88}} {
		code := append([]byte(nil), valid...)
		code[mutation.index] = mutation.value
		_, _, known, err := decodedX86PackedAverageInstruction(code, 64)
		if known && err == nil {
			t.Fatalf("reserved encoding acquired semantics: %x", code)
		}
	}
	ins, _, known, err := decodedX86PackedAverageInstruction(valid, 32)
	if !known || err != nil {
		t.Fatal("valid physical mask rejected", err)
	}
	ins.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Base: AX}}
	for _, bits := range []int{16, 32, 64} {
		local := ins
		local.x86AddressBits = bits
		if _, _, err := x86PackedAverageProperties(local.Op, local, "386"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("changed address prefix retained a source shape", bits, err)
		}
	}
}
