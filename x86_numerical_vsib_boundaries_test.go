package plan9asm

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86NumericalNativeBoundariesVSIBCompleteOfficialRows(t *testing.T) {
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86IndexedMemoryRows(goasmrules.X86LegacyCatalog{}, avx)
	if err != nil || len(rows) != 80 {
		t.Fatal("incomplete Go VSIB rows", len(rows), err)
	}
	for _, target := range []struct {
		arch string
		mode int
	}{
		{"amd64", 64},
		{"386", 32},
	} {
		t.Run(target.arch, func(t *testing.T) {
			var operations []string
			for _, row := range rows {
				for _, witness := range row.Witnesses {
					operation := witness.Instruction
					if target.mode == 32 && witness.Generation == "evex" {
						// Use the low physical register bank with the same widths.
						operation = strings.NewReplacer(
							"X16", "X0", "Y16", "Y0", "Z16", "Z0",
							"X18", "X2", "Y18", "Y2", "Z18", "Z2",
						).Replace(operation)
					}
					for _, base := range []string{"(AX)", "-64(SP)", "127"} {
						operations = append(operations, strings.Replace(operation, "(AX)", base, 1))
					}
				}
			}
			if len(operations) != 960 {
				t.Fatal("incomplete Go VSIB address/scale inventory", len(operations))
			}
			code, pcs := x86NumericalBoundaryGoBytes(t, target.arch, strings.Join(operations, "\n")+"\nRET")
			if len(pcs) != len(operations)+1 {
				t.Fatal("original Go did not retain all VSIB operations")
			}
			for index, operation := range operations {
				encoded := code[pcs[index]:pcs[index+1]]
				length, err := x86NumericalVectorBoundary(encoded, target.mode)
				if err != nil || length != len(encoded) {
					t.Fatalf("%s: original bytes %x: boundary %d/%d: %v", operation, encoded, length, len(encoded), err)
				}
				if _, err := x86NumericalVectorBoundary(encoded[:len(encoded)-1], target.mode); err == nil {
					t.Fatalf("%s: accepted truncated bytes %x", operation, encoded)
				}
			}
		})
	}
}

func TestX86VSIBVEXGatherRejectsEVEXIndexWidth(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"VGATHERQPS", "VPGATHERQD"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				operation := op + " Y1,(AX)(Z0*2),Y2"
				source := "TEXT Value(SB),4,$0-0\n" + operation + "\nRET\n"
				requireX86GoAssemblerResult(t, arch, source, false)
				ins := x86ScalarLaneInstruction(t, operation)
				if _, known, err := x86VSIBProperties(ins, arch); !known || err == nil {
					t.Fatalf("accepted EVEX-only index width with a VEX vector mask: %v", err)
				}
			})
		}
	}
}

func TestX86VSIBRawPrefetchComplete(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86IndexedMemoryRows(goasmrules.X86LegacyCatalog{}, avx)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"386", "i386-unknown-linux-gnu"},
	} {
		t.Run(target.arch, func(t *testing.T) {
			var operations []string
			var opcodes []Op
			for _, row := range rows {
				if _, known := amd64VSIBPrefetchSpecs[Op(row.Opcode)]; !known {
					continue
				}
				for _, witness := range row.Witnesses {
					operation := witness.Instruction
					if target.arch == "386" {
						operation = strings.NewReplacer("Y16", "Y0", "Z16", "Z0").Replace(operation)
					}
					operations = append(operations, operation)
					opcodes = append(opcodes, Op(row.Opcode))
				}
			}
			if len(operations) != 64 {
				t.Fatal("incomplete prefetch inventory", len(operations))
			}
			code, pcs := x86NumericalBoundaryGoBytes(t, target.arch, strings.Join(operations, "\n")+"\nRET")
			if len(pcs) != len(operations)+1 {
				t.Fatal("original Go did not retain all prefetch boundaries")
			}
			code = code[:pcs[len(operations)]]
			decoded, err := decodeX86RawDirectives(rawX86Function(code), target.arch)
			if err != nil || len(decoded.Instrs) != len(opcodes) {
				t.Fatal("incomplete raw prefetch decoding", len(decoded.Instrs), err)
			}
			for i, ins := range decoded.Instrs {
				named := x86ScalarLaneInstruction(t, operations[i])
				if ins.Op != opcodes[i] || !reflect.DeepEqual(ins.Args, named.Args) {
					t.Fatalf("raw %s did not retain named operands: %v", operations[i], ins.Args)
				}
			}
			source := "TEXT Value(SB),4,$0-0\n" + x86DwordProductDirectives(code) + "RET\n"
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", target.arch, target.triple, api)
				if err != nil || !strings.Contains(ir, "ret void") || strings.Contains(ir, "load volatile") || strings.Contains(ir, "prefetch") {
					t.Fatalf("%s: raw hint introduced an access or lost its continuation: %v", api, err)
				}
				x86PackedStringCompileObject(t, llc, target.triple, ir, "-O2")
			}
		})
	}
}

func TestX86VSIBRawPrefetchRejectsReservedEncoding(t *testing.T) {
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", "VSCATTERPF1QPS K7,8(BP)(Z16*4)\nRET")
	valid := code[:pcs[1]]
	if _, size, known, err := decodedX86RawVSIBInstruction(valid, 64); !known || size != len(valid) || err != nil {
		t.Fatalf("valid hint %x: length %d, known %t: %v", valid, size, known, err)
	}
	for _, change := range []struct {
		name  string
		index int
		clear byte
		set   byte
	}{
		{"reserved opcode extension", 5, 0x38, 0},
		{"narrow length", 3, 0x60, 0},
		{"register operand", 5, 0, 0xc0},
		{"implicit mask", 3, 7, 0},
	} {
		t.Run(change.name, func(t *testing.T) {
			malformed := append([]byte(nil), valid...)
			malformed[change.index] = malformed[change.index]&^change.clear | change.set
			if _, _, known, err := decodedX86RawVSIBInstruction(malformed, 64); !known || err == nil {
				t.Fatalf("malformed hint %x: known %t: %v", malformed, known, err)
			}
		})
	}
	if _, _, known, err := decodedX86RawVSIBInstruction(valid, 32); !known || err == nil {
		t.Fatalf("high VSIB index in mode32 %x: known %t: %v", valid, known, err)
	}
}
