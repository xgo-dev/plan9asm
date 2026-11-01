package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86ScalarRMWTLSRows(arch string) []string {
	var rows []string
	for _, stem := range []string{"ADC", "ADD", "AND", "OR", "SBB", "SUB", "XOR", "INC", "DEC", "NEG", "NOT", "BTC", "BTR", "BTS"} {
		unary := stem == "INC" || stem == "DEC" || stem == "NEG" || stem == "NOT"
		bitString := strings.HasPrefix(stem, "BT")
		for _, width := range "BWLQ" {
			if width == 'Q' && arch == "386" || width == 'B' && bitString {
				continue
			}
			opcode := stem + string(width)
			for _, address := range []string{"8(TLS)", "8(CX)(TLS*1)", "8(CX)(TLS*4)"} {
				if unary {
					rows = append(rows, opcode+" "+address)
					continue
				}
				rows = append(rows, opcode+" AX,"+address, opcode+" $1,"+address)
				if !bitString {
					rows = append(rows, opcode+" "+address+",AX")
				}
			}
		}
	}
	return rows
}

func TestX86ScalarRMWTLSCompleteFamilyNeedsSourceContext(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86ScalarRMWTLSRows(arch)
		var original strings.Builder
		for index, row := range rows {
			fmt.Fprintf(&original, "TEXT ·tls%d(SB),4,$0-0\n%s\nRET\n", index, row)
		}
		goos := "linux"
		if arch == "386" {
			goos = "freebsd" // This actual profile accepts direct TLS source.
		}
		x86ScalarCompareTLSGoObject(t, original.String(), arch, goos, false)
		for _, row := range rows {
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86PureGPUnknownInstruction(t, row)
				_, recognized, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
				if !recognized || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("Go-accepted TLS row must retain its source role: %v", err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·probe(SB),4,$0-0\n"+row+"\nRET\n",
						"func probe()", arch, "", api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("%s emitted or reclassified unbound TLS: %v", api, err)
					}
				}
			})
		}
	}
}

func TestX86ScalarRMWTLSCannotHideMalformedOperands(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ScalarRMWTLSRows(arch) {
			for _, mutate := range []func(*MemRef){
				func(memory *MemRef) { memory.Scale = 3 },
				func(memory *MemRef) { memory.OffRaw = "missing" },
				func(memory *MemRef) { memory.IndexExt = ExtendUXTW },
			} {
				ins := x86PureGPUnknownInstruction(t, row)
				for index := range ins.Args {
					if ins.Args[index].Kind == OpMem {
						mutate(&ins.Args[index].Mem)
					}
				}
				_, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
				if !known || err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s invalid TLS shape hidden by Context: %+v: %v", arch, ins.Args, err)
				}
			}
		}
	}
}
