package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86IntegerMinMaxIndependentRows(arch string) []string {
	var rows []string
	for _, op := range []string{
		"VPMINSB", "VPMINUB", "VPMAXSB", "VPMAXUB",
		"VPMINSW", "VPMINUW", "VPMAXSW", "VPMAXUW",
		"VPMINSD", "VPMINUD", "VPMAXSD", "VPMAXUD",
		"VPMINSQ", "VPMINUQ", "VPMAXSQ", "VPMAXUQ",
	} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, first := range []string{bank + "0", "(SI)"} {
				rows = append(rows, op+" "+first+","+bank+"1,"+bank+"2")
				if arch == "amd64" {
					rows = append(rows, op+" "+first+","+bank+"1,K1,"+bank+"2",
						op+".Z "+first+","+bank+"1,K1,"+bank+"2")
				}
			}
			if strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q") {
				rows = append(rows, op+".BCST (SI),"+bank+"1,"+bank+"2")
				if arch == "amd64" {
					rows = append(rows, op+".BCST (SI),"+bank+"1,K1,"+bank+"2",
						op+".BCST.Z (SI),"+bank+"1,K1,"+bank+"2")
				}
			}
		}
	}
	return rows
}

func TestX86IntegerMinMaxCompleteTypedNamedRows(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86IntegerMinMaxIndependentRows(arch)
		want := 120
		if arch == "amd64" {
			want = 360
		}
		if len(rows) != want {
			t.Fatal("independent min/max row denominator changed", arch, len(rows))
		}
		requireX86GoAssemblerResult(t, arch,
			"TEXT forms(SB),4,$0-0\n"+strings.Join(rows, "\n")+"\nRET\n", true)
		for _, row := range rows {
			ins := x86ScalarLaneInstruction(t, row)
			effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
			if !known || err != nil || !effect.requiresResultProof ||
				effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
				t.Fatal("complete min/max grammar lacks its typed numerical obligation", row, known, err)
			}
		}
	}
}

func TestX86IntegerMinMaxPhysicalMode32DoesNotGrantNamedArity(t *testing.T) {
	rows := x86IntegerMinMaxIndependentRows("amd64")
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(rows, "\n")+"\nRET")
	if len(pcs) != len(rows)+1 {
		t.Fatal("incomplete physical instruction boundaries")
	}
	// This observer owns decoded instruction identity, not a raw-return PC
	// contract. Keep the terminator named while preserving every min/max byte.
	file := mustParseX86RawReturn(t, "TEXT Value(SB),4,$0-0\n"+
		x86RawDisplacementDirectives(code[:pcs[len(rows)]])+"RET\n")
	file, err := normalizeX86RawFile(file, "386")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, ins := range file.Funcs[0].Instrs {
		_, known, err := x86IntegerMinMaxProperties(ins.Op, ins, "386")
		if !known {
			continue
		}
		if err != nil || !x86RawIntegerMinMaxSource(ins, "386") {
			t.Fatal("physical mode32 min/max lost its decoded mask form", ins.Raw, err)
		}
		count++
		for _, mutation := range []string{"origin", "encoded", "operand", "address", "segment"} {
			changed := ins
			switch mutation {
			case "origin":
				changed.x86SourceRaw = nil
			case "encoded":
				changed.x86Encoded = false
			case "operand":
				changed.Args = append([]Operand(nil), ins.Args...)
				changed.Args[1] = Operand{Kind: OpReg, Reg: "Z7"}
			case "address":
				changed.x86AddressBits = 16
			case "segment":
				changed.x86SegmentPrefix = 0x64
			}
			if x86RawIntegerMinMaxSource(changed, "386") {
				t.Fatal("edited physical source borrowed its old shape", ins.Raw, mutation)
			}
		}
		if len(ins.Args) == 4 {
			named := x86ScalarLaneInstruction(t, string(ins.Op)+" "+
				strings.Join([]string{ins.Args[0].String(), ins.Args[1].String(),
					ins.Args[2].String(), ins.Args[3].String()}, ","))
			if _, _, err := x86IntegerMinMaxProperties(named.Op, named, "386"); err == nil {
				t.Fatal("physical decoder expanded the named mode32 frontend", named.Raw)
			}
		}
	}
	if count != len(rows) {
		t.Fatal("incomplete physical min/max family", count, len(rows))
	}
}

func TestX86IntegerMinMaxSelectedBytesAndState(t *testing.T) {
	for _, row := range x86IntegerMinMaxIndependentRows("amd64") {
		ins := x86ScalarLaneInstruction(t, row)
		if ins.Args[0].Kind != OpReg {
			continue // Native reads retain a separate paired continuation.
		}
		width := amd64VectorByteWidth(ins.Args[0].Reg)
		bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[string(ins.Op)[6]]
		lane := bits / 8
		for missingRegister := 0; missingRegister < 3; missingRegister++ {
			for missingByte := 0; missingByte < 64; missingByte++ {
				state := x86ResultState{flags: x86ByteFlagsAll}
				for register := 0; register < 3; register++ {
					state.writeVector(register, 64, ^uint64(0), false)
				}
				state.writeVector(missingRegister, 64, ^uint64(0)&^(uint64(1)<<uint(missingByte)), false)
				state.masks[1] = true
				before := state.clone()
				if !x86ResultTransfer(ins, &state, nil, 0, "amd64") {
					t.Fatal("unknown data bytes cannot invent instruction effects", row)
				}
				want := ^uint64(0)
				merge := len(ins.Args) == 4 && !strings.HasSuffix(string(ins.Op), ".Z")
				if missingByte < width && (missingRegister < 2 || merge) {
					if missingRegister == 2 {
						want &^= uint64(1) << uint(missingByte)
					} else {
						want &^= x86CallerVectorByteMask(int64(lane)) << uint(missingByte/lane*lane)
					}
				}
				if state.vectorBytes(2) != want || state.flags != before.flags ||
					state.gp != before.gp || state.masks != before.masks {
					t.Fatal("min/max supplied missing lane bytes or altered unrelated state", row, missingRegister, missingByte)
				}
				state.writeVector(2, 64, before.vectorBytes(2), false)
				if !reflect.DeepEqual(state, before) {
					t.Fatal("min/max altered unrelated source identities", row)
				}
			}
		}
	}
}

func TestX86IntegerMinMaxInitializedPublicFamily(t *testing.T) {
	var source, declarations strings.Builder
	for index, op := range x86MinMaxTestOps {
		name := fmt.Sprint("MinMax", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-12\nMOVQ p+0(FP),SI\n"+
			"VPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\nMOVL $85,CX\nKMOVD CX,K1\n"+
			"%s (SI),Z1,K1,Z2\nVPEXTRD $0,X2,CX\nMOVL CX,ret+8(FP)\nRET\n", name, op)
		fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", "x86_64-unknown-linux-gnu", api)
		if err != nil || ir == "" {
			t.Fatal("initialized complete min/max family rejected", api, err)
		}
	}
}
