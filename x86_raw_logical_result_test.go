package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent Go _yvandnpd/_yvaddsubpd/_yvblendmpd witnesses: twelve VEX
// names, sixteen EVEX names, every vector width, mask role and memory tuple.
// No production spec supplies this directory or its expected cardinality.
func x86RawLogicalResultCases() []x86RawVectorLiteralCase {
	var rows []x86RawVectorLiteralCase
	for _, operation := range []struct {
		opcode byte
		stem   string
	}{{0x54, "VAND"}, {0x55, "VANDN"}, {0x56, "VOR"}, {0x57, "VXOR"}} {
		for pp, suffix := range []string{"PS", "PD"} {
			for _, width := range []int{16, 32} {
				for _, vex3 := range []bool{false, true} {
					rows = append(rows, x86RawVectorLiteralCase{
						name: fmt.Sprintf("%s%sVEX%d_%t", operation.stem, suffix, width, vex3),
						code: x86RawFloatLogicalLiteral(operation.opcode, byte(pp), vex3, width),
					})
				}
			}
			for _, width := range []int{16, 32, 64} {
				for _, mask := range []int{0, 3, 7} {
					for _, broadcast := range []bool{false, true} {
						rows = append(rows, x86RawVectorLiteralCase{
							name: fmt.Sprintf("%s%sEVEX%d_%d_%t", operation.stem, suffix, width, mask, broadcast),
							code: x86RawEVEXFloatLogicalLiteral(operation.opcode, byte(pp), width, mask, mask == 7, broadcast),
							mask: mask,
						})
					}
				}
			}
		}
	}
	for _, op := range []Op{"VPAND", "VPANDN", "VPOR", "VPXOR"} {
		for _, width := range []int{16, 32} {
			for _, vex3 := range []bool{false, true} {
				code := x86RawPackedLogicalLiteral(op, false, width, 0, false, false)
				if !vex3 {
					code = append([]byte{0xc5, code[2] | 0x80}, code[3:]...)
				}
				rows = append(rows, x86RawVectorLiteralCase{
					name: fmt.Sprintf("%sVEX%d_%t", op, width, vex3), code: code,
				})
			}
		}
	}
	for _, op := range []Op{"VPANDD", "VPANDQ", "VPANDND", "VPANDNQ", "VPORD", "VPORQ", "VPXORD", "VPXORQ"} {
		for _, width := range []int{16, 32, 64} {
			for _, mask := range []int{0, 3, 7} {
				for _, broadcast := range []bool{false, true} {
					rows = append(rows, x86RawVectorLiteralCase{
						name: fmt.Sprintf("%sEVEX%d_%d_%t", op, width, mask, broadcast),
						code: x86RawPackedLogicalLiteral(op, true, width, mask, mask == 7, broadcast),
						mask: mask,
					})
				}
			}
		}
	}
	return rows
}

func x86RawLogicalLiteralObjects(t *testing.T, triple string) {
	t.Helper()
	rows := x86RawLogicalResultCases()
	if len(rows) != 336 {
		t.Fatal("complete independent logical literal directory changed", len(rows))
	}
	x86RawVectorLiteralObjects(t, triple, rows)
}

func TestX86RawLogicalLiteralCompleteLinuxObjects(t *testing.T) {
	x86RawLogicalLiteralObjects(t, "x86_64-unknown-linux-gnu")
}

func TestX86RawLogicalLiteralCompleteDarwinObjects(t *testing.T) {
	x86RawLogicalLiteralObjects(t, "x86_64-apple-darwin")
}

func TestX86RawLogicalLiteralCompleteWindowsObjects(t *testing.T) {
	x86RawLogicalLiteralObjects(t, "x86_64-pc-windows-msvc")
}

func TestX86RawLogicalLiteralKeepsIndependentInputsAndSource(t *testing.T) {
	for _, row := range x86RawLogicalResultCases() {
		source := x86RawVectorLiteralSource(row)
		declaration := "func " + row.name + "()"
		variants := []string{
			strings.Replace(source, "$0-0", "$16-0", 1),
			strings.Replace(source, "MOVL $5,AX", "MOVQ $0,SP\nMOVL $5,AX", 1),
		}
		if row.mask != 0 {
			variants = append(variants, strings.NewReplacer("KMOVD AX,K3\n", "", "KMOVD AX,K7\n", "").Replace(source))
		}
		for _, changed := range variants {
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("literal borrowed a missing mask or raw-return frame", row.name, api, err)
				}
			}
		}
		for _, change := range []string{"operand", "DATA"} {
			file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
			if err != nil || len(file.Data) != 1 {
				t.Fatal("original literal source lost its exact DATA", row.name, err)
			}
			if err := checkX86ScalarFPResultInitialization(file.Funcs[0], FuncSig{Name: row.name, Ret: Void}, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("declaration-only query acquired lowering DATA", row.name, err)
			}
			if change == "DATA" {
				file.Data[0].Payload[0] ^= 1
			} else {
				for index := range file.Funcs[0].Instrs {
					instruction := &file.Funcs[0].Instrs[index]
					if instruction.x86RIPLiteral {
						instruction.Args[0].Sym += "changed"
						break
					}
				}
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs:       map[string]FuncSig{row.name: {Name: row.name, Ret: Void}},
				ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
			if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed source borrowed original literal identity", row.name, change, err)
			}
		}
	}
}

func TestX86RawLogicalLiteralUsesExactTypedByteEffects(t *testing.T) {
	for _, row := range x86RawLogicalResultCases() {
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, x86RawVectorLiteralSource(row)), "amd64")
		if err != nil {
			t.Fatal(row.name, err)
		}
		for _, instruction := range file.Funcs[0].Instrs {
			if !instruction.x86RIPLiteral {
				continue
			}
			form, known, err := x86PackedLogicalProperties(instruction, "amd64")
			if !known || err != nil || !x86RawLogicalLiteralForm(instruction, "amd64") ||
				x86RawLogicalLiteralForm(instruction, "386") {
				t.Fatal("literal lost its typed mode64 tuple", row.name, err)
			}
			address, valid := x86StaticSBReadAddress(form.source, "amd64")
			if !valid {
				t.Fatal("literal has no static DATA identity", row.name)
			}
			second, _ := amd64VectorRegisterIndex(instruction.Args[form.second].Reg, form.byteWidth)
			destination, _ := amd64VectorRegisterIndex(instruction.Args[form.destination].Reg, form.byteWidth)
			wantDestination := 0
			if !strings.HasPrefix(row.name, "VP") {
				wantDestination = 1
				if strings.Contains(row.name, "EVEX") {
					wantDestination = 2
				}
			}
			if destination != wantDestination {
				t.Fatal("independent bytes changed the physical destination", row.name, destination)
			}
			for missing := -1; missing < form.byteWidth; missing++ {
				state := x86ResultState{flags: 0x3f,
					loweredStaticReads: map[x86StaticSBAddress]int64{address: int64(form.memoryBytes)}}
				state.masks[3], state.masks[7] = true, true
				for index := range state.xmm {
					state.writeVector(index, 64, ^uint64(0), false)
				}
				want := ^uint64(0)
				if missing >= 0 {
					want &^= uint64(1) << uint(missing)
					state.writeVector(second, 64, want, false)
				}
				if !x86ScalarFPLogicalTransfer(instruction, form, &state, nil, "amd64") ||
					state.vectorBytes(destination) != want || state.flags != 0x3f {
					t.Fatal("literal invented a source byte or changed FLAGS", row.name, missing)
				}
				state.loweredStaticReads[address]--
				if x86ScalarFPLogicalTransfer(instruction, form, &state, nil, "amd64") {
					t.Fatal("literal accepted a shortened full/broadcast tuple", row.name)
				}
			}
		}
	}
}
