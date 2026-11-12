package plan9asm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// The independent TestX86ADXGrammarMatchesCompleteGoEncoder owns all four
// yml_rl/Pq4/Pq4w/Pq5/Pq5w rows. These concrete original-Go/LLVM witnesses
// require a separate physical-PC consumer, not an invented x86asm scalar op.
func TestX86NumericalADXCompletePhysicalBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"ADCXL", "ADCXQ", "ADOXL", "ADOXQ"} {
			if arch == "386" && strings.HasSuffix(op, "Q") {
				continue // Go rejects Q-width ADX outside long mode.
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				var rows []string
				for _, input := range []string{
					"AX", "(AX)", "127(AX)", "-128(AX)", "-129(AX)", "128(AX)",
					"-2147483648(BX)", "2147483647(BX)", "0x12345678",
					"19(AX)(CX*1)", "19(AX)(CX*2)", "19(AX)(CX*4)", "19(AX)(CX*8)",
					"8(AX)(FS)", "8(AX)(GS)",
				} {
					rows = append(rows, op+" "+input+",DX")
				}
				if arch == "amd64" {
					rows = append(rows, op+" R13,R15", op+" -129(R11)(R9*4),R12")
				}
				code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nCMPL AX,$1\nRET")
				want, mode := 17, 64
				if arch == "386" {
					want, mode = 15, 32
				}
				if len(rows) != want || len(pcs) != len(rows)+2 {
					t.Fatal("complete original ADX width/address/REX inventory changed", len(rows), pcs)
				}
				// Independently bind the mandatory prefix, map, opcode and
				// REX.W on every actual instruction before observing its PC.
				prefix := byte(0x66)
				if strings.HasPrefix(op, "ADOX") {
					prefix = 0xf3
				}
				for index := range rows {
					instruction := code[pcs[index]:pcs[index+1]]
					at := bytes.Index(instruction, []byte{0x0f, 0x38, 0xf6})
					if at < 1 || !bytes.Contains(instruction[:at], []byte{prefix}) {
						t.Fatal("actual Go lost an original mandatory ADX prefix/map", rows[index], instruction)
					}
					wide := instruction[at-1]&0xf8 == 0x48
					if wide != strings.HasSuffix(op, "Q") {
						t.Fatal("mandatory 66 was mistaken for operand width or REX.W was lost", rows[index], instruction)
					}
				}
				x86NumericalNativeRequireMC(t, code, mode, len(pcs), "+adx")
				boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
				if err != nil || len(boundaries) != len(pcs) || len(scalar) != 2 {
					t.Fatal("complete legacy ADX native boundaries need a non-scalar observer", boundaries, scalar, err)
				}
				for index, pc := range pcs {
					end := int64(len(code))
					if index+1 < len(pcs) {
						end = pcs[index+1]
					}
					if boundaries[index] != (x86NumericalNativeBoundary{PC: pc, Length: int(end - pc)}) {
						t.Fatal("original complete Go ADX PC/length changed", index, boundaries[index], pc, end)
					}
					if index < len(rows) {
						if _, exists := scalar[pc]; exists {
							t.Fatal("physical ADX boundary acquired an SDK scalar-read role", pc)
						}
					}
				}
				if scalar[pcs[len(rows)]].Op != x86asm.CMP || scalar[pcs[len(rows)+1]].Op != x86asm.RET {
					t.Fatal("ADX registration displaced independent scalar CMP/RET", scalar)
				}
			})
		}
	}
}

func TestX86NumericalADXRIPBoundaryKeepsSourceRoles(t *testing.T) {
	for _, op := range []string{"ADCXL", "ADCXQ", "ADOXL", "ADOXQ"} {
		for _, offset := range []int{-17, 17} {
			t.Run(fmt.Sprintf("%s/%+d", op, offset), func(t *testing.T) {
				code, pcs, listing := x86NumericalBoundaryGoBytesAndListing(t, "amd64", fmt.Sprintf("%s table%+d(SB),BX\nRET", op, offset))
				disp, width := 5, 4
				if strings.HasSuffix(op, "Q") {
					disp, width = 6, 8
				}
				length := int64(disp + 4)
				if !reflect.DeepEqual(pcs, []int64{0, length}) || len(code) != int(length)+1 {
					t.Fatalf("actual Go ADX RIP relocation/extent prerequisite differs: %x %v\n%s", code, pcs, listing)
				}
				x86NumericalRequirePCRelListing(t, listing, disp, offset)
				x86NumericalNativeRequireMC(t, code, 64, 2, "+adx")
				// The existing raw decoder requires real in-group literal bytes,
				// whereas physical PC observation must not require or patch them.
				if _, _, _, known, err := decodeX86RawADX(code, 0, 64); !known || err == nil {
					t.Fatal("unlinked native RIP displacement acquired source-local DATA", known, err)
				}
				boundaries, scalar, err := x86NumericalNativeBoundaries(code, 64)
				if err != nil || !reflect.DeepEqual(boundaries, []x86NumericalNativeBoundary{{PC: 0, Length: int(length)}, {PC: length, Length: 1}}) ||
					len(scalar) != 1 || scalar[length].Op != x86asm.RET {
					t.Fatal("native ADX RIP must own only length/PC, not a scalar source", boundaries, scalar, err)
				}
				reads, err := numericalNativeReads(code, 64)
				if err != nil || len(reads) != 0 {
					t.Fatal("physical ADX invented an SDK numerical-read owner", reads, err)
				}
				// Preserve the separate preexisting source-local raw literal
				// contract, rather than accidentally deleting it to pass a guard.
				literal := append([]byte(nil), code...)
				binary.LittleEndian.PutUint32(literal[disp:disp+4], 1)
				literal = append(literal, bytes.Repeat([]byte{7}, width)...)
				decoded, err := decodeX86RawDirectiveGroup(literal, 64, 0, op, map[string]bool{})
				if err != nil || len(decoded) != 2 || decoded[0].Op != Op(op) || len(decoded[0].x86RIPLiteralData) != width {
					t.Fatal("physical observer changed the original complete raw-literal role", decoded, err)
				}
			})
		}
	}
}

func TestX86NumericalADXBoundaryGuardsAndMissingInputs(t *testing.T) {
	for _, op := range []string{"ADCXL", "ADCXQ", "ADOXL", "ADOXQ"} {
		t.Run(op, func(t *testing.T) {
			code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", op+" AX,BX\nRET")
			code = code[:pcs[1]]
			x86NumericalNativeRequireMC(t, code, 64, 1, "+adx")
			at := bytes.Index(code, []byte{0x0f, 0x38, 0xf6})
			badPrefix := append([]byte(nil), code...)
			badPrefix[0] = 0xf2
			badMap := append([]byte(nil), code...)
			badMap[at+1] = 0x39
			controls := [][]byte{
				append([]byte{0xf0}, code...), badPrefix, badMap,
				append(bytes.Repeat([]byte{0x67}, 16), code...),
				append(append([]byte(nil), code...), 0xe8, 0, 0, 0, 0, 0xc3),
			}
			for cut := 1; cut < len(code); cut++ {
				controls = append(controls, code[:cut])
			}
			for _, control := range controls {
				for _, prefix := range [][]byte{nil, {0x90, 0xc3}} {
					whole := append(append([]byte(nil), prefix...), control...)
					boundaries, scalar, err := x86NumericalNativeBoundaries(whole, 64)
					if !errors.Is(err, ErrProbeNeedsContext) || boundaries != nil || scalar != nil {
						t.Fatal("invalid/unreachable/calling ADX TEXT retained a partial observation", whole, err)
					}
				}
			}
			move := "MOVL"
			if strings.HasSuffix(op, "Q") {
				move = "MOVQ"
			}
			// Independent status and destination are initialized. The only
			// absent input is BX's pointer, not a legitimate dead DATA value.
			source := "TEXT ·Value(SB),4,$0-0\n" + move + " $0,AX\nXORL AX,AX\n" + op + " (BX),AX\nRET\n"
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("a physical ADX boundary granted a missing address/NUM input", api, err)
				}
			}
		})
	}
	// In mode32 0x48 is DEC AX, never a Q-width REX prefix on ADX.
	code, pcs := x86NumericalBoundaryGoBytes(t, "386", "DECL AX\nADCXL AX,BX\nRET")
	x86NumericalNativeRequireMC(t, code, 32, 3, "+adx")
	for _, mode := range []int{0, 16, 128} {
		boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
		if !errors.Is(err, ErrProbeNeedsContext) || boundaries != nil || scalar != nil {
			t.Fatal("ADX bytes inferred a physical source mode instead of checking its actual owner", mode, err)
		}
	}
	boundaries, scalar, err := x86NumericalNativeBoundaries(code, 32)
	if err != nil || len(boundaries) != 3 || len(scalar) != 2 || scalar[pcs[0]].Op != x86asm.DEC || scalar[pcs[2]].Op != x86asm.RET {
		t.Fatal("mode32 legacy DEC became an ADX Q-prefix/scalar read", boundaries, scalar, err)
	}
}
