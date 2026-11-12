package plan9asm

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func x86PackedReductionOriginalRawRows(t *testing.T, rows []x86PackedReductionOracleRow) []string {
	t.Helper()
	var instructions []string
	for _, row := range rows {
		instructions = append(instructions, row.row)
	}
	listing, err := x86ExtensionGoListing(t, "amd64", strings.Join(instructions, "\n"))
	if err != nil {
		t.Fatalf("actual original reduction listing: %v\n%s", err, listing)
	}
	raw, err := x86PackedReductionRawRowsFromGoListing(listing, rows)
	if err != nil {
		t.Fatalf("complete original reduction Go PC/byte boundaries: %v\n%s", err, listing)
	}
	return raw
}

var x86PackedReductionListingInstruction = regexp.MustCompile(`^\s*0x([0-9a-f]+)\s+([0-9]+)\s+\(.*:([0-9]+)\)\s+([A-Z0-9]+)(?:\s|$)`)

// The fixture's boundaries come from the actual Go listing, not our decoder.
// In particular x86asm may accept just a VEX prefix as a shorter instruction.
// Bind every source line and PC, then independently check all original bytes,
// including the terminal RET. Neither padding nor an unexplained suffix is
// silently dropped from the source used by the raw continuation tests.
func x86PackedReductionRawRowsFromGoListing(listing string, rows []x86PackedReductionOracleRow) ([]string, error) {
	var expected [][]byte
	for _, row := range rows {
		expected = append(expected, x86PackedReductionIndependentFixtureBytes(row))
	}
	return x86PackedReductionRawRowsFromGoListingWithExpected(listing, rows, expected)
}

func x86PackedReductionRawRowsFromGoListingWithExpected(listing string, rows []x86PackedReductionOracleRow, expected [][]byte) ([]string, error) {
	if len(expected) != len(rows) {
		return nil, fmt.Errorf("incomplete independent original byte inventory")
	}
	var code []byte
	var pcs []int
	for _, line := range strings.Split(listing, "\n") {
		if encoded := x86InsertExtractListedBytes(line); len(encoded) != 0 {
			fields := strings.Fields(line)
			pc, err := strconv.ParseUint(strings.TrimPrefix(fields[0], "0x"), 16, 32)
			if err != nil || int(pc) != len(code) {
				return nil, fmt.Errorf("noncontiguous Go byte listing at %q", line)
			}
			code = append(code, encoded...)
			continue
		}
		match := x86PackedReductionListingInstruction.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		pc, pcErr := strconv.ParseUint(match[1], 16, 32)
		decimalPC, decimalErr := strconv.ParseUint(match[2], 10, 32)
		sourceLine, sourceErr := strconv.Atoi(match[3])
		if pcErr != nil || decimalErr != nil || sourceErr != nil || pc != decimalPC {
			return nil, fmt.Errorf("invalid Go PC/source row %q", line)
		}
		if sourceLine == 1 && pc == 0 && (match[4] == "TEXT" || match[4] == "FUNCDATA") {
			continue
		}
		index := len(pcs)
		mnemonic := "RET"
		if index < len(rows) {
			mnemonic = strings.ToUpper(rows[index].mnemonic)
		}
		if index > len(rows) || sourceLine != index+2 || match[4] != mnemonic ||
			index == 0 && pc != 0 || index > 0 && int(pc) <= pcs[index-1] {
			return nil, fmt.Errorf("missing, duplicate or changed original Go instruction %q", line)
		}
		pcs = append(pcs, int(pc))
	}
	if len(pcs) != len(rows)+1 || len(code) != pcs[len(pcs)-1]+1 || code[len(code)-1] != 0xc3 {
		return nil, fmt.Errorf("incomplete original Go program: PCs=%v bytes=%x", pcs, code)
	}
	var raw []string
	for index, row := range rows {
		start, end := pcs[index], pcs[index+1]
		if end > len(code) {
			return nil, fmt.Errorf("original Go PC outside byte listing: %s at %d:%d", row.row, start, end)
		}
		want := expected[index]
		if !bytes.Equal(code[start:end], want) {
			return nil, fmt.Errorf("original Go instruction bytes changed: %s at %d:%d got=%x want=%x", row.row, start, end, code[start:end], want)
		}
		raw = append(raw, strings.TrimSuffix(x86RawDisplacementDirectives(code[start:end]), "\n"))
	}
	return raw, nil
}

// These independent oracle rows use only X/Y0, X/Y1, X/Y2 and bare (BX).
// Check each actual Go encoding's opcode, pp/L, register fields and selector;
// the production parser, typed spec and decoder do not supply these bytes.
func x86PackedReductionIndependentFixtureBytes(row x86PackedReductionOracleRow) []byte {
	memory := strings.Contains(row.row, "(BX)")
	modRM := byte(0xc8)
	if memory {
		modRM = 0x0b
	}
	if !row.legacy {
		modRM += 8
	}
	opcode := byte(0x7c)
	if strings.Contains(row.mnemonic, "hsub") {
		opcode = 0x7d
	}
	if row.dot {
		opcode = 0x40
		if strings.HasSuffix(row.mnemonic, "pd") {
			opcode = 0x41
		}
		if row.legacy {
			return []byte{0x66, 0x0f, 0x3a, opcode, modRM, 0xff}
		}
		control := byte(0x71)
		if row.width == 32 {
			control |= 4
		}
		return []byte{0xc4, 0xe3, control, opcode, modRM, 0xff}
	}
	prefix := byte(0xf2)
	if strings.HasSuffix(row.mnemonic, "pd") {
		prefix = 0x66
	}
	if row.legacy {
		return []byte{prefix, 0x0f, opcode, modRM}
	}
	control := byte(0xf3)
	if prefix == 0x66 {
		control = 0xf1
	}
	if row.width == 32 {
		control |= 4
	}
	return []byte{0xc5, control, opcode, modRM}
}

func TestX86PackedReductionGoListingKeepsWholeBoundaries(t *testing.T) {
	rows := []x86PackedReductionOracleRow{
		{row: "VDPPS $255,X0,X1,X2", mnemonic: "vdpps", width: 16, dot: true},
		{row: "VHADDPD Y0,Y1,Y2", mnemonic: "vhaddpd", width: 32},
	}
	const listing = `extension.extension STEXT nosplit asm size=11 align=0x0 args=0x0 locals=0x0
  0x0000 00000 (extension.s:1) TEXT extension.extension(SB), NOSPLIT|NOFRAME, $0-0
  0x0000 00000 (extension.s:1) FUNCDATA $0, gclocals(SB)
  0x0000 00000 (extension.s:2) VDPPS $255, X0, X1, X2
  0x0006 00006 (extension.s:3) VHADDPD Y0, Y1, Y2
  0x000a 00010 (extension.s:4) RET
  0x0000 c4 e3 71 40 d0 ff c5 f5 7c d0 c3                 ..q@....|..
`
	raw, err := x86PackedReductionRawRowsFromGoListing(listing, rows)
	if err != nil || len(raw) != 2 {
		t.Fatal("independent complete VEX/RET listing rejected", raw, err)
	}
	for name, changed := range map[string]string{
		"partial VEX boundary": strings.Replace(listing, "0x0006 00006", "0x0002 00002", 1),
		"source row changed":   strings.Replace(listing, "extension.s:3", "extension.s:5", 1),
		"opcode changed":       strings.Replace(listing, ") VHADDPD", ") VHSUBPD", 1),
		"physical opcode":      strings.Replace(strings.Replace(listing, "71 40 d0", "71 41 d0", 1), "..q@", "..qA", 1),
		"physical vector L":    strings.Replace(listing, "c5 f5", "c5 f1", 1),
		"missing RET":          strings.Replace(listing, "  0x000a 00010 (extension.s:4) RET\n", "", 1),
		"byte gap":             strings.Replace(listing, "0x0000 c4", "0x0001 c4", 1),
		"trailing bytes":       strings.Replace(listing, "c3                 ..q@....|..", "c3 90              ..q@....|...", 1),
		"abbreviated bytes":    strings.Replace(listing, "                 ..q@....|..", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := x86PackedReductionRawRowsFromGoListing(changed, rows); err == nil {
				t.Fatal("incomplete or changed whole-instruction listing accepted")
			}
		})
	}
}

func x86PackedReductionOracleState(width int) x86ResultState {
	state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
	for index := 0; index < 3; index++ {
		state.writeVector(index, 64, uint64(0xa5a55a5affff0000)|x86CallerVectorByteMask(int64(width)), true)
	}
	state.gp[3], state.pointerGP[3] = 0xff, true
	return state
}

func TestX86PackedReductionEverySelectorMeaningfulByteAndUpperAlias(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86PackedReductionOracleRows() {
			if strings.Contains(row.row, "(BX)") || arch == "386" && row.dot && !row.legacy {
				continue
			}
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				selectors := 1
				if row.dot {
					selectors = 256
				}
				for selector := 0; selector < selectors; selector++ {
					spelling := strings.Replace(row.row, "$255", fmt.Sprintf("$%d", selector), 1)
					ins := x86ScalarLaneInstruction(t, spelling)
					initial := x86PackedReductionOracleState(row.width)
					destination, _ := amd64VectorRegisterIndex(ins.Args[row.destination].Reg, row.width)
					want := initial.clone()
					want.writeVector(destination, row.width, x86CallerVectorByteMask(int64(row.width)), row.legacy)
					state := initial.clone()
					if !x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
						t.Fatal("complete initialized reduction changed unrelated input/FLAGS/DF/upper bytes", spelling)
					}
					for _, input := range []int{row.first, row.second} {
						source, _ := amd64VectorRegisterIndex(ins.Args[input].Reg, row.width)
						for missing := 0; missing < row.width; missing++ {
							required := true
							if row.dot {
								laneBytes := 4
								if strings.HasSuffix(row.mnemonic, "pd") {
									laneBytes = 8
								}
								required = selector&(1<<uint(4+(missing%16)/laneBytes)) != 0
							}
							state := initial.clone()
							state.writeVector(source, 64, state.vectorBytes(source)&^(uint64(1)<<uint(missing)), true)
							before := state.clone()
							accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
							if accepted == required || !accepted && !reflect.DeepEqual(state, before) {
								t.Fatal("selector borrowed a missing meaningful byte or rejected a suppressed lane", spelling, input, missing, required)
							}
						}
					}
				}
			})
		}
	}
}

func TestX86PackedReductionRawIdentityAndStandaloneBoundaries(t *testing.T) {
	rows := x86PackedReductionOracleRows()
	raw := x86PackedReductionOriginalRawRows(t, rows)
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		for index := range rows {
			fmt.Fprintf(&source, "TEXT F%d(SB),4,$0-0\n%s\nRET\n", index, raw[index])
		}
		original := mustParseX86RawReturn(t, source.String())
		file, err := normalizeX86RawFile(original, arch)
		if err != nil || len(file.Funcs) != 34 {
			t.Fatal("complete original reduction decoder failed", arch, err)
		}
		for index, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				function := file.Funcs[index]
				ins := function.Instrs[1]
				if !x86RawPackedReductionSource(ins, arch) {
					t.Fatal("missing complete physical source identity", row.row)
				}
				state := x86PackedReductionOracleState(row.width)
				before := state.clone()
				if x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
					t.Fatal("standalone query acquired raw source/native memory authority")
				}
				if accepted, known := x86LoweredRawPackedReductionStep(ins, &state, nil, arch); !accepted || !known {
					t.Fatal("exact complete raw inputs did not compose with paired native opcode")
				}
				for _, mutate := range []func(*Instr){
					func(ins *Instr) { ins.Op = "UNKNOWN" },
					func(ins *Instr) {
						ins.Args = append([]Operand(nil), ins.Args...)
						ins.Args[0] = Operand{Kind: OpReg, Reg: "X7"}
					},
					func(ins *Instr) { ins.x86Encoded = !ins.x86Encoded },
					func(ins *Instr) { ins.x86AddressBits = 32 },
					func(ins *Instr) { ins.x86VectorBytes++ },
					func(ins *Instr) { ins.x86SegmentPrefix = 0x64 },
					func(ins *Instr) { ins.x86UnboundAddressOverride = true },
					func(ins *Instr) { ins.x86SourceRaw = nil },
					func(ins *Instr) {
						origin := *ins.x86SourceRaw
						origin.packedReduction = x86RawPackedReductionIdentity{}
						ins.x86SourceRaw = &origin
					},
				} {
					changed := ins
					mutate(&changed)
					if x86RawPackedReductionSource(changed, arch) {
						t.Fatal("edited selector/physical/source identity borrowed a raw continuation")
					}
					state := before.clone()
					if accepted, _ := x86LoweredRawPackedReductionStep(changed, &state, nil, arch); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("edited raw reduction changed a rejected state")
					}
				}
				other := "386"
				if arch == "386" {
					other = "amd64"
				}
				if x86RawPackedReductionSource(ins, other) {
					t.Fatal("raw physical source borrowed another creation mode")
				}
				cloned := cloneX86ReplayInstrs(function.Instrs)
				if cloned[1].x86SourceRaw == ins.x86SourceRaw || !x86RawPackedReductionSource(cloned[1], arch) {
					t.Fatal("immutable raw replay clone lost its physical identity snapshot")
				}
			})
		}
	}
}
