package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// Independent physical directory: Go's three VEX B/W/D names with WIG,
// and four EVEX B/W/D/Q names with every width, mask role and memory tuple.
// Each displacement points past the original encoded RET to complete data.
func x86RawAbsLiteralCases() []x86RawVectorLiteralCase {
	var rows []x86RawVectorLiteralCase
	for index, suffix := range []string{"B", "W", "D", "Q"} {
		lane := 1 << uint(index)
		add := func(width, mask int, evex, w, broadcast bool) {
			length := map[int]byte{16: 0, 32: 1, 64: 2}[width]
			var code []byte
			if evex {
				p1, p2 := byte(0x7d), byte(0x08)|length<<5|byte(mask)
				if w {
					p1 |= 0x80
				}
				if mask == 7 {
					p2 |= 0x80
				}
				if broadcast {
					p2 |= 0x10
				}
				code = []byte{0x62, 0xf2, p1, p2, byte(0x1c + index), 0x15}
			} else {
				p1 := byte(0x79) | length<<2
				if w {
					p1 |= 0x80
				}
				code = []byte{0xc4, 0xe2, p1, byte(0x1c + index), 0x15}
			}
			code = append(code, 1, 0, 0, 0, 0xc3)
			size := width
			if broadcast {
				size = lane
			}
			for at := 0; at < size; at++ {
				code = append(code, byte(at*23+0x85))
			}
			rows = append(rows, x86RawVectorLiteralCase{
				name: fmt.Sprintf("Abs%s_%d_K%d_EVEX%t_W%t_BCST%t", suffix, width, mask, evex, w, broadcast),
				code: code, mask: mask,
			})
		}
		for _, width := range []int{16, 32, 64} {
			if index < 3 && width < 64 {
				add(width, 0, false, false, false)
				add(width, 0, false, true, false)
			}
			for _, mask := range []int{0, 3, 7} {
				add(width, mask, true, index == 3, false)
				if index >= 2 {
					add(width, mask, true, index == 3, true)
				}
			}
		}
	}
	if len(rows) != 66 {
		panic("independent complete ABS literal directory changed")
	}
	return rows
}

func TestX86RawAbsLiteralActualPhysicalRows(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("independent ABS physical prior requires LLVM22 llvm-mc")
	}
	var input strings.Builder
	want := make(map[string]int)
	for _, row := range x86RawAbsLiteralCases() {
		size := 9
		if row.code[0] == 0x62 {
			size = 10
		}
		for _, value := range row.code[:size] {
			fmt.Fprintf(&input, "0x%02x ", value)
		}
		input.WriteByte('\n')
		suffix := strings.Split(strings.TrimPrefix(row.name, "Abs"), "_")[0]
		want["vpabs"+strings.ToLower(suffix)]++
	}
	stage, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(stage, mc, "--disassemble", "--triple=x86_64-unknown-linux-gnu",
		"--mattr=+avx2,+avx512f,+avx512bw,+avx512vl")
	command.Stdin = strings.NewReader(input.String())
	output, err := runtimeOracleCombinedOutput(stage, command)
	if err != nil || strings.Contains(string(output), "warning") || strings.Contains(string(output), "invalid") {
		t.Fatalf("independent complete ABS physical prior failed: %v\n%s", err, output)
	}
	for mnemonic, count := range want {
		if strings.Count(string(output), mnemonic) != count {
			t.Fatal("physical ABS opcode count changed", mnemonic, count)
		}
	}
}

func TestX86RawAbsLiteralCompleteLinuxObjects(t *testing.T) {
	x86RawVectorLiteralObjects(t, "x86_64-unknown-linux-gnu", x86RawAbsLiteralCases())
}

func TestX86RawAbsLiteralCompleteDarwinObjects(t *testing.T) {
	x86RawVectorLiteralObjects(t, "x86_64-apple-darwin", x86RawAbsLiteralCases())
}

func TestX86RawAbsLiteralCompleteWindowsObjects(t *testing.T) {
	x86RawVectorLiteralObjects(t, "x86_64-pc-windows-msvc", x86RawAbsLiteralCases())
}

func x86RawAbsLiteralNormalized(t *testing.T, row x86RawVectorLiteralCase) (*File, Instr) {
	t.Helper()
	file, err := normalizeX86RawFile(mustParseX86RawReturn(t, x86RawVectorLiteralSource(row)), "amd64")
	if err != nil || len(file.Funcs) != 1 || len(file.Data) != 1 {
		t.Fatal("original ABS literal lost its one complete DATA body", row.name, err)
	}
	for _, ins := range file.Funcs[0].Instrs {
		if ins.x86RIPLiteral {
			return file, ins
		}
	}
	t.Fatal("original ABS literal has no exact decoded source", row.name)
	return nil, Instr{}
}

func TestX86RawAbsLiteralExactTupleMasksAndPreservedState(t *testing.T) {
	for _, row := range x86RawAbsLiteralCases() {
		t.Run(row.name, func(t *testing.T) {
			_, ins := x86RawAbsLiteralNormalized(t, row)
			form, known, err := x86PackedAbsSignProperties(ins.Op, ins, "amd64")
			if !known || err != nil || !x86RawResultLiteralForm(ins, "amd64") || x86RawResultLiteralForm(ins, "386") {
				t.Fatal("complete ABS literal lost its exact mode64 typed role", err)
			}
			address, valid := x86StaticSBReadAddress(ins.Args[0], "amd64")
			if !valid {
				t.Fatal("original ABS literal has no independently bound DATA address")
			}
			original := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
				loweredStaticReads: map[x86StaticSBAddress]int64{address: int64(form.memoryBytes)}}
			original.masks[3], original.masks[7] = true, true
			original.writeVector(2, 64, 0x55aa55aa55aa55aa, false)
			state, want := original, original
			initialized := ^uint64(0)
			if row.mask == 3 {
				initialized = original.vectorBytes(2) | ^x86CallerVectorByteMask(int64(form.byteWidth))
			}
			want.writeVector(2, 64, initialized, false)
			if accepted, recognized := x86ResultPackedAbsSignStep(ins, &state, nil, "amd64", false); !accepted || !recognized || !reflect.DeepEqual(state, want) {
				t.Fatal("literal invented merge bytes or changed unrelated aliases/FLAGS/DF")
			}
			for size := 0; size < form.memoryBytes; size++ {
				state = original
				state.loweredStaticReads = map[x86StaticSBAddress]int64{address: int64(size)}
				before := state
				if accepted, recognized := x86ResultPackedAbsSignStep(ins, &state, nil, "amd64", false); accepted || !recognized || !reflect.DeepEqual(state, before) {
					t.Fatal("ABS literal borrowed a missing full/broadcast tuple byte", size)
				}
			}
			if row.mask != 0 {
				state = original
				state.masks[row.mask] = false
				before := state
				if accepted, _ := x86ResultPackedAbsSignStep(ins, &state, nil, "amd64", false); accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("ABS literal borrowed a missing numerical mask")
				}
			}
			changed := ins
			changed.x86PackedAbsEVEX = !changed.x86PackedAbsEVEX
			if x86RawResultLiteralForm(changed, "amd64") {
				t.Fatal("ABS literal forgot its original physical generation")
			}
		})
	}
}

func TestX86RawAbsLiteralKeepsOriginalDataAndReturnAuthority(t *testing.T) {
	rows := x86RawAbsLiteralCases()
	for _, index := range []int{0, 4, 30, len(rows) - 1} {
		row := rows[index]
		source := x86RawVectorLiteralSource(row)
		for _, changed := range []string{
			strings.Replace(source, "$0-0", "$16-0", 1),
			strings.Replace(source, "BYTE ", "MOVQ $0,SP\nBYTE ", 1),
		} {
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, changed, "func "+row.name+"()", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("complete ABS literal invented a raw-return frame", row.name, api, err)
				}
			}
		}
		for _, change := range []string{"DATA", "operand", "opcode", "origin", "generation"} {
			file, _ := x86RawAbsLiteralNormalized(t, row)
			if err := checkX86ScalarFPResultInitialization(file.Funcs[0], FuncSig{Name: row.name, Ret: Void}, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("standalone query borrowed the lowering's static byte owner", err)
			}
			if change == "DATA" {
				file.Data[0].Payload[0] ^= 1
			} else {
				for at := range file.Funcs[0].Instrs {
					ins := &file.Funcs[0].Instrs[at]
					if !ins.x86RIPLiteral {
						continue
					}
					switch change {
					case "operand":
						ins.Args[0].Sym += "foreign"
					case "opcode":
						ins.Op = "VPABSW"
						if strings.HasPrefix(row.name, "AbsW_") {
							ins.Op = "VPABSD"
						}
					case "origin":
						ins.x86SourceRaw = nil
					case "generation":
						ins.x86PackedAbsEVEX = !ins.x86PackedAbsEVEX
					}
					break
				}
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs:       map[string]FuncSig{row.name: {Name: row.name, Ret: Void}},
				ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
			if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed ABS literal borrowed original DATA/source identity", row.name, change, err)
			}
		}
	}
}
