package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
	"golang.org/x/arch/x86/x86asm"
)

// Independent complete Go VEX GP inventory. A ytab's numerical/read/write
// roles remain distinct; this consumer requests only exact physical PCs.
var x86NumericalVEXGPFamilies = []struct {
	stem, table, zcase, prefix, opcode, extension string
	offset                                        int
	classes                                       []string
}{
	{"ANDN", "_yandnl", "Zvex_rm_v_r", "", "0xF2", "", 2, []string{"Yml", "Yrl", "Yrl"}},
	{"BEXTR", "_ybextrl", "Zvex_v_rm_r", "", "0xF7", "", 2, []string{"Yrl", "Yml", "Yrl"}},
	{"BLSI", "_yblsil", "Zvex_rm_r_vo", "", "0xF3", "03", 3, []string{"Yml", "Yrl"}},
	{"BLSMSK", "_yblsil", "Zvex_rm_r_vo", "", "0xF3", "02", 3, []string{"Yml", "Yrl"}},
	{"BLSR", "_yblsil", "Zvex_rm_r_vo", "", "0xF3", "01", 3, []string{"Yml", "Yrl"}},
	{"BZHI", "_ybextrl", "Zvex_v_rm_r", "", "0xF5", "", 2, []string{"Yrl", "Yml", "Yrl"}},
	{"MULX", "_yandnl", "Zvex_rm_v_r", "vexF2", "0xF6", "", 2, []string{"Yml", "Yrl", "Yrl"}},
	{"PDEP", "_yandnl", "Zvex_rm_v_r", "vexF2", "0xF5", "", 2, []string{"Yml", "Yrl", "Yrl"}},
	{"PEXT", "_yandnl", "Zvex_rm_v_r", "vexF3", "0xF5", "", 2, []string{"Yml", "Yrl", "Yrl"}},
	{"RORX", "_yrorxl", "Zvex_i_rm_r", "vexF2", "0xF0", "", 0, []string{"Yu8", "Yml", "Yrl"}},
	{"SARX", "_ybextrl", "Zvex_v_rm_r", "vexF3", "0xF7", "", 2, []string{"Yrl", "Yml", "Yrl"}},
	{"SHLX", "_ybextrl", "Zvex_v_rm_r", "vex66", "0xF7", "", 2, []string{"Yrl", "Yml", "Yrl"}},
	{"SHRX", "_ybextrl", "Zvex_v_rm_r", "vexF2", "0xF7", "", 2, []string{"Yrl", "Yml", "Yrl"}},
}

func TestX86NumericalVEXGPCompleteOfficialEncoderRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, family := range x86NumericalVEXGPFamilies {
		for w, suffix := range []string{"L", "Q"} {
			name, mapName := family.stem+suffix, "vex0F38"
			if family.stem == "RORX" {
				mapName = "vex0F3A"
			}
			attributes := "avxEscape | vex128 | "
			if family.prefix != "" {
				attributes += family.prefix + " | "
			}
			encoding := []string{fmt.Sprintf("%s%s | vexW%d", attributes, mapName, w), family.opcode}
			if family.extension != "" {
				encoding = append(encoding, family.extension)
			}
			first := goasmrules.X86AVXRule{Opcode: name, Ytab: family.table, Prefix: "Pavx",
				Classes: family.classes, ZCase: family.zcase, ZOffset: family.offset, OpBytes: encoding}
			want := []goasmrules.X86AVXRule{first}
			if family.stem == "RORX" {
				second := first
				second.RowIndex, second.ZOffset = 1, 2
				second.Classes = []string{"Yi8", "Yml", "Yrl"}
				want = append(want, second)
			}
			var actual []goasmrules.X86AVXRule
			for _, rule := range rules {
				if rule.Opcode == name {
					actual = append(actual, rule)
				}
			}
			if !reflect.DeepEqual(actual, want) {
				t.Fatal("complete official GP operand/encoding row differs", name, actual, want)
			}
			count += len(actual)
		}
	}
	if len(x86NumericalVEXGPFamilies) != 13 || count != 28 {
		t.Fatal("complete 26-member/28-row independent VEX GP denominator changed", count)
	}
}

func x86NumericalVEXGPRow(stem, suffix, input string) string {
	arguments := input + ",CX,DX"
	switch stem {
	case "BEXTR", "BZHI", "SARX", "SHLX", "SHRX":
		arguments = "CX," + input + ",DX"
	case "BLSI", "BLSMSK", "BLSR":
		arguments = input + ",DX"
	case "RORX":
		arguments = "$255," + input + ",DX"
	}
	return stem + suffix + " " + arguments
}

func x86NumericalVEXGPRequireMC(t *testing.T, code []byte, mode, instructions int) {
	t.Helper()
	x86NumericalNativeRequireMC(t, code, mode, instructions, "+bmi,+bmi2")
}

func x86NumericalNativeRequireMC(t *testing.T, code []byte, mode, instructions int, features string) {
	t.Helper()
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("independent complete native boundary prior requires LLVM22 llvm-mc")
	}
	triple := "x86_64-unknown-linux-gnu"
	if mode == 32 {
		triple = "i386-unknown-linux-gnu"
	}
	var input strings.Builder
	for _, value := range code {
		fmt.Fprintf(&input, "0x%02x ", value)
	}
	input.WriteByte('\n')
	stage, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+triple, "--mattr="+features)
	command.Stdin = strings.NewReader(input.String())
	output, err := runtimeOracleCombinedOutput(stage, command)
	cancel()
	text := strings.ToLower(string(output))
	count := 0
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 0 && !strings.HasPrefix(fields[0], ".") {
			count++
		}
	}
	if err != nil || strings.Contains(text, "warning") || strings.Contains(text, "invalid") || count != instructions {
		t.Fatalf("actual Go bytes lack their independent LLVM22 physical prior: count=%d want=%d: %v\n%s", count, instructions, err, output)
	}
}

func TestX86NumericalVEXGPCompleteOriginalPhysicalBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, family := range x86NumericalVEXGPFamilies {
			t.Run(arch+"/"+family.stem, func(t *testing.T) {
				var rows []string
				for _, suffix := range []string{"L", "Q"} {
					for _, input := range []string{
						"AX", "(AX)", "127(AX)", "-128(AX)", "-129(AX)", "128(AX)",
						"-2147483648(BX)", "2147483647(BX)", "0x12345678",
						"19(AX)(CX*1)", "19(AX)(CX*2)", "19(AX)(CX*4)", "19(AX)(CX*8)",
						"8(AX)(FS)", "8(AX)(GS)",
					} {
						rows = append(rows, x86NumericalVEXGPRow(family.stem, suffix, input))
					}
					if arch == "amd64" {
						rows = append(rows,
							strings.NewReplacer("CX", "R14", "DX", "R15").Replace(x86NumericalVEXGPRow(family.stem, suffix, "R13")),
							x86NumericalVEXGPRow(family.stem, suffix, "-129(R11)(R9*4)"))
					}
					if family.stem == "RORX" {
						rows = append(rows, strings.Replace(x86NumericalVEXGPRow(family.stem, suffix, "AX"), "$255", "$-1", 1))
					}
				}
				want := map[string]int{"386": 30, "amd64": 34}[arch]
				if family.stem == "RORX" {
					want += 2
				}
				if len(rows) != want {
					t.Fatal("complete orthogonal physical GP axis inventory changed", len(rows), want)
				}
				code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nCMPL AX,$1\nRET")
				if len(pcs) != len(rows)+2 {
					t.Fatal("actual Go omitted or expanded a physical GP witness", len(rows), pcs)
				}
				mode := 64
				if arch == "386" {
					mode = 32
				}
				x86NumericalVEXGPRequireMC(t, code, mode, len(pcs))
				// Includes mode32 W1: SDM BMI instruction descriptions ignore
				// that bit outside long mode. This grants no named/raw entry.
				x86CheckNumericalFloatingBoundaries(t, code, pcs, mode, len(rows))
			})
		}
	}
}

func TestX86NumericalVEXGPRIPIsOnlyPhysicalBoundary(t *testing.T) {
	for _, family := range x86NumericalVEXGPFamilies {
		for _, suffix := range []string{"L", "Q"} {
			for _, offset := range []int{-17, 17} {
				t.Run(fmt.Sprintf("%s%s/%+d", family.stem, suffix, offset), func(t *testing.T) {
					row := x86NumericalVEXGPRow(family.stem, suffix, fmt.Sprintf("table%+d(SB)", offset))
					code, pcs, listing := x86NumericalBoundaryGoBytesAndListing(t, "amd64", row+"\nRET")
					length, add := int64(9), offset
					if family.stem == "RORX" {
						length, add = 10, offset-1
					}
					if !reflect.DeepEqual(pcs, []int64{0, length}) || len(code) != int(length)+1 {
						t.Fatalf("actual original RIP PC/relocation prior differs: %x %v\n%s", code, pcs, listing)
					}
					x86NumericalRequirePCRelListing(t, listing, 5, add)
					x86NumericalVEXGPRequireMC(t, code, 64, 2)
					boundaries, scalar, err := x86NumericalNativeBoundaries(code, 64)
					if err != nil || !reflect.DeepEqual(boundaries, []x86NumericalNativeBoundary{{PC: 0, Length: int(length)}, {PC: length, Length: 1}}) ||
						len(scalar) != 1 || scalar[length].Op != x86asm.RET {
						t.Fatal("RIP GP opcode must supply only its whole physical PC", boundaries, scalar, err)
					}
					reads, err := numericalNativeReads(code, 64)
					if err != nil || len(reads) != 0 {
						t.Fatal("physical GP boundary acquired an SDK scalar/numerical-read role", reads, err)
					}
					// The original object's unlinked zero displacement has no
					// source DATA. It must not become a raw source instruction.
					original := "TEXT ·Value(SB),4,$0-0\n" + x86RawDisplacementDirectives(code)
					if _, err := normalizeX86RawFile(mustParseX86RawReturn(t, original), "amd64"); err == nil {
						t.Fatal("boundary-only RIP permission leaked to the default raw source decoder")
					}
				})
			}
		}
		t.Run(family.stem+"/owned-DATA-versus-missing-pointer", func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$0-0\n" + x86NumericalVEXGPRow(family.stem, "Q", "table(SB)") + "\nRET\n" +
				"DATA table+0(SB)/8,$7\nGLOBL table(SB),8,$8\n"
			// This complete DATA was already a legitimate source before the
			// physical observer existed. BLS/RORX need no extra GP operand;
			// ordinary nontrapping MULX may leave its dead result unknown.
			// The other families still lack their explicit CX control/source.
			ownedAccepted := strings.HasPrefix(family.stem, "BLS") || family.stem == "MULX" || family.stem == "RORX"
			for _, control := range []struct {
				name, source string
				accepted     bool
			}{
				{"original-owned-DATA", source, ownedAccepted},
				// Change only the instruction's address. The unrelated original
				// DATA cannot supply BX: this exact func Value() has no pointer.
				{"missing-BX-pointer", strings.Replace(source, "table(SB)", "(BX)", 1), false},
			} {
				t.Run(control.name, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", control.source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, control.source, "func Value()", "amd64", "x86_64-unknown-linux-gnu", api)
						if control.accepted {
							if err != nil || ir == "" {
								t.Fatal("ordinary owned DATA lost its independent preexisting source role", api, err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("physical boundary or unrelated DATA invented a missing GP/pointer input", api, err)
						}
					}
				})
			}
		})
	}
}

func TestX86NumericalVEXGPBoundariesRetainAllGuards(t *testing.T) {
	for _, family := range x86NumericalVEXGPFamilies {
		code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", x86NumericalVEXGPRow(family.stem, "L", "AX")+"\nRET")
		code = append([]byte(nil), code[:pcs[1]]...)
		x86NumericalVEXGPRequireMC(t, code, 64, 1)
		for _, control := range []string{"L1", "address-override", "legacy-prefix", "unknown-map", "mode32-high-vvvv"} {
			t.Run(family.stem+"/"+control, func(t *testing.T) {
				changed, mode := append([]byte(nil), code...), 64
				switch control {
				case "L1":
					changed[2] |= 4
				case "address-override":
					changed = append([]byte{0x67}, changed...)
				case "legacy-prefix":
					changed = append([]byte{0x66}, changed...)
				case "unknown-map":
					changed[1] = changed[1]&0xe0 | 0x1f
				case "mode32-high-vvvv":
					mode, changed[2] = 32, changed[2]&^0x40
					if !x86NumericalVectorPrefix(changed, mode) {
						t.Fatal("mode32 guard accidentally constructed a legacy LES/LDS identity")
					}
				}
				for _, prefix := range [][]byte{nil, {0x90, 0xc3}} {
					whole := append(append([]byte(nil), prefix...), changed...)
					boundaries, scalar, err := x86NumericalNativeBoundaries(whole, mode)
					if !errors.Is(err, ErrProbeNeedsContext) || boundaries != nil || scalar != nil {
						t.Fatal("malformed/default-address GP encoding retained a partial observation", whole, err)
					}
				}
			})
		}
		t.Run(family.stem+"/every-cut", func(t *testing.T) {
			for cut := 0; cut < len(code); cut++ {
				boundaries, scalar, err := x86NumericalNativeBoundaries(append([]byte{0x90, 0xc3}, code[:cut]...), 64)
				if cut == 0 {
					continue // The independent NOP/RET prefix alone is complete.
				}
				if !errors.Is(err, ErrProbeNeedsContext) || boundaries != nil || scalar != nil {
					t.Fatal("unreachable truncated GP encoding retained its valid prefix", cut, err)
				}
			}
		})
	}
	// Physical mode32 C4/C5 memory ModRM prefixes remain LES/LDS, not
	// malformed BMI. The existing complete legacy-prefix root owns them.
	for _, code := range [][]byte{{0xc4, 0x00, 0xc3}, {0xc5, 0x00, 0xc3}} {
		boundaries, scalar, err := x86NumericalNativeBoundaries(code, 32)
		want := x86asm.LES
		if code[0] == 0xc5 {
			want = x86asm.LDS
		}
		if err != nil || len(boundaries) != 2 || len(scalar) != 2 || scalar[0].Op != want || scalar[2].Op != x86asm.RET {
			t.Fatal("mode32 legacy prefix identity was reclassified as VEX GP", code, err)
		}
	}
}

func TestX86NumericalVEXGPPhysicalProjectionPreservesDefaultRawRole(t *testing.T) {
	for _, row := range []struct {
		stem    string
		decode  x86RawInstructionDecoder
		project func([]byte, int, x86RawMemoryDecoder) (Instr, int, bool, error)
	}{
		{"ANDN", decodedX86ANDNInstruction, decodedX86ANDNInstructionWithMemory},
		{"BLSI", decodedX86BLSInstruction, decodedX86BLSInstructionWithMemory},
		{"BZHI", decodedX86RawBZHIInstruction, decodedX86RawBZHIInstructionWithMemory},
		{"MULX", decodedX86MULXInstruction, decodedX86MULXInstructionWithMemory},
		{"PDEP", decodedX86ParallelBitsInstruction, decodedX86ParallelBitsInstructionWithMemory},
		{"RORX", decodedX86RORXInstruction, decodedX86RORXInstructionWithMemory},
		{"SHLX", decodedX86BMI2ShiftInstruction, decodedX86BMI2ShiftInstructionWithMemory},
	} {
		t.Run(row.stem, func(t *testing.T) {
			code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", x86NumericalVEXGPRow(row.stem, "Q", "table+17(SB)")+"\nRET")
			code = code[:pcs[1]]
			x86NumericalVEXGPRequireMC(t, code, 64, 1)
			_, _, known, err := row.decode(code, 64)
			if !known || err == nil || !strings.Contains(err.Error(), "RIP-relative") {
				t.Fatal("the original default raw entry gained physical RIP permission", known, err)
			}
			_, _, known, err = row.project(code, 64, x86RawMemoryDecoder{})
			if !known || err == nil || !strings.Contains(err.Error(), "RIP-relative") {
				t.Fatal("the zero-value memory strategy no longer preserves the raw-source contract", known, err)
			}
			instruction, size, known, err := row.project(code, 64, x86RawMemoryDecoder{physicalPC: true})
			if !known || err != nil || size != len(code) {
				t.Fatal("the separate physical observer lost an independently decoded instruction", instruction, size, known, err)
			}
		})
	}
	t.Run("MULX-mode32-WIG-is-not-raw-entry", func(t *testing.T) {
		code, pcs := x86NumericalBoundaryGoBytes(t, "386", "MULXQ AX,CX,DX\nRET")
		code = code[:pcs[1]]
		x86NumericalVEXGPRequireMC(t, code, 32, 1)
		if _, _, known, err := decodedX86MULXInstruction(code, 32); !known || err == nil {
			t.Fatal("native-PC WIG observation broadened the old ordinary MULX raw entry", known, err)
		}
		instruction, size, known, err := decodedX86MULXInstructionWithMemory(code, 32, x86RawMemoryDecoder{physicalPC: true})
		if !known || err != nil || size != len(code) || instruction.Op != "MULXL" {
			t.Fatal("physical mode32 WIG projection acquired a qword operation or lost its real PC", instruction, size, known, err)
		}
	})
}
