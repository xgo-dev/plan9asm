package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86RawMoveLiteralInputCases() []x86RawMoveOriginCase {
	var rows []x86RawMoveOriginCase
	for _, row := range x86RawMoveOriginCases() {
		if row.role != "load" {
			continue
		}
		aligned := false
		for _, spec := range x86PackedMoveResultOracle {
			aligned = aligned || spec.aligned && strings.HasPrefix(row.row, spec.name+" ") ||
				spec.aligned && strings.HasPrefix(row.row, spec.name+".")
		}
		if !aligned {
			rows = append(rows, row)
		}
	}
	return rows
}

func x86RawMoveLiteralInputBytes(t *testing.T, rows []x86RawMoveOriginCase) ([][]byte, [][]byte) {
	t.Helper()
	observed := x86RawMoveOriginGoBytes(t, "amd64", rows)
	code, payloads := make([][]byte, len(rows)), make([][]byte, len(rows))
	for index, row := range rows {
		if len(observed[index]) < 4 || observed[index][len(observed[index])-1] != 0x13 {
			t.Fatal("independent Go (BX)-to-vector2 ModRM changed", row.row, observed[index])
		}
		width := map[string]int{"X": 16, "Y": 32, "Z": 64}[row.bank]
		if row.scalar {
			width = 4
			if strings.HasPrefix(row.row, "VMOVSD") {
				width = 8
			}
		}
		payload := make([]byte, width)
		for i := range payload {
			payload[i] = byte(i*37 + 19)
		}
		code[index] = append([]byte(nil), observed[index]...)
		code[index][len(code[index])-1] = 0x15 // RIP+disp32, vector2 unchanged.
		code[index] = append(code[index], 1, 0, 0, 0, 0xc3)
		code[index] = append(code[index], payload...)
		payloads[index] = payload
	}
	return code, payloads
}

// These are fully initialized original source-local reads, not unbound format
// fixtures. Existing raw RET and DATA checks must remain effective; adding a
// mandatory numerical obligation cannot reject their valid unmasked instances.
func TestX86RawMoveInitializedLiteralInputsAndReturnStillWork(t *testing.T) {
	rows := x86RawMoveLiteralInputCases()
	if len(rows) != 62 {
		t.Fatal("complete unaligned packed/scalar literal directory changed", len(rows))
	}
	code, payloads := x86RawMoveLiteralInputBytes(t, rows)
	var source, declarations strings.Builder
	for index := range rows {
		fmt.Fprintf(&declarations, "func Literal%d(mask uint64)\n", index)
		fmt.Fprintf(&source, "TEXT ·Literal%d(SB),4,$0-8\nKMOVD mask+0(FP),K1\nVPXORQ Z2,Z2,Z2\n", index)
		for _, value := range code[index] {
			fmt.Fprintf(&source, "BYTE $%d\n", value)
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64")
	if err != nil || len(normalized.Data) != len(rows) {
		t.Fatal("initialized literal source lost its complete data directory", err)
	}
	for index, data := range normalized.Data {
		if data.Width != int64(len(payloads[index])) || !bytes.Equal(data.Payload, payloads[index]) {
			t.Fatal("literal capture changed the exact original source tuple", rows[index].row, data)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("valid initialized raw literal/RET regressed under the mandatory move proof", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "move-literal.ll", "move-literal.o", body)
					}
				})
			}
		})
	}
}

func TestX86RawMoveLiteralInputsDoNotGrantMasksMergeOrReturnRoles(t *testing.T) {
	rows := x86RawMoveLiteralInputCases()
	code, payloads := x86RawMoveLiteralInputBytes(t, rows)
	for index, row := range rows {
		if row.masking == "plain" {
			continue
		}
		for _, control := range []string{"mask", "merge", "raw return width", "raw return cleanup", "frame"} {
			if control == "merge" && row.masking != "merge" {
				continue
			}
			t.Run(row.row+"/"+control, func(t *testing.T) {
				var source strings.Builder
				frame := 0
				if control == "frame" {
					frame = 16
				}
				fmt.Fprintf(&source, "TEXT ·Literal(SB),4,$%d-8\n", frame)
				if control != "mask" {
					source.WriteString("KMOVD mask+0(FP),K1\n")
				}
				if control != "merge" {
					source.WriteString("VPXORQ Z2,Z2,Z2\n")
				}
				original := append([]byte(nil), code[index]...)
				if strings.HasPrefix(control, "raw return") {
					// The original source has one instruction then C3 and the
					// exact pool. Keep that pool's target and complete tuple.
					ret := len(original) - len(payloads[index]) - 1
					if ret < 5 || original[ret] != 0xc3 {
						t.Fatal("independent literal return boundary missing")
					}
					replacement := []byte{0x66, 0xc3}
					if control == "raw return cleanup" {
						replacement = []byte{0xc2, 8, 0}
					}
					original[ret-4] = byte(len(replacement))
					original = append(append(append([]byte(nil), original[:ret]...), replacement...), original[ret+1:]...)
				}
				for _, value := range original {
					fmt.Fprintf(&source, "BYTE $%d\n", value)
				}
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source.String(), "func Literal(mask uint64)", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("literal DATA invented an input or native return/frame role", api, err)
					}
				}
			})
		}
	}
}
