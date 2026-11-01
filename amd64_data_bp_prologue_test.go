package plan9asm

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Observe either complete stock-Go encoding, never choose by the SDK version.
// This recognizes only the exact first-party fixture, including its original
// body, adjusted FP input, total frame and both halves of the saved BP cell.
// It remains a test observation, not a source-frame permission producer.
func amd64DataBPSavedFrameListing(listing string, frame int) (string, error) {
	if frame != 8 && frame != 16 {
		return "", fmt.Errorf("unregistered first-party frame %d", frame)
	}
	line := regexp.MustCompile(`(?m)^[ \t]*0x[0-9a-f]+[ \t]+[0-9]+[ \t]+\([^\r\n]*:[0-9]+\)[ \t]+([A-Z][A-Z0-9]*)(?:[ \t]+([^\r\n]*))?\r?$`)
	var instructions []string
	texts := 0
	for _, match := range line.FindAllStringSubmatch(listing, -1) {
		op, args := match[1], strings.Join(strings.Fields(match[2]), " ")
		if op == "TEXT" {
			parts := strings.Split(args, ",")
			if texts != 0 || len(instructions) != 0 || len(parts) != 3 ||
				!strings.HasSuffix(strings.TrimSpace(parts[0]), ".Value(SB)") ||
				strings.TrimSpace(parts[1]) != "NOSPLIT" || strings.TrimSpace(parts[2]) != fmt.Sprintf("$%d-8", frame+8) {
				return "", fmt.Errorf("original Go TEXT lost its exact saved-word frame: %s", args)
			}
			texts++
			continue
		}
		if op == "FUNCDATA" || op == "PCDATA" {
			continue // Zero-width compiler metadata is not an executed instruction.
		}
		instructions = append(instructions, strings.TrimSpace(op+" "+args))
	}
	if texts != 1 || len(instructions) != 10 {
		return "", fmt.Errorf("incomplete or extended fixture: TEXTs=%d instructions=%v", texts, instructions)
	}
	body := []string{
		fmt.Sprintf("MOVQ p+%d(FP), BP", frame+16),
		"MOVL (BP), AX", "ROLL $7, AX", "MOVL AX, 12(BP)",
	}
	var style string
	var expected []string
	switch instructions[0] {
	case "PUSHQ BP":
		style = "PUSH/MOV/SUB + ADD/POP/RET"
		expected = []string{"PUSHQ BP", "MOVQ SP, BP", fmt.Sprintf("SUBQ $%d, SP", frame)}
		expected = append(expected, body...)
		expected = append(expected, fmt.Sprintf("ADDQ $%d, SP", frame), "POPQ BP", "RET")
	case fmt.Sprintf("SUBQ $%d, SP", frame+8):
		style = "SUB/store/LEA + load/ADD/RET"
		expected = []string{
			fmt.Sprintf("SUBQ $%d, SP", frame+8), fmt.Sprintf("MOVQ BP, %d(SP)", frame),
			fmt.Sprintf("LEAQ %d(SP), BP", frame),
		}
		expected = append(expected, body...)
		expected = append(expected, fmt.Sprintf("MOVQ %d(SP), BP", frame), fmt.Sprintf("ADDQ $%d, SP", frame+8), "RET")
	default:
		return "", fmt.Errorf("unknown original Go frame entry: %s", instructions[0])
	}
	for index := range expected {
		if instructions[index] != expected[index] {
			return "", fmt.Errorf("%s instruction %d=%q, want %q", style, index, instructions[index], expected[index])
		}
	}
	return style, nil
}

func TestAMD64DataBPSavedFrameListingRequiresCompleteOrderedEnvelope(t *testing.T) {
	for _, frame := range []int{8, 16} {
		for _, style := range []string{"PUSH", "SP-cell"} {
			name := fmt.Sprintf("%s/%d", style, frame)
			var instructions []string
			if style == "PUSH" {
				instructions = []string{
					"PUSHQ BP", "MOVQ SP, BP", fmt.Sprintf("SUBQ $%d, SP", frame),
					fmt.Sprintf("MOVQ p+%d(FP), BP", frame+16), "MOVL (BP), AX", "ROLL $7, AX", "MOVL AX, 12(BP)",
					fmt.Sprintf("ADDQ $%d, SP", frame), "POPQ BP", "RET",
				}
			} else {
				instructions = []string{
					fmt.Sprintf("SUBQ $%d, SP", frame+8), fmt.Sprintf("MOVQ BP, %d(SP)", frame), fmt.Sprintf("LEAQ %d(SP), BP", frame),
					fmt.Sprintf("MOVQ p+%d(FP), BP", frame+16), "MOVL (BP), AX", "ROLL $7, AX", "MOVL AX, 12(BP)",
					fmt.Sprintf("MOVQ %d(SP), BP", frame), fmt.Sprintf("ADDQ $%d, SP", frame+8), "RET",
				}
			}
			listing := func(rows []string, extent int) string {
				var text strings.Builder
				fmt.Fprintf(&text, "\t0x0000 00000 (fixture.s:1)\tTEXT\tfixture.Value(SB), NOSPLIT, $%d-8\n", extent)
				for index, row := range rows {
					op, args, _ := strings.Cut(row, " ")
					fmt.Fprintf(&text, "\t0x%04x %05d (fixture.s:%d)\t%s\t%s\n", index, index, index+1, op, args)
				}
				return text.String()
			}
			t.Run(name+"/complete", func(t *testing.T) {
				if _, err := amd64DataBPSavedFrameListing(listing(instructions, frame+8), frame); err != nil {
					t.Fatal("independent complete stock-Go fixture was rejected", err)
				}
			})
			for _, mutation := range []string{
				"delete-save", "delete-restore", "wrong-save", "wrong-restore", "wrong-frame-setup",
				"wrong-allocation", "wrong-release", "wrong-FP-input", "swap-save-and-setup", "duplicate-save", "delete-return", "wrong-TEXT",
			} {
				t.Run(name+"/"+mutation, func(t *testing.T) {
					rows := append([]string(nil), instructions...)
					save, setup, allocation, restore, release := 0, 1, 2, 8, 7
					if style == "SP-cell" {
						save, setup, allocation, restore, release = 1, 2, 0, 7, 8
					}
					extent := frame + 8
					switch mutation {
					case "delete-save":
						rows = append(rows[:save], rows[save+1:]...)
					case "delete-restore":
						rows = append(rows[:restore], rows[restore+1:]...)
					case "wrong-save":
						rows[save] = fmt.Sprintf("MOVQ BP, %d(SP)", frame+8)
					case "wrong-restore":
						rows[restore] = fmt.Sprintf("MOVQ %d(SP), BP", frame+8)
					case "wrong-frame-setup":
						rows[setup] = fmt.Sprintf("LEAQ %d(SP), BP", frame+8)
					case "wrong-allocation":
						rows[allocation] = fmt.Sprintf("SUBQ $%d, SP", frame+16)
					case "wrong-release":
						rows[release] = fmt.Sprintf("ADDQ $%d, SP", frame+16)
					case "wrong-FP-input":
						rows[3] = fmt.Sprintf("MOVQ p+%d(FP), BP", frame+8)
					case "swap-save-and-setup":
						rows[save], rows[setup] = rows[setup], rows[save]
					case "duplicate-save":
						rows = append(rows, rows[save])
					case "delete-return":
						rows = rows[:len(rows)-1]
					case "wrong-TEXT":
						extent += 8
					}
					if _, err := amd64DataBPSavedFrameListing(listing(rows, extent), frame); err == nil {
						t.Fatal("an incomplete, reordered or wrong-width saved-BP frame passed observation")
					}
				})
			}
		}
	}
}
