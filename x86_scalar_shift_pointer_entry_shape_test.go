package plan9asm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Keep the SDK's complete diff8 numerical tail, including its original scan,
// shift, mask and result mapping. This is not a new caller/aggregate contract.
const x86CompareDiff8ShiftTail = `BSWAPQ AX
BSWAPQ CX
XORQ AX,CX
BSRQ CX,CX
SHRQ CX,AX
ANDQ $1,AX
LEAQ -1(AX*2),AX
RET
`

func x86CompareShiftRegisterSource(t *testing.T, declaration, body string) string {
	t.Helper()
	source := x86ResultGPSIMDAdmissionSource(t, "amd64", declaration, body)
	return strings.Replace(source, "·view(SB)", "·view<ABIInternal>(SB)", 1)
}

func TestAMD64ScalarShiftPointerEntryOverwriteDoesNotPolluteSourceShape(t *testing.T) {
	original, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "internal", "bytealg", "compare_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	canonical := func(source string) string {
		var lines []string
		for _, line := range strings.Split(source, "\n") {
			line, _, _ = strings.Cut(line, "//")
			if fields := strings.Fields(line); len(fields) != 0 {
				lines = append(lines, strings.Join(fields, ""))
			}
		}
		return strings.Join(lines, "\n")
	}
	if !strings.Contains(canonical(string(original)), canonical(x86CompareDiff8ShiftTail)) {
		t.Fatal("the unchanged complete SDK diff8 shift/result sequence differs")
	}

	for _, row := range []struct{ name, declaration, body string }{
		{"value-native-overwrite", "func view(data *uint64,count uint64) uint64\n",
			"MOVQ (AX),AX\nMOVQ BX,CX\nSHRQ CX,AX"},
		{"value-immediate-overwrite", "func view(data *uint64,count uint64) uint64\n",
			"MOVQ $0x1122334455667788,AX\nMOVQ BX,CX\nSHRQ CX,AX"},
		{"count-native-overwrite", "func view(value,unused uint64,count *uint64) uint64\n",
			"MOVQ (CX),CX\nSHRQ CX,AX"},
		{"diff8-native-overwrite", "func view(a,b *uint64) int64\n",
			"MOVQ AX,SI\nMOVQ BX,DI\nMOVQ (SI),AX\nMOVQ (DI),CX\nCMPQ AX,CX\nJEQ same\n" +
				x86CompareDiff8ShiftTail + "same:\nXORQ AX,AX"},
		{"diff8-numerical-control", "func view(a,b uint64) int64\n",
			"MOVQ BX,CX\nCMPQ AX,CX\nJEQ same\n" + x86CompareDiff8ShiftTail + "same:\nXORQ AX,AX"},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := x86CompareShiftRegisterSource(t, row.declaration, row.body)
			// The reaching source explicitly replaces the original opaque
			// entry register. An independent source-shape check must not
			// mistake that stale entry role for the instruction's live role.
			x86ResultGPSIMDAdmissionAPIs(t, "amd64", source, row.declaration, true)
		})
	}
}

func TestAMD64ScalarShiftSourceShapeDoesNotSupplyReachingNUMOrFlags(t *testing.T) {
	for _, row := range []struct{ name, declaration, body string }{
		{"pointer-is-not-value", "func view(data *uint64,count uint64) uint64\n",
			"MOVQ BX,CX\nSHRQ CX,AX"},
		{"pointer-is-not-count", "func view(value,unused uint64,count *uint64) uint64\n",
			"SHRQ CX,AX"},
		{"partial-native-value", "func view(data *uint64,count uint64) uint64\n",
			"MOVB (AX),AL\nMOVQ BX,CX\nSHRQ CX,AX"},
		{"missing-count-byte", "func view(data *uint64,count uint64) uint64\n",
			"MOVQ (AX),AX\nMOVB R12,CL\nSHRQ CX,AX"},
		{"scan-does-not-define-carry", "func view(value,count uint64) uint64\n",
			"MOVQ BX,CX\nBSRQ CX,CX\nRCRQ CX,AX"},
		{"scan-carry-cannot-be-observed", "func view(value,count uint64) uint64\n",
			"MOVQ BX,CX\nBSRQ CX,CX\nSETCS DL\nSHRQ CX,AX"},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := x86CompareShiftRegisterSource(t, row.declaration, row.body)
			x86ResultGPSIMDAdmissionAPIs(t, "amd64", source, row.declaration, false)
		})
	}
}
