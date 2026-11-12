package plan9asm

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86TLSMoveCompleteIndependentGoMovtab(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	compact := func(source string) string {
		return strings.Join(strings.Fields(source), "")
	}
	var actual []string
	for _, row := range regexp.MustCompile(`\{AMOV[LQ],\s*Ytls,[^\n]+`).FindAllString(string(source), -1) {
		actual = append(actual, compact(row))
	}
	want := []string{
		"{AMOVL,Ytls,Ynone,Yrl,movTLSReg,[4]uint8{0,0,0,0}},",
		"{AMOVQ,Ytls,Ynone,Yrl,movTLSReg,[4]uint8{0,0,0,0}},",
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("complete Ytls encoder rows changed: %v", actual)
	}
	// Retain every segment-register MOVW memory row and opcode extension.
	// Those shapes are part of TLS memory grammar, but grant no segment state.
	var segments []string
	for _, row := range regexp.MustCompile(`\{AMOVW,\s*(?:Y(?:es|cs|ss|ds|fs|gs),\s*Ynone,\s*Yml|Yml,\s*Ynone,\s*Y(?:es|cs|ss|ds|fs|gs)),[^\n]+`).FindAllString(string(source), -1) {
		segments = append(segments, compact(row))
	}
	var expected []string
	for _, classes := range []struct{ source, destination, zcase, opcode string }{
		{"Yseg", "Yml", "movRegMem", "0x8c"}, {"Yml", "Yseg", "movMemReg", "0x8e"},
	} {
		for index, class := range []string{"Yes", "Ycs", "Yss", "Yds", "Yfs", "Ygs"} {
			expected = append(expected, "{AMOVW,"+strings.ReplaceAll(classes.source, "Yseg", class)+",Ynone,"+
				strings.ReplaceAll(classes.destination, "Yseg", class)+","+classes.zcase+",[4]uint8{"+classes.opcode+","+
				string(rune('0'+index))+",0,0}},")
		}
	}
	if !reflect.DeepEqual(segments, expected) {
		t.Fatalf("complete TLS segment/memory encoder rows changed: %v", segments)
	}
}
