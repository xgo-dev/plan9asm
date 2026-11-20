package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestInspectAssemblyCPPStringTokensPhysicalAndRecorded(t *testing.T) {
	source := "// ignored \"comment.h\"\n" +
		"#define INCLUDE(file) #include file\n" +
		"INCLUDE(\"header∕one.h\")\nDATA ·x(SB)/4,$\"data\"\n" +
		"`raw.h`\n#line 1 \"logical-file\"\n"
	tokens, err := InspectAssemblyCPPStringTokens(source, "original.s")
	if err != nil || len(tokens) != 3 {
		t.Fatalf("physical String query: %+v %v", tokens, err)
	}
	if tokens[0].Text != "\"header∕one.h\"" || tokens[0].RecordedValue != "\"header/one.h\"" ||
		tokens[0].Line != 3 || source[tokens[0].Start:tokens[0].End] != tokens[0].Text {
		t.Fatalf("physical/recorded operand identity: %+v", tokens[0])
	}
	again, err := InspectAssemblyCPPStringTokens(source, "original.s")
	if err != nil || !reflect.DeepEqual(tokens, again) {
		t.Fatalf("independent String query: %v", err)
	}
	tokens[0].Text = "forged"
	third, err := InspectAssemblyCPPStringTokens(source, "original.s")
	if err != nil || !reflect.DeepEqual(again, third) {
		t.Fatal("query results share caller-mutable state")
	}
}

func TestInspectAssemblyCPPStringTokensBoundsAndLexicalErrors(t *testing.T) {
	for _, source := range []string{
		strings.Repeat("\"x\"\n", 4097), "\"unterminated\n", strings.Repeat("x", (64<<20)+1),
	} {
		if tokens, err := InspectAssemblyCPPStringTokens(source, "source.s"); err == nil || tokens != nil {
			t.Fatal("unbounded or malformed String source produced a query")
		}
	}
	if tokens, err := InspectAssemblyCPPStringTokens("", ""); err == nil || tokens != nil {
		t.Fatal("unnamed original source produced a query")
	}
	if tokens, err := InspectAssemblyCPPStringTokens("MOVQ $1, AX\n", "source.s"); err != nil || tokens == nil || len(tokens) != 0 {
		t.Fatal("complete empty String set was not explicit")
	}
}
