package plan9asm

import (
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestInspectAssemblyCPPSourcePhysicalDefinitionIdentity(t *testing.T) {
	source := "#define OBJECT (A)\n#define ZERO() x·h\n#define FUNCTION(A,B) A \\\n# include B \\\n\n#define SPACED (P)\n#define COMMENTED/*gap*/(P)\n"
	got, err := InspectAssemblyCPPSource(source, "header.h", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.File != "header.h" || got.ByteLength != len(source) || !got.FinalNewline || len(got.Records) != 5 {
		t.Fatalf("physical source inventory differs: %+v", got)
	}
	wantNames := []string{"OBJECT", "ZERO", "FUNCTION", "SPACED", "COMMENTED"}
	for index, record := range got.Records {
		macro := record.Definition
		if record.Kind != "directive" || macro == nil || macro.Name != wantNames[index] ||
			record.Text != source[record.Start:record.End] {
			t.Fatalf("definition %d lost physical identity: %+v", index, record)
		}
		function := index == 1 || index == 2
		if macro.Function != function || (macro.Parameters != nil) != function {
			t.Fatalf("definition %s lost object/function adjacency", macro.Name)
		}
	}
	if len(got.Records[1].Definition.Parameters) != 0 ||
		!reflect.DeepEqual(got.Records[2].Definition.Parameters, []string{"A", "B"}) {
		t.Fatal("zero-argument/function formals changed")
	}
	body := got.Records[1].Definition.Replacement
	if len(body) != 1 || body[0].Text != "x·h" || body[0].RecordedValue != "x.h" {
		t.Fatalf("raw and recorded token spellings collapsed: %+v", body)
	}
	if !strings.Contains(got.Records[2].Text, "# include B") {
		t.Fatal("directive-generating replacement disappeared")
	}
}

func TestInspectAssemblyCPPSourceCandidateOrderAndEOF(t *testing.T) {
	source := "F\nMOVQ $1, AX\n#define F() RET\nF()\nF /*not invoked*/\nRET"
	got, err := InspectAssemblyCPPSource(source, "original.s", []string{"F"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 4 || got.FinalNewline || got.EOF.Kind != "eof" || got.EOF.Start != len(source) {
		t.Fatalf("candidate/EOF inventory changed: %+v", got)
	}
	for index, line := range []int{1, 3, 4, 5} {
		if got.Records[index].Line != line || index != 0 && got.Records[index].Start <= got.Records[index-1].End-1 {
			t.Fatal("physical invocation/definition order changed")
		}
	}
	if got.Records[0].Kind != "candidate" || got.Records[0].Text != "F\n" ||
		got.Records[3].Text != "F /*not invoked*/\n" {
		t.Fatal("a potential invocation became an asserted active function call")
	}
}

func TestInspectAssemblyCPPSourceBuildCommentsAndTokenBoundaries(t *testing.T) {
	source := "//go:build amd64\n\nRET; //go:build ignored\n/ * A * /\n/ / B\nSHLQ $1<<2, AX\n"
	got, err := InspectAssemblyCPPSource(source, "source.s", []string{"A", "B", "SHLQ"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 5 || got.Records[0].Tokens[0].Kind != "build_comment" ||
		got.Records[1].Tokens[2].Kind != "build_comment" {
		t.Fatalf("build-comment source role disappeared: %+v", got)
	}
	if got.Records[2].Tokens[0].Text != "/" || got.Records[2].Tokens[1].Text != "*" ||
		got.Records[3].Tokens[0].Text != "/" || got.Records[3].Tokens[1].Text != "/" {
		t.Fatal("separate comment-seam tokens were re-lexed")
	}
	shift := got.Records[4].Tokens[3]
	if shift.Text != "<<" || shift.End-shift.Start != 2 {
		t.Fatalf("combined Go tokenizer operator changed: %+v", shift)
	}
}

func TestInspectAssemblyCPPSourceRawInactiveAndHeaderEOF(t *testing.T) {
	for _, source := range []string{
		"#ifdef NEVER\n#define MISSING() \\\n# include \"missing.h\" \\\n\nMISSING()\n#endif\n",
		"#define EMPTY", "#ifdef BORROWED", "#include \"literal.h\"",
		"#line 27 \"logical.h\"\n", "#unknown anything\n",
	} {
		t.Run(source, func(t *testing.T) {
			got, err := InspectAssemblyCPPSource(source, "raw.h", []string{"MISSING"})
			if err != nil || len(got.Records) == 0 {
				t.Fatalf("raw inventory became execution/acceptance: %v", err)
			}
			for _, record := range got.Records {
				if record.Text != source[record.Start:record.End] {
					t.Fatal("physical header source was completed or rewritten")
				}
			}
		})
	}
}

func TestInspectAssemblyCPPSourceBoundsAndIndependentQueries(t *testing.T) {
	source := "#define F(X) X\nMOVQ $123456789, AX\nF(17)\n"
	first, err := InspectAssemblyCPPSource(source, "source.s", []string{"F"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectAssemblyCPPSource(source, "source.s", nil)
	if err != nil || len(first.Records) != 2 || len(second.Records) != 1 {
		t.Fatalf("query name sets leaked or omitted calls: %v", err)
	}
	first.Records[0].Definition.Parameters[0] = "changed"
	first.Records[0].Tokens[0].Text = "changed"
	again, err := InspectAssemblyCPPSource(source, "source.s", nil)
	if err != nil || !reflect.DeepEqual(again, second) {
		t.Fatal("returned inventory aliases a subsequent query")
	}
	for _, names := range [][]string{{"F", "F"}, {""}, {"not-a-name"}} {
		if _, err := InspectAssemblyCPPSource(source, "source.s", names); err == nil {
			t.Fatal("invalid or duplicate query names accepted")
		}
	}
	if _, err := InspectAssemblyCPPSource("#define X \"unterminated\n", "source.s", nil); err == nil {
		t.Fatal("lexical error was hidden by query-only inventory")
	}
}

func TestInspectAssemblyCPPSourcePhysicalOffsetsAndConcurrentQueries(t *testing.T) {
	source := "\ufeff  #define F() x·h\r\n  F()\r\n//go:build amd64"
	want, err := InspectAssemblyCPPSource(source, "source.s", []string{"F"})
	if err != nil || len(want.Records) != 3 || want.Records[0].Start != 5 ||
		want.Records[0].Definition.Replacement[0].RecordedValue != "x.h" {
		t.Fatalf("BOM/CRLF/Unicode physical identity changed: %+v %v", want, err)
	}
	for _, record := range want.Records {
		if record.Text != source[record.Start:record.End] {
			t.Fatal("record byte offsets changed under Unicode/CRLF")
		}
		for _, token := range record.Tokens {
			if token.Kind == "eof" {
				continue
			}
			if token.Text != source[token.Start:token.End] {
				t.Fatalf("token byte offsets changed: %+v", token)
			}
		}
	}
	var work sync.WaitGroup
	for index := 0; index < 16; index++ {
		work.Add(1)
		go func() {
			defer work.Done()
			got, err := InspectAssemblyCPPSource(source, "source.s", []string{"F"})
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("independent query changed under concurrency: %v", err)
			}
		}()
	}
	work.Wait()
}
