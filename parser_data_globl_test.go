package plan9asm

import (
	"strings"
	"testing"
)

func TestParseDataOnlyFile(t *testing.T) {
	file, err := Parse(ArchARM64, `DATA ·value(SB)/8, $42
GLOBL ·value(SB),RODATA,$8
`)
	if err != nil {
		t.Fatalf("Parse(data-only) error = %v", err)
	}
	if len(file.Funcs) != 0 || len(file.Data) != 1 || len(file.Globl) != 1 {
		t.Fatalf("Parse(data-only) = funcs:%d data:%d globl:%d", len(file.Funcs), len(file.Data), len(file.Globl))
	}
	mod, err := TranslateModule(file, Options{
		Goarch: "arm64",
		ResolveSym: func(sym string) string {
			return "test." + strings.TrimPrefix(sym, "·")
		},
	})
	if err != nil {
		t.Fatalf("TranslateModule(data-only) error = %v", err)
	}
	defer mod.Dispose()
	if ir := mod.String(); !strings.Contains(ir, `@test.value = constant [8 x i8]`) || !strings.Contains(ir, `c"*\00`) {
		t.Fatalf("TranslateModule(data-only) missing initialized global:\n%s", ir)
	}
}

func TestParseDataAndGloblDirectives(t *testing.T) {
	file, err := Parse(ArchARM64, `TEXT ·Fn(SB),NOSPLIT,$0-0
	RET

DATA ·tab<>+8(SB)/PTRSIZE, $1
DATA ·str<>(SB)/8, $"hello"
DATA ·symptr<>(SB)/8, $runtime·main(SB)
GLOBL ·tab<>(SB), RODATA, $16
GLOBL ·symptr<>(SB), NOPTR, $(machTimebaseInfo__size)
`)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(file.Data), 3; got != want {
		t.Fatalf("len(Data) = %d, want %d", got, want)
	}
	if got, want := len(file.Globl), 2; got != want {
		t.Fatalf("len(Globl) = %d, want %d", got, want)
	}

	if ds := file.Data[0]; ds.Sym != "·tab<>" || ds.Off != 8 || ds.Width != 8 || ds.Value != 1 {
		t.Fatalf("unexpected first DATA: %#v", ds)
	}
	if ds := file.Data[1]; ds.Sym != "·str<>" || string(ds.Payload) != "hello" {
		t.Fatalf("unexpected string DATA payload: %#v", ds)
	}
	payload, err := dataStmtPayload(file.Data[1])
	if err != nil || string(payload[:5]) != "hello" || len(payload) != 8 || payload[5] != 0 {
		t.Fatalf("padded string DATA payload = (%v, %v)", payload, err)
	}
	if ds := file.Data[2]; ds.Sym != "·symptr<>" || ds.Value != 0 {
		t.Fatalf("unexpected symbol DATA placeholder: %#v", ds)
	}

	if gs := file.Globl[0]; gs.Sym != "·tab<>" || gs.Flags != "RODATA" || gs.Size != 16 {
		t.Fatalf("unexpected first GLOBL: %#v", gs)
	}
	if gs := file.Globl[1]; gs.Sym != "·symptr<>" || gs.Flags != "NOPTR" || gs.Size != 64 {
		t.Fatalf("unexpected macro-sized GLOBL: %#v", gs)
	}

	comma, err := parseDATAStmt(ArchARM64, `·comma(SB)/12, $"hello, world"`)
	if err != nil || string(comma.Payload) != "hello, world" {
		t.Fatalf("parse comma string DATA = (%#v, %v)", comma, err)
	}
	if _, err := parseDATAStmt(ArchARM64, `·short(SB)/4, $"hello"`); err == nil {
		t.Fatal("oversized string DATA unexpectedly parsed")
	}
}

func TestParseLegacyTwoOperandGloblDirective(t *testing.T) {
	file, err := Parse(ArchAMD64, `DATA ·REDMASK51(SB)/8, $0x0007FFFFFFFFFFFF
GLOBL ·REDMASK51(SB), $8
DATA ·ROUNDING(SB)/2, $0x137f
GLOBL ·ROUNDING(SB), $2
`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(file.Globl), 2; got != want {
		t.Fatalf("len(Globl) = %d, want %d", got, want)
	}
	for i, want := range []GloblStmt{
		{Sym: "·REDMASK51", Size: 8},
		{Sym: "·ROUNDING", Size: 2},
	} {
		if got := file.Globl[i]; got != want {
			t.Fatalf("Globl[%d] = %#v, want %#v", i, got, want)
		}
	}
	mod, err := TranslateModule(file, Options{
		Goarch: "amd64",
		ResolveSym: func(sym string) string {
			return "legacy." + strings.TrimPrefix(sym, "·")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mod.Dispose()
	for _, want := range []string{
		`@legacy.REDMASK51 = global [8 x i8]`,
		`@legacy.ROUNDING = global [2 x i8]`,
	} {
		if ir := mod.String(); !strings.Contains(ir, want) {
			t.Fatalf("legacy GLOBL translation missing %q:\n%s", want, ir)
		}
	}
}

func TestParseDataRejectsMalformedPayloads(t *testing.T) {
	for _, stmt := range []string{
		`·missing(SB)/8 $1`,
		`, $1`,
		`·empty(SB)/8,`,
		`·quote(SB)/8, $"unterminated`,
	} {
		if _, err := parseDATAStmt(ArchARM64, stmt); err == nil {
			t.Errorf("parseDATAStmt(%q) unexpectedly succeeded", stmt)
		}
	}
	if _, err := Parse(ArchARM64, "// no directives\n"); err == nil {
		t.Fatal("directive-free file unexpectedly parsed")
	}
}

func TestDataGlobalBounds(t *testing.T) {
	for _, data := range []DataStmt{
		{Sym: "·negative", Off: -1, Width: 1},
		{Sym: "·wide", Width: maxDataGlobalSize + 1},
		{Sym: "·overflow", Off: maxDataGlobalSize, Width: 1},
	} {
		if _, err := dataStmtEnd(data); err == nil {
			t.Errorf("dataStmtEnd(%#v) unexpectedly succeeded", data)
		}
	}
	if _, err := dataStmtPayload(DataStmt{Sym: "·wide", Width: maxDataGlobalSize + 1}); err == nil {
		t.Fatal("oversized DATA payload unexpectedly accepted")
	}
	if _, err := makeDataGlobal("negative", -1); err == nil {
		t.Fatal("negative global size unexpectedly accepted")
	}
	if _, err := makeDataGlobal("huge", maxDataGlobalSize+1); err == nil {
		t.Fatal("oversized global unexpectedly accepted")
	}
}
