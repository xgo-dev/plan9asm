package plan9asm

import (
	"strings"
	"testing"
)

func TestPreprocessCommentLexicalBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, source, want string }{
		{"line-before-block", "//*** assembly header\nTEXT foo(SB),$0-0\nRET\n", "TEXT foo(SB),$0-0\nRET"},
		{"line-hides-open-block", "// /* not a block\nTEXT foo(SB),$0-0\nRET\n", "TEXT foo(SB),$0-0\nRET"},
		{"block-token-boundary", "TEXT/* header */foo(SB),$0-0\nRET\n", "TEXT foo(SB),$0-0\nRET"},
		{"string", "DATA blob(SB)/8, $\"/* // */\" // tail\n", "DATA blob(SB)/8, $\"/* // */\""},
		{"escaped-string", "DATA blob(SB)/8, $\"\\\"// /*\"\n", "DATA blob(SB)/8, $\"\\\"// /*\""},
		{"character", "BYTE $'/' /* block */\nBYTE $'\\'' // line\n", "BYTE $'/'\nBYTE $'\\''"},
		{"multiline-block", "/* // ignored\nstill ignored */ TEXT foo(SB),$0-0\nRET\n", "TEXT foo(SB),$0-0\nRET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := preprocess(tc.source)
			if err != nil || strings.TrimSpace(got) != tc.want {
				t.Fatalf("preprocess = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for _, arch := range []Arch{ArchAMD64, ArchARM, ArchARM64, ArchWASM} {
		if _, err := Parse(arch, "//*** reported simd header\nTEXT foo(SB),$0-0\nRET\n"); err != nil {
			t.Errorf("%s line-comment header: %v", arch, err)
		}
	}
}

func TestPreprocessExpandsFunctionLikeMacrosWithSpaceBeforeParen(t *testing.T) {
	src := `
#define ST(dst) MOVQ AX, dst
#define ROUNDS(a,b,c,d) ADDQ a, b; ADDQ c, d
TEXT foo(SB),NOSPLIT,$0-0
	ST (x+0(FP))
	ROUNDS (AX, BX, CX, DX)
	RET
`
	pp, err := preprocess(src)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pp, "ST (") {
		t.Fatalf("macro call with space was not expanded: %q", pp)
	}
	if strings.Contains(pp, "ROUNDS (") {
		t.Fatalf("inline macro call with space was not expanded: %q", pp)
	}
	if !strings.Contains(pp, "MOVQ AX, x+0(FP)") {
		t.Fatalf("expected ST expansion, got: %q", pp)
	}
	if !strings.Contains(pp, "ADDQ AX, BX") || !strings.Contains(pp, "ADDQ CX, DX") {
		t.Fatalf("expected ROUNDS expansion, got: %q", pp)
	}
}

func TestPreprocessExpandsUnicodeFunctionMacroNamesAcceptedByGo(t *testing.T) {
	for _, source := range []string{`
#define NEON_TANH_PADÉ(src, dst) MOVD src, dst
TEXT unicodeMacro(SB),$0-0
	NEON_TANH_PADÉ(R5, R6)
	RET
	`, `
#define REGÉ R5
#define MOVEÉ(srcé, dst) MOVD srcé, dst
TEXT unicodeMacro(SB),$0-0
	MOVEÉ(REGÉ, R6)
	RET
	`} {
		requireARM64GoAssemblerResult(t, source, true)
		got, err := preprocess(source)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(got, "NEON_TANH_PADÉ") || strings.Contains(got, "MOVEÉ") ||
			strings.Contains(got, "REGÉ") || !strings.Contains(got, "MOVD R5, R6") {
			t.Fatalf("Unicode macro was not expanded: %q", got)
		}
	}
}

func TestPreprocessDoesNotExpandFunctionMacroInsideMiddleDotSymbol(t *testing.T) {
	const src = `
#define g(r) 0(r)(TLS*1)
TEXT ·g(SB),NOSPLIT,$0-8
	MOVQ g(CX), BX
	RET
`
	pp, err := preprocessWithDefines(src, []string{"GOARCH_amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pp, "TEXT ·g(SB),NOSPLIT,$0-8") {
		t.Fatalf("function-like macro rewrote a middle-dot function symbol:\n%s", pp)
	}
	if !strings.Contains(pp, "MOVQ 0(CX)(TLS*1), BX") {
		t.Fatalf("function-like macro call in an operand was not expanded:\n%s", pp)
	}
	if _, err := Parse(ArchAMD64, src); err != nil {
		t.Fatalf("Parse rejected a macro whose name matches a middle-dot function symbol: %v", err)
	}
}

func TestPreprocessKeepsMultilineDefineAcrossBlockCommentsAndBlankContinuations(t *testing.T) {
	// C preprocessing splices backslash-newline pairs before removing comments.
	// Real assembly such as buildbarn/bb-storage relies on that ordering inside
	// large function-like macros.
	const src = `
#define ROUND(dst, src) \
	MOVQ src, dst \
	/* Explain the next operation. \
	 * The comment itself spans physical lines. \
	 */ \
	\
	ADDQ $1, dst
TEXT macro(SB),$0-0
	ROUND(AX, BX)
	RET
`
	pp, err := preprocess(src)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pp, "\\") {
		t.Fatalf("physical continuation escaped into preprocessed assembly:\n%s", pp)
	}
	for _, want := range []string{"MOVQ BX, AX", "ADDQ $1, AX"} {
		if !strings.Contains(pp, want) {
			t.Fatalf("multiline macro omitted %q:\n%s", want, pp)
		}
	}
	if _, err := Parse(ArchAMD64, src); err != nil {
		t.Fatalf("Parse rejected a Go-assembler-compatible multiline macro: %v\n%s", err, pp)
	}
}

func TestPreprocessKeepsMultilineDefineWhenContinuationPrecedesLineComment(t *testing.T) {
	// Several Go assembly packages, including IOTA, MinIO HighwayHash, and
	// go-ethereum, put a line comment after the continuation slash. The Go
	// assembler's preprocessor accepts this historical spelling.
	const src = `
#define ROUND(dst, src) \
	MOVQ src, dst; \ // copy the input
	\ // keep this comment-only continuation in the macro
	ADDQ $1, dst
TEXT macro(SB),$0-0
	ROUND(AX, BX)
	RET
`
	pp, err := preprocess(src)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pp, "\\") {
		t.Fatalf("commented continuation escaped into preprocessed assembly:\n%s", pp)
	}
	for _, want := range []string{"MOVQ BX, AX", "ADDQ $1, AX"} {
		if !strings.Contains(pp, want) {
			t.Fatalf("multiline macro omitted %q:\n%s", want, pp)
		}
	}
	if _, err := Parse(ArchAMD64, src); err != nil {
		t.Fatalf("Parse rejected a Go-assembler-compatible commented continuation: %v\n%s", err, pp)
	}
}

func TestPreprocessEvaluatesConditionalDirectivesExpandedFromMacro(t *testing.T) {
	const src = `
#define BREAK \
#ifdef GOOS_windows \
	BRK $0xf000 \
#else \
	BRK \
#endif \

TEXT breakpoint(SB),NOSPLIT,$0-0
	BREAK
	RET
`
	linux, err := preprocessWithDefines(src, []string{"GOOS_linux", "GOARCH_arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(linux, "#if") || strings.Contains(linux, "#else") || strings.Contains(linux, "#endif") {
		t.Fatalf("conditional directive escaped from Linux macro expansion:\n%s", linux)
	}
	if !strings.Contains(linux, "BRK\n") || strings.Contains(linux, "$0xf000") {
		t.Fatalf("Linux macro selected the wrong branch:\n%s", linux)
	}

	windows, err := preprocessWithDefines(src, []string{"GOOS_windows", "GOARCH_arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(windows, "#if") || strings.Contains(windows, "#else") || strings.Contains(windows, "#endif") {
		t.Fatalf("conditional directive escaped from Windows macro expansion:\n%s", windows)
	}
	if !strings.Contains(windows, "BRK $0xf000") {
		t.Fatalf("Windows macro selected the wrong branch:\n%s", windows)
	}
}

func TestPreprocessExpandsMacrosAtInvocationBeforeRedefinition(t *testing.T) {
	const source = `
#define V0 X0
#define BODY(src) VPCMPGTD V0, src, V0
TEXT early(SB),$0-0
	BODY(X1)
	RET
#undef V0
#define V0 Z0
TEXT late(SB),$0-0
	VPCMPGTD V0, Z1, K1
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	got, err := preprocess(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"VPCMPGTD X0, X1, X0",
		"VPCMPGTD Z0, Z1, K1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("macro redefinition changed an earlier instruction; missing %q:\n%s", want, got)
		}
	}
	if _, err := Parse(ArchAMD64, source); err != nil {
		t.Fatalf("Parse rejected the Go-accepted assembly: %v", err)
	}
}

func TestPreprocessExpandedConditionUsesInvocationDefinitions(t *testing.T) {
	const source = `
#define FEATURE
#define CONDITIONAL \
#ifdef FEATURE \
	MOVQ $1, AX \
#else \
	MOVQ $2, AX \
#endif \

TEXT first(SB),$0-0
	CONDITIONAL
	RET
#undef FEATURE
TEXT second(SB),$0-0
	CONDITIONAL
	RET
`
	got, err := preprocess(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"TEXT first(SB),$0-0\nMOVQ $1, AX\nRET",
		"TEXT second(SB),$0-0\nMOVQ $2, AX\nRET",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expanded condition used the wrong definition epoch; missing %q:\n%s", want, got)
		}
	}
}

func TestGoAssemblerDefinesMatchToolchainFeatureRules(t *testing.T) {
	t.Setenv("GOAMD64", "v3")
	if got := strings.Join(GoAssemblerDefines("linux", "amd64"), ","); got != "GOOS_linux,GOARCH_amd64,GOAMD64_v3" {
		t.Fatalf("amd64 defines = %q", got)
	}
	t.Setenv("GOARM", "7,hardfloat")
	if got := strings.Join(GoAssemblerDefines("linux", "arm"), ","); got != "GOOS_linux,GOARCH_arm,GOARM_7,GOARM_6,GOARM_5" {
		t.Fatalf("arm defines = %q", got)
	}
	t.Setenv("GOARM64", "v8.0,lse")
	if got := strings.Join(GoAssemblerDefines("windows", "arm64"), ","); got != "GOOS_windows,GOARCH_arm64,GOARM64_LSE" {
		t.Fatalf("arm64 defines = %q", got)
	}
}
