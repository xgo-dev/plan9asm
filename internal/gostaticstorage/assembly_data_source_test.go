package gostaticstorage

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

var asmDataGrammarCases = []struct {
	name, value string
	width       int64
	kind        ASMDataValueKind
	bits        uint64
	text        string
}{
	{"byte-truncation", "-1", 1, ASMDataInteger, 255, ""},
	{"word-truncation", "0x12345", 2, ASMDataInteger, 0x2345, ""},
	{"uint64-wrap", "(~0)+2", 8, ASMDataInteger, 1, ""},
	{"binary-radix", "0b1010_0110", 1, ASMDataInteger, 0xa6, ""},
	{"octal-radix", "0o1234", 2, ASMDataInteger, 668, ""},
	{"go-precedence", "1|2^3+4*5&7", 8, ASMDataInteger, 4, ""},
	{"division-modulo", "29/4%3", 8, ASMDataInteger, 1, ""},
	{"left-shift", "1<<65", 8, ASMDataInteger, 0, ""},
	{"right-associative-shift", "64>>4>>1", 8, ASMDataInteger, 16, ""},
	{"char-truncation", "'世'", 1, ASMDataInteger, 0x16, ""},
	{"char-lex-normalization", "'·'", 1, ASMDataInteger, '.', ""},
	{"float32", "1.25", 4, ASMDataFloat, uint64(math.Float32bits(1.25)), ""},
	{"float64", "-(3.5)", 8, ASMDataFloat, math.Float64bits(-3.5), ""},
	{"negative-zero", "-0.0", 8, ASMDataFloat, uint64(1) << 63, ""},
	{"hex-float", "0x1.8p+1", 4, ASMDataFloat, uint64(math.Float32bits(3)), ""},
	{"float32-overflow", "1e40", 4, ASMDataFloat, uint64(0x7f800000), ""},
	{"float64-subnormal", "5e-324", 8, ASMDataFloat, 1, ""},
	// Official asm parses float64 first. Direct Go constant conversion to
	// float32 would instead round this decimal to the next float32 value.
	{"float32-rounding", "1.0000000596046448", 4, ASMDataFloat, uint64(math.Float32bits(1)), ""},
	{"string-padding", `"A\x00B"`, 8, ASMDataString, 0, "A\x00B"},
	{"arbitrary-string-width", `"abcde"`, 5, ASMDataString, 0, "abcde"},
	{"string-utf8", `"世"`, 4, ASMDataString, 0, "世"},
	{"string-lex-normalization", `"·∕"`, 4, ASMDataString, 0, "./"},
	{"zero-string", `""`, 0, ASMDataString, 0, ""},
}

func TestASMDataTypedGrammar(t *testing.T) {
	for _, test := range asmDataGrammarCases {
		t.Run(test.name, func(t *testing.T) {
			source := fmt.Sprintf("DATA value<>+0(SB)/%d,$%s\nGLOBL value<>(SB),8,$16\n", test.width, test.value)
			states, err := parseASMDataSource([]byte(source), "example.invalid/fixture", "linux/amd64")
			if err != nil || len(states) != 1 || len(states[0].layout.Fragments) != 1 {
				t.Fatal("complete typed fragment differs", err)
			}
			fragment := states[0].layout.Fragments[0]
			if fragment.Kind != test.kind || fragment.Bits != test.bits || string(fragment.String) != test.text {
				t.Fatal("typed source value differs", fragment)
			}
		})
	}
}

func TestASMDataSourceGuards(t *testing.T) {
	for name, source := range map[string]string{
		"width-expression":       "DATA a(SB)/(1+1),$3\nGLOBL a(SB),$8",
		"width-hex":              "DATA a(SB)/0x4,$3\nGLOBL a(SB),$8",
		"width-int3":             "DATA a(SB)/3,$3\nGLOBL a(SB),$8",
		"width-float1":           "DATA a(SB)/1,$3.0\nGLOBL a(SB),$8",
		"width-address4-amd64":   "DATA a(SB)/4,$b(SB)\nGLOBL a(SB),$8",
		"non-immediate":          "DATA a(SB)/1,3\nGLOBL a(SB),$8",
		"oversized-string":       "DATA a(SB)/1,$\"ab\"\nGLOBL a(SB),$8",
		"float-arithmetic":       "DATA a(SB)/8,$1.0+2.0\nGLOBL a(SB),$8",
		"integer-float":          "DATA a(SB)/8,$1+2.0\nGLOBL a(SB),$8",
		"integer-overflow":       "DATA a(SB)/8,$18446744073709551616\nGLOBL a(SB),$8",
		"float-overflow":         "DATA a(SB)/8,$1e999\nGLOBL a(SB),$8",
		"zero-divisor":           "DATA a(SB)/8,$1/0\nGLOBL a(SB),$8",
		"high-bit-divisor":       "DATA a(SB)/8,$(~0)/2\nGLOBL a(SB),$8",
		"high-bit-modulo":        "DATA a(SB)/8,$(~0)%2\nGLOBL a(SB),$8",
		"high-bit-right-shift":   "DATA a(SB)/8,$(~0)>>1\nGLOBL a(SB),$8",
		"negative-left-shift":    "DATA a(SB)/8,$1<<-1\nGLOBL a(SB),$8",
		"negative-right-shift":   "DATA a(SB)/8,$1>>-1\nGLOBL a(SB),$8",
		"left-shift-tail":        "DATA a(SB)/8,$1<<2*3\nGLOBL a(SB),$8",
		"overlap":                "DATA a(SB)/4,$1\nDATA a+3(SB)/1,$2\nGLOBL a(SB),$8",
		"backwards":              "DATA a+4(SB)/1,$1\nDATA a+2(SB)/1,$2\nGLOBL a(SB),$8",
		"negative-offset":        "DATA a-1(SB)/1,$1\nGLOBL a(SB),$8",
		"global-offset":          "GLOBL a+1(SB),$8",
		"global-non-immediate":   "GLOBL a(SB),8",
		"global-duplicate":       "GLOBL a(SB),$8\nGLOBL a(SB),$8",
		"missing-global":         "DATA a(SB)/1,$1",
		"unknown-ABI":            "GLOBL a<ABI99>(SB),$8",
		"wrong-register":         "GLOBL a(FP),$8",
		"pointer-tail":           "DATA a(SB)/8,$b(SB)+1\nGLOBL a(SB),$8",
		"macro":                  "#define SIZE 8\nGLOBL a(SB),$SIZE",
		"generated-header":       "#include \"go_asm.h\"\nGLOBL a(SB),$8",
		"tls-initialization":     "GLOBL a(SB),256,$8\nDATA a(SB)/1,$1",
		"unclosed-expression":    "DATA a(SB)/8,$(1+2\nGLOBL a(SB),$8",
		"excessive-expr-depth":   "DATA a(SB)/8,$" + strings.Repeat("(", 300) + "1" + strings.Repeat(")", 300) + "\nGLOBL a(SB),$8",
		"aggregate-sparse-bound": "DATA a+16777215(SB)/1,$1\nGLOBL a(SB),$1\nDATA b+16777215(SB)/1,$1\nGLOBL b(SB),$1",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseASMDataSource([]byte(source), "example.invalid/fixture", "linux/amd64"); !errors.Is(err, ErrContext) {
				t.Fatal("invalid/unbounded/unclosed DATA grammar did not fail closed", err)
			}
		})
	}
}

func TestASMDataLayoutOrderAndFlags(t *testing.T) {
	for _, test := range []struct {
		name, source string
		size, length int64
		kind         uint8
		flags        uint64
	}{
		{"before-data", "GLOBL a<>(SB),16,$1\nDATA a<>+2(SB)/4,$7", 6, 6, 5, 16},
		{"after-data", "DATA a<>+2(SB)/4,$7\nGLOBL a<>(SB),8,$1", 1, 6, 3, 8},
		{"declared-tail", "DATA a<>(SB)/1,$7\nGLOBL a<>(SB),8,$24", 24, 1, 3, 8},
		{"noptr-data", "DATA a<>(SB)/1,$7\nGLOBL a<>(SB),16,$1", 1, 1, 5, 16},
		{"flag-priority", "DATA a<>(SB)/1,$7\nGLOBL a<>(SB),8|16|256,$1", 1, 1, 3, 280},
		{"ignored-other-flags", "DATA a<>(SB)/1,$7\nGLOBL a<>(SB),1|4|32|64|512|1024|2048|4096,$1", 1, 1, 7, 7781},
	} {
		t.Run(test.name, func(t *testing.T) {
			states, err := parseASMDataSource([]byte(test.source), "example.invalid/fixture", "linux/amd64")
			if err != nil || len(states) != 1 || states[0].actualSize != test.size || int64(len(states[0].data)) != test.length ||
				states[0].kind != test.kind || states[0].layout.Flags != test.flags {
				t.Fatal("GLOBL size/P length/source flag order differs", states, err)
			}
		})
	}
}
