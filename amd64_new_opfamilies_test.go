package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTranslateAMD64NOTB(t *testing.T) {
	src := `
TEXT notb(SB),NOSPLIT,$0-0
	MOVQ $0x1234, R11
	NOTB R11
	NOTB 3(AX)
	RET
`
	ir := x86UnboundVoidScalarFormatObject(t, src, "notb", "amd64", "x86_64-unknown-linux-gnu")
	if got := strings.Count(ir, "xor i8"); got != 2 {
		t.Fatalf("NOTB xor count = %d, want 2:\n%s", got, ir)
	}
	for _, want := range []string{"and i64", "or i64", "load volatile i8", "store volatile i8"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("NOTB output missing %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "not-byte-forms.ll", "not-byte-forms.o", ir)
}

func TestTranslateAMD64SHA1Family(t *testing.T) {
	src := `
TEXT sha1ops(SB),NOSPLIT,$0-0
	SHA1MSG1 X2, X1
	SHA1MSG2 X3, X1
	SHA1NEXTE X4, X1
	SHA1RNDS4 $3, X5, X1
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"sha1ops": {Name: "sha1ops", Ret: Void},
		},
		Goarch: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateAMD64AVX512CRCSubset(t *testing.T) {
	src := `
GLOBL table<>(SB), RODATA, $64
DATA table<>+0(SB)/8, $0

TEXT crcops(SB),NOSPLIT,$0-0
	VPXORQ Z10, Z10, Z10
	VMOVAPS X0, X10
	VMOVDQU64 (AX), Z1
	VPXORQ Z10, Z1, Z1
	VMOVDQU64 table<>+0(SB), Z0
	VPCLMULQDQ $0x11, Z0, Z1, Z5
	VPTERNLOGD $0x96, Z11, Z5, Z1
	VEXTRACTF32X4 $1, Z1, X2
	VZEROUPPER
	RET
`
	// This original format sequence does not supply AX, X0 or Z11.
	// Its object checks must not invent those public-entry inputs.
	ir := x86UnboundVoidScalarFormatObject(t, src, "crcops", "amd64", "x86_64-unknown-linux-gnu")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "crc-subset-forms.ll", "crc-subset-forms.o", ir)
}

const x86Go126FamiliesSource = `
GLOBL mat<>(SB), RODATA, $64
DATA mat<>+0(SB)/8, $0

TEXT go126ops(SB),NOSPLIT,$0-0
	MOVQ $0xff, AX
	KMOVQ AX, K1
	VPERMB Z4, Z0, Z0
	VGF2P8AFFINEQB $0, mat<>+0(SB), Z0, Z0
	VPERMI2B Z3, Z2, Z1
	VPERMI2B.Z Z3, Z2, K1, Z5
	VPERMB.Z Z4, Z6, K1, Z0
	VPOPCNTB Z1, Z3
	VPCMPUQ $4, Z1, Z15, K1
	VPCOMPRESSQ Z1, K1, Z2
	RET
`

var x86Go126FamiliesInputs = []string{"Z0", "Z1", "Z2", "Z3", "Z4", "Z5", "Z6", "Z15"}

func x86Go126FamiliesInitializedSource(omit string) string {
	var initialization strings.Builder
	for _, reg := range x86Go126FamiliesInputs {
		if reg != omit {
			fmt.Fprintf(&initialization, "VPXORD %s,%s,%s\n", reg, reg, reg)
		}
	}
	return strings.Replace(x86Go126FamiliesSource, "\tMOVQ $0xff, AX", initialization.String()+"\tMOVQ $0xff, AX", 1)
}

func TestTranslateAMD64AVX512Go126Families(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	source := x86Go126FamiliesInitializedSource("")
	// Supply Go's textflag constants without changing the original body or
	// relying on an ambient include search path in the cross-object helper.
	oracleSource := "#define NOSPLIT 4\n#define RODATA 8\n" + source
	goAssemblerOracleOutput(t, "amd64", oracleSource, "", true)
	for _, target := range dataRelocationTargets {
		if target.goarch != "amd64" {
			continue
		}
		t.Run(target.triple, func(t *testing.T) {
			dataRelocationGoObject(t, oracleSource, target.goos, target.goarch, true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func go126ops()", target.goarch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized whole instruction sequence rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, []string{"go126ops"})
					for _, optimized := range []bool{false, true} {
						objectIR := ir
						if optimized {
							objectIR = x86DwordProductIROptimize(t, ir)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR-O2=%t/backend%s", optimized, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, objectIR, level)
							})
						}
					}
				})
			}
		})
	}
}

func TestX86Go126FamiliesCannotBorrowUninitializedVectorInputs(t *testing.T) {
	sources := map[string]string{"original": x86Go126FamiliesSource}
	for _, reg := range x86Go126FamiliesInputs {
		sources["missing-"+reg] = x86Go126FamiliesInitializedSource(reg)
	}
	sources["missing-mask"] = strings.Replace(x86Go126FamiliesInitializedSource(""), "KMOVQ AX, K1", "NOP", 1)
	for name, source := range sources {
		t.Run(name, func(t *testing.T) {
			goAssemblerOracleOutput(t, "amd64", "#include \"textflag.h\"\n"+source, "", true)
			for _, target := range dataRelocationTargets {
				if target.goarch != "amd64" {
					continue
				}
				t.Run(target.triple, func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							if _, err := x86ScalarFPBitViewAPI(t, source, "func go126ops()", target.goarch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("unknown source acquired implementation-slot bytes", err)
							}
						})
					}
				})
			}
		})
	}
}
