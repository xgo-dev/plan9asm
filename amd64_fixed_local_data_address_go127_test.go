//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixedLocalAddressData = "DATA literal<>+0(SB)/8,$0x0102030405060708\n" +
	"DATA literal<>+8(SB)/8,$0x1112131415161718\n" +
	"DATA literal<>+16(SB)/8,$0x2122232425262728\n" +
	"DATA literal<>+24(SB)/8,$0x3132333435363738\nGLOBL literal<>(SB),8,$32\n"

func fixedLocalDataAddressFunction(name, body string) string {
	return fmt.Sprintf("TEXT ·%s(SB),4,$32-16\nMOVQ a+0(FP),CX\nMOVQ $0,DX\n%s\nMOVQ DX,ret+8(FP)\nRET\n", name, body)
}

func fixedLocalDataAddressKernels() (string, string, int) {
	var assembly, declarations strings.Builder
	assembly.WriteString(fixedLocalAddressData)
	count := 0
	// The register inventory is independent of the translator's bank helper.
	// SP is the private frame, not an ordinary destination for a DATA address.
	for _, register := range strings.Fields("AX BX CX DX DI SI BP R8 R9 R10 R11 R12 R13 R14 R15") {
		for _, address := range []string{"MOVQ $literal<>(SB),", "LEAQ literal<>(SB),"} {
			name := fmt.Sprintf("Value%d", count)
			body := fmt.Sprintf(`%s%s
MOVQ %s,8(SP)
MOVQ $0,%s
MOVQ 8(SP),%s
ADDQ $16,%s
SUBQ $8,%s
LEAQ 8(%s),%s
INCQ %s
DECQ %s
MOVOU (%s),X0
PADDQ X0,X0
MOVQ X0,DX`, address, register, register, register, register,
				register, register, register, register, register, register, register)
			assembly.WriteString(fixedLocalDataAddressFunction(name, body))
			fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
			count++
		}
	}
	return assembly.String(), declarations.String(), count
}

func TestGoAMD64FixedLocalReadonlyDataAddressObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	assembly, declarations, count := fixedLocalDataAddressKernels()
	if count != 30 {
		t.Fatal("complete GP bank/address grammar denominator changed", count)
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("bounded readonly DATA addresses must compose with the complete private frame", err)
					}
					if !strings.Contains(ir, "internal constant [32 x i8]") {
						t.Fatal("original private readonly DATA definition missing")
					}
					compileLLVMToObject(t, llc, target.triple, "data-address.ll", "data-address.o", ir)
					compileLLVMToObject(t, llc, target.triple, "data-address-opt.ll", "data-address-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
	t.Log("30 original-Go kernels: two address forms, full non-SP GP bank, complete spills and constant affine offsets; three APIs at O0/O2")
}

func TestGoAMD64FixedLocalReadonlyDataAddressGuards(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	const acquire = "LEAQ literal<>(SB),SI\n"
	// These complete machine addresses need their original storage, but not a
	// universal bound for every possible invocation. This is translation only.
	dynamic := map[string]bool{
		"unknown affine offset":  true,
		"unknown index":          true,
		"joined offset past end": true,
	}
	for _, row := range []struct{ name, body string }{
		{"past end", acquire + "MOVQ 25(SI),DX"},
		{"negative", acquire + "MOVQ -1(SI),DX"},
		{"affine past end", acquire + "ADDQ $25,SI\nMOVQ (SI),DX"},
		{"affine negative", acquire + "SUBQ $1,SI\nMOVQ (SI),DX"},
		{"initial displacement", "LEAQ literal<>+25(SB),SI\nMOVQ (SI),DX"},
		{"unaligned", acquire + "INCQ SI\nMOVO (SI),X0"},
		{"unknown affine offset", acquire + "ADDQ CX,SI\nMOVQ (SI),DX"},
		{"unknown index", acquire + "MOVQ (SI)(CX*1),DX"},
		{"offset overflow", acquire + "MOVQ $9223372036854775807,R8\nADDQ R8,SI\nINCQ SI\nMOVQ (SI),DX"},
		{"joined offset past end", acquire + "CMPQ CX,$0\nJEQ joined\nADDQ $32,SI\njoined:\nMOVQ (SI),DX"},
		{"joined readonly write", acquire + "CMPQ CX,$0\nJEQ joined\nADDQ $8,SI\njoined:\nMOVQ DX,(SI)"},
		{"partial spill", acquire + "MOVL SI,8(SP)\nMOVQ 8(SP),SI\nMOVQ (SI),DX"},
		{"write", acquire + "MOVQ DX,(SI)"},
		{"write after spill", acquire + "MOVQ SI,8(SP)\nMOVQ 8(SP),BP\nMOVQ DX,(BP)"},
		{"numeric result", acquire + "MOVQ SI,DX"},
		{"numeric pointer", "MOVQ $1234,SI\nMOVQ (SI),DX"},
		{"unowned symbol", "MOVQ $foreign(SB),SI\nMOVQ (SI),DX"},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalAddressData + fixedLocalDataAddressFunction("Value", row.body)
			pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
				"func Value(a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
			// Capture must succeed first: a producer/tool failure does not
			// establish that the translator rejects an unsafe memory role.
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			_, err := source.BindFixedLocal(ctx, pkg, file, options)
			if dynamic[row.name] {
				if err != nil {
					t.Fatal("dynamic native address incorrectly required a caller bounds proof", err)
				}
				return
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("readonly address acquired unknown bytes, alignment, mutable or numerical permission", err)
			}
		})
	}
	t.Run("different bounded offsets at join", func(t *testing.T) {
		assembly := fixedLocalAddressData + fixedLocalDataAddressFunction("Value",
			acquire+"CMPQ CX,$0\nJEQ joined\nADDQ $8,SI\njoined:\nMOVQ (SI),DX")
		pkg, request, _, options := fixedLocalTransportFixture(t, assembly,
			"func Value(a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc required")
		}
		fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
			func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal("both readonly alternatives must retain their bounded read", err)
				}
				compileLLVMToObject(t, llc, options.TargetTriple, "joined-data.ll", "joined-data.o", ir)
				compileLLVMToObject(t, llc, options.TargetTriple, "joined-data-opt.ll", "joined-data-opt.o", x86MulDivRoundOptimize(t, ir))
			})
	})
	t.Run("pointer result cannot escape its bounds", func(t *testing.T) {
		assembly := fixedLocalAddressData + "TEXT ·Value(SB),4,$32-8\n" + acquire + "MOVQ SI,ret+0(FP)\nRET\n"
		pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
			"func Value() *uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
		source := requireGoAMD64FrameCapture(t, pkg, request)
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("private literal escaped as an unbounded externally mutable pointer", err)
		}
	})
}

func TestGoAMD64FixedLocalReadonlyDataAddressBinding(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	assembly := fixedLocalAddressData + fixedLocalDataAddressFunction("Value",
		"MOVQ SP,R12\nADDQ $16,R12\nANDQ $-16,R12\n"+
			"MOVQ $literal<>+8(SB),BP\nMOVQ BP,(R12)\nMOVQ (R12),R14\nMOVQ 16(R14),DX")
	pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
		"func Value(a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
	fixedLocalDataAPIs(t, pkg, file, assembly, options, fixedLocalRequireContext)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal("actual original DATA address failed binding", err)
	}
	for _, mutation := range []string{"resolver", "JSON", "byte", "extent"} {
		t.Run(mutation, func(t *testing.T) {
			changed, input := bound, assembly
			switch mutation {
			case "resolver":
				changed.ResolveSym = func(symbol string) string {
					if symbol == "·literal<>" {
						return "foreign.literal<>"
					}
					return options.ResolveSym(symbol)
				}
			case "JSON":
				changed.Sigs, err = cloneFixedLocalSigs(bound.Sigs)
				if err != nil {
					t.Fatal(err)
				}
			case "byte":
				input = strings.Replace(input, "0x3132333435363738", "0x3132333435363739", 1)
			case "extent":
				input = strings.Replace(input, ",8,$32", ",8,$64", 1)
			}
			parsed, err := Parse(ArchAMD64, input)
			if err != nil {
				t.Fatal(err)
			}
			fixedLocalDataAPIs(t, pkg, parsed, input, changed, fixedLocalRequireContext)
		})
	}
	path := filepath.Join(request.Directory, request.AssemblyFile)
	changed := strings.Replace(assembly, "0x3132333435363738", "0x3132333435363739", 1)
	if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	fixedLocalDataAPIs(t, pkg, file, assembly, bound, fixedLocalRequireContext)
	if err := os.WriteFile(path, []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	fixedLocalDataAPIs(t, pkg, file, assembly, bound, fixedLocalRequireContext)
}

func TestGoAMD64FixedLocalReadonlyDataAddressLayoutFlags(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const acquire = "LEAQ literal<>(SB),SI\n"
	const other = "DATA other<>+0(SB)/8,$77\nGLOBL other<>(SB),8,$32\n"
	for _, row := range []struct {
		name, body string
		emit       bool
	}{
		{"ADD carry", acquire + "ADDQ $8,SI\nSETCS DL", true},
		{"SUB carry", acquire + "ADDQ $8,SI\nSUBQ $8,SI\nSETCS DL", true},
		{"INC zero", acquire + "INCQ SI\nSETEQ DL", true},
		{"DEC zero", acquire + "ADDQ $8,SI\nDECQ SI\nSETEQ DL", true},
		{"cross literal comparison", acquire + "LEAQ other<>(SB),DI\nCMPQ SI,DI\nSETCS DL", true},
		{"literal numerical comparison", acquire + "CMPQ SI,$1234\nSETCS DL", true},
		{"spilled literal comparison", acquire + "MOVQ SI,8(SP)\nCMPQ 8(SP),$0\nSETEQ DL", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalAddressData + other + fixedLocalDataAddressFunction("Value", row.body)
			pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
				"func Value(a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
			if row.emit {
				// Preserve the actual machine operation. Compiling independent
				// globals does not promise Go's final linked addresses, relative
				// ordering or cross-object adjacency; this is object evidence.
				fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
					func(t *testing.T, ir string, err error) {
						if err != nil {
							t.Fatal("complete native address FLAGS source rejected", err)
						}
						x86CompactExpandRequireAllDefinitions(t, ir, []string{pkg.Path + ".Value"})
						compileLLVMToObject(t, llc, options.TargetTriple, "address-flags.ll", "address-flags.o", ir)
						compileLLVMToObject(t, llc, options.TargetTriple, "address-flags-opt.ll", "address-flags-opt.o", x86MulDivRoundOptimize(t, ir))
					})
				return
			}
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unsupported literal/immediate comparator acquired an address role", err)
			}
		})
	}
	for _, row := range []struct{ name, body string }{
		{"LEA preserves flags", "CMPQ CX,$1\n" + acquire + "LEAQ 8(SI),SI\nSETEQ DL"},
		{"INC preserves carry", "CMPQ CX,$1\n" + acquire + "INCQ SI\nSETCS DL"},
		{"DATA bytes are numeric", acquire + "CMPQ (SI),$0\nSETNE DL"},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalAddressData + fixedLocalDataAddressFunction("Value", row.body)
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly,
				"func Value(a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil || ir == "" {
						t.Fatal("unaffected numerical FLAGS were lost across a DATA address operation", err)
					}
				})
		})
	}
}
