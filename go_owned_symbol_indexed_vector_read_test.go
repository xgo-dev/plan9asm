package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func ownedSymbolIndexedVectorSource(t *testing.T, rows []ordinaryGlobalVectorCase) (string, string) {
	t.Helper()
	source, declarations := ownedIndexedVectorSource(t, rows, "386")
	const materialize = "MOVL $numericBytes<>(SB),AX\n"
	const indirect = "(AX)(CX*8)"
	if strings.Count(source, materialize) != len(rows) || strings.Count(source, indirect) != len(rows) {
		t.Fatal("complete source fixture lost its exact address/read pairs")
	}
	// Mode32 directly encodes a static symbol plus an index. There is no GP
	// address materialization to borrow, and CX keeps its actual bounded ADDL.
	source = strings.ReplaceAll(source, materialize, "")
	source = strings.ReplaceAll(source, indirect, "numericBytes<>(SB)(CX*8)")
	return source, declarations
}

func TestGoModuleOwnedReadonlySymbolIndexedVectorSourceFacts(t *testing.T) {
	for _, opcode := range []string{"PAND", "PSHUFB"} {
		t.Run(opcode, func(t *testing.T) {
			source, _ := ownedSymbolIndexedVectorSource(t,
				[]ordinaryGlobalVectorCase{{opcode + " ·words+16(SB),X2", "X", 2}})
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			resolve := testResolveSym(ordinaryGlobalReadPackage)
			values := x86LoweredStaticAddressValues(file, resolve, nil, "386")
			if values == nil || values.numericLiterals["numericBytes<>"] != 256 {
				t.Fatal("complete private RODATA directory missing", values)
			}
			sig := FuncSig{Name: resolve(file.Funcs[0].Sym), Args: []LLVMType{I32}, Ret: I32,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}},
				}}
			facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], sig, "386", values.numericLiterals)
			if err != nil || len(facts) != 1 || facts[0].Address || facts[0].Width != 16 ||
				facts[0].Minimum != 0 || facts[0].Maximum != 240 {
				t.Fatal("direct symbol/index lost its complete pure CFG range proof", facts, err)
			}
			c := &amd64Ctx{fpStaticAddressValues: values}
			reads := c.ownedIndexedVectorReads(file.Funcs[0], sig, "386")
			if len(reads) != 1 || !reflect.DeepEqual(reads[facts[0].Instruction], facts[0]) {
				t.Fatal("proved direct symbol/index read was not handed off unchanged", facts, reads)
			}
		})
	}
}

func TestGoModuleOwnedReadonlySymbolIndexedVectorCompleteFamilies(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows := ownedIndexedVectorCases(t, "386") // All 116 logical plus four shuffle forms.
	for _, target := range []string{"i386-unknown-linux-gnu", "i386-pc-windows-gnu", "i686-pc-windows-msvc"} {
		t.Run(target, func(t *testing.T) {
			for start := 0; start < len(rows); start += 32 {
				end := start + 32
				if end > len(rows) {
					end = len(rows)
				}
				t.Run(fmt.Sprintf("batch-%02d", start/32), func(t *testing.T) {
					source, declarations := ownedSymbolIndexedVectorSource(t, rows[start:end])
					goAssemblerOracleOutput(t, "386", source, "", true)
					for _, api := range []string{"public", "owned-context"} {
						t.Run(api, func(t *testing.T) {
							pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
							ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), "386", target, api)
							if err != nil || ir == "" {
								t.Fatal("bounded direct-symbol table read needs no SDK or GP-address capture", err)
							}
							compileLLVMToObject(t, llc, target, "owned-symbol-indexed.ll", "owned-symbol-indexed.o", ir)
						})
					}
				})
			}
			t.Logf("complete mode32 direct-symbol union: %d logical/shuffle memory forms", len(rows))
		})
	}
}

func TestGoModuleOwnedReadonlySymbolIndexedVectorRetainsBounds(t *testing.T) {
	base, declarations := ownedSymbolIndexedVectorSource(t,
		[]ordinaryGlobalVectorCase{{"PAND ·words+16(SB),X2", "X", 2}})
	const read = "PAND numericBytes<>(SB)(CX*8),X2"
	for _, mutation := range []struct{ name, before, after string }{
		{"no-bound", "CMPL CX,$16\nJAE outside0\n", ""},
		{"wrong-edge", "JAE outside0", "JB outside0"},
		{"stale-flags", "JAE outside0", "ADDL $1,CX\nJAE outside0"},
		{"past-extent", "CMPL CX,$16", "CMPL CX,$17"},
		{"unknown-index", "MOVL n+0(FP),CX", "NOP"},
		{"partial-index", "ADDL CX,CX", "MOVB $255,CL\nADDL CX,CX"},
		{"overflowing-index", "ADDL CX,CX", "ADDL $0x7ffffff0,CX\nADDL CX,CX"},
		{"literal-index", "ADDL CX,CX", "MOVL $numericBytes<>(SB),CX"},
		{"displaced-outside", read, "PAND numericBytes<>+16(SB)(CX*8),X2"},
		{"mutable-table", "GLOBL numericBytes<>(SB),8,$256", "GLOBL numericBytes<>(SB),0,$256"},
		{"relocation", "DATA numericBytes<>+0(SB)/8,$0x719283a4b5c6d7e8", "DATA numericBytes<>+0(SB)/8,$external(SB)"},
		{"write", read, "MOVOU X2,numericBytes<>(SB)(CX*8)\n" + read},
		{"raw", "ADDL CX,CX", "BYTE $0x90\nADDL CX,CX"},
		{"unowned-symbol", read, "PAND foreignBytes<>(SB)(CX*8),X2"},
		{"unknown-vector", "PXOR X2,X2\n", ""},
	} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(mutation.name+"/"+api, func(t *testing.T) {
				if strings.Count(base, mutation.before) != 1 {
					t.Fatal("negative control did not select one actual source boundary", mutation.name)
				}
				source := strings.Replace(base, mutation.before, mutation.after, 1)
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
				ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), "386", "i386-pc-windows-gnu", api)
				if err == nil || ir != "" {
					t.Fatal("direct-symbol table read gained unbounded, mutable or uninitialized authority", err)
				}
			})
		}
	}
}
