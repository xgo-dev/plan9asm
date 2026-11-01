package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func ownedIndexedVectorCases(t *testing.T, arch string) []ordinaryGlobalVectorCase {
	t.Helper()
	rows := ordinaryGlobalLogicalCases(t, arch)
	// Reuse the independently Go-table-checked shuffle family. Its source is
	// a complete control tuple; byte selection never shrinks the access width.
	for _, instruction := range x86ByteShuffleFormatRows(arch) {
		if !strings.Contains(instruction, "·data(SB)") {
			continue
		}
		instruction = strings.Replace(instruction, "·data(SB)", "·words+16(SB)", 1)
		args := strings.Split(strings.Fields(instruction)[1], ",")
		destination := args[len(args)-1]
		rows = append(rows, ordinaryGlobalVectorCase{instruction, destination[:1], int(destination[1] - '0')})
	}
	want := 318 // The 308 logical rows plus legacy PSHUFB and nine VPSHUFB rows.
	if arch == "386" {
		want = 120 // Existing named mode32 grammar excludes masked forms.
	}
	if len(rows) != want {
		t.Fatal("complete indexed vector source union changed", len(rows), want)
	}
	return rows
}

func ownedIndexedVectorTable() string {
	var source strings.Builder
	for offset := 0; offset < 256; offset += 8 {
		fmt.Fprintf(&source, "DATA numericBytes<>+%d(SB)/8,$0x%016x\n", offset,
			uint64(0x719283a4b5c6d7e8)^uint64(offset)*0x0102030405060708)
	}
	source.WriteString("GLOBL numericBytes<>(SB),8,$256\n")
	return source.String()
}

func ownedIndexedVectorSource(t *testing.T, rows []ordinaryGlobalVectorCase, arch string) (string, string) {
	t.Helper()
	move, compare, test, add, word := "MOVQ", "CMPQ", "TESTQ", "ADDQ", 8
	if arch == "386" {
		move, compare, test, add, word = "MOVL", "CMPL", "TESTL", "ADDL", 4
	}
	var source, declarations strings.Builder
	source.WriteString(ownedIndexedVectorTable())
	for index, row := range rows {
		instruction := strings.Replace(row.instruction, "·words+16(SB)", "(AX)(CX*8)", 1)
		parsed := x86YMMReadSource(t, instruction)
		width, write, known := x86InstructionMemoryShape(parsed, 0, arch)
		if !known || write || width <= 0 || width > 64 {
			t.Fatal("missing complete typed memory-source width", instruction, width, write, known)
		}
		// The source computes a 16-byte table stride using two real integer
		// operations. Its CFG proves the complete source width stays in 256B.
		limit := (256-width)/16 + 1
		name := fmt.Sprintf("indexed%d", index)
		fmt.Fprintf(&declarations, "func %s(n uintptr) uintptr\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s n+0(FP),CX\n%s CX,$%d\nJAE outside%d\n%s CX,CX\nJE outside%d\n%s CX,CX\n",
			name, 2*word, move, compare, limit, index, test, index, add)
		source.WriteString(ordinaryGlobalVectorZero(row.bank, 1))
		source.WriteString(ordinaryGlobalVectorZero(row.bank, 2))
		source.WriteString("MOVL $0xa55a,AX\nKMOVW AX,K1\nKMOVW AX,K7\n")
		fmt.Fprintf(&source, "%s $numericBytes<>(SB),AX\n%s\nPEXTRD $0,X%d,AX\n%s AX,ret+%d(FP)\nRET\noutside%d:\n%s $0,AX\n%s AX,ret+%d(FP)\nRET\n",
			move, instruction, row.destination, move, word, index, move, move, word)
	}
	return source.String(), declarations.String()
}

func TestGoModuleOwnedReadonlyIndexedVectorSourceFacts(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			source, _ := ownedIndexedVectorSource(t,
				[]ordinaryGlobalVectorCase{{"ANDNPD ·words+16(SB),X2", "X", 2}}, arch)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			resolve := testResolveSym(ordinaryGlobalReadPackage)
			values := x86LoweredStaticAddressValues(file, resolve, nil, arch)
			if values == nil || values.numericLiterals["numericBytes<>"] != 256 {
				t.Fatal("complete private RODATA directory missing", values)
			}
			typ := I64
			if arch == "386" {
				typ = I32
			}
			word := x86ResultPointerWord(arch)
			sig := FuncSig{Name: resolve(file.Funcs[0].Sym), Args: []LLVMType{typ}, Ret: typ,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: word, Type: typ, Index: 0, Field: -1}},
				}}
			facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], sig, arch, values.numericLiterals)
			if err != nil {
				t.Fatal("bounded typed source lost its range proof", err)
			}
			if len(facts) != 2 || !facts[0].Address || facts[1].Address ||
				facts[1].Width != 16 || facts[1].Minimum != 0 || facts[1].Maximum != 240 {
				t.Fatal("complete exact source range changed", facts)
			}
			c := &amd64Ctx{fpStaticAddressValues: values}
			reads := c.ownedIndexedVectorReads(file.Funcs[0], sig, arch)
			if len(reads) != 1 {
				t.Fatal("proved exact indexed operand was not handed off", facts, reads)
			}
		})
	}
}

func TestGoModuleOwnedReadonlyIndexedVectorCompleteFamilies(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := ownedIndexedVectorCases(t, target.arch)
			for start := 0; start < len(rows); start += 32 {
				end := start + 32
				if end > len(rows) {
					end = len(rows)
				}
				t.Run(fmt.Sprintf("batch-%02d", start/32), func(t *testing.T) {
					source, declarations := ownedIndexedVectorSource(t, rows[start:end], target.arch)
					goAssemblerOracleOutput(t, target.arch, source, "", true)
					for _, api := range []string{"public", "owned-context"} {
						t.Run(api, func(t *testing.T) {
							pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
							ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("the complete bounded owned RODATA source needs no SDK capture", err)
							}
							compileLLVMToObject(t, llc, target.triple, "owned-indexed.ll", "owned-indexed.o", ir)
						})
					}
				})
			}
			t.Logf("complete owned numeric table read union: %d logical/shuffle memory forms", len(rows))
		})
	}
}

func TestGoModuleOwnedReadonlyIndexedVectorRejectsOtherAuthority(t *testing.T) {
	base, declarations := ownedIndexedVectorSource(t,
		[]ordinaryGlobalVectorCase{{"PAND ·words+16(SB),X2", "X", 2}}, "amd64")
	read := "PAND (AX)(CX*8),X2"
	for _, mutation := range []struct{ name, before, after string }{
		{"no bound", "CMPQ CX,$16\nJAE outside0\n", ""},
		{"wrong edge", "JAE outside0", "JB outside0"},
		{"stale flags", "JAE outside0", "ADDQ $1,CX\nJAE outside0"},
		{"past extent", "CMPQ CX,$16", "CMPQ CX,$17"},
		{"unknown index", "MOVQ n+0(FP),CX", "NOP"},
		{"partial address", read, "MOVB $0,AL\n" + read},
		{"literal index", read, "PAND (AX)(AX*8),X2"},
		{"mutable table", "GLOBL numericBytes<>(SB),8,$256", "GLOBL numericBytes<>(SB),0,$256"},
		{"relocation", "DATA numericBytes<>+0(SB)/8,$0x719283a4b5c6d7e8", "DATA numericBytes<>+0(SB)/8,$external(SB)"},
		{"write", read, "MOVOU X2,(AX)(CX*8)\n" + read},
		{"escape", read, "MOVQ AX,ret+8(FP)\n" + read},
		{"raw", "ADDQ CX,CX", "BYTE $0x90\nADDQ CX,CX"},
		{"mixed origin", "MOVQ $numericBytes<>(SB),AX", "CMPQ CX,$4\nJB incoming\nMOVQ $numericBytes<>(SB),AX\nJMP joined\nincoming:\nMOVQ n+0(FP),AX\njoined:"},
		{"unknown source", read, "PAND (DX)(CX*8),X2"},
		{"unregistered store", read, "MOVQ AX,(DX)\n" + read},
	} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(mutation.name+"/"+api, func(t *testing.T) {
				if strings.Count(base, mutation.before) != 1 {
					t.Fatal("negative control did not select one real source boundary", mutation.name)
				}
				source := strings.Replace(base, mutation.before, mutation.after, 1)
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
				ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || err == nil {
					t.Fatal("owned table lent unbounded/mutable/non-numerical/raw authority", ir != "", err)
				}
			})
		}
	}
}
