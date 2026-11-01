package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type ordinaryGlobalVectorCase struct {
	instruction, bank string
	destination       int
}

func ordinaryGlobalLogicalCases(t *testing.T, arch string) []ordinaryGlobalVectorCase {
	t.Helper()
	// Independent mnemonic inventory; the existing complete Go-table oracle
	// checks every row and opcode attribute behind the shared form fixtures.
	names := strings.Fields(`
		ANDPS ANDPD ANDNPS ANDNPD ORPS ORPD XORPS XORPD PAND PANDN POR PXOR
		VANDPS VANDPD VANDNPS VANDNPD VORPS VORPD VXORPS VXORPD
		VPAND VPANDN VPOR VPXOR VPANDD VPANDQ VPANDND VPANDNQ
		VPORD VPORQ VPXORD VPXORQ
	`)
	actual := make([]string, 0, len(x86PackedLogicalSpecs))
	for name := range x86PackedLogicalSpecs {
		actual = append(actual, string(name))
	}
	sort.Strings(names)
	sort.Strings(actual)
	if !reflect.DeepEqual(names, actual) {
		t.Fatal("the complete independent logical namespace changed", names, actual)
	}
	var result []ordinaryGlobalVectorCase
	for _, name := range names {
		for _, instruction := range x86LogicalAcceptedForms(Op(name), arch) {
			if !strings.Contains(instruction, "8(AX)") || strings.Contains(instruction, ",M") {
				continue // Physical MMX remains a separate entry/state contract.
			}
			instruction = strings.Replace(instruction, "8(AX)", "·words+16(SB)", 1)
			// Grammar fixtures independently exercise high banks. This fixture
			// keeps every target physically bound and observes the low result.
			instruction = regexp.MustCompile(`\b([XYZ])(?:7|15|31)\b`).ReplaceAllString(instruction, "${1}2")
			args := strings.Split(strings.Fields(instruction)[1], ",")
			destination := args[len(args)-1]
			result = append(result, ordinaryGlobalVectorCase{instruction, destination[:1], 2})
		}
	}
	return result
}

func ordinaryGlobalAESCases() []ordinaryGlobalVectorCase {
	var result []ordinaryGlobalVectorCase
	for index, name := range x86AESOracleNames {
		widths := []string{"X"}
		if index >= 6 && index%6 < 4 {
			widths = append(widths, "Y", "Z")
		}
		for _, bank := range widths {
			instruction, destination := x86AESOracleRow(name, "·words+16(SB)", bank)
			result = append(result, ordinaryGlobalVectorCase{instruction, bank, destination})
		}
	}
	return result
}

func ordinaryGlobalVectorZero(bank string, index int) string {
	register := fmt.Sprintf("%s%d", bank, index)
	switch bank {
	case "X":
		return fmt.Sprintf("PXOR %s,%s\n", register, register)
	case "Y":
		return fmt.Sprintf("VPXOR %s,%s,%s\n", register, register, register)
	default:
		return fmt.Sprintf("VPXORD %s,%s,%s\n", register, register, register)
	}
}

func ordinaryGlobalVectorSource(rows []ordinaryGlobalVectorCase) (string, string) {
	var source, declarations strings.Builder
	declarations.WriteString("var words [96]byte\n")
	for index, row := range rows {
		name := fmt.Sprintf("vector%d", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\n", name)
		fmt.Fprintf(&declarations, "func %s() uint32\n", name)
		source.WriteString(ordinaryGlobalVectorZero(row.bank, 1))
		source.WriteString(ordinaryGlobalVectorZero(row.bank, 2))
		source.WriteString("MOVL $0xa55a,AX\nKMOVW AX,K1\nKMOVW AX,K7\n")
		source.WriteString(row.instruction + "\n")
		fmt.Fprintf(&source, "PEXTRD $0,X%d,AX\nMOVL AX,ret+0(FP)\nRET\n", row.destination)
	}
	return source.String(), declarations.String()
}

func TestGoModuleOrdinaryGlobalVectorReadCompleteFamilies(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, family := range []string{"logical", "AES"} {
			t.Run(target.triple+"/"+family, func(t *testing.T) {
				rows := ordinaryGlobalAESCases()
				if family == "logical" {
					rows = ordinaryGlobalLogicalCases(t, target.arch)
				}
				want := 20 // Six legacy AES rows, four wide rounds, two AVX unary rows.
				if family == "logical" {
					want = 308 // 12 legacy + 4 VEX x2 widths + 16 EVEX x3 widths x6 memory forms.
					if target.arch == "386" {
						want = 116 // The original Go mode32 grammar has no named K operand.
					}
				}
				if len(rows) != want {
					t.Fatalf("complete memory-source denominator changed: got %d, want %d", len(rows), want)
				}
				// Keep source verification and object generation bounded without
				// dropping a format, width, broadcast or masked source row.
				for start := 0; start < len(rows); start += 32 {
					end := start + 32
					if end > len(rows) {
						end = len(rows)
					}
					t.Run(fmt.Sprintf("batch-%02d", start/32), func(t *testing.T) {
						source, declarations := ordinaryGlobalVectorSource(rows[start:end])
						goAssemblerOracleOutput(t, target.arch, source, "", true)
						for _, api := range []string{"public", "owned-context"} {
							t.Run(api, func(t *testing.T) {
								pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
								ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), target.arch, target.triple, api)
								if err != nil || ir == "" {
									t.Fatal("complete named vector reads need ordinary declarations, not an SDK capability", err)
								}
								compileLLVMToObject(t, llc, target.triple, "ordinary-vector.ll", "ordinary-vector.o", ir)
							})
						}
						for _, row := range rows[start:end] {
							instruction := x86YMMReadSource(t, row.instruction)
							operand, width, known := goReadOnlyOperand(instruction, target.arch)
							form, valid := x86NumericalSBVectorReadProperties(instruction, target.arch)
							if !known || !valid || width != form.spec.sourceBytes || !reflect.DeepEqual(operand, instruction.Args[form.operand]) {
								t.Fatal("ordinary storage did not use the existing complete typed read shape", row.instruction)
							}
						}
					})
				}
				t.Logf("complete %s numerical-global source union: %d forms", family, len(rows))
			})
		}
	}
}

func TestGoModuleOrdinaryGlobalVectorReadRetainsAuthorityBoundaries(t *testing.T) {
	for _, test := range []struct{ name, declaration, prefix, instruction string }{
		{"past-object", "var words [31]byte", "PXOR X0,X0\n", "PXOR ·words+16(SB),X0"},
		{"negative-offset", "var words [96]byte", "PXOR X0,X0\n", "PXOR ·words-1(SB),X0"},
		{"padding", "var words struct { A byte; B [16]uint64 }", "PXOR X0,X0\n", "PXOR ·words+1(SB),X0"},
		{"blank-field", "var words struct { _ [16]byte; A [16]byte }", "PXOR X0,X0\n", "PXOR ·words(SB),X0"},
		{"pointer-array", "var words [16]*byte", "PXOR X0,X0\n", "PXOR ·words(SB),X0"},
		{"slice", "var words []byte", "PXOR X0,X0\n", "PXOR ·words(SB),X0"},
		{"foreign", "var words [96]byte", "PXOR X0,X0\n", "PXOR other.words(SB),X0"},
		{"unknown-register", "var words [96]byte", "", "PXOR ·words(SB),X0"},
		{"unknown-AES-state", "var words [96]byte", "", "AESENC ·words(SB),X0"},
		{"unknown-mask", "var words [96]byte", "PXOR X0,X0\n", "VPXORD ·words(SB),X0,K1,X0"},
		{"unknown-merge", "var words [96]byte", "PXOR X1,X1\nMOVL $1,AX\nKMOVW AX,K1\n", "VPXORD ·words(SB),X1,K1,X0"},
		{"zero-mask-missing-extent", "var words [3]byte", "PXOR X0,X0\nMOVL $0,AX\nKMOVW AX,K1\n", "VPXORD.BCST.Z ·words(SB),X0,K1,X0"},
		{"write", "var words [96]byte", "PXOR X0,X0\nMOVOU X0,·words(SB)\n", "PXOR ·words(SB),X0"},
		{"address", "var words [96]byte", "PXOR X0,X0\nLEAQ ·words(SB),DX\nMOVL (DX),AX\n", "PXOR ·words(SB),X0"},
		// This negative only preserves the separate physical MMX contract; it
		// is not a complete MMX family acceptance/execution certificate.
		{"physical-MMX", "var words [96]byte", "PXOR M0,M0\n", "PXOR ·words(SB),M0"},
	} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(test.name+"/"+api, func(t *testing.T) {
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\n"+test.declaration+"\nfunc view() uint32\n")
				source := "TEXT ·view(SB),4,$0-4\n" + test.prefix + test.instruction +
					"\nPEXTRD $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n"
				ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("a numerical-global read lent another authority or missing input", ir != "", err)
				}
			})
		}
	}
}

func TestGoModuleOrdinaryGlobalVectorReadRejectsRawAndStaleBindings(t *testing.T) {
	row := ordinaryGlobalVectorCase{"PXOR ·words+16(SB),X2", "X", 2}
	source, declarations := ordinaryGlobalVectorSource([]ordinaryGlobalVectorCase{row})
	for _, api := range []string{"text", "module"} {
		t.Run(api, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
			ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, "amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("an unbound API borrowed typed Go storage", ir != "", err)
			}
		})
	}
	for _, change := range []string{"raw-origin", "address-size", "segment", "syntax", "assembly"} {
		t.Run(change, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			storage, err := bindGoReadOnlyStorage(pkg, file, types.SizesFor("gc", "amd64"), "amd64", testResolveSym(pkg.Path))
			if err != nil || storage == nil {
				t.Fatal("ordinary vector storage was not actually bound", err)
			}
			instruction := x86YMMReadSource(t, row.instruction)
			switch change {
			case "raw-origin":
				instruction.x86Encoded = true
			case "address-size":
				instruction.x86AddressBits = 32
			case "segment":
				instruction.x86SegmentPrefix = 'F'
			case "syntax":
				pkg.Syntax[0].Name.Name = "changed"
			case "assembly":
				storage.file.Funcs[0].Instrs[1].Op = "NOP"
			}
			if change == "syntax" || change == "assembly" {
				if err := storage.verify(); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed complete source did not revoke its read binding", err)
				}
			} else if storage.readFor(instruction, "amd64") != nil {
				t.Fatal("a named declaration lent raw/physical override authority")
			}
		})
	}
}

func TestGoModuleOrdinaryGlobalVectorReadObservableSources(t *testing.T) {
	for _, test := range []struct {
		instruction, bank, access string
		loads                     int
		masked                    bool
	}{
		{"PXOR ·words+16(SB),X2", "X", `asm sideeffect "pxor `, 1, false},
		{"AESENC ·words+16(SB),X2", "X", `asm sideeffect "aesenc `, 1, false},
		{"VPXOR ·words+16(SB),Y1,Y2", "Y", "load volatile <32 x i8>", 1, false},
		{"VXORPD.BCST ·words+16(SB),Z1,Z2", "Z", "load volatile <8 x i8>", 1, false},
		{"VPXORD ·words+16(SB),Z1,K1,Z2", "Z", "load volatile i32", 16, true},
		{"VPXORD.BCST.Z ·words+16(SB),Z1,K1,Z2", "Z", "load volatile i32", 1, true},
		{"VAESENC ·words+16(SB),Z1,Z2", "Z", "load volatile <64 x i8>", 1, false},
	} {
		t.Run(test.instruction, func(t *testing.T) {
			source, declarations := ordinaryGlobalVectorSource([]ordinaryGlobalVectorCase{{test.instruction, test.bank, 2}})
			// Discard the numerical result. Observable native reads must not
			// disappear merely because an independent scalar value is returned.
			source = strings.Replace(source, "MOVL AX,ret+0(FP)", "MOVL $7,ret+0(FP)", 1)
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
			ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), "amd64", "x86_64-unknown-linux-gnu", "public")
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ir, test.access); got != test.loads {
				t.Fatalf("source access changed: got %d %q, want %d", got, test.access, test.loads)
			}
			if test.masked && !strings.Contains(ir, "br i1") {
				t.Fatal("masked source lost its actual conditional access")
			}
			if strings.Contains(test.access, "asm sideeffect") && !strings.Contains(ir, "~{memory}") {
				t.Fatal("legacy native memory opcode lost its observable access")
			}
			optimized := x86MulDivRoundOptimize(t, ir)
			if !strings.Contains(optimized, test.access) {
				t.Fatal("IR optimization removed the dead-result native/volatile source access")
			}
		})
	}
}
