//go:build go1.27

package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

type arm64SignedCarrierCase struct {
	name, typ, load       string
	resultBits, storeBits int
	op                    Op
	signed, twoParameters bool
}

// Independent scalar memory family: exact and wider native stores retain both
// signed/unsigned spellings. The logical Go result and native store are separate
// axes; this inventory is not generated from the consumer's decoder.
func arm64SignedCarrierCases() []arm64SignedCarrierCase {
	var result []arm64SignedCarrierCase
	for _, bits := range []int{8, 16, 32, 64} {
		for _, signed := range []bool{false, true} {
			prefix := "uint"
			load := map[int]string{8: "MOVBU", 16: "MOVHU", 32: "MOVWU", 64: "MOVD"}[bits]
			if signed {
				prefix = "int"
				load = map[int]string{8: "MOVB", 16: "MOVH", 32: "MOVW", 64: "MOVD"}[bits]
			}
			for _, store := range []struct {
				op   Op
				bits int
			}{{"MOVB", 8}, {"MOVBU", 8}, {"MOVH", 16}, {"MOVHU", 16}, {"MOVW", 32}, {"MOVWU", 32}, {"MOVD", 64}} {
				if store.bits < bits {
					continue
				}
				for _, two := range []bool{false, true} {
					result = append(result, arm64SignedCarrierCase{
						name: fmt.Sprintf("value_%s%d_%s_two%t", prefix, bits, strings.ToLower(string(store.op)), two),
						typ:  fmt.Sprintf("%s%d", prefix, bits), load: load, op: store.op,
						resultBits: bits, storeBits: store.bits, signed: signed, twoParameters: two,
					})
				}
			}
		}
	}
	return result
}

func arm64SignedCarrierMatrixFixture(t *testing.T) (string, string, []arm64SignedCarrierCase) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	packagePath := "example.invalid/signedcarriermatrix"
	cases := arm64SignedCarrierCases()
	if len(cases) != 64 {
		t.Fatal("complete independent signed/store/parameter denominator changed", len(cases))
	}
	var declarations, assembly strings.Builder
	declarations.WriteString("package signedcarriermatrix\n")
	for _, row := range cases {
		parameters, resultOffset := "input uint64", 8
		if row.twoParameters {
			parameters, resultOffset = parameters+", spare uint32", 16
		}
		fmt.Fprintf(&declarations, "func %s(%s) %s\n", row.name, parameters, row.typ)
		fmt.Fprintf(&declarations, "func observe_%s(input uint64) (value,native,guard,paramgap uint64)\n", row.name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\nMOVD input+0(FP),R0\n%s R0,result+%d(FP)\nRET\n",
			row.name, resultOffset+row.resultBits/8, row.op, resultOffset)
		fmt.Fprintf(&assembly, "TEXT ·observe_%s(SB),4,$48-40\nMOVD input+0(FP),R0\nMOVD R0,8(RSP)\n", row.name)
		if row.twoParameters {
			assembly.WriteString("MOVD $0xabad1dea00123456,R1\nMOVD R1,16(RSP)\n")
		}
		fmt.Fprintf(&assembly, "MOVD $0xfeedfacecafebeef,R1\nMOVD R1,%d(RSP)\n"+
			"MOVD $0x7ac35ef012345678,R1\nMOVD R1,%d(RSP)\nCALL ·%s(SB)\n"+
			"MOVD %d(RSP),R0\nMOVD R0,native+16(FP)\n%s %d(RSP),R0\nMOVD R0,value+8(FP)\n"+
			"MOVD %d(RSP),R0\nMOVD R0,guard+24(FP)\n",
			resultOffset+8, resultOffset+16, row.name, resultOffset+8, row.load, resultOffset+8, resultOffset+16)
		if row.twoParameters {
			assembly.WriteString("MOVD 16(RSP),R0\n")
		} else {
			assembly.WriteString("MOVD ZR,R0\n")
		}
		assembly.WriteString("MOVD R0,paramgap+32(FP)\nRET\n")
	}
	for name, data := range map[string]string{
		"go.mod":  "module " + packagePath + "\ngo 1.20\n",
		"decl.go": declarations.String(), "original_arm64.s": assembly.String(),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return directory, packagePath, cases
}

func arm64SignedCarrierEntry(t *testing.T, source *GoARM64ByteCarrierSource, name string) gostaticstorage.TextRecord {
	t.Helper()
	for _, text := range source.report.Archive[1].Texts {
		if text.Name == source.request.PackagePath+"."+name && text.ABI == 1 {
			return text
		}
	}
	t.Fatal("missing complete actual compiler entry", name)
	return gostaticstorage.TextRecord{}
}

func TestARM64ByteCarrierSignedCompleteWidthObjects(t *testing.T) {
	buildCache := t.TempDir()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ goos, triple string }{
		{"linux", "aarch64-unknown-linux-gnu"}, {"darwin", "aarch64-apple-darwin"},
		{"windows", "aarch64-pc-windows-msvc"}, {"freebsd", "aarch64-unknown-freebsd"},
		{"openbsd", "aarch64-unknown-openbsd"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			directory, packagePath, cases := arm64SignedCarrierMatrixFixture(t)
			request := arm64ByteCarrierRequestWithBuildCache(t, directory, packagePath, buildCache)
			request.Target = target.goos + "/arm64"
			for index, pair := range request.Environment {
				if strings.HasPrefix(pair, "GOOS=") {
					request.Environment[index] = "GOOS=" + target.goos
				}
			}
			lease, release := runtimeOracleStageContext(t)
			defer release()
			source, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil {
				t.Fatal("actual source owner", err)
			}
			defer source.Close()
			for _, row := range cases {
				text := arm64SignedCarrierEntry(t, source, row.name)
				entry, err := arm64ByteCarrierTypedEntry(text, source.declarations[row.name])
				if err != nil || len(entry.resultLoads) != 1 || entry.resultLoads[0].Bytes != int64(row.resultBits/8) {
					t.Fatal("actual logical/native result width mismatch", row.name, entry, err)
				}
				base := uint32(0x394003e0)
				if row.signed && row.resultBits < 64 {
					base = 0x398003e0
				}
				if entry.resultLoads[0].Instruction&0x3fc003e0 != base {
					t.Fatal("actual compiler sign extension differs", row.name, entry.resultLoads[0])
				}
			}
			declaration, err := os.ReadFile(filepath.Join(directory, "decl.go"))
			if err != nil {
				t.Fatal(err)
			}
			assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
			if err != nil {
				t.Fatal(err)
			}
			pkg := mustGoPackage(t, packagePath, string(declaration))
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), target.triple, nil)
				if err != nil {
					t.Fatal(api, err)
				}
				compileLLVMToObject(t, llc, target.triple, "signed-carrier-"+api+".ll", "signed-carrier-"+api+".o", ir)
			}
			t.Logf("actual original %s/arm64: %d result wrappers and 3 LLVM objects", target.goos, len(cases))
		})
	}
}

func TestARM64ByteCarrierSignedEntryRejectsAdjacentFormats(t *testing.T) {
	directory, packagePath := arm64ByteCarrierSignedFixture(t)
	lease, release := runtimeOracleStageContext(t)
	defer release()
	source, err := CaptureGoARM64ByteCarrierSource(lease, arm64ByteCarrierRequest(t, directory, packagePath))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, bits := range []int{8, 16, 32} {
		name := fmt.Sprintf("value_int%d", bits)
		original := arm64SignedCarrierEntry(t, source, name)
		for mutation, edit := range map[string]func(uint32) uint32{
			"unsigned-width":        func(word uint32) uint32 { return word ^ 1<<30 },
			"W-result":              func(word uint32) uint32 { return word | 1<<22 },
			"SIMD":                  func(word uint32) uint32 { return word | 1<<26 },
			"non-SP-base":           func(word uint32) uint32 { return word &^ (31 << 5) },
			"wrong-result-register": func(word uint32) uint32 { return word | 1 },
			"wrong-result-offset":   func(word uint32) uint32 { return word + 1<<10 },
			"writeback":             func(word uint32) uint32 { return word&^(1<<24) | 1<<10 },
			"store":                 func(word uint32) uint32 { return word &^ (3 << 22) },
		} {
			t.Run(name+"/"+mutation, func(t *testing.T) {
				text := original
				text.Code = append([]byte(nil), original.Code...)
				binary.LittleEndian.PutUint32(text.Code[20:], edit(binary.LittleEndian.Uint32(text.Code[20:])))
				if _, err := arm64ByteCarrierTypedEntry(text, source.declarations[name]); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("adjacent width/native effect acquired result permission", err)
				}
			})
		}
	}
}
