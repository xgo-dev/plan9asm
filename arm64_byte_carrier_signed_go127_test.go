//go:build go1.27

package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func arm64ByteCarrierSignedFixture(t *testing.T) (string, string) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	packagePath := "example.invalid/signedcarrier"
	var declarations, assembly strings.Builder
	declarations.WriteString("package signedcarrier\n")
	for _, bits := range []int{8, 16, 32} {
		for _, prefix := range []string{"int", "uint"} {
			typ := fmt.Sprintf("%s%d", prefix, bits)
			name := "value_" + typ
			fmt.Fprintf(&declarations, "func %s(input uint64) %s\n", name, typ)
			fmt.Fprintf(&declarations, "func entry_%s(input uint64) %s { return %s(input) }\n", name, typ, name)
			fmt.Fprintf(&declarations, "func observe_%s(input uint64) (value,native,guard uint64)\n", name)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\nMOVD input+0(FP),R0\nMOVD R0,result+8(FP)\nRET\n", name, 8+bits/8)
			width := arm64NativeResultTailCase{op: "MOVD", resultBits: bits, storeBits: 64}
			assembly.WriteString(strings.ReplaceAll(arm64NativeResultTailObserver(width), width.name(), name))
		}
	}
	for name, data := range map[string]string{
		"go.mod":  "module " + packagePath + "\ngo 1.20\n",
		"decl.go": declarations.String(), "original_arm64.s": assembly.String(),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return directory, packagePath
}

func TestARM64ByteCarrierSignedActualWrapper(t *testing.T) {
	directory, packagePath := arm64ByteCarrierSignedFixture(t)
	lease, release := runtimeOracleStageContext(t)
	defer release()
	source, err := CaptureGoARM64ByteCarrierSource(lease, arm64ByteCarrierRequest(t, directory, packagePath))
	if err != nil {
		t.Fatalf("actual original owner precondition: %v", err)
	}
	defer source.Close()
	for _, bits := range []int{8, 16, 32} {
		for _, prefix := range []string{"int", "uint"} {
			name := fmt.Sprintf("value_%s%d", prefix, bits)
			t.Run(name, func(t *testing.T) {
				found := false
				for _, text := range source.report.Archive[1].Texts {
					if text.Name != packagePath+"."+name || text.ABI != 1 {
						continue
					}
					found = true
					if len(text.Code) < 36 {
						t.Fatal("actual wrapper is incomplete")
					}
					t.Logf("actual %s wrapper code=%x result-read@20=%08x", name, text.Code, binary.LittleEndian.Uint32(text.Code[20:]))
					if _, err := arm64ByteCarrierTypedEntry(text, source.declarations[name]); err != nil {
						t.Errorf("actual signed/unsigned wrapper effect is not closed: %v", err)
					}
				}
				if !found {
					t.Fatal("actual compiler did not emit the original ABI1 wrapper")
				}
			})
		}
	}
}
