//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func numericalMutableFixture(t *testing.T, arch, body string) (GoNumericalStorageCaptureRequest, GoX86NumericalReadCaptureRequest) {
	t.Helper()
	_, original, _, _ := numericalSBFixture(t, arch)
	if err := os.Remove(filepath.Join(original.Directory, original.AssemblyFile)); err != nil {
		t.Fatal(err)
	}
	goSource := `package numericalfixture
var Mutable [32]byte
var Initial = [4]byte{1,2,3,4}
var Relocated = struct { N uint32; P *byte }{7, &Mutable[0]}
var Mixed struct {
	N byte
	_ [3]byte
	P *byte
	Bytes [16]byte
}
`
	if err := os.WriteFile(filepath.Join(original.Directory, "value.go"), []byte(goSource), 0600); err != nil {
		t.Fatal(err)
	}
	consumer := filepath.Join(original.Directory, "consumer")
	if err := os.Mkdir(consumer, 0700); err != nil {
		t.Fatal(err)
	}
	goConsumer := `package consumer
import owner "example.invalid/numericalfixture"
var _ = owner.Mutable
func Feature() byte
`
	assembly := "#include \"textflag.h\"\n#include \"local.h\"\nTEXT ·Feature(SB),NOSPLIT,$0-1\n" + body + "\nMOVB AL,ret+0(FP)\nRET\n"
	header := `#define DATA example·invalid∕numericalfixture·Mutable
#define READ(off,dst) MOVL DATA+off(SB),dst
`
	for name, data := range map[string][]byte{
		"value.go":            []byte(goConsumer),
		original.AssemblyFile: []byte(assembly),
		"local.h":             []byte(header),
	} {
		if err := os.WriteFile(filepath.Join(consumer, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	owner := GoNumericalStorageCaptureRequest{GoBinary: original.GoBinary, Directory: original.Directory, PackagePath: "example.invalid/numericalfixture",
		Target: original.Target, Environment: original.Environment,
		Variables: []GoNumericalStorageReference{{"example.invalid/numericalfixture", "Mutable"}, {"example.invalid/numericalfixture", "Initial"},
			{"example.invalid/numericalfixture", "Mixed"}, {"example.invalid/numericalfixture", "Relocated"}}}
	read := GoX86NumericalReadCaptureRequest{GoBinary: original.GoBinary, Directory: consumer, PackagePath: "example.invalid/numericalfixture/consumer",
		AssemblyFile: original.AssemblyFile, Target: original.Target, Environment: original.Environment}
	return owner, read
}

func TestGoX86NumericalSBReadActualMutableWidthsAndCPP(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			forms := []string{"MOVB", "MOVW", "MOVL", "MOVBWSX", "MOVBWZX", "MOVBLSX", "MOVBLZX", "MOVWLSX", "MOVWLZX", "MOVLQZX", "MOVSWW", "MOVZWW"}
			if arch == "amd64" {
				forms = append(forms, "MOVQ", "MOVBQSX", "MOVBQZX", "MOVWQSX", "MOVWQZX", "MOVLQSX")
			}
			var body strings.Builder
			for _, form := range forms {
				fmt.Fprintf(&body, "%s DATA+(2*4)(SB),AX\n", form)
			}
			body.WriteString("MOVB DATA+1(SB),AH\nMOVB DATA+2(SB),AL\nCMPB AH,DATA+3(SB)\n")
			if arch == "amd64" {
				body.WriteString("MOVB DATA+1(SB),R8\nMOVW DATA+2(SB),R8\nMOVL DATA+4(SB),R8\nMOVQ DATA+8(SB),R8\n")
			}
			for _, width := range []string{"B", "W", "L"} {
				fmt.Fprintf(&body, "CMP%s DATA+16(SB),$1\nCMP%s DATA+16(SB),AX\nCMP%s AX,DATA+16(SB)\n", width, width, width)
			}
			if arch == "amd64" {
				body.WriteString("CMPQ DATA+16(SB),$1\nCMPQ DATA+16(SB),AX\nCMPQ AX,DATA+16(SB)\n")
			}
			body.WriteString("READ(4,AX)\nMOVL example·invalid∕numericalfixture·Relocated+0(SB),AX\nMOVB example·invalid∕numericalfixture·Initial+3(SB),AL\n")
			ownerRequest, readRequest := numericalMutableFixture(t, arch, body.String())
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoNumericalStorageOwner(ctx, ownerRequest)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			original, err := goasmcmd.Run(ctx, readRequest.Directory, readRequest.Environment, readRequest.GoBinary, "list", "-json", "-compiled", "-export", "-mod=readonly", ".")
			if err != nil {
				t.Fatalf("independent actual original mutable export failed: %v\n%s", err, original)
			}
			readRequest.Owners = []*GoNumericalStorageOwner{owner}
			source, err := CaptureGoX86NumericalReadSource(ctx, readRequest)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			expected := len(forms) + 9 + 6
			if arch == "amd64" {
				expected += 7
			}
			if len(source.reads) != expected {
				t.Fatalf("full read shape count = %d, want %d", len(source.reads), expected)
			}
			raw, err := source.Readback(ctx)
			if err != nil || source.CheckReadback(ctx, raw) != nil {
				t.Fatalf("sealed mutable readback failed: %v", err)
			}
			retainNumericalRead(t, source, "mutable")
			mutated := append([]byte(nil), raw...)
			mutated[len(mutated)/2] ^= 1
			if !errors.Is(source.CheckReadback(ctx, mutated), ErrProbeNeedsContext) {
				t.Fatal("edited portable readback gained authority")
			}
			for _, read := range source.reads {
				if read.original.Op == "MOVLQZX" && read.width != 4 {
					t.Fatal("Go's mode32-compatible MOVLQZX acquired a qword source width")
				}
			}
			// The numerical BSS observation is mutable storage, not a folded zero.
			// Restoring an altered join cannot undo permanent revocation.
			originalOffset := source.reads[0].offset
			source.reads[0].offset++
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("changed native/read offset retained live seal")
			}
			source.reads[0].offset = originalOffset
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("restored offset resurrected revoked source")
			}
		})
	}
}

func TestGoX86NumericalSBReadActualOwnerSpanAndAddressNegatives(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, test := range []struct{ name, body string }{
			{"cross end", "MOVL DATA+30(SB),AX"},
			{"negative offset", "MOVB DATA-1(SB),AL"},
			{"blank field", "MOVB example·invalid∕numericalfixture·Mixed+1(SB),AL"},
			{"pointer field", "MOVL example·invalid∕numericalfixture·Mixed+4(SB),AX"},
			{"relocated pointer field", "MOVL example·invalid∕numericalfixture·Relocated+4(SB),AX"},
			{"address", "MOVL $DATA(SB),AX"},
			{"LEA", "LEAL DATA(SB),AX"},
			{"store", "MOVL $1,DATA(SB)"},
		} {
			t.Run(arch+"/"+test.name, func(t *testing.T) {
				if arch == "amd64" && test.name == "pointer field" {
					test.body = "MOVL example·invalid∕numericalfixture·Mixed+8(SB),AX"
				} else if arch == "amd64" && test.name == "relocated pointer field" {
					test.body = "MOVL example·invalid∕numericalfixture·Relocated+8(SB),AX"
				}
				ownerRequest, readRequest := numericalMutableFixture(t, arch, test.body)
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				owner, err := CaptureGoNumericalStorageOwner(ctx, ownerRequest)
				if err != nil {
					t.Fatal(err)
				}
				defer owner.Close()
				original, err := goasmcmd.Run(ctx, readRequest.Directory, readRequest.Environment, readRequest.GoBinary, "list", "-json", "-compiled", "-export", "-mod=readonly", ".")
				if err != nil {
					t.Fatalf("independent actual original negative fixture failed: %v\n%s", err, original)
				}
				readRequest.Owners = []*GoNumericalStorageOwner{owner}
				source, err := CaptureGoX86NumericalReadSource(ctx, readRequest)
				if source != nil {
					source.Close()
					t.Fatal("non-numerical/address/write bytes obtained source read join")
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("expected exact Context rejection, not infrastructure: %v", err)
				}
			})
		}
	}
}

func TestGoX86NumericalSBReadActualRepeatedSourceOrdinals(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			body := "MOVB DATA+0(SB),AL\nMOVB AL,ret+0(FP)\nRET\n" +
				"TEXT ·Other(SB),NOSPLIT,$0-1\nMOVB DATA+0(SB),AL"
			ownerRequest, readRequest := numericalMutableFixture(t, arch, body)
			goFile := filepath.Join(readRequest.Directory, "value.go")
			data, err := os.ReadFile(goFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(goFile, append(data, []byte("func Other() byte\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoNumericalStorageOwner(ctx, ownerRequest)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			original, err := goasmcmd.Run(ctx, readRequest.Directory, readRequest.Environment, readRequest.GoBinary,
				"list", "-json", "-compiled", "-export", "-mod=readonly", ".")
			if err != nil {
				t.Fatalf("actual two-TEXT original export failed: %v\n%s", err, original)
			}
			readRequest.Owners = []*GoNumericalStorageOwner{owner}
			source, err := CaptureGoX86NumericalReadSource(ctx, readRequest)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if len(source.reads) != 2 || source.reads[0].function == source.reads[1].function {
				t.Fatal("repeated source read borrowed another TEXT's ordinal")
			}
			retainNumericalRead(t, source, "repeated")
		})
	}
}
