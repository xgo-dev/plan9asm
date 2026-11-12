package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func arm64VectorLaneTranslation(t *testing.T, declaration, body string) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "test/lanebits", "package lanebits\n"+declaration+"\n")
	result, err := TranslateGoModule(pkg, []byte("TEXT ·Pass<ABIInternal>(SB),4,$0-16\n"+body), GoModuleOptions{GOARCH: "arm64"})
	if result == nil {
		return "", err
	}
	defer result.Module.Dispose()
	return result.Module.String(), err
}

func TestARM64GoRegisterVectorLaneInsertKeepsUnwrittenBitsUnknown(t *testing.T) {
	for _, element := range []struct {
		name string
		bits int
	}{
		{name: "B", bits: 8},
		{name: "H", bits: 16},
		{name: "S", bits: 32},
		{name: "D", bits: 64},
	} {
		for lane := 0; lane < 128/element.bits; lane++ {
			name := fmt.Sprintf("%s%d", element.name, lane)
			t.Run(name, func(t *testing.T) {
				body := fmt.Sprintf("VMOV R0,V21.%s[%d]\nVMOV V21.%s[%d],R0\nRET\n", element.name, lane, element.name, lane)
				// The instruction family exists in both supported SDKs. This
				// actual ordinary object observes its machine encoding only;
				// it is not an ABIInternal caller or runtime certificate.
				bytes := arm64ImmediateOriginalGoBytes(t, "TEXT lane(SB),4,$0-0\n"+body, "linux")
				if len(bytes) < 12 {
					t.Fatalf("original VMOV insert/extract object is incomplete: %x", bytes)
				}
				pkg := mustGoPackage(t, "test/lanebits", "package lanebits\nfunc Pass(uint64) uint64\n")
				result, err := TranslateGoModule(pkg, []byte("TEXT ·Pass<ABIInternal>(SB),4,$0-16\n"+body), GoModuleOptions{GOARCH: "arm64"})
				if result != nil {
					result.Module.Dispose()
				}
				if err != nil {
					t.Fatalf("a defined inserted lane incorrectly read preserved unknown destination bits: %v", err)
				}
			})
		}
	}
}

func TestARM64GoRegisterVectorLaneTransferDefinedSpans(t *testing.T) {
	for name, body := range map[string]string{
		"matching lane copy":         "VMOV R0,V20.S[3]\nVMOV V20.S[3],V21.S[1]\nVMOV V21.S[1],R0\nRET\n",
		"scalar lane clears upper":   "VMOV R0,V20.B[15]\nVMOV V20.B[15],V21\nVMOV V21.D[1],R0\nRET\n",
		"lane duplicate":             "VMOV R0,V20.H[7]\nVDUP V20.H[7],V21.H8\nVMOV V21.D[1],R0\nRET\n",
		"mixed suffix encoded width": "VMOV R0,V20.B[1]\nVDUP V20.D[1],V21.B16\nVMOV V21.D[1],R0\nRET\n",
		"GP duplicate clears upper":  "VMOV R0,V21.B8\nVMOV V21.D[1],R0\nRET\n",
		"low copy clears upper":      "VMOV R0,V20.D[0]\nVMOV V20.B8,V21.B8\nVMOV V21.D[1],R0\nRET\n",
		"complete copy":              "VMOV R0,V20.D[0]\nVMOV R0,V20.D[1]\nVMOV V20.B16,V21.B16\nVMOV V21.D[1],R0\nRET\n",
		"same register lane alias":   "VMOV R0,V20.D[0]\nVMOV V20.D[0],V20.D[1]\nVMOV V20.B16,V21.B16\nVMOV V21.D[1],R0\nRET\n",
		"scalar F/V low alias":       "VMOV R0,V21.D[0]\nFMOVD F21,R0\nRET\n",
		"both incoming paths":        "CBZ R0,left\nVMOV R0,V21.D[1]\nB join\nleft:\nVMOV ZR,V21.D[1]\njoin:\nVMOV V21.D[1],R0\nRET\n",
	} {
		t.Run(name, func(t *testing.T) {
			arm64ImmediateOriginalGoBytes(t, "TEXT lane(SB),4,$0-0\n"+body, "linux")
			if _, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", body); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, bits := range []int{8, 16, 32, 64} {
		t.Run(fmt.Sprintf("narrow GP %d", bits), func(t *testing.T) {
			kind := map[int]string{8: "B", 16: "H", 32: "S", 64: "D"}[bits]
			body := fmt.Sprintf("VMOV R0,V21.%s[0]\nVMOV V21.%s[0],R0\nRET\n", kind, kind)
			if _, err := arm64VectorLaneTranslation(t, fmt.Sprintf("func Pass(uint%d) uint64", bits), body); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := arm64VectorLaneTranslation(t, "func Pass(float64) uint64", "VMOV V0.D[0],V21.D[1]\nVMOV V21.D[1],R0\nRET\n"); err != nil {
		t.Fatalf("typed F/V scalar alias lost its defined low double: %v", err)
	}
}

func TestARM64GoRegisterVectorLaneCannotInitializePreservedInputs(t *testing.T) {
	for name, body := range map[string]string{
		"unwritten lane":                "VMOV R0,V21.D[0]\nVMOV V21.D[1],R0\nRET\n",
		"whole vector":                  "VMOV R0,V21.D[0]\nVMOV V21.B16,V22.B16\nVMOV V22.D[0],R0\nRET\n",
		"unknown source lane":           "VMOV V20.D[1],V21.D[0]\nVMOV V21.D[0],R0\nRET\n",
		"unknown GP source":             "VMOV R9,V21.D[0]\nVMOV V21.D[0],R0\nRET\n",
		"scalar alias reads low":        "VMOV R0,V21.D[1]\nFMOVD F21,R0\nRET\n",
		"missing path":                  "CBZ R0,join\nVMOV R0,V21.D[0]\njoin:\nVMOV V21.D[0],R0\nRET\n",
		"different incoming lanes":      "CBZ R0,left\nVMOV R0,V21.D[0]\nB join\nleft:\nVMOV R0,V21.D[1]\njoin:\nVMOV V21.D[0],R0\nRET\n",
		"typed call resets vector bank": "VMOV R0,V21.D[0]\nCALL ·Compute<ABIInternal>(SB)\nVMOV V21.D[0],R0\nRET\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64\nfunc Compute() uint64", body)
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "read") {
				t.Fatalf("unknown preserved/input bits acquired numerical authority: %v", err)
			}
		})
	}
	for _, test := range []struct {
		declaration string
		body        string
	}{
		{declaration: "func Pass(uint8) uint64", body: "VMOV R0,V21.H[0]\nVMOV V21.H[0],R0\nRET\n"},
		{declaration: "func Pass(float32) uint64", body: "VMOV V0.S[1],V21.S[0]\nVMOV V21.S[0],R0\nRET\n"},
	} {
		if _, err := arm64VectorLaneTranslation(t, test.declaration, test.body); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("narrow scalar entry supplied undefined wider/later bits: %v", err)
		}
	}
	if _, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", "VMOV R0,V21.D[0]\nCALL ·Unknown<ABIInternal>(SB)\nVMOV V21.D[0],R0\nRET\n"); err == nil {
		t.Fatal("unknown callee inherited a lane or continuation contract")
	}
}

func TestARM64GoRegisterVectorLaneActualRejectsAdjacentForms(t *testing.T) {
	for _, instruction := range []string{
		"VMOV R0,V21.B[16]", "VMOV R0,V21.H[8]", "VMOV R0,V21.S[4]", "VMOV R0,V21.D[2]",
		"VMOV V20.B[-1],R0", "VMOV V20.Q[0],R0", "VMOV V20.S[0],V21.H[0]",
		"VMOV RSP,V21.D[0]", "VMOV V21.D[0],RSP", "VMOV.P R0,V21.D[0]",
		"VMOV V20.B8,V21.B16", "VMOV (R0),V21.B16", "VMOV V20,V21",
		"VDUP V20.S[4],V21.S4", "VDUP V20.D[1],V21.D1", "VDUP RSP,V21.B16",
		"VDUP.P R0,V21.B16", "VDUP R0,V21", "VDUP V20.S4,V21.S4",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			goAssemblerOracleOutput(t, "arm64", "TEXT invalid(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
			if _, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", instruction+"\nRET\n"); err == nil {
				t.Fatalf("Go-rejected vector lane form acquired defined-bit permission: %s", instruction)
			}
		})
	}
}
