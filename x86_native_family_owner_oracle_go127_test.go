//go:build go1.27

package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type x86NativeFamilyOwnerOracle struct {
	literal   *x86SDKLiteralCertificate
	numerical *x86NumericalReadCertificate
}

// Share actual SDK factory products, not a mock namespace or a fabricated
// certificate. Every caller retains the complete source/type/object capture,
// both independent owners, their actual valid API controls and live cleanup.
func x86CaptureNativeFamilyOwnerOracle(t *testing.T) x86NativeFamilyOwnerOracle {
	t.Helper()
	source, err := numericalSDKMapsReadCapture(t, "linux/amd64", "memhash_amd64.s")
	if err != nil {
		t.Fatal("actual complete SDK owner/source precondition", err)
	}
	ctx := source.sdk.originalContext
	minimum, err := CaptureGoX86SDKLiteralAlignment(ctx, source.literals.owner)
	if err != nil {
		t.Fatal("actual independent SDK literal alignment precondition", err)
	}
	t.Cleanup(func() { minimum.Close() })
	pkg, original, options := numericalSDKLiteralPackage(t, source.literals.source, source.request.AssemblyFile)
	bound, err := source.BindNumericalReadsWithLiteralAlignment(ctx, pkg, original, options, minimum)
	if err != nil {
		t.Fatal("complete unchanged SDK numerical/literal binding", err)
	}
	frozen, _, err := freezeNumericalReadInputs(original, bound)
	if err != nil {
		t.Fatal("complete SDK source/declaration/certificate identity", err)
	}
	var owners x86NativeFamilyOwnerOracle
	var literalOriginal, numericalOriginal Instr
	for _, function := range frozen.Funcs {
		for _, instruction := range function.Instrs {
			if instruction.x86SDKLiteral != nil && owners.literal == nil {
				if _, valid := certifiedSDKLiteralAccess(instruction, "amd64"); !valid {
					t.Fatal("actual original SDK literal certificate was not valid before use")
				}
				owners.literal, literalOriginal = instruction.x86SDKLiteral, instruction
			}
			if instruction.x86NumericalRead != nil && owners.numerical == nil {
				if _, _, valid := numericalCertifiedRead(instruction, "amd64"); !valid {
					t.Fatal("actual original mutable SDK read certificate was not valid before use")
				}
				owners.numerical, numericalOriginal = instruction.x86NumericalRead, instruction
			}
		}
	}
	if owners.literal == nil || owners.numerical == nil {
		t.Fatal("actual complete SDK source lost either independent owner class")
	}
	for _, api := range []string{"text", "module", "go-module"} {
		t.Run("actual-original-SDK/"+api, func(t *testing.T) {
			if ir := numericalFamilyTranslate(t, api, pkg, original, bound); ir == "" {
				t.Fatal("actual original whole-SDK valid certificate control emitted no module")
			}
		})
	}
	t.Cleanup(func() {
		if _, valid := certifiedSDKLiteralAccess(literalOriginal, "amd64"); !valid {
			t.Error("foreign-source negative revoked or mutated the independent original literal owner")
		}
		if _, _, valid := numericalCertifiedRead(numericalOriginal, "amd64"); !valid {
			t.Error("foreign-source negative revoked or mutated the independent original numerical owner")
		}
	})
	return owners
}

func (owners x86NativeFamilyOwnerOracle) checkProgram(t *testing.T, text, declaration, target string) {
	t.Helper()
	goAssemblerOracleOutput(t, "amd64", text, "", true)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("baseline/"+api, func(t *testing.T) {
			if _, err := x86ScalarFPBitViewAPI(t, text, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
				t.Fatal("complete legitimate source baseline was relabeled or rejected", err)
			}
		})
	}
	program, err := Parse(ArchAMD64, text)
	if err != nil {
		t.Fatal(err)
	}
	programPackage := mustGoPackage(t, "ownercontrol", "package ownercontrol\n"+declaration)
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	signatures, err := goSigsForAsmFile(programPackage, program, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	program, err = normalizeX86RawFile(program, "amd64")
	if err != nil {
		t.Fatal("complete original raw source identity was not retained", err)
	}
	function := program.Funcs[0]
	expected := x86ScalarLaneInstruction(t, target)
	ordinal := -1
	for index, instruction := range function.Instrs {
		if instruction.Op == expected.Op && reflect.DeepEqual(instruction.Args, expected.Args) {
			if ordinal != -1 {
				t.Fatal("ambiguous complete original native-family consumer")
			}
			ordinal = index
		}
	}
	if ordinal == -1 {
		t.Fatal("complete original native-family instruction was not retained", target)
	}
	consumer := func(function Func) *amd64Ctx {
		return newX86Ctx(new(strings.Builder), function, signatures["Value"], resolve, signatures,
			"amd64", "x86_64-unknown-linux-gnu", false)
	}
	if err := consumer(function).checkLoweredScalarFPResultInitialization(); err != nil {
		t.Fatal("complete unmodified private source control failed before ownership mutation", err)
	}
	for _, owner := range []string{"SDKLiteral", "NumericalRead"} {
		t.Run(owner+"/original-certificate-on-foreign-source", func(t *testing.T) {
			changed := function
			changed.Instrs = append([]Instr(nil), function.Instrs...)
			instruction := &changed.Instrs[ordinal]
			if owner == "SDKLiteral" {
				instruction.x86SDKLiteral = owners.literal
				if _, valid := certifiedSDKLiteralAccess(*instruction, "amd64"); valid {
					t.Fatal("actual original SDK certificate was forged into a foreign source")
				}
			} else {
				instruction.x86NumericalRead = owners.numerical
				if _, _, valid := numericalCertifiedRead(*instruction, "amd64"); valid {
					t.Fatal("actual original mutable-read certificate was forged into a foreign source")
				}
			}
			if err := consumer(changed).checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("family native continuation bypassed the existing owner's invalid complete identity", owner, err)
			}
			if !reflect.DeepEqual(program.Funcs[0], function) {
				t.Fatal("negative changed the complete original source control")
			}
		})
	}
}
