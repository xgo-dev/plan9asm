package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86PackedStringFullFlagsObservationNeedsIndependentDFAndID(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range strings.Fields("PCMPESTRI PCMPESTRM PCMPISTRI PCMPISTRM VPCMPESTRI VPCMPESTRM VPCMPISTRI VPCMPISTRM") {
			t.Run(arch+"/"+op, func(t *testing.T) {
				declaration, source := x86PackedStringVectorFixture([]x86PackedStringVectorCase{{op, 0, 1, false, 0}}, arch)
				original := strings.Replace(source, x86PackedStringStatusObservation(arch, true), x86PackedStringStatusObservation(arch, false), 1)
				if original == source {
					t.Fatal("original unrefined FLAGS observation was not retained")
				}
				x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], original)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, original, declaration, arch, x86AddressMemoryTargets(arch)[0], api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("six arithmetic flags supplied unknown incoming DF/ID bits", api, err)
					}
				}
			})
		}
	}
}
