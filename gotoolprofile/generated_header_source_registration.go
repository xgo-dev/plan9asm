package gotoolprofile

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
)

// NativeHeaderSourceRules registers only the audited closed header property
// model. It does not authenticate package bytes or create a compiler/ABI role.
type NativeHeaderSourceRules struct {
	Protocol     string            `json:"protocol"`
	GoVersion    string            `json:"go_version"`
	SourceSHA256 map[string]string `json:"source_sha256"`
}

const nativeHeaderSourceRulesProtocol = "closed_native_gc_header_rules_v1"

var nativeHeaderSourceRegistration = map[string]map[string]string{
	"go1.20.14": {
		"src/cmd/compile/internal/amd64/galign.go":    "c0e78fbcf303739d661616a6d2fb58ffdd91477a1830dd37de12b42a32b77a92",
		"src/cmd/compile/internal/arm/galign.go":      "36bf9475606bf6da4971dc044212cf9a0332971e53a50ec1889d4e84a3dfbc91",
		"src/cmd/compile/internal/arm64/galign.go":    "8240611dc6d7933d40898ddf0abdede0e30433118fc1cc9343b70b5835a4a541",
		"src/cmd/compile/internal/gc/export.go":       "b0181c71f9857cec9a3d589e81f885cc54a58be100919df79b7efee6df40eb12",
		"src/cmd/compile/internal/gc/main.go":         "297d56f5e9b5cd3248d0cf685e39aeebd5513473532049d6748039de45f98ac8",
		"src/cmd/compile/internal/ir/package.go":      "83c8cfe6681a3f26ffbec558aeb33e5eea424bd073ff23036b28ad2a0c4ff4d7",
		"src/cmd/compile/internal/noder/helpers.go":   "d4264706539b096bc106b941d1ef37b653167efc47b7b477dd90f7754f38762b",
		"src/cmd/compile/internal/noder/object.go":    "ae6c179b51a7e53c89350aa893f79c28ccee438334167549f6c80ede5de8e483",
		"src/cmd/compile/internal/noder/reader.go":    "7ee01a4dfb3b2bc42027eab9fd5979d3a86be2fe0b0ce76cb9e9e7dcb7a58442",
		"src/cmd/compile/internal/noder/writer.go":    "32ea040e4cfae703c9f9337f66ed293fd15a6d6ed7d7b9a625efe061c924e760",
		"src/cmd/compile/internal/typecheck/const.go": "8c14d900fbeb4d3c5c46e89893f30bdf2e3c59b99ffe8729388dc8ad826e5bdd",
		"src/cmd/compile/internal/typecheck/dcl.go":   "b35fee55dce8983c7f45157138db0771239f86c533465af26fda76a00bd09323",
		"src/cmd/compile/internal/types/size.go":      "85a99896588d88b72026e1adbe82781612e61a42be5ad68150d5791f5d866558",
		"src/cmd/compile/internal/types/type.go":      "e32891b13866cf3f96ed5b8570ac73f4f123cb1e0cfe9ecd3f38693c165676e9",
		"src/cmd/compile/internal/types/universe.go":  "d4fb6989ac1e1d8d0d4afa40a747e295f7b428e368b44a3763b7e3c5a44cec56",
		"src/cmd/compile/internal/wasm/ssa.go":        "3b6909e83756647d1a8ae67f4d934461362cbb7dd9e1cc12b16fa89922e2c215",
		"src/cmd/compile/internal/x86/galign.go":      "6f5939341fb89f0357346667d282c5ce622ef58ce467c08fe6f0641edf60a1b7",
		"src/cmd/internal/sys/arch.go":                "2ffa390a665fcd3ddf11b02310b47f6fd991a7a6ac875a732a4fc85632912498",
		"src/go/constant/value.go":                    "e8aeb7562c1620179d2cf9846ec6c087ed3fb01c58b991934e8beb2c83da9ea9",
		"src/go/types/builtins.go":                    "7b58bbeb58d133bb75f86a4af901d7f39de56cfcb5dd620a9529ee737e9ce689",
		"src/go/types/resolver.go":                    "12f7e9a0a113467c8e4627a6e3d61962da3adbaa1fa957bc39e1ba01ceb1c975",
		"src/go/types/sizes.go":                       "dae5a89f838c84cb8e2952862f7b7e23075465fb025853a7cd30d7722d3b1058",
		"src/go/types/universe.go":                    "c3bb75082a60d673a8fe1ed1fbccb0065dac51a4c0f38c265b1c07fb35ed47a0",
	},
	"go1.27.1": {
		"src/cmd/compile/internal/amd64/galign.go":    "c0e78fbcf303739d661616a6d2fb58ffdd91477a1830dd37de12b42a32b77a92",
		"src/cmd/compile/internal/arm/galign.go":      "ebb81e7128fd8e4f2dd9a4d0820d86423334c13c04b433aee4f436bd1e60bae3",
		"src/cmd/compile/internal/arm64/galign.go":    "8240611dc6d7933d40898ddf0abdede0e30433118fc1cc9343b70b5835a4a541",
		"src/cmd/compile/internal/gc/export.go":       "74ac999b6213246274723e2b87d1b24aa76a7da7ac559c8a6fd574f1c34ba5cd",
		"src/cmd/compile/internal/gc/main.go":         "630003459bf6c39ee0c795be1de24d184ae27ddc432a923a4ae7ec86256ad05c",
		"src/cmd/compile/internal/ir/package.go":      "c4fd54d2ced005e666ff4e1f3db996af140cb34eadd2f0aaebefd010400c720a",
		"src/cmd/compile/internal/noder/helpers.go":   "05afcf568b75e953a0e4ed8687c81f7f775ca891a220d10f119f2431721cedbc",
		"src/cmd/compile/internal/noder/reader.go":    "d141b8f59f973af2a3c3cd22f9d3d8857c802d684074e0d15131cf8f778bb7d9",
		"src/cmd/compile/internal/noder/writer.go":    "7ed9f0326c5794128110aaa796bb870ce5155a3e34fd47d5546cbeaa6269e52c",
		"src/cmd/compile/internal/typecheck/const.go": "4cc3238f8b9afff771bf72a2753682f84f0b0be2d750179b0bb6d9daedfb8d4c",
		"src/cmd/compile/internal/types/size.go":      "d32090d796ae53dc8d1430e206b9e98aee8e1e1b2407f952aa7fdd64b8fb9ad5",
		"src/cmd/compile/internal/types/type.go":      "50e7b9332dd700aebbd6999f9a5d1bc17e8d24e3f21b06b3c30a628ea751e696",
		"src/cmd/compile/internal/types/universe.go":  "410606b5ecb3e404bf3e6bc76d13b26c789dc0fb509d41b4b4ff95f158a8c40b",
		"src/cmd/compile/internal/wasm/ssa.go":        "56d8eefdfecf0d2aaeeefcf73664b209deb487606db8184c8d9975e98df75def",
		"src/cmd/compile/internal/x86/galign.go":      "6f5939341fb89f0357346667d282c5ce622ef58ce467c08fe6f0641edf60a1b7",
		"src/cmd/internal/sys/arch.go":                "07ac549fe63e0df269822d5b10b704ca710489b2aa25e176df5d98f2a2c6b8f2",
		"src/go/constant/value.go":                    "9a4afa576639c98ec2be2602e4b6aecb24760a3dbd386cc8ce8bb5c1d5c4895e",
		"src/go/types/builtins.go":                    "5a85992f8539b3f64fd99efd827d5a6a518ffd379a8f75f3e5cc5f1efc0fe240",
		"src/go/types/gcsizes.go":                     "129d9bc7a0fd76b818a8631fcbe8063a87236aa9ca6775280de29d96cf5ef6f7",
		"src/go/types/resolver.go":                    "7c419b0161a73e57065e334a1a6fa186f782a7b7c616d635818ee93faa8d0bbf",
		"src/go/types/sizes.go":                       "d097bbaba4237da84f93fd67c9133bcf2df7b429351283774895b7b909da5e93",
		"src/go/types/universe.go":                    "5b59136965ddfb9aadec2f2a37165beece517445ce3871c3616a71088c63ba13",
	},
}

func CaptureNativeHeaderSourceRules(root, version string) (*NativeHeaderSourceRules, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("native header source rules require an audited actual SDK")
	}
	actualVersion, err := readInstrumentationRegistration(filepath.Join(root, "VERSION"))
	if err != nil || strings.SplitN(string(actualVersion), "\n", 2)[0] != version {
		return nil, fmt.Errorf("native header source rules differ from actual SDK VERSION: %v", err)
	}
	registration := nativeHeaderSourceHashes(version)
	if registration == nil {
		return nil, &nativeHeaderUnsupportedDomain{"actual SDK has no registered native header property query model"}
	}
	proof := &NativeHeaderSourceRules{Protocol: nativeHeaderSourceRulesProtocol, GoVersion: version, SourceSHA256: make(map[string]string)}
	for name := range registration {
		data, err := readInstrumentationRegistration(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return nil, err
		}
		proof.SourceSHA256[name] = bytesSHA256(data)
	}
	if err := ValidateNativeHeaderSourceRules(proof, version); err != nil {
		return nil, err
	}
	return proof, nil
}

func ValidateNativeHeaderSourceRules(proof *NativeHeaderSourceRules, version string) error {
	wanted := nativeHeaderSourceHashes(version)
	if proof == nil || proof.Protocol != nativeHeaderSourceRulesProtocol || proof.GoVersion != version || wanted == nil || !reflect.DeepEqual(wanted, proof.SourceSHA256) {
		return fmt.Errorf("native generated-header rule registration is missing, changed or unaudited")
	}
	return nil
}

func nativeHeaderSourceHashes(version string) map[string]string {
	if version != "go1.27.2" && version != "go1.27.3" {
		return nativeHeaderSourceRegistration[version]
	}
	// Go 1.27.2 adds method-order fields to unified export data without changing
	// these header layout rules or their complete source inventory.
	// Go 1.27.3 has byte-identical sources for all 22 registered rules. Keep
	// the two changes from 1.27.1 pinned separately, without admitting future
	// unaudited patches or duplicating the unchanged source registration.
	result := make(map[string]string, len(nativeHeaderSourceRegistration["go1.27.1"]))
	for name, hash := range nativeHeaderSourceRegistration["go1.27.1"] {
		result[name] = hash
	}
	result["src/cmd/compile/internal/noder/reader.go"] = "10051996ac541466c4f0f3ccfb3ca7181c38726050d49d2c113ab784119d8be6"
	result["src/cmd/compile/internal/noder/writer.go"] = "53550393cf60bd31892e18a4a79715670a7243289445b57919faa69163a256e0"
	return result
}

func RecheckNativeHeaderSourceRules(root string, proof *NativeHeaderSourceRules) error {
	if proof == nil {
		return fmt.Errorf("native generated-header rule recheck lacks its capture")
	}
	actual, err := CaptureNativeHeaderSourceRules(root, proof.GoVersion)
	if err != nil || !reflect.DeepEqual(actual, proof) {
		return fmt.Errorf("actual native generated-header SDK rules changed: %v", err)
	}
	return nil
}
