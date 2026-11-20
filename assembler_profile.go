package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// GoAssemblerDefinesForEnvironment returns the CPU and target macros passed by
// cmd/go for an explicitly observed target environment. Unlike
// GoAssemblerDefines it never substitutes host/default CPU values. The caller
// must supply the actual go env values used for source selection and assembly.
//
// GOEXPERIMENT macros are deliberately not included here: cmd/asm adds those
// only to packages permitted by its package-special registration, not to
// ordinary external packages merely because an experiment is enabled.
func GoAssemblerDefinesForEnvironment(goos, goarch string, environment map[string]string) ([]string, error) {
	if goos == "" || environment["GOOS"] != goos || environment["GOARCH"] != goarch {
		return nil, fmt.Errorf("assembler profile target does not match its observed environment")
	}
	version := strings.Split(strings.TrimPrefix(environment["GOVERSION"], "go1."), ".")[0]
	minor, err := strconv.Atoi(version)
	if !strings.HasPrefix(environment["GOVERSION"], "go1.") || err != nil || minor < 20 || minor > 27 {
		return nil, fmt.Errorf("assembler profile requires an audited observed Go 1.20–1.27 GOVERSION")
	}
	defines := []string{"GOOS_" + goos, "GOARCH_" + goarch}
	key := map[string]string{"386": "GO386", "amd64": "GOAMD64", "arm": "GOARM", "arm64": "GOARM64", "wasm": "GOWASM"}[goarch]
	if key == "" {
		return nil, fmt.Errorf("unsupported assembler profile architecture %q", goarch)
	}
	value, exists := environment[key]
	if !exists {
		return nil, fmt.Errorf("assembler profile is missing observed %s", key)
	}
	switch goarch {
	case "386":
		if value != "sse2" && value != "softfloat" {
			return nil, fmt.Errorf("invalid observed GO386 %q", value)
		}
		defines = append(defines, "GO386_"+value)
	case "amd64":
		if value != "v1" && value != "v2" && value != "v3" && value != "v4" {
			return nil, fmt.Errorf("invalid observed GOAMD64 %q", value)
		}
		// Unlike cumulative build tags, cmd/go defines only the chosen level.
		defines = append(defines, "GOAMD64_"+value)
	case "arm":
		parts := strings.Split(value, ",")
		if len(parts) > 2 || parts[0] != "5" && parts[0] != "6" && parts[0] != "7" || len(parts) == 2 && (minor < 22 || parts[1] != "softfloat" && parts[1] != "hardfloat") {
			return nil, fmt.Errorf("invalid observed GOARM %q", value)
		}
		if minor < 22 {
			break // Go 1.20–1.21 asmArgs does not define GOARM_*.
		}
		for level := parts[0][0]; level >= '5'; level-- {
			defines = append(defines, "GOARM_"+string(level))
		}
	case "arm64":
		// Before Go 1.23 GOARM64 is absent (go env reports an empty string).
		if minor < 23 && value == "" {
			break
		}
		if minor < 23 {
			return nil, fmt.Errorf("GOARM64 profile requires Go 1.23 or newer")
		}
		lse, err := goARM64ProfileLSE(value)
		if err != nil {
			return nil, err
		}
		if lse {
			defines = append(defines, "GOARM64_LSE")
		}
	case "wasm":
		for _, option := range strings.Split(value, ",") {
			if option != "" && option != "satconv" && option != "signext" {
				return nil, fmt.Errorf("invalid observed GOWASM %q", value)
			}
		}
		// cmd/go does not register a GOWASM_* assembler macro.
	}
	return defines, nil
}

func goARM64ProfileLSE(value string) (bool, error) {
	lse := false
	for {
		if strings.HasSuffix(value, ",lse") {
			lse = true
			value = strings.TrimSuffix(value, ",lse")
		} else if strings.HasSuffix(value, ",crypto") {
			value = strings.TrimSuffix(value, ",crypto")
		} else {
			break
		}
	}
	if len(value) != 4 || value[0] != 'v' || value[2] != '.' || value[1] != '8' && value[1] != '9' || value[3] < '0' || value[3] > '9' || value[1] == '9' && value[3] > '5' {
		return false, fmt.Errorf("invalid observed GOARM64 %q", value)
	}
	return lse || value != "v8.0", nil
}
