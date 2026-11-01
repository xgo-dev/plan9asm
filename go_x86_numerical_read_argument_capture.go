package plan9asm

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// These exact selected Go1.27 rules derive an ABI assignment; this is not an
// assertion that an absent wrapper physically contains an assignment table.
// Every role is retained by the same live source/tool input guard.
var amd64GoArgumentCompilerSchema = map[string]string{
	"src/cmd/compile/internal/abi/abiutils.go": "35b17262580c3c9e180a5f7c03e26813678fad8b50bac090c68b8f3ade57d030",
	"src/cmd/compile/internal/types/size.go":   "d32090d796ae53dc8d1430e206b9e98aee8e1e1b2407f952aa7fdd64b8fb9ad5",
	"src/cmd/compile/internal/ssa/config.go":   "064c69f9217f704adf726980edb6cb7fd1fda99a9204f573db54a620ba891746",
	"src/cmd/compile/internal/ssa/opGen.go":    "4d0aab8c3eb9b1d438c38ced71852f7f3d3ffc25e2c57efa9f36d7d00cb86f32",
	"src/cmd/compile/internal/ssagen/ssa.go":   "c4049961202dbfdf8b281b857a55e62ddbab04e109c1722aecbbf0a794983f81",
	"src/cmd/compile/internal/ssagen/abi.go":   "35b5cea74c417723ff4778cea5175d3a7bdd9c58584af163229e9624a1ee709c",
	"src/internal/buildcfg/exp.go":             "5825d40b47471bca28a00c0c19215930efef22b758120b6d972da1a955f21fa0",
	"src/internal/abi/abi_amd64.go":            "b8d763278ba88322c8a7eb1b0aec4ec04063e0a86c2940eeee865a04b12b78c7",
}

func (source *GoX86NumericalReadSource) captureAMD64GoArgumentRules() error {
	if source.role != numericalSBSDKSource || source.sdkAssemblyJoin() == nil || source.guard.env["GOARCH"] != "amd64" {
		return nil
	}
	needed := false
	for _, fn := range source.file.Funcs {
		needed = needed || strings.HasSuffix(fn.Sym, "<ABIInternal>")
	}
	if !needed {
		return nil
	}
	rules := make(map[string]string, len(amd64GoArgumentCompilerSchema))
	for role, expected := range amd64GoArgumentCompilerSchema {
		data, err := source.guard.read(filepath.Join(source.guard.env["GOROOT"], filepath.FromSlash(role)))
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != expected {
			return numericalSBContext("selected argument ABI compiler rule differs: %s", role)
		}
		rules[role] = expected
	}
	source.native.ArgumentRules = rules
	return nil
}
