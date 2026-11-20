package plan9asm

import (
	"crypto/sha256"
	"encoding/hex"
)

// These exact source facts bind the selected386 compiler's ABIInternal body,
// disabled register-ABI wrappers and the linker's ABIToVersion normalization.
// They do not assert a native entry, GC map, memory extent or non-return role.
var x86GoPanicTerminal386Schema = map[string]string{
	"src/internal/buildcfg/exp.go":                "5825d40b47471bca28a00c0c19215930efef22b758120b6d972da1a955f21fa0",
	"src/cmd/internal/obj/link.go":                "918978ac6b04e839f5222282b2526230c6ca95b50248456ba9f73e9083258e1f",
	"src/cmd/compile/internal/ir/func.go":         "185b5f070932048b28c173de6d770ee7415b0490c1130623ab8b69dadd2d8387",
	"src/cmd/compile/internal/ssagen/abi.go":      "35b5cea74c417723ff4778cea5175d3a7bdd9c58584af163229e9624a1ee709c",
	"src/cmd/link/internal/sym/symbol.go":         "46ff2bfa4dec86d6c77c09fa5ef8f11f13d49ba55aee30507f4102a9750cfb04",
	"src/cmd/link/internal/loader/loader.go":      "b85dcd0c6f017f2455ba2d553bc20fd8b29105a98e4b6a6a0293ff32f6eca204",
	"src/cmd/link/internal/ld/main.go":            "0fe8ad02e4b244bbaa82f14a86aaa005155e43c9ba7492c98c9e9650b86cd41e",
	"src/cmd/internal/objabi/reloctype_string.go": "6e1a80d8c32bcb6c599a75e08a1e69d54f88a52941a0c831fb37b8e11ce3fc28",
}

func x86GoPanicTerminalCompilerSourceRoles() map[string]string {
	roles := make(map[string]string, len(x86GoPanicTerminal386Schema)+len(numericalCompilerAliasSchema))
	for role, hash := range numericalCompilerAliasSchema {
		roles[role] = hash
	}
	for role, hash := range x86GoPanicTerminal386Schema {
		roles[role] = hash
	}
	return roles
}

func x86GoPanicTerminalCompilerSources(env map[string]string, read func(string) ([]byte, error)) error {
	version := env["GOVERSION"]
	if version != "go1.27.1" && version != "go1.27.2" && version != "go1.27.3" ||
		env["GOOS"] != "linux" || env["GOARCH"] != "386" ||
		env["GO386"] != "sse2" || env["GOEXPERIMENT"] != "" || read == nil {
		return sdkASMDataContext("panic association lacks its selected non-regabi386 source/profile")
	}
	for role, expected := range x86GoPanicTerminalCompilerSourceRoles() {
		data, err := read(role)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(data)
		if hex.EncodeToString(hash[:]) != expected {
			return sdkASMDataContext("panic compiler/linker producer source differs: %s", role)
		}
	}
	return nil
}
