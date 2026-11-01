package gostaticstorage

import "strings"

// These inputs bind the complete SEH producer, object writer/schema, symbol
// traversal, listing writer and builtin namespace. A schema pin is SHA256 of
// the eight lowercase file SHA256s, joined with LF in this exact order.
var windowsUnwindSourceRoles = [...]string{
	"src/cmd/internal/obj/x86/seh.go",
	"src/cmd/internal/goobj/objfile.go",
	"src/cmd/internal/obj/objfile.go",
	"src/cmd/internal/obj/sym.go",
	"src/cmd/internal/obj/plist.go",
	"src/cmd/internal/objabi/symkind.go",
	"src/cmd/internal/objabi/reloctype.go",
	builtinSourceRole,
}

type windowsUnwindSchema struct {
	sources, builtin string
	kind, aux, flag2 uint8
	relocationMax    uint16
	listingAlignment bool
}

// Go 1.23 introduced the listed, hashed SEH definitions observed here. Earlier
// package-local SEH objects are a different role. None of these registrations
// expands the generic Go 1.27 compiler archive or DATA observation contracts.
func windowsUnwindFormat(version string) (windowsUnwindSchema, bool) {
	var schema windowsUnwindSchema
	switch version {
	case "go1.23.12":
		schema = windowsUnwindSchema{
			"616a38a54d0f9782a2266c8dc04d75ab77a3c5c3db4b9d07339617ec73320b1e",
			"a49b363c40c3d3bd8b477e72bf53a6ffab49220559a64260b806ba9f44ff8ae2",
			20, 13, 16, 91, false,
		}
	case "go1.24.13":
		schema = windowsUnwindSchema{
			"1282c8c5aa1e786f73c3e754d2cc238d8dd662ff00d0ecb70b65784e142c40d9",
			"aa40a9079a0ce71b9f44eea97b54271eaee0ab869f5cb6c5d00e3c157aee951f",
			24, 14, 16, 95, false,
		}
	case "go1.25.14":
		schema = windowsUnwindSchema{
			"812ce8a0cdfa179c7375b510044ceef1a511cddcc419d250d8f80fe328dbe7e9",
			"acb5795f8a9a22d3f44dc1993ac269e11733c971a6f4dee83d96343f2de527a8",
			25, 14, 16, 99, false,
		}
	case "go1.26.8", "go1.26.9", "go1.26.10":
		schema = windowsUnwindSchema{
			"5428221d6c92317f9d80594122a4eef9f82abb9865499fd39d92522d72cd79a9",
			"7dc5b3b8dff057b9f7e8c75afacecadc238f7538995f161bd55576ad448a4101",
			25, 14, 16, 103, false,
		}
	case "go1.27.1", "go1.27.2", "go1.27.3":
		schema = windowsUnwindSchema{
			"836468efd5f9e8b71f828b4c0e5b7fc5fc2eb99842b5f16ca5b47c1eb611b86e",
			"8f38ef757cdebb27963ee9befe24dd8041b86d217937db30f13e4d3d91207311",
			25, 14, 0, 106, true,
		}
	default:
		return schema, false
	}
	return schema, true
}

// WindowsAMD64UnwindSources reads every required actual SDK input through the
// live factory's guarded reader. It returns the matching builtin source, not
// authority to use a caller-provided schema or grant native unwind behavior.
func WindowsAMD64UnwindSources(version string, read func(string) ([]byte, error)) ([]byte, error) {
	schema, ok := windowsUnwindFormat(version)
	if !ok || read == nil {
		return nil, contextError("unregistered Windows unwind producer")
	}
	var hashes []string
	var builtin []byte
	for _, role := range windowsUnwindSourceRoles {
		data, err := read(role)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, digest(data))
		if role == builtinSourceRole {
			builtin = data
		}
	}
	if digest([]byte(strings.Join(hashes, "\n"))) != schema.sources {
		return nil, contextError("Windows unwind producer/schema differs from actual pinned SDK")
	}
	return builtin, nil
}
