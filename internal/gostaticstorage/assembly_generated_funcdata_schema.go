package gostaticstorage

// These actual source hashes bind the reserved FUNCDATA rewrite, generated
// content-addressable identity, writer hash/namespace and ordered auxiliaries.
// Source identity is distinct from the offline object observation, which cannot
// authenticate its caller or construct a live source/storage capability.
var generatedFuncdataSourceRoles = map[string]string{
	"src/cmd/internal/obj/plist.go":      "50c121d6c72c356c605176e02bce549dd6e0e8107af6c0eed467f7b3adb418e3",
	"src/cmd/internal/obj/sym.go":        "2bb2646a6ccff23aa42d8c4960be7cf82af5570ae5a83a1a355b7b822ee2149d",
	"src/cmd/internal/obj/objfile.go":    "803546227c02cf46bfa4158be3dfd8067e7457f4e4f78349cb6d42c700b2fcb7",
	"src/cmd/internal/hash/hash.go":      "8574000887ab8f24695355bc9247f189a332698db89c63b2ac13a6149ca36350",
	"pkg/include/funcdata.h":             "bd73b7c27a4d3f8560a5a9dd1a5da54e0e48572311a744cf7843e709b7f2a015",
	"src/cmd/internal/goobj/objfile.go":  "caf835a17e23aa02cae9bda6e8723d8be359846fc4453bd53f3a3947744b938a",
	"src/cmd/internal/objabi/symkind.go": "de287864b7ff9a3614becc538cbabdccdecc030a848aad5d5bbef6ec7ec5c225",
}

// GeneratedFuncdataSources reads the required producer facts through the live
// factory's guarded reader. It supplies no DATA, GC, native or numerical role.
func GeneratedFuncdataSources(version string, read func(string) ([]byte, error)) error {
	if version != "go1.27.1" && version != "go1.27.2" && version != "go1.27.3" || read == nil {
		return contextError("unregistered generated FUNCDATA source/schema")
	}
	for role, expected := range generatedFuncdataSourceRoles {
		data, err := read(role)
		if err != nil {
			return err
		}
		if digest(data) != expected {
			return contextError("generated FUNCDATA producer source differs from the registered actual SDK")
		}
	}
	return nil
}
