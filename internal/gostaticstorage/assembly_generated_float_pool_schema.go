package gostaticstorage

// Bind the actual FCONST producer, IEEE definition attributes, Hash64 writer,
// namespaces and relocation kinds through the existing live guarded reader.
// Offline metadata alone authenticates no source or executable tool identity.
var generatedFloatPoolSourceRoles = map[string]string{
	"src/cmd/internal/obj/x86/obj6.go":     "01fda250221982020a6cd368d95c47f8eda1a987a4113425fe28de3dade992d3",
	"src/cmd/internal/obj/sym.go":          "2bb2646a6ccff23aa42d8c4960be7cf82af5570ae5a83a1a355b7b822ee2149d",
	"src/cmd/internal/obj/objfile.go":      "803546227c02cf46bfa4158be3dfd8067e7457f4e4f78349cb6d42c700b2fcb7",
	"src/cmd/internal/goobj/objfile.go":    "caf835a17e23aa02cae9bda6e8723d8be359846fc4453bd53f3a3947744b938a",
	"src/cmd/internal/objabi/symkind.go":   "de287864b7ff9a3614becc538cbabdccdecc030a848aad5d5bbef6ec7ec5c225",
	"src/cmd/internal/objabi/reloctype.go": "49bebd30a27d05a24de77398ab524dfbeb0630c8b88c06646c1e4734e4f1fc9d",
}

// GeneratedFloatPoolSources checks observation-only producer source identity.
// It does not make generated pools eligible for literal or numerical readers.
func GeneratedFloatPoolSources(version string, read func(string) ([]byte, error)) error {
	if version != "go1.27.1" && version != "go1.27.2" && version != "go1.27.3" || read == nil {
		return contextError("unregistered generated float-pool source/schema")
	}
	for role, expected := range generatedFloatPoolSourceRoles {
		data, err := read(role)
		if err != nil {
			return err
		}
		if digest(data) != expected {
			return contextError("generated float-pool producer source differs from the registered actual SDK")
		}
	}
	return nil
}
