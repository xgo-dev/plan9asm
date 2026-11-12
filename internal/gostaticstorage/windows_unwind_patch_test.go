package gostaticstorage

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestWindowsUnwindAuditedPatchProducerSchema(t *testing.T) {
	// Independently compared complete sources at golang/go tags go1.26.9
	// (2ae494ef9fb90e0da0073c31800ba38870249994) and go1.26.10
	// (4e8c85f5319d999bfd7617fdc191631e5634e3c5). Every role is byte-identical;
	// another patch number alone does not register its producer or object schema.
	inputs := []struct{ role, sha256 string }{
		{"src/cmd/internal/obj/x86/seh.go", "552514c6d05a8943a77527e2a9b9d993c31200b659cc871d194239d970879f22"},
		{"src/cmd/internal/goobj/objfile.go", "d33fd9dd676fed9d8c10c31af6b728112413dabfe8ba34b928126af27ced40b0"},
		{"src/cmd/internal/obj/objfile.go", "e839648ca9e4fccfae70e089e3f836f5d6fd82228ffe1712cd4423169cb0f6ee"},
		{"src/cmd/internal/obj/sym.go", "4695f8b4d4084314634a0173fb5a94c76f81b5a28137025143a54b7139dfb529"},
		{"src/cmd/internal/obj/plist.go", "59ef5068404a639eeb87c1c706b7b79c46884d22c459d2c7458c793220ec4afc"},
		{"src/cmd/internal/objabi/symkind.go", "de287864b7ff9a3614becc538cbabdccdecc030a848aad5d5bbef6ec7ec5c225"},
		{"src/cmd/internal/objabi/reloctype.go", "eca81bff6d4f34b3b6f0b0fcf06f0e40b293cef68a0b81be3829094b56d8a822"},
		{"src/cmd/internal/goobj/builtinlist.go", "7dc5b3b8dff057b9f7e8c75afacecadc238f7538995f161bd55576ad448a4101"},
	}
	var roles, hashes []string
	for _, input := range inputs {
		roles = append(roles, input.role)
		hashes = append(hashes, input.sha256)
	}
	if !reflect.DeepEqual(windowsUnwindSourceRoles[:], roles) {
		t.Fatal("Windows unwind source-role census changed", windowsUnwindSourceRoles)
	}
	want := windowsUnwindSchema{
		sources:          fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(hashes, "\n")))),
		builtin:          inputs[len(inputs)-1].sha256,
		kind:             25,
		aux:              14,
		flag2:            16,
		relocationMax:    103,
		listingAlignment: false,
	}
	for _, version := range []string{"go1.26.8", "go1.26.9", "go1.26.10"} {
		t.Run(version, func(t *testing.T) {
			got, ok := windowsUnwindFormat(version)
			if !ok || got != want {
				t.Fatalf("audited role-specific producer/schema missing or changed: %#v, registered=%t", got, ok)
			}
			// This role must not admit historical compiler archives to the
			// unrelated current-only object reader, even for a Windows target.
			for _, target := range []string{"windows/amd64", "linux/amd64", "darwin/amd64"} {
				object := []byte("go object " + strings.ReplaceAll(target, "/", " ") + " " + version + "\n!\n\x00go120ld")
				if _, err := objectBody(object, target); !errors.Is(err, ErrContext) {
					t.Fatal("a Windows unwind producer registered a generic compiler archive", target, err)
				}
			}
		})
	}
}

func TestWindowsUnwindCurrentPatchProducerSchema(t *testing.T) {
	// The complete eight source roles are byte-identical in Go 1.27.2 and
	// 1.27.3. Keep their independent file census rather than admitting a minor
	// version range or deriving expected identity from the production schema.
	inputs := []struct{ role, sha256 string }{
		{"src/cmd/internal/obj/x86/seh.go", "3e7b9a27ed35bb507c39685d3aff193c758566baa4a392816cdf4d19e8419e67"},
		{"src/cmd/internal/goobj/objfile.go", "caf835a17e23aa02cae9bda6e8723d8be359846fc4453bd53f3a3947744b938a"},
		{"src/cmd/internal/obj/objfile.go", "803546227c02cf46bfa4158be3dfd8067e7457f4e4f78349cb6d42c700b2fcb7"},
		{"src/cmd/internal/obj/sym.go", "2bb2646a6ccff23aa42d8c4960be7cf82af5570ae5a83a1a355b7b822ee2149d"},
		{"src/cmd/internal/obj/plist.go", "50c121d6c72c356c605176e02bce549dd6e0e8107af6c0eed467f7b3adb418e3"},
		{"src/cmd/internal/objabi/symkind.go", "de287864b7ff9a3614becc538cbabdccdecc030a848aad5d5bbef6ec7ec5c225"},
		{"src/cmd/internal/objabi/reloctype.go", "49bebd30a27d05a24de77398ab524dfbeb0630c8b88c06646c1e4734e4f1fc9d"},
		{"src/cmd/internal/goobj/builtinlist.go", "8f38ef757cdebb27963ee9befe24dd8041b86d217937db30f13e4d3d91207311"},
	}
	var roles, hashes []string
	for _, input := range inputs {
		roles = append(roles, input.role)
		hashes = append(hashes, input.sha256)
	}
	if !reflect.DeepEqual(windowsUnwindSourceRoles[:], roles) {
		t.Fatal("Windows unwind source-role census changed", windowsUnwindSourceRoles)
	}
	want := windowsUnwindSchema{
		sources:          fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(hashes, "\n")))),
		builtin:          inputs[len(inputs)-1].sha256,
		kind:             25,
		aux:              14,
		flag2:            0,
		relocationMax:    106,
		listingAlignment: true,
	}
	for _, version := range []string{"go1.27.1", "go1.27.2", "go1.27.3"} {
		t.Run(version, func(t *testing.T) {
			if got, ok := windowsUnwindFormat(version); !ok || got != want {
				t.Fatalf("audited Windows producer/schema missing or changed: %#v, registered=%t", got, ok)
			}
		})
	}
	object := []byte("go object windows amd64 go1.27.4\n!\n\x00go120ld")
	if _, err := objectBody(object, "windows/amd64"); !errors.Is(err, ErrContext) {
		t.Fatal("Windows observation registered an unaudited generic object format", err)
	}
}

func TestWindowsUnwindPatchProducerSourcesFailClosed(t *testing.T) {
	for _, version := range []string{
		"", "go1.26", "go1.26.7", "go1.26.11", "go1.26.100", "go1.26.10rc1", "devel go1.26.10",
		"go1.27.4", "go1.27.3rc1", "go1.27.3-custom", "devel go1.27.3",
	} {
		t.Run(version, func(t *testing.T) {
			called := false
			data, err := WindowsAMD64UnwindSources(version, func(string) ([]byte, error) {
				called = true
				return nil, nil
			})
			if !errors.Is(err, ErrContext) || called || data != nil {
				t.Fatal("an unaudited patch gained or read a producer source role", called, data, err)
			}
		})
	}
	for _, version := range []string{"go1.26.8", "go1.26.9", "go1.26.10", "go1.27.3"} {
		t.Run(version, func(t *testing.T) {
			if data, err := WindowsAMD64UnwindSources(version, nil); !errors.Is(err, ErrContext) || data != nil {
				t.Fatal("missing guarded source reader gained a role", data, err)
			}
			var read []string
			data, err := WindowsAMD64UnwindSources(version, func(role string) ([]byte, error) {
				read = append(read, role)
				return []byte("different actual source: " + role), nil
			})
			if !errors.Is(err, ErrContext) || data != nil || !reflect.DeepEqual(read, windowsUnwindSourceRoles[:]) {
				t.Fatal("changed source was admitted or the complete census was not read", read, data, err)
			}
			for index, role := range windowsUnwindSourceRoles {
				t.Run(role, func(t *testing.T) {
					want := errors.New("guarded source unavailable")
					var read []string
					data, err := WindowsAMD64UnwindSources(version, func(name string) ([]byte, error) {
						read = append(read, name)
						if name == role {
							return nil, want
						}
						return []byte("different actual source: " + name), nil
					})
					if !errors.Is(err, want) || data != nil || !reflect.DeepEqual(read, windowsUnwindSourceRoles[:index+1]) {
						t.Fatal("guarded source error or exact role traversal changed", read, data, err)
					}
				})
			}
		})
	}
}
