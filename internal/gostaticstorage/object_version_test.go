package gostaticstorage

import "testing"

func TestObjectVersionRetainsExactAuditedProducer(t *testing.T) {
	for _, version := range []string{"go1.27.1", "go1.27.2", "go1.27.3"} {
		object := []byte("go object linux arm64 " + version + " GOARM64=v8.0\n!\nbody")
		if body, err := objectBody(object, "linux/arm64"); err != nil || string(body) != "body" {
			t.Fatalf("audited object %s: %q %v", version, body, err)
		}
		if err := ValidateObjectVersion(object, "linux/arm64", version); err != nil {
			t.Fatal(err)
		}
		for _, other := range []string{"", "go1.27.1", "go1.27.2", "go1.27.3"} {
			if other != version && ValidateObjectVersion(object, "linux/arm64", other) == nil {
				t.Fatalf("object %s borrowed producer %s", version, other)
			}
		}
		if ValidateObjectVersion(object, "linux/amd64", version) == nil {
			t.Fatal("object borrowed a different target")
		}
	}
	for _, version := range []string{"go1.27.4", "go1.28.1", "go1.27.3rc1", "go1.27.3-custom", "devel go1.27.3"} {
		object := []byte("go object linux arm64 " + version + "\n!\nbody")
		if _, err := objectBody(object, "linux/arm64"); err == nil {
			t.Fatalf("unaudited object %s accepted", version)
		}
	}
}
