package main

import "testing"

// Only immutable compiler artifacts may be shared. The existing dynamic
// SharedCacheKeepsSourcesIndependent regression owns the package/observer
// separation; these checks bind the wide runtime plan to that same setup.
func TestFixedLocalPackedRuntimeCacheIsOwnedByTheWholeTarget(t *testing.T) {
	fixedLocalRequireOwnedObjectCache(t, "amd64_fixed_local_packed_runtime_test.go", "fixedLocalPackedRuntimeAPIs")
}

func TestFixedLocalPackedRuntimePreparesLazyToolsBeforeSourceCapture(t *testing.T) {
	fixedLocalRequirePreparedTools(t, "amd64_fixed_local_packed_runtime_test.go", "fixedLocalPackedRuntimeAPIs")
}
