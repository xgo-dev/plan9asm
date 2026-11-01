package gotoolchain

// AuditedGo127 identifies releases whose observation formats have been
// reviewed. It is only a version gate: consumers must still bind the actual
// SDK sources, tools and object bytes. Unknown patches need a fresh audit.
func AuditedGo127(version string) bool {
	return version == "go1.27.1" || version == "go1.27.2" || version == "go1.27.3"
}
