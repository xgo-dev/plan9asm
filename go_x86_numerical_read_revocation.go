package plan9asm

// Revoke permanently invalidates this original source's read bindings without
// disposing any artifact or invoking borrowed contexts/owners. Owning adapters
// can revoke publication immediately while deferring Close until callbacks end.
// It creates no source, numerical read, linked minimum or entry permission.
func (source *GoX86NumericalReadSource) Revoke() error {
	if source == nil || source.identity != source {
		return numericalSBContext("foreign numerical source cannot revoke original bindings")
	}
	source.revoked.Store(true)
	return nil
}
