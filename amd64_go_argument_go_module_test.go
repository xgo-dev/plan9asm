package plan9asm

import (
	"errors"
	"reflect"
	"testing"
)

func TestAMD64GoArgumentGoModuleGraphSignatureTransport(t *testing.T) {
	// This model exercises only the existing signature/graph comparison seam.
	// It cannot pass a public source consumer without the real live producer.
	fn, bound, entry := amd64ArgumentBoundModel(t, "a string, f float32", "MOVQ BX,AX")
	original, err := numericalCloneSignatures(entry.owner.options.Sigs)
	if err != nil {
		t.Fatal(err)
	}
	derived := map[string]FuncSig{bound.Name: numericalSignatureShape(bound)}
	if derived[bound.Name].amd64GoArguments != nil {
		t.Fatal("a fresh language signature retained private entry metadata")
	}

	transported, err := numericalGoSignatures(entry.owner, derived)
	if err != nil || transported[bound.Name].amd64GoArguments != entry ||
		!entry.valid(fn, transported[bound.Name], "amd64") {
		t.Fatal("the authenticated signature identity was lost before the graph consumer", err)
	}
	if derived[bound.Name].amd64GoArguments != nil ||
		!reflect.DeepEqual(entry.owner.options.Sigs, original) {
		t.Fatal("transport changed the caller's fresh signatures or the owner's inventory")
	}

	file := &File{Arch: ArchAMD64, Funcs: []Func{fn}}
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: transported, ResolveSym: func(string) string { return bound.Name }}
	graph, _, err := newX86DirectTailGraph(file, options, nil, "amd64")
	if err != nil || graph.signatures[bound.Name].amd64GoArguments != entry {
		t.Fatal("a graph snapshot replaced its existing bound argument identity", err)
	}
	if err := graph.verify(file, options); err != nil {
		t.Fatal("the exact signature snapshot did not survive the final graph comparison", err)
	}

	options.Sigs = derived
	if !errors.Is(graph.verify(file, options), ErrProbeNeedsContext) {
		t.Fatal("the final graph comparison accepted language shapes in place of private identities")
	}
	if !graph.revoked.Load() {
		t.Fatal("signature substitution did not revoke the graph")
	}

	for _, name := range []string{"missing", "extra", "name", "argument", "result", "layout"} {
		t.Run(name, func(t *testing.T) {
			changed, err := numericalCloneSignatures(derived)
			if err != nil {
				t.Fatal(err)
			}
			sig := changed[bound.Name]
			switch name {
			case "missing":
				delete(changed, bound.Name)
			case "extra":
				changed["unrelated"] = sig
			case "name":
				sig.Name = "unrelated"
			case "argument":
				sig.Args[1] = I32
			case "result":
				sig.Ret = Ptr
			case "layout":
				sig.Frame.Params[0].Offset++
			}
			if name != "missing" && name != "extra" {
				changed[bound.Name] = sig
			}
			if _, err := numericalGoSignatures(entry.owner, changed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("Go signature transport accepted changed declarations/layout", err)
			}
		})
	}

	t.Run("supplied-token-is-not-authority", func(t *testing.T) {
		forged := *entry
		sig := derived[bound.Name]
		sig.amd64GoArguments = &forged
		transported, err := numericalGoSignatures(entry.owner, map[string]FuncSig{bound.Name: sig})
		if err != nil || transported[bound.Name].amd64GoArguments != entry ||
			transported[bound.Name].amd64GoArguments == &forged {
			t.Fatal("caller metadata replaced the original live binding identity", err)
		}
	})
}
