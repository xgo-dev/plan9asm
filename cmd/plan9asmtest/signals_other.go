//go:build !unix

package main

import "os"

func cancellationSignals() []os.Signal { return []os.Signal{os.Interrupt} }
